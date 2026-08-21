// SPDX-License-Identifier: Apache-2.0

// Command connector-template is a copy-me starting point for a new Ajar connector
// in Go. Make the two edits marked EDIT 1 and EDIT 2 below, then run it.
//
// See a sealed event right now — no key, no NATS, no feed:
//
//	echo '{"lat":26.4,"lon":50.9,"alt_m":11000,"quality":0.9}' | go run ./connector-template -dry-run
//
// Run for real (key from scripts/gen-connector-key.sh; mTLS materials + endpoint
// issued by your operator):
//
//	AJAR_TLS_CA=ca.pem AJAR_TLS_CERT=client.pem AJAR_TLS_KEY=client.key \
//	AJAR_SIGNING_SEED=connector.seed AJAR_SOURCE_ID=acme-radar-1 \
//	NATS_URL=tls://nats.you.mil:443  go run ./connector-template
//
// Production behaviour (built in, no edits): a malformed/un-mappable record is
// logged and skipped, publish errors are non-fatal (auto-reconnect), and setting
// AJAR_HEALTH_ADDR exposes GET /healthz + GET /metrics.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/promaka/ajar-connectors/go/ajarconnector"
	"github.com/promaka/ajar-connectors/go/eventpb"
)

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ EDIT 1 — describe ONE record from your feed.                              ║
// ║ (These fields match the demo JSON above; change them to match your data.) ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
type MyRecord struct {
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`
	AltM    float64 `json:"alt_m"`
	Quality float64 `json:"quality"`
}

// ╔═══════════════════════════════════════════════════════════════════════════╗
// ║ EDIT 2 — map your record into a canonical Event.                          ║
// ║ Use the entity_type your operator assigned. Add .Attribute(k, v) only for ║
// ║ attributes that type's ontology schema defines.                          ║
// ╚═══════════════════════════════════════════════════════════════════════════╝
func toEvent(sourceID string, r MyRecord) (*eventpb.Event, error) {
	return ajarconnector.NewEventBuilder(sourceID, "mim:aircraft").
		NewID().
		Now().
		Location(r.Lat, r.Lon, r.AltM).
		Confidence(r.Quality).
		Build()
}

// ─────────────────────────────────────────────────────────────────────────────
// You usually don't need to touch anything below this line.
// ─────────────────────────────────────────────────────────────────────────────

var (
	publishedTotal     atomic.Uint64
	skippedTotal       atomic.Uint64
	publishErrorsTotal atomic.Uint64
)

func main() {
	dryRun := flag.Bool("dry-run", false, "build + seal + print, do not publish")
	flag.Parse()

	sourceID := envOr("AJAR_SOURCE_ID", "demo-connector")
	prefix := envOr("AJAR_INGEST_PREFIX", "ajar.ingest")
	natsURL := envOr("NATS_URL", "nats://127.0.0.1:4222")
	subject := prefix + "." + sourceID

	key, err := ajarconnector.SigningKeyFromSeed(loadSeed(*dryRun))
	if err != nil {
		log.Fatalf("signing key: %v", err)
	}

	spawnHealth() // no-op unless AJAR_HEALTH_ADDR is set

	var nc *nats.Conn
	if *dryRun {
		log.Println("[connector] -dry-run: building + sealing, not publishing")
	} else {
		log.Printf("[connector] connecting to NATS at %s", natsURL)
		nc, err = natsConnect(natsURL)
		if err != nil {
			log.Fatalf("connect NATS: %v", err)
		}
		defer nc.Close()
	}
	log.Printf("[connector] source_id=%s  subject=%s", sourceID, subject)

	// Your feed: by default, newline-delimited JSON on stdin. Swap this scanner
	// for your TCP socket / file / API / serial port — the rest stays the same.
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		// Resilient: a bad record is logged and skipped, never fatal.
		var rec MyRecord
		if err := json.Unmarshal(line, &rec); err != nil {
			log.Printf("[connector] skip: malformed record: %v", err)
			skippedTotal.Add(1)
			continue
		}
		ev, err := toEvent(sourceID, rec)
		if err != nil {
			log.Printf("[connector] skip: cannot map record: %v", err)
			skippedTotal.Add(1)
			continue
		}
		canonical, err := ajarconnector.CanonicalBytes(ev)
		if err != nil {
			log.Printf("[connector] skip: canonical encode: %v", err)
			skippedTotal.Add(1)
			continue
		}
		sealed := ajarconnector.Seal(canonical, key)
		if nc != nil {
			if err := nc.Publish(subject, sealed); err != nil {
				log.Printf("[connector] publish error (continuing): %v", err)
				publishErrorsTotal.Add(1)
				continue
			}
		}
		publishedTotal.Add(1)
		tag := ""
		if nc == nil {
			tag = "  [dry-run]"
		}
		fmt.Printf("%s -> %s (%d sealed bytes)%s\n", ev.GetId(), subject, len(sealed), tag)
	}
	if err := sc.Err(); err != nil {
		log.Fatalf("read stdin: %v", err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// natsConnect dials NATS, enabling mTLS when AJAR_TLS_CA / AJAR_TLS_CERT /
// AJAR_TLS_KEY are all set (production; client-cert CN = source_id) and falling
// back to plaintext for local dev. Retries the initial connect and auto-reconnects.
func natsConnect(url string) (*nats.Conn, error) {
	opts := []nats.Option{
		nats.RetryOnFailedConnect(true),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(time.Second),
	}
	if ca, cert, k := os.Getenv("AJAR_TLS_CA"), os.Getenv("AJAR_TLS_CERT"), os.Getenv("AJAR_TLS_KEY"); ca != "" && cert != "" && k != "" {
		log.Println("[connector] mTLS enabled (client cert = source identity)")
		opts = append(opts, nats.ClientCert(cert, k), nats.RootCAs(ca))
	} else {
		log.Println("[connector] no AJAR_TLS_* set — connecting without TLS (dev only)")
	}
	return nats.Connect(url, opts...)
}

// loadSeed reads the 32-byte Ed25519 seed from the file named by
// AJAR_SIGNING_SEED. In -dry-run with no seed set, falls back to a dev seed so
// you can try it instantly — never used for real publishing.
func loadSeed(dryRun bool) []byte {
	if path := os.Getenv("AJAR_SIGNING_SEED"); path != "" {
		seed, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read AJAR_SIGNING_SEED %s: %v", path, err)
		}
		return seed
	}
	if dryRun {
		log.Println("[connector] no AJAR_SIGNING_SEED set — ephemeral throwaway key (dry-run only)")
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			log.Fatalf("minting an ephemeral seed: %v", err)
		}
		return seed
	}
	log.Fatal("set AJAR_SIGNING_SEED to your 32-byte key file (see scripts/gen-connector-key.sh)")
	return nil
}

// spawnHealth starts a tiny health/metrics HTTP server if AJAR_HEALTH_ADDR is set
// (e.g. 0.0.0.0:9090). GET /healthz -> liveness; GET /metrics -> Prometheus text.
func spawnHealth() {
	addr := os.Getenv("AJAR_HEALTH_ADDR")
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w,
			"# TYPE ajar_connector_published_total counter\najar_connector_published_total %d\n"+
				"# TYPE ajar_connector_skipped_total counter\najar_connector_skipped_total %d\n"+
				"# TYPE ajar_connector_publish_errors_total counter\najar_connector_publish_errors_total %d\n",
			publishedTotal.Load(), skippedTotal.Load(), publishErrorsTotal.Load())
	})
	log.Printf("[connector] health/metrics on http://%s/healthz and /metrics", addr)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil { //nolint:gosec // example endpoint
			log.Printf("[connector] health endpoint disabled: %v", err)
		}
	}()
}
