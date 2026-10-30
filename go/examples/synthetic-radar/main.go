// SPDX-License-Identifier: Apache-2.0

// Command synthetic-radar streams synthetic mim:aircraft tracks into a locally
// running Ajar Core so a developer can watch the full path
// connector -> NATS -> Core -> audit + Postgres. Each tick it builds, seals and
// publishes one event per track. The examples are their own Go module, so the
// nats.go dependency stays out of the SDK.
//
// Run (from go/examples):
//
//	go run ./synthetic-radar                 # publish to nats://127.0.0.1:4222
//	go run ./synthetic-radar -dry-run        # build+seal+print, no NATS
//	go run ./synthetic-radar -dry-run -ticks 3   # bounded (CI)
//
// Env overrides: NATS_URL, AJAR_SOURCE_ID, AJAR_INGEST_PREFIX.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/promaka/ajar-connectors/go/ajarconnector"
)

// Process counters, surfaced at /metrics when AJAR_HEALTH_ADDR is set.
var (
	publishedTotal     atomic.Uint64
	publishErrorsTotal atomic.Uint64
)

// spawnHealth serves GET /healthz (liveness) and GET /metrics (Prometheus text)
// on AJAR_HEALTH_ADDR (e.g. 0.0.0.0:9090), and does nothing when it is unset.
func spawnHealth() {
	addr := os.Getenv("AJAR_HEALTH_ADDR")
	if addr == "" {
		return
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w,
			"# TYPE ajar_connector_published_total counter\n"+
				"ajar_connector_published_total %d\n"+
				"# TYPE ajar_connector_publish_errors_total counter\n"+
				"ajar_connector_publish_errors_total %d\n",
			publishedTotal.Load(), publishErrorsTotal.Load())
	})
	log.Printf("[synthetic-radar] health/metrics on http://%s/healthz and /metrics", addr)
	go func() {
		if err := http.ListenAndServe(addr, mux); err != nil { //nolint:gosec // example endpoint
			log.Printf("[synthetic-radar] health endpoint disabled: %v", err)
		}
	}()
}

// loadSeed reads the Ed25519 seed file named by AJAR_SIGNING_SEED (the demo
// stack mints one); unset, it mints an ephemeral seed for this run, whose
// events a registry refuses.
func loadSeed() []byte {
	if path := os.Getenv("AJAR_SIGNING_SEED"); path != "" {
		seed, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("read AJAR_SIGNING_SEED %s: %v", path, err)
		}
		return seed
	}
	log.Println("[synthetic-radar] no AJAR_SIGNING_SEED — ephemeral throwaway key")
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		log.Fatalf("minting an ephemeral seed: %v", err)
	}
	return seed
}

// track is a synthetic aircraft moving over a region (around the Gulf, matching
// the corpus fixtures). heading is in radians; speedDeg is degrees per tick.
type track struct {
	label    string
	lat      float64
	lon      float64
	altM     float64
	heading  float64
	speedDeg float64
}

// advance moves the track one tick, reflecting off the region bounds.
func (t *track) advance() {
	t.lat += math.Cos(t.heading) * t.speedDeg
	t.lon += math.Sin(t.heading) * t.speedDeg
	if t.lat < 25.0 || t.lat > 28.0 {
		t.heading = -t.heading
		t.lat = math.Max(25.0, math.Min(28.0, t.lat))
	}
	if t.lon < 49.0 || t.lon > 52.0 {
		t.heading = math.Pi - t.heading
		t.lon = math.Max(49.0, math.Min(52.0, t.lon))
	}
}

// EDIT: replace these synthetic tracks and the advance() loop in main() with
// reads from your feed (socket, file, API or serial), one record per iteration.
func initialTracks() []*track {
	const pi = math.Pi
	return []*track{
		{label: "AJX-01", lat: 26.4, lon: 50.9, altM: 11000, heading: 0.3 * pi, speedDeg: 0.012},
		{label: "AJX-02", lat: 25.6, lon: 51.4, altM: 9500, heading: 1.1 * pi, speedDeg: 0.009},
		{label: "AJX-03", lat: 27.2, lon: 49.7, altM: 12500, heading: 1.7 * pi, speedDeg: 0.015},
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	dryRun := flag.Bool("dry-run", false, "build + seal + print, do not publish")
	maxTicks := flag.Int("ticks", 0, "run a bounded number of ticks then exit (0 = forever)")
	flag.Parse()

	sourceID := envOr("AJAR_SOURCE_ID", "demo-connector")
	prefix := envOr("AJAR_INGEST_PREFIX", "ajar.ingest")
	natsURL := envOr("NATS_URL", "nats://127.0.0.1:4222")

	// sourceID must equal Core's AJAR_SOURCE_ID; Core's ingest listens on subject.
	subject := prefix + "." + sourceID
	key := ed25519.NewKeyFromSeed(loadSeed())

	spawnHealth()

	var nc *nats.Conn
	if *dryRun {
		log.Println("[synthetic-radar] -dry-run: building + sealing events, not publishing")
	} else {
		log.Printf("[synthetic-radar] connecting to NATS at %s", natsURL)
		var err error
		// NATS may start after this pod.
		opts := []nats.Option{
			nats.RetryOnFailedConnect(true),
			nats.MaxReconnects(-1),
			nats.ReconnectWait(time.Second),
		}
		// mTLS when AJAR_TLS_CA/CERT/KEY are all set (the client-cert CN is the
		// source_id; the Helm chart mounts them under /etc/ajar/tls), else plaintext.
		if ca, cert, key := os.Getenv("AJAR_TLS_CA"), os.Getenv("AJAR_TLS_CERT"), os.Getenv("AJAR_TLS_KEY"); ca != "" && cert != "" && key != "" {
			log.Println("[synthetic-radar] mTLS enabled (client cert = source identity)")
			opts = append(opts, nats.ClientCert(cert, key), nats.RootCAs(ca))
		} else {
			log.Println("[synthetic-radar] no AJAR_TLS_* set — connecting without TLS (dev only)")
		}
		nc, err = nats.Connect(natsURL, opts...)
		if err != nil {
			log.Fatalf("connect NATS: %v", err)
		}
		defer nc.Close()
	}

	log.Printf("[synthetic-radar] source_id=%s  subject=%s", sourceID, subject)
	log.Printf("[synthetic-radar] entity_type=mim:aircraft, no attributes (seed ontology has " +
		"no aircraft attribute schema), Core stamps received_at")
	log.Printf("[synthetic-radar] Ctrl-C to stop.")

	tracks := initialTracks()
	for tick := 0; ; tick++ {
		for _, t := range tracks {
			t.advance()

			// 1. Normalize (synthesised here). EDIT: map one record to an Event. Use
			// the entity_type your operator registered, and add .Attribute(k, v) for
			// attributes its ontology declares.
			event, err := ajarconnector.NewEventBuilder(sourceID, "mim:aircraft").
				NewID().
				Now().
				Location(t.lat, t.lon, t.altM).
				Confidence(0.9).
				PolicyTag("air-defence").
				Build()
			if err != nil {
				log.Fatalf("build event: %v", err)
			}

			// 2. Seal.
			canonical, err := ajarconnector.CanonicalBytes(event)
			if err != nil {
				log.Fatalf("canonical bytes: %v", err)
			}
			sealed := ajarconnector.Seal(canonical, key)

			// 3. Publish. The broker's duplicate window drops retransmissions keyed on the
			// Nats-Msg-Id header; a failed publish is logged and skipped.
			if nc != nil {
				msg := &nats.Msg{
					Subject: subject,
					Data:    sealed,
					Header:  nats.Header(ajarconnector.IngestHeaders(event)),
				}
				if err := nc.PublishMsg(msg); err != nil {
					log.Printf("[synthetic-radar] publish error (continuing): %v", err)
					publishErrorsTotal.Add(1)
					continue
				}
			}
			publishedTotal.Add(1)

			suffix := ""
			if nc == nil {
				suffix = "  [dry-run]"
			}
			fmt.Printf("%s %6s  lat=%8.4f lon=%8.4f alt=%7.0fm  -> %s (%d sealed bytes)%s\n",
				event.GetId(), t.label, t.lat, t.lon, t.altM, subject, len(sealed), suffix)
		}

		// Flush before idling, and before exiting after -ticks.
		if nc != nil {
			if err := nc.Flush(); err != nil {
				log.Fatalf("flush: %v", err)
			}
		}

		if *maxTicks > 0 && tick+1 >= *maxTicks {
			break
		}
		time.Sleep(time.Second)
	}
}
