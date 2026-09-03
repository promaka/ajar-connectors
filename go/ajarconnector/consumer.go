// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/ed25519"
	"log"

	"google.golang.org/protobuf/proto"

	"github.com/promaka/ajar-connectors/go/eventpb"
)

// Delivery is one verified governed event, as delivered: the decoded Event
// (its signature verified - a consumer never sees one that did not), the
// rendered payload bytes, and the subject it arrived on.
type Delivery struct {
	Event   *eventpb.Event
	Payload []byte
	Subject string
}

// ConsumerGuards are the skip rules a deriving platform needs: its own
// events come back out of egress like everything else, and without a guard
// the loop assesses its own output forever.
type ConsumerGuards struct {
	// SkipSourceIDs drops events published under these identities.
	SkipSourceIDs map[string]bool
	// SkipDerived drops any event carrying a "model" attribute - anything
	// produced by an AI/analytics platform.
	SkipDerived bool
}

// ConsumerStats counts what the verifying consumer did. Rejected events were
// dropped inside the loop and never reached the handler.
type ConsumerStats struct {
	Accepted uint64
	Rejected uint64
	Skipped  uint64
}

// VerifyingHandler wraps a per-event handler so that verification is
// structurally unskippable: the returned function is given raw egress
// messages (payload + subject, e.g. from a NATS subscription) and calls
// `handle` only for events whose Ed25519 signature verifies under the
// deployment's egress key. Everything else is counted and dropped.
//
// The SDK deliberately has no transport dependency, so the subscription is
// yours; the security-critical middle is this function's:
//
//	sub, _ := nc.Subscribe("ajar.egress.geojson.>", func(m *nats.Msg) {
//	    deliver(m.Data, m.Subject)
//	})
//
// where deliver came from:
//
//	deliver := ajarconnector.VerifyingHandler(egressKey, guards, stats, handle)
func VerifyingHandler(
	egressKey ed25519.PublicKey,
	guards ConsumerGuards,
	stats *ConsumerStats,
	handle func(Delivery),
) func(data []byte, subject string) {
	return func(data []byte, subject string) {
		canonical, err := Verify(data, egressKey)
		if err != nil {
			stats.Rejected++
			log.Printf("[ajar] rejected an event that does not verify under the egress key (total rejected: %d)", stats.Rejected)
			return
		}
		var event eventpb.Event
		if err := proto.Unmarshal(canonical, &event); err != nil {
			stats.Rejected++
			log.Printf("[ajar] rejected: verified bytes are not an event: %v", err)
			return
		}
		if guards.SkipSourceIDs[event.SourceId] {
			stats.Skipped++
			return
		}
		if guards.SkipDerived {
			for _, a := range event.Attributes {
				if a.Key == "model" {
					stats.Skipped++
					return
				}
			}
		}
		stats.Accepted++
		handle(Delivery{Event: &event, Payload: event.Payload, Subject: subject})
	}
}
