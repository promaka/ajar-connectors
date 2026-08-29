// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import "github.com/promaka/ajar-connectors/go/eventpb"

// NatsMsgIDHeader is the NATS header the ingest broker dedupes on. Publish
// every sealed event with this header set to the event's Id: the broker keeps
// a duplicate window keyed on it, so a retransmission or reconnect race is
// dropped instead of stored twice. The SDK deliberately has no transport
// dependency, so this is the contract as data; your NATS client sets it.
const NatsMsgIDHeader = "Nats-Msg-Id"

// IngestHeaders returns the headers an ingest publish must carry for event,
// shaped so nats.Header can adopt it directly:
//
//	msg := &nats.Msg{Subject: subject, Data: sealed,
//	    Header: nats.Header(ajarconnector.IngestHeaders(event))}
func IngestHeaders(event *eventpb.Event) map[string][]string {
	return map[string][]string{NatsMsgIDHeader: {event.Id}}
}
