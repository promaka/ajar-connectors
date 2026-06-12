// SPDX-License-Identifier: Apache-2.0

// Package cot is a reference connector: Cursor-on-Target (CoT) XML <-> canonical
// Ajar event. It is a teaching example, not a production CoT stack — the XML
// handling is deliberately minimal (no XML dependency) so the data flow stays
// readable. It mirrors the Rust cot-connector, including the
// canonical -> CoT -> canonical round-trip test.
package cot

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/promaka/ajar-connectors/go/ajarconnector"
	"github.com/promaka/ajar-connectors/go/eventpb"
)

// Connector is a CoT connector bound to one source identity. CoT messages carry
// no Ajar source identity, so it comes from configuration (and matches the
// connector's signing-key profile).
type Connector struct {
	sourceID string
}

// New returns a CoT connector that signs as sourceID.
func New(sourceID string) *Connector { return &Connector{sourceID: sourceID} }

// Normalize turns a CoT message into a canonical event.
func (c *Connector) Normalize(native []byte) (*eventpb.Event, error) {
	xml := string(native)

	eventAttrs, ok := tagAttrs(xml, "event")
	if !ok {
		return nil, fmt.Errorf("malformed CoT: no <event>")
	}
	uid, ok := eventAttrs["uid"]
	if !ok {
		return nil, fmt.Errorf("malformed CoT: event/@uid")
	}
	cotType, ok := eventAttrs["type"]
	if !ok {
		return nil, fmt.Errorf("malformed CoT: event/@type")
	}
	t, ok := eventAttrs["time"]
	if !ok {
		return nil, fmt.Errorf("malformed CoT: event/@time")
	}

	b := ajarconnector.NewEventBuilder(c.sourceID, cotTypeToEntity(cotType)).
		ID(uid).
		Timestamp(t)

	if point, ok := tagAttrs(xml, "point"); ok {
		latStr, okLat := point["lat"]
		lonStr, okLon := point["lon"]
		if okLat && okLon {
			lat, err := strconv.ParseFloat(latStr, 64)
			if err != nil {
				return nil, fmt.Errorf("malformed CoT: point/@lat")
			}
			lon, err := strconv.ParseFloat(lonStr, 64)
			if err != nil {
				return nil, fmt.Errorf("malformed CoT: point/@lon")
			}
			hae := 0.0
			if haeStr, ok := point["hae"]; ok {
				if v, err := strconv.ParseFloat(haeStr, 64); err == nil {
					hae = v
				}
			}
			b = b.Location(lat, lon, hae)
		}
	}

	return b.Build()
}

// Target implements ajarconnector.OutboundProfile.
func (c *Connector) Target() string { return "Cursor-on-Target" }

// Slug implements ajarconnector.OutboundProfile.
func (c *Connector) Slug() string { return "tak-cot" }

// Version implements ajarconnector.OutboundProfile.
func (c *Connector) Version() string { return "0.1.0" }

// ModeledFields implements ajarconnector.OutboundProfile.
func (c *Connector) ModeledFields() []string {
	return []string{"id", "entity_type", "timestamp", "location"}
}

// LossyFields implements ajarconnector.OutboundProfile.
func (c *Connector) LossyFields() []string {
	// CoT has no home for these, so an outbound CoT render drops them.
	return []string{"source_id", "payload", "policy_tags", "confidence", "attributes"}
}

// Render implements ajarconnector.OutboundProfile.
func (c *Connector) Render(event *eventpb.Event) []byte {
	cotType := entityToCot(event.GetEntityType())
	var lat, lon, hae float64
	if g := event.GetLocation(); g != nil {
		lat, lon, hae = g.GetLatitude(), g.GetLongitude(), g.GetAltitudeM()
	}
	xml := fmt.Sprintf(
		`<event version="2.0" uid="%s" type="%s" time="%s" start="%s" stale="%s">`+
			`<point lat="%s" lon="%s" hae="%s" ce="9999999.0" le="9999999.0"/>`+
			`</event>`,
		event.GetId(), cotType, event.GetTimestamp(), event.GetTimestamp(), event.GetTimestamp(),
		formatFloat(lat), formatFloat(lon), formatFloat(hae),
	)
	return []byte(xml)
}

// formatFloat renders a float the way Go parses it back exactly (shortest
// round-trippable form), so location survives the round trip.
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}

// cotTypeToEntity maps a CoT type code to a namespaced entity type. Unknown
// codes fall back to a vendor extension namespace so nothing is silently dropped.
func cotTypeToEntity(cotType string) string {
	switch cotType {
	case "a-f-A", "a-f-A-M-F-Q":
		return "mim:aircraft"
	case "a-f-S":
		return "mim:vessel"
	case "a-f-G-U-C-D":
		return "mim:drone"
	default:
		return "x:cot:" + strings.ReplaceAll(cotType, "-", "_")
	}
}

// entityToCot is the inverse of cotTypeToEntity for the canonical mappings.
func entityToCot(entityType string) string {
	switch entityType {
	case "mim:aircraft":
		return "a-f-A"
	case "mim:vessel":
		return "a-f-S"
	case "mim:drone":
		return "a-f-G-U-C-D"
	default:
		if rest, ok := strings.CutPrefix(entityType, "x:cot:"); ok {
			return strings.ReplaceAll(rest, "_", "-")
		}
		return "a-u-G"
	}
}

// tagAttrs returns the attribute map of the first <tag ...> (or <tag ... />).
func tagAttrs(xml, tag string) (map[string]string, bool) {
	open := "<" + tag
	start := strings.Index(xml, open)
	if start < 0 {
		return nil, false
	}
	after := xml[start+len(open):]
	if after == "" {
		return nil, false
	}
	// Next rune must be space, '>' or '/', so we don't match <eventfoo for <event.
	switch after[0] {
	case ' ', '\t', '\n', '\r', '>', '/':
	default:
		return nil, false
	}
	end := strings.IndexByte(after, '>')
	if end < 0 {
		return nil, false
	}
	attrStr := strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(after[:end]), "/"))
	return parseAttrs(attrStr), true
}

// parseAttrs parses a run of key="value" XML attributes.
func parseAttrs(s string) map[string]string {
	m := map[string]string{}
	i, n := 0, len(s)
	for i < n {
		for i < n && isSpace(s[i]) {
			i++
		}
		keyStart := i
		for i < n && s[i] != '=' && !isSpace(s[i]) {
			i++
		}
		if i >= n || s[i] != '=' {
			break
		}
		key := s[keyStart:i]
		i++ // '='
		if i >= n || s[i] != '"' {
			break
		}
		i++ // opening quote
		valStart := i
		for i < n && s[i] != '"' {
			i++
		}
		if i >= n {
			break
		}
		m[key] = s[valStart:i]
		i++ // closing quote
	}
	return m
}

func isSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' }
