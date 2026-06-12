// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/rand"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/promaka/ajar-connectors/go/eventpb"
)

// Contract limits (§3).
const (
	MaxAttributes = 128
	MaxPolicyTags = 64
	schemaVersion = "v1"
)

// EventBuilder constructs a canonical Event so a connector author cannot emit a
// non-canonical one by accident: it auto-sorts attributes, rejects duplicate
// keys, enforces required fields and limits, and offers UUIDv7 / RFC 3339
// helpers. received_at is intentionally absent — Ajar stamps its own clock.
//
// Setters return the builder for chaining; the first error encountered is held
// and returned by Build.
type EventBuilder struct {
	sourceID              string
	entityType            string
	id                    string
	timestamp             string
	location              *eventpb.GeoPoint
	payload               []byte
	policyTags            []string
	confidence            float64
	attributes            []*eventpb.Attribute
	strictEntityNamespace bool
}

// NewEventBuilder starts a builder for the given source identity and entity type.
// entity_type is expected to be namespaced (mim:<type> or x:<vendor>:<type>);
// see AllowUnnamespacedEntityType to opt out.
func NewEventBuilder(sourceID, entityType string) *EventBuilder {
	return &EventBuilder{
		sourceID:              sourceID,
		entityType:            entityType,
		strictEntityNamespace: true,
	}
}

// ID sets the event id explicitly. Prefer NewID unless carrying an id through
// from an upstream system.
func (b *EventBuilder) ID(id string) *EventBuilder { b.id = id; return b }

// NewID generates a fresh UUIDv7 id (time-ordered, recommended).
func (b *EventBuilder) NewID() *EventBuilder { b.id = newUUIDv7(); return b }

// Timestamp sets the source observation timestamp (RFC 3339).
func (b *EventBuilder) Timestamp(ts string) *EventBuilder { b.timestamp = ts; return b }

// Now sets the source observation timestamp to now (RFC 3339, UTC).
func (b *EventBuilder) Now() *EventBuilder {
	b.timestamp = time.Now().UTC().Format(time.RFC3339)
	return b
}

// Location sets an optional geospatial position.
func (b *EventBuilder) Location(latitude, longitude, altitudeM float64) *EventBuilder {
	b.location = &eventpb.GeoPoint{Latitude: latitude, Longitude: longitude, AltitudeM: altitudeM}
	return b
}

// Payload sets the opaque payload bytes. Keep this small — a reference or
// metadata, never bulk media.
func (b *EventBuilder) Payload(payload []byte) *EventBuilder { b.payload = payload; return b }

// PolicyTag adds one policy tag (e.g. class:secret, rel:DEU).
func (b *EventBuilder) PolicyTag(tag string) *EventBuilder {
	b.policyTags = append(b.policyTags, tag)
	return b
}

// Confidence sets the detection/correlation confidence in [0.0, 1.0].
func (b *EventBuilder) Confidence(confidence float64) *EventBuilder {
	b.confidence = confidence
	return b
}

// Attribute adds one structured attribute. Order does not matter — Build sorts
// by key and rejects duplicate keys.
func (b *EventBuilder) Attribute(key, value string) *EventBuilder {
	b.attributes = append(b.attributes, &eventpb.Attribute{Key: key, Value: value})
	return b
}

// AllowUnnamespacedEntityType disables the default mim:/x: namespace check.
func (b *EventBuilder) AllowUnnamespacedEntityType() *EventBuilder {
	b.strictEntityNamespace = false
	return b
}

// Build validates invariants and produces the canonical Event.
func (b *EventBuilder) Build() (*eventpb.Event, error) {
	if b.id == "" {
		return nil, fmt.Errorf("ajarconnector: missing required field: id")
	}
	if b.timestamp == "" {
		return nil, fmt.Errorf("ajarconnector: missing required field: timestamp")
	}
	if b.sourceID == "" {
		return nil, fmt.Errorf("ajarconnector: missing required field: source_id")
	}
	if b.entityType == "" {
		return nil, fmt.Errorf("ajarconnector: missing required field: entity_type")
	}
	if b.strictEntityNamespace && !isNamespaced(b.entityType) {
		return nil, fmt.Errorf("ajarconnector: entity_type %q is not namespaced as mim:<type> or x:<vendor>:<type>", b.entityType)
	}
	if b.confidence < 0.0 || b.confidence > 1.0 {
		return nil, fmt.Errorf("ajarconnector: confidence %v is outside [0.0, 1.0]", b.confidence)
	}
	if len(b.policyTags) > MaxPolicyTags {
		return nil, fmt.Errorf("ajarconnector: too many policy tags: %d (max %d)", len(b.policyTags), MaxPolicyTags)
	}
	if len(b.attributes) > MaxAttributes {
		return nil, fmt.Errorf("ajarconnector: too many attributes: %d (max %d)", len(b.attributes), MaxAttributes)
	}

	// Canonical rule: attributes sorted by key, unique.
	attrs := make([]*eventpb.Attribute, len(b.attributes))
	copy(attrs, b.attributes)
	sort.SliceStable(attrs, func(i, j int) bool { return attrs[i].Key < attrs[j].Key })
	for i := 1; i < len(attrs); i++ {
		if attrs[i].Key == attrs[i-1].Key {
			return nil, fmt.Errorf("ajarconnector: duplicate attribute key: %q", attrs[i].Key)
		}
	}

	return &eventpb.Event{
		SchemaVersion: schemaVersion,
		Id:            b.id,
		SourceId:      b.sourceID,
		EntityType:    b.entityType,
		Timestamp:     b.timestamp,
		ReceivedAt:    "", // Ajar stamps its own clock.
		Location:      b.location,
		Payload:       b.payload,
		PolicyTags:    b.policyTags,
		Confidence:    b.confidence,
		Attributes:    attrs,
	}, nil
}

// isNamespaced reports whether entityType follows mim:<type> or x:<vendor>:<type>.
func isNamespaced(entityType string) bool {
	if rest, ok := strings.CutPrefix(entityType, "mim:"); ok {
		return rest != "" && !strings.Contains(rest, ":")
	}
	if rest, ok := strings.CutPrefix(entityType, "x:"); ok {
		vendor, ty, ok := strings.Cut(rest, ":")
		return ok && vendor != "" && ty != "" && !strings.Contains(ty, ":")
	}
	return false
}

// newUUIDv7 builds a UUIDv7 string (48-bit ms timestamp + random) without an
// external dependency.
func newUUIDv7() string {
	var b [16]byte
	ms := uint64(time.Now().UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		panic("ajarconnector: crypto/rand failed: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x70 // version 7
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
