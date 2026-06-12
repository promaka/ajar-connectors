// SPDX-License-Identifier: Apache-2.0

package ajarconnector

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
)

// ConnectorProfile is a connector's published self-declaration: what it is
// allowed to emit and how Ajar authenticates it. It is a declaration, not
// policy — core decides what to do with it. The SDK serializes it
// deterministically, projecting the verifying key to lowercase hex.
type ConnectorProfile struct {
	// SourceID is the stable source identity this connector signs as.
	SourceID string
	// AllowedEntityTypes are the (namespaced) entity types it may emit.
	AllowedEntityTypes []string
	// MaxPayloadBytes is the upper bound on payload size.
	MaxPayloadBytes uint64
	// RateCapacity is the token-bucket capacity (burst).
	RateCapacity uint32
	// RateRefillPerSec is the token-bucket refill rate, tokens per second.
	RateRefillPerSec float64
	// VerifyingKey is the Ed25519 public key Ajar uses to verify sealed events.
	VerifyingKey ed25519.PublicKey
}

// NewConnectorProfile returns a profile with sensible defaults.
func NewConnectorProfile(sourceID string, verifyingKey ed25519.PublicKey) *ConnectorProfile {
	return &ConnectorProfile{
		SourceID:         sourceID,
		MaxPayloadBytes:  64 * 1024,
		RateCapacity:     100,
		RateRefillPerSec: 10.0,
		VerifyingKey:     verifyingKey,
	}
}

// AllowEntityType adds an allowed (namespaced) entity type.
func (p *ConnectorProfile) AllowEntityType(entityType string) *ConnectorProfile {
	p.AllowedEntityTypes = append(p.AllowedEntityTypes, entityType)
	return p
}

// MaxPayload sets the payload-size ceiling in bytes.
func (p *ConnectorProfile) MaxPayload(max uint64) *ConnectorProfile {
	p.MaxPayloadBytes = max
	return p
}

// RateLimit sets the ingest rate-limit bucket (capacity / refill-per-second).
func (p *ConnectorProfile) RateLimit(capacity uint32, refillPerSec float64) *ConnectorProfile {
	p.RateCapacity = capacity
	p.RateRefillPerSec = refillPerSec
	return p
}

type profileWire struct {
	SourceID           string   `json:"source_id"`
	AllowedEntityTypes []string `json:"allowed_entity_types"`
	MaxPayloadBytes    uint64   `json:"max_payload_bytes"`
	RateCapacity       uint32   `json:"rate_capacity"`
	RateRefillPerSec   float64  `json:"rate_refill_per_sec"`
	VerifyingKeyHex    string   `json:"verifying_key_hex"`
}

func (p *ConnectorProfile) wire() profileWire {
	allowed := p.AllowedEntityTypes
	if allowed == nil {
		allowed = []string{}
	}
	return profileWire{
		SourceID:           p.SourceID,
		AllowedEntityTypes: allowed,
		MaxPayloadBytes:    p.MaxPayloadBytes,
		RateCapacity:       p.RateCapacity,
		RateRefillPerSec:   p.RateRefillPerSec,
		VerifyingKeyHex:    hex.EncodeToString(p.VerifyingKey),
	}
}

// ToJSON serializes the profile to compact JSON.
func (p *ConnectorProfile) ToJSON() (string, error) {
	b, err := json.Marshal(p.wire())
	return string(b), err
}

// ToJSONPretty serializes the profile to indented JSON.
func (p *ConnectorProfile) ToJSONPretty() (string, error) {
	b, err := json.MarshalIndent(p.wire(), "", "  ")
	return string(b), err
}
