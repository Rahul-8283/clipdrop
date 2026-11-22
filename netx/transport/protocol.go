// Package transport defines the peer-to-peer communication protocol,
// cryptographic mTLS configuration, and network transfer primitives.
package transport

// HTTP headers used by the Clipdrop sync protocol.
const (
	HeaderProtoVersion = "X-Proto-Version"
	HeaderSha256       = "X-Sha256"
)

// Protocol version identifiers.
const (
	ProtoVersion    = "1"
	ProtoVersionInt = 1
)

// Actions returned in response to transfer offers.
const (
	ActionSend = "send"
	ActionSkip = "skip"
)

// Reasons for skipping an offered item.
const (
	ReasonDuplicate    = "duplicate"
	ReasonTooLarge     = "too_large"
	ReasonKindDisabled = "kind_disabled"
	ReasonPaused       = "paused"
)

// PingResponse represents the payload returned by GET /v1/ping.
type PingResponse struct {
	DeviceName      string `json:"device_name"`
	ProtocolVersion int    `json:"protocol_version"`
	CurrentTime     string `json:"current_time"`
}

// OfferRequest represents the pre-flight transfer metadata sent to POST /v1/offer.
type OfferRequest struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Size   int64  `json:"size"`
	Sha256 string `json:"sha256"`
	Mime   string `json:"mime"`
}

// OfferResponse represents the peer decision returned by POST /v1/offer.
type OfferResponse struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}
