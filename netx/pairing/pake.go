package pairing

import (
	"errors"
	"fmt"

	"github.com/schollz/pake/v3"
)

// Standard PAKE errors.
var (
	ErrInvalidCode       = errors.New("pairing: pairing code cannot be empty")
	ErrInvalidPoint      = errors.New("pairing: empty or corrupt elliptic curve point")
	ErrNilSession        = errors.New("pairing: session is uninitialized or nil")
	ErrRoleMismatch      = errors.New("pairing: unexpected role for this operation")
	ErrKeyNotNegotiated  = errors.New("pairing: session key has not been negotiated yet")
)

// PAKE protocol role identifiers.
const (
	RoleHost   = 0 // Party A (initiator displaying code)
	RoleJoiner = 1 // Party B (responder entering code)
)

// CurveP256 specifies the NIST P-256 elliptic curve used for the PAKE exchange.
const CurveP256 = "p256"

// Session encapsulates state for an in-progress PAKE handshake.
type Session struct {
	pake *pake.Pake
	role int
}

// InitHost creates the host-side PAKE session (party A) with the generated pairing code
// and computes the initial public point A to be transmitted to the joiner.
func InitHost(code string) (*Session, []byte, error) {
	norm := NormalizeCode(code)
	if norm == "" {
		return nil, nil, ErrInvalidCode
	}

	p, err := pake.InitCurve([]byte(norm), RoleHost, CurveP256)
	if err != nil {
		return nil, nil, fmt.Errorf("pairing: failed to initialize host PAKE: %w", err)
	}

	pointA := p.Bytes()
	if len(pointA) == 0 {
		return nil, nil, errors.New("pairing: failed to generate host point")
	}

	return &Session{
		pake: p,
		role: RoleHost,
	}, pointA, nil
}

// InitJoiner creates the joiner-side PAKE session (party B) with the entered pairing code,
// ingests the host's public point A, and computes public point B to return to the host.
func InitJoiner(code string, pointA []byte) (*Session, []byte, error) {
	norm := NormalizeCode(code)
	if norm == "" {
		return nil, nil, ErrInvalidCode
	}
	if len(pointA) == 0 {
		return nil, nil, ErrInvalidPoint
	}

	p, err := pake.InitCurve([]byte(norm), RoleJoiner, CurveP256)
	if err != nil {
		return nil, nil, fmt.Errorf("pairing: failed to initialize joiner PAKE: %w", err)
	}

	if err := p.Update(pointA); err != nil {
		return nil, nil, fmt.Errorf("pairing: joiner failed to update with point A: %w", err)
	}

	pointB := p.Bytes()
	if len(pointB) == 0 {
		return nil, nil, errors.New("pairing: failed to generate joiner point")
	}

	return &Session{
		pake: p,
		role: RoleJoiner,
	}, pointB, nil
}

// CompleteHost ingests the joiner's public point B into the host session
// and derives the 32-byte shared symmetric key.
func CompleteHost(s *Session, pointB []byte) ([]byte, error) {
	if s == nil || s.pake == nil {
		return nil, ErrNilSession
	}
	if s.role != RoleHost {
		return nil, ErrRoleMismatch
	}
	if len(pointB) == 0 {
		return nil, ErrInvalidPoint
	}

	if err := s.pake.Update(pointB); err != nil {
		return nil, fmt.Errorf("pairing: host failed to update with point B: %w", err)
	}

	key, err := s.pake.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("pairing: host failed to derive session key: %w", err)
	}

	return key, nil
}

// SessionKey retrieves the 32-byte shared symmetric key from a joiner session
// (or completed host session).
func SessionKey(s *Session) ([]byte, error) {
	if s == nil || s.pake == nil {
		return nil, ErrNilSession
	}

	key, err := s.pake.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("pairing: failed to extract session key: %w", err)
	}

	return key, nil
}
