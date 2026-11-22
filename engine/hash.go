// Package engine implements the local synchronization pipeline, content hashing,
// echo loop suppression, and deduplication policies.
package engine

import (
	"crypto/sha256"
	"encoding/hex"
)

// ComputeHash computes the SHA-256 cryptographic digest of data
// and returns it formatted as a lowercase hexadecimal string.
func ComputeHash(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
