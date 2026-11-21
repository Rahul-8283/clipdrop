// Package imaging provides high-performance validation and dimension
// inspection for raw image byte streams without full raster decoding.
package imaging

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Constants defining PNG validation guardrails and limits.
const (
	// MaxImageBytes defines the maximum permissible image payload (25 MB).
	MaxImageBytes = 26_214_400

	// MaxDimension defines the maximum width or height in pixels (16,384 px).
	MaxDimension = 16_384

	// MinPNGSize is the minimum valid size for a PNG with header + IHDR chunk (33 bytes).
	MinPNGSize = 33
)

// pngSignature is the standard 8-byte magic header for PNG files (\x89PNG\r\n\x1a\n).
var pngSignature = [8]byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a}

// Standard validation errors.
var (
	ErrTooLarge          = fmt.Errorf("image exceeds maximum size of %d bytes (25 MB)", MaxImageBytes)
	ErrTooSmall          = errors.New("image data too small to be a valid PNG")
	ErrBadSignature      = errors.New("invalid PNG magic signature")
	ErrMissingIHDR       = errors.New("invalid PNG: IHDR chunk missing or corrupt")
	ErrInvalidDimensions = errors.New("image dimensions exceed allowable bounds (must be 1-16384 px)")
)

// ImageInfo captures basic dimension and size metadata extracted from a validated image.
type ImageInfo struct {
	Width  uint32
	Height uint32
	Size   int64
}

// ValidatePNG inspects the raw byte slice of a PNG image. It verifies magic bytes,
// parses the IHDR chunk headers to extract dimensions, and validates security limits
// without decoding the raster scanlines into RAM.
func ValidatePNG(data []byte) (*ImageInfo, error) {
	size := int64(len(data))
	if size > MaxImageBytes {
		return nil, ErrTooLarge
	}
	if size < MinPNGSize {
		return nil, ErrTooSmall
	}

	// 1. Verify 8-byte magic header
	for i := 0; i < 8; i++ {
		if data[i] != pngSignature[i] {
			return nil, ErrBadSignature
		}
	}

	// 2. Parse first chunk: must be IHDR
	// Bytes 8-11: chunk length (big-endian uint32)
	// Bytes 12-15: chunk type (must be "IHDR")
	chunkType := string(data[12:16])
	if chunkType != "IHDR" {
		return nil, ErrMissingIHDR
	}

	ihdrLength := binary.BigEndian.Uint32(data[8:12])
	if ihdrLength < 13 {
		return nil, ErrMissingIHDR
	}

	// Bytes 16-19: Width (big-endian uint32)
	// Bytes 20-23: Height (big-endian uint32)
	width := binary.BigEndian.Uint32(data[16:20])
	height := binary.BigEndian.Uint32(data[20:24])

	// 3. Enforce dimension boundaries (1 <= dimension <= 16384)
	if width == 0 || width > MaxDimension || height == 0 || height > MaxDimension {
		return nil, fmt.Errorf("%w: %dx%d", ErrInvalidDimensions, width, height)
	}

	return &ImageInfo{
		Width:  width,
		Height: height,
		Size:   size,
	}, nil
}
