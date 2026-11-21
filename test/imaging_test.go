package test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/Rahul-8283/clipdrop/imaging"
)

// makeMockPNG constructs a minimal PNG byte slice containing the 8-byte header and a valid IHDR chunk.
func makeMockPNG(width, height uint32) []byte {
	buf := make([]byte, 33)
	// 8-byte magic
	copy(buf[0:8], []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})
	// IHDR length: 13 bytes
	binary.BigEndian.PutUint32(buf[8:12], 13)
	// Chunk type: "IHDR"
	copy(buf[12:16], "IHDR")
	// Width & Height
	binary.BigEndian.PutUint32(buf[16:20], width)
	binary.BigEndian.PutUint32(buf[20:24], height)
	// Bit depth (8), Color type (2: Truecolor), Compression (0), Filter (0), Interlace (0)
	buf[24] = 8
	buf[25] = 2
	buf[26] = 0
	buf[27] = 0
	buf[28] = 0
	// 4 bytes CRC (dummy for header-only check)
	binary.BigEndian.PutUint32(buf[29:33], 0x12345678)
	return buf
}

func TestValidatePNG_Valid(t *testing.T) {
	data := makeMockPNG(1920, 1080)
	info, err := imaging.ValidatePNG(data)
	if err != nil {
		t.Fatalf("expected valid PNG, got error: %v", err)
	}
	if info.Width != 1920 || info.Height != 1080 {
		t.Fatalf("unexpected dimensions: %dx%d, want 1920x1080", info.Width, info.Height)
	}
	if info.Size != int64(len(data)) {
		t.Fatalf("unexpected size: %d, want %d", info.Size, len(data))
	}
}

func TestValidatePNG_TooSmall(t *testing.T) {
	data := []byte{0x89, 0x50, 0x4e, 0x47} // only 4 bytes
	_, err := imaging.ValidatePNG(data)
	if !errors.Is(err, imaging.ErrTooSmall) {
		t.Fatalf("expected ErrTooSmall, got: %v", err)
	}
}

func TestValidatePNG_BadSignature(t *testing.T) {
	// JPEG magic bytes (\xFF\xD8\xFF\xE0...)
	data := make([]byte, 40)
	copy(data, []byte{0xFF, 0xD8, 0xFF, 0xE0})
	_, err := imaging.ValidatePNG(data)
	if !errors.Is(err, imaging.ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got: %v", err)
	}
}

func TestValidatePNG_MissingIHDR(t *testing.T) {
	data := makeMockPNG(100, 100)
	// Corrupt chunk type from "IHDR" to "PLTE"
	copy(data[12:16], "PLTE")
	_, err := imaging.ValidatePNG(data)
	if !errors.Is(err, imaging.ErrMissingIHDR) {
		t.Fatalf("expected ErrMissingIHDR, got: %v", err)
	}
}

func TestValidatePNG_ZeroDimensions(t *testing.T) {
	data := makeMockPNG(0, 1080)
	_, err := imaging.ValidatePNG(data)
	if !errors.Is(err, imaging.ErrInvalidDimensions) {
		t.Fatalf("expected ErrInvalidDimensions for 0 width, got: %v", err)
	}

	data = makeMockPNG(1920, 0)
	_, err = imaging.ValidatePNG(data)
	if !errors.Is(err, imaging.ErrInvalidDimensions) {
		t.Fatalf("expected ErrInvalidDimensions for 0 height, got: %v", err)
	}
}

func TestValidatePNG_ExceedsMaxDimensions(t *testing.T) {
	data := makeMockPNG(16385, 1080)
	_, err := imaging.ValidatePNG(data)
	if !errors.Is(err, imaging.ErrInvalidDimensions) {
		t.Fatalf("expected ErrInvalidDimensions for >16384 width, got: %v", err)
	}

	data = makeMockPNG(1920, 20000)
	_, err = imaging.ValidatePNG(data)
	if !errors.Is(err, imaging.ErrInvalidDimensions) {
		t.Fatalf("expected ErrInvalidDimensions for >16384 height, got: %v", err)
	}
}

func TestValidatePNG_MaxImageBytes(t *testing.T) {
	// Create oversized slice (> 25MB)
	oversized := make([]byte, imaging.MaxImageBytes+1)
	copy(oversized[0:8], []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a})

	_, err := imaging.ValidatePNG(oversized)
	if !errors.Is(err, imaging.ErrTooLarge) {
		t.Fatalf("expected ErrTooLarge, got: %v", err)
	}
}
