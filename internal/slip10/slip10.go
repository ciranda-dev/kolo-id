// Package slip10 implements SLIP-0010 key derivation for ed25519, which supports hardened children only.
package slip10

import (
	"crypto/fips140"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
)

// Hardened is 2^31; a path index at or above it is hardened.
const Hardened = 0x80000000

var (
	// ErrFIPSOnly is returned when the runtime is in FIPS 140-only mode.
	ErrFIPSOnly = fmt.Errorf("koloid: SLIP-0010 is not available in FIPS 140-only mode: %w", errors.ErrUnsupported)
	// ErrSeedLength is returned when the seed is not 16 to 64 bytes.
	ErrSeedLength = errors.New("koloid: invalid seed length")
	// ErrNotHardened is returned for a path index below Hardened.
	ErrNotHardened = errors.New("koloid: derivation index is not hardened")
)

// Derive returns the ed25519 key seed and chain code at a hardened path under the SLIP-0010 master key of seed; an empty path is the master.
func Derive(seed []byte, path []uint32) (key, chain [32]byte, err error) {
	if fips140.Enforced() { // hmac.New panics on the 12-byte master key in FIPS 140-only mode
		return key, chain, ErrFIPSOnly
	}
	if len(seed) < 16 || len(seed) > 64 {
		return key, chain, ErrSeedLength
	}
	for _, i := range path {
		if i < Hardened {
			return key, chain, ErrNotHardened
		}
	}
	// SLIP-0010, "Master key generation": I = HMAC-SHA512("ed25519 seed", seed); "Child key derivation": HMAC-SHA512(c_par, 0x00 || k_par || ser32(i)).
	var sum [sha512.Size]byte
	defer clear(sum[:])
	mac := hmac.New(sha512.New, []byte("ed25519 seed"))
	mac.Write(seed)
	mac.Sum(sum[:0])
	for _, i := range path {
		var data [37]byte // 0x00 || key || ser32(i)
		copy(data[1:], sum[:32])
		binary.BigEndian.PutUint32(data[33:], i)
		mac = hmac.New(sha512.New, sum[32:])
		mac.Write(data[:])
		clear(data[:])
		mac.Sum(sum[:0])
	}
	copy(key[:], sum[:32])
	copy(chain[:], sum[32:])
	return key, chain, nil
}
