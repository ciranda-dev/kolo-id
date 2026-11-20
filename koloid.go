package koloid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/ciranda-dev/kolo-id/internal/keyfile"
)

var (
	// ErrInvalidKeyFile is returned by [Load] when the file is not a regular 32-byte file, and by [LoadCert] for an empty or over-514-byte file.
	ErrInvalidKeyFile = keyfile.ErrInvalid
	// ErrInsecureKeyFile is returned by [Load], [LoadCert], [SaveCert], [Identity.Save] and [Identity.SaveNew] when the key directory is a symlink
	// or others can access or another user owns the key file or its directory (see [Load]).
	ErrInsecureKeyFile = keyfile.ErrInsecure
	// ErrInvalidContext is returned by [Identity.Sign] for an empty, over-255-byte or reserved ("kolo-id/device-") context.
	ErrInvalidContext = errors.New("koloid: invalid signing context")
	// ErrInvalidIdentity is returned for a nil or zero Identity.
	ErrInvalidIdentity = errors.New("koloid: invalid identity")
	// ErrSavedNotSynced is returned by [Identity.Save] and [Identity.SaveNew] when the new key is in place but the directory sync failed.
	ErrSavedNotSynced = keyfile.ErrSavedNotSynced
	// ErrTempLeft is wrapped by [Identity.Save] and [Identity.SaveNew] when a temporary file could not be removed; the error text says whether the key was saved.
	ErrTempLeft = keyfile.ErrTempLeft
	// ErrNotDecodable is returned when decoding an Identity from text or JSON.
	ErrNotDecodable = errors.New("koloid: identities cannot be decoded; use Load or FromSeed")
)

// Identity is a Kolo node identity; hold it as *Identity.
// A *Identity prints and encodes as its public key; the seed never appears in any output.
// A plain Identity value prints an opaque code address and should not be logged; log the *Identity.
type Identity struct {
	key   func() ed25519.PrivateKey // a func, so fmt and reflection never reach the key
	clear func()
}

func newIdentity(priv ed25519.PrivateKey) *Identity {
	return &Identity{
		key:   func() ed25519.PrivateKey { return priv },
		clear: func() { clear(priv); priv = nil },
	}
}

// Clear erases the private key that i holds; i is invalid afterwards and so is every copy of it.
// It is not safe to call while another goroutine uses i, and it cannot erase copies made by the Go runtime or the standard library.
func (i *Identity) Clear() {
	if i != nil && i.clear != nil {
		i.clear()
	}
}

// Generate creates a new random Identity.
func Generate() (*Identity, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return newIdentity(priv), nil
}

// FromSeed creates an Identity from a 32-byte Ed25519 seed.
// It copies what it needs and leaves seed untouched; the caller should clear seed when done.
func FromSeed(seed []byte) (*Identity, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("koloid: invalid seed length %d, want %d", len(seed), ed25519.SeedSize)
	}
	return newIdentity(ed25519.NewKeyFromSeed(seed)), nil
}

func (i *Identity) valid() bool {
	return i != nil && i.key != nil && len(i.key()) == ed25519.PrivateKeySize
}

// PublicKey returns the public key, or nil for a nil or zero Identity.
func (i *Identity) PublicKey() ed25519.PublicKey {
	if !i.valid() {
		return nil
	}
	return i.key().Public().(ed25519.PublicKey)
}

// PublicKeyString returns the public key as hex.
func (i *Identity) PublicKeyString() string {
	return hex.EncodeToString(i.PublicKey())
}

// String returns the public key, never the private key.
func (i *Identity) String() string {
	if !i.valid() {
		return "koloid.Identity{invalid}"
	}
	return "koloid.Identity{" + i.PublicKeyString() + "}"
}

// GoString returns the same as [Identity.String].
func (i *Identity) GoString() string { return i.String() }

// Format prints [Identity.String] for every verb.
func (i *Identity) Format(f fmt.State, _ rune) { io.WriteString(f, i.String()) }

// LogValue makes log/slog print only the public key.
func (i *Identity) LogValue() slog.Value { return slog.StringValue(i.String()) }

// MarshalText returns the public key as hex.
func (i *Identity) MarshalText() ([]byte, error) {
	if !i.valid() {
		return nil, ErrInvalidIdentity
	}
	return []byte(i.PublicKeyString()), nil
}

// MarshalJSON returns the public key as a hex JSON string.
func (i *Identity) MarshalJSON() ([]byte, error) {
	text, err := i.MarshalText()
	if err != nil {
		return nil, err
	}
	return json.Marshal(string(text))
}

// UnmarshalText always returns [ErrNotDecodable].
func (i *Identity) UnmarshalText([]byte) error {
	return ErrNotDecodable
}

// UnmarshalJSON always returns [ErrNotDecodable], so JSON never yields an empty Identity.
func (i *Identity) UnmarshalJSON([]byte) error {
	return ErrNotDecodable
}

// Sign returns the Ed25519ctx (RFC 8032) signature of msg under context; contexts that start with "kolo-id/device-" are reserved and refused.
func (i *Identity) Sign(context string, msg []byte) ([]byte, error) {
	if reservedContext(context) {
		return nil, ErrInvalidContext
	}
	return i.sign(context, msg)
}

// sign is [Identity.Sign] without the reserved-context rule, for the library's own messages.
func (i *Identity) sign(context string, msg []byte) ([]byte, error) {
	if !i.valid() {
		return nil, ErrInvalidIdentity
	}
	if !validContext(context) {
		return nil, ErrInvalidContext
	}
	return i.key().Sign(nil, msg, &ed25519.Options{Context: context})
}

// Verify reports whether sig is a valid signature of msg by pub under context.
// It never panics on untrusted input.
// Verify rejects small-order public keys, for which a signature can be forged without a private key.
func Verify(pub ed25519.PublicKey, context string, msg, sig []byte) bool {
	if len(pub) != ed25519.PublicKeySize || !validContext(context) || smallOrder(pub) {
		return false
	}
	return ed25519.VerifyWithOptions(pub, msg, sig, &ed25519.Options{Context: context}) == nil
}

// smallOrderY holds the y coordinates (little-endian, sign bit clear) of the small-order points,
// canonical and not: the points of order 1, 2, 4 and 8 of the curve (RFC 8032 section 5.1).
// With either sign bit they are the 14 encodings crypto/ed25519 accepts.
var smallOrderY = [7][32]byte{
	{0x00}, // 0, order 4
	{0x01}, // 1, order 1
	{0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05}, // order 8
	{0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a}, // order 8
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p-1, order 2
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p, that is 0
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f}, // p+1, that is 1
}

// smallOrder reports whether the 32-byte pub encodes a small-order point; public keys are not secret.
func smallOrder(pub []byte) bool {
	for _, y := range smallOrderY {
		if bytes.Equal(pub[:31], y[:31]) && pub[31]&0x7f == y[31] {
			return true
		}
	}
	return false
}

func validContext(context string) bool {
	return len(context) > 0 && len(context) <= 255
}

// reservedContext reports whether context belongs to the certificate messages of this library.
func reservedContext(context string) bool { return strings.HasPrefix(context, contextReservedPrefix) }

// Save atomically replaces path with the 32-byte seed, mode 0600 (on Windows, the directory's access rules).
// A symlink at path is replaced, not followed, and a missing parent directory is created with mode 0700.
// The directory is checked like in [Load] before anything is written.
// If the temporary file cannot be removed, the error wraps [ErrTempLeft]; the key was not saved.
func (i *Identity) Save(path string) error {
	return i.save(path, true)
}

// SaveNew is like [Identity.Save] but never replaces anything at path, not even a dangling symlink:
// it returns an error wrapping [io/fs.ErrExist] instead. It needs a filesystem with hard links.
// If the temporary file cannot be removed, the error wraps [ErrTempLeft] and says whether the key was saved.
func (i *Identity) SaveNew(path string) error {
	return i.save(path, false)
}

func (i *Identity) save(path string, replace bool) error {
	if !i.valid() {
		return ErrInvalidIdentity
	}
	seed := i.key().Seed()
	defer clear(seed)
	return keyfile.Write(path, seed, replace)
}

// Load reads an Identity written by [Identity.Save] or [Identity.SaveNew].
// The path must end in a file name that names a regular 32-byte file, not a symlink ([ErrInvalidKeyFile]).
// It never blocks on a FIFO or device. The key file and its directory must belong to the effective user
// and have no group or other bits, or Load returns [ErrInsecureKeyFile]. The checks, which are
// stricter on Linux and macOS and absent on non-unix systems, are listed in docs/guide.md.
func Load(path string) (*Identity, error) {
	var seed [ed25519.SeedSize]byte
	defer clear(seed[:])
	if err := keyfile.Read(path, &seed); err != nil {
		return nil, err
	}
	return FromSeed(seed[:])
}
