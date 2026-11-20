package koloid

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"strings"

	"github.com/ciranda-dev/kolo-id/internal/bip39"
	"github.com/ciranda-dev/kolo-id/internal/slip10"
)

var (
	// ErrInvalidPhrase is returned for a nil, zero or cleared Phrase.
	ErrInvalidPhrase = errors.New("koloid: invalid phrase")
	// ErrPhraseLength is returned when the input is not 24 words or is over 1024 bytes.
	ErrPhraseLength = errors.New("koloid: a phrase has 24 words")
	// ErrPhraseChecksum is returned when the 24 words are in the list but their checksum does not match.
	ErrPhraseChecksum = errors.New("koloid: phrase checksum does not match")
	// ErrUnknownWord is matched by [UnknownWordError]; no error text holds a word of the input.
	ErrUnknownWord = errors.New("koloid: unknown word in phrase")
	// ErrNotEncodable is returned when encoding or decoding a Phrase as text or JSON.
	ErrNotEncodable = errors.New("koloid: phrases cannot be encoded or decoded; use ParsePhrase")
)

// UnknownWordError says which word of the input (1-based position) is not in the word list; it matches [ErrUnknownWord].
type UnknownWordError struct{ Position int }

// Error reports the position of the unknown word and never the word.
func (e *UnknownWordError) Error() string {
	return "koloid: unknown word at position " + strconv.Itoa(e.Position)
}

// Is reports whether target is [ErrUnknownWord].
func (e *UnknownWordError) Is(target error) bool { return target == ErrUnknownWord }

// phraseError maps an error of the internal word list code to the exported ones.
func phraseError(err error) error {
	var uw *bip39.UnknownWordError
	switch {
	case errors.As(err, &uw):
		return &UnknownWordError{Position: uw.Position}
	case errors.Is(err, bip39.ErrChecksum):
		return ErrPhraseChecksum
	}
	return err
}

const (
	phraseWords    = 24
	maxPhraseInput = 1024 // 24 words of at most 8 letters and 23 spaces are 215 bytes; the rest is room for whitespace
)

// personPath is m/1802464367'/0'/0' of SLIP-0010 (BIP-43 purpose 0x6B6F6C6F, ASCII "kolo"; role 0, person key; account 0).
// It is permanent: a different path would give a different person key for the same words.
var personPath = []uint32{slip10.Hardened + 1802464367, slip10.Hardened, slip10.Hardened}

// Phrase is a 24-word recovery phrase (BIP-39); hold it as *Phrase, which prints as redacted and never encodes.
type Phrase struct {
	state func() *phraseState // a func, so fmt and reflection never reach the entropy
}

type phraseState struct {
	entropy [32]byte
	cleared bool
}

func newPhrase(entropy []byte) *Phrase {
	st := &phraseState{}
	copy(st.entropy[:], entropy)
	return &Phrase{state: func() *phraseState { return st }}
}

// GeneratePhrase creates a phrase from 256 bits of crypto/rand (BIP-39, section "Generating the mnemonic").
func GeneratePhrase() (*Phrase, error) {
	var e [32]byte
	defer clear(e[:])
	if _, err := io.ReadFull(rand.Reader, e[:]); err != nil {
		return nil, err
	}
	return newPhrase(e[:]), nil
}

// ParsePhrase parses 24 words separated by spaces, tabs or line breaks, ignoring ASCII case; an error never holds a word.
func ParsePhrase(s string) (*Phrase, error) {
	if len(s) > maxPhraseInput {
		return nil, ErrPhraseLength
	}
	return ParseWords(strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' }))
}

// ParseWords is like [ParsePhrase] for words already split; a word holding a space is unknown.
func ParseWords(words []string) (*Phrase, error) {
	if len(words) != phraseWords {
		return nil, ErrPhraseLength
	}
	entropy, err := bip39.Decode(words)
	if err != nil {
		return nil, phraseError(err)
	}
	defer clear(entropy)
	return newPhrase(entropy), nil
}

func (p *Phrase) valid() bool {
	return p != nil && p.state != nil && !p.state().cleared
}

// Words returns the 24 words in a fresh slice, or nil for an invalid phrase; Go strings cannot be erased, so show them and drop them.
func (p *Phrase) Words() []string {
	if !p.valid() {
		return nil
	}
	words, _ := bip39.Encode(p.state().entropy[:])
	return words
}

// Person returns the person key at m/1802464367'/0'/0' under the phrase's BIP-39 seed; it fails under GODEBUG=fips140=only.
func (p *Phrase) Person() (*Identity, error) {
	if !p.valid() {
		return nil, ErrInvalidPhrase
	}
	words, err := bip39.Encode(p.state().entropy[:])
	if err != nil {
		return nil, err
	}
	seed, err := bip39.Seed(bip39.Sentence(words), "")
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	key, chain, err := slip10.Derive(seed, personPath)
	if err != nil {
		return nil, err
	}
	defer clear(key[:])
	defer clear(chain[:])
	return FromSeed(key[:])
}

// Clear erases the entropy held by p, which is invalid afterwards; it is not safe to call while another goroutine uses p.
func (p *Phrase) Clear() {
	if p == nil || p.state == nil {
		return
	}
	st := p.state()
	clear(st.entropy[:])
	st.cleared = true
}

// String returns "koloid.Phrase{redacted}", never a word.
func (p *Phrase) String() string { return "koloid.Phrase{redacted}" }

// GoString returns the same as [Phrase.String].
func (p *Phrase) GoString() string { return p.String() }

// Format prints [Phrase.String] for every verb.
func (p *Phrase) Format(f fmt.State, _ rune) { io.WriteString(f, p.String()) }

// LogValue makes log/slog print [Phrase.String].
func (p *Phrase) LogValue() slog.Value { return slog.StringValue(p.String()) }

// MarshalText always returns [ErrNotEncodable].
func (p *Phrase) MarshalText() ([]byte, error) { return nil, ErrNotEncodable }

// MarshalJSON always returns [ErrNotEncodable].
func (p *Phrase) MarshalJSON() ([]byte, error) { return nil, ErrNotEncodable }

// UnmarshalText always returns [ErrNotEncodable].
func (p *Phrase) UnmarshalText([]byte) error { return ErrNotEncodable }

// UnmarshalJSON always returns [ErrNotEncodable].
func (p *Phrase) UnmarshalJSON([]byte) error { return ErrNotEncodable }
