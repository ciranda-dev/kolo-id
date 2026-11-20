// Package bip39 implements BIP-39 for the English word list: entropy to words, words to entropy and
// words to seed. The public API of koloid uses only 24 words and the empty passphrase.
package bip39

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
)

//go:embed english.txt
var englishRaw string

// wordlist is the official BIP-39 English word list, 2048 words in sorted order; it is unexported so no importer can change it.
var wordlist = strings.Split(strings.TrimSuffix(englishRaw, "\n"), "\n")

// wordlistSHA256 is the SHA-256 of english.txt as published with BIP-39.
const wordlistSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"

// The koloid package maps these errors to its own.
var (
	ErrWordlist    = errors.New("koloid: the embedded word list is corrupt")
	ErrChecksum    = errors.New("koloid: phrase checksum does not match")
	ErrUnknownWord = errors.New("koloid: unknown word in phrase")
	ErrWordCount   = errors.New("koloid: invalid number of words")
	ErrEntropySize = errors.New("koloid: invalid entropy size")
	ErrPassphrase  = errors.New("koloid: passphrase must be ASCII")
)

// UnknownWordError reports the 1-based position of a word that is not in the list; it never holds the word.
type UnknownWordError struct{ Position int }

// Error reports the position of the unknown word and never the word.
func (e *UnknownWordError) Error() string {
	return "koloid: unknown word at position " + strconv.Itoa(e.Position)
}

// Is reports whether target is [ErrUnknownWord].
func (e *UnknownWordError) Is(target error) bool { return target == ErrUnknownWord }

var (
	wordlistOnce sync.Once
	wordlistErr  error
)

// checkWordlist verifies the size and the hash of the embedded list at first use.
func checkWordlist() error {
	wordlistOnce.Do(func() { wordlistErr = verifyWordlist(englishRaw, wordlist) })
	return wordlistErr
}

func verifyWordlist(raw string, words []string) error {
	sum := sha256.Sum256([]byte(raw))
	if len(words) != 2048 || hex.EncodeToString(sum[:]) != wordlistSHA256 {
		return ErrWordlist
	}
	return nil
}

// Encode returns the words for entropy of 16, 20, 24, 28 or 32 bytes.
func Encode(entropy []byte) ([]string, error) {
	if err := checkWordlist(); err != nil {
		return nil, err
	}
	if len(entropy) < 16 || len(entropy) > 32 || len(entropy)%4 != 0 {
		return nil, ErrEntropySize
	}
	// BIP-39, section "Generating the mnemonic": the first ENT/32 bits of SHA-256(entropy) follow the entropy, in 11-bit groups.
	sum := sha256.Sum256(entropy)
	bits := append(append(make([]byte, 0, len(entropy)+1), entropy...), sum[0])
	defer clear(bits)
	n := (len(entropy)*8 + len(entropy)/4) / 11 // MS = (ENT + CS) / 11
	words := make([]string, n)
	for i := range words {
		var idx int
		for b := i * 11; b < i*11+11; b++ {
			idx = idx<<1 | int(bits[b/8]>>(7-b%8)&1)
		}
		words[i] = wordlist[idx]
	}
	return words, nil
}

// Decode returns the entropy of 12, 15, 18, 21 or 24 words, ignoring ASCII case; it is the inverse of [Encode].
// It returns [*UnknownWordError] for the first word not in the list and [ErrChecksum] for a bad checksum.
func Decode(words []string) ([]byte, error) {
	if err := checkWordlist(); err != nil {
		return nil, err
	}
	n := len(words)
	if n < 12 || n > 24 || n%3 != 0 {
		return nil, ErrWordCount
	}
	var bits [33]byte // 264 bits, the most for 24 words
	defer clear(bits[:])
	for i, w := range words {
		idx, ok := lookup(w)
		if !ok {
			return nil, &UnknownWordError{Position: i + 1}
		}
		for b := 10; b >= 0; b-- {
			if idx>>b&1 == 1 {
				p := i*11 + 10 - b
				bits[p/8] |= 1 << (7 - p%8)
			}
		}
	}
	ent, cs := n*4/3, n/3 // bytes of entropy, bits of checksum
	sum := sha256.Sum256(bits[:ent])
	mask := byte(0xff << (8 - cs))
	if subtle.ConstantTimeByteEq(bits[ent]&mask, sum[0]&mask) != 1 {
		return nil, ErrChecksum
	}
	return append([]byte(nil), bits[:ent]...), nil
}

// lookup finds w in the sorted list by binary search; the list words are 3 to 8 lowercase ASCII letters, so any other byte never matches.
func lookup(w string) (int, bool) {
	if len(w) < 3 || len(w) > 8 {
		return 0, false
	}
	var buf [8]byte
	for i := 0; i < len(w); i++ {
		c := w[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	key := string(buf[:len(w)])
	lo, hi := 0, len(wordlist)
	for lo < hi {
		mid := (lo + hi) / 2
		if wordlist[mid] < key {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo, lo < len(wordlist) && wordlist[lo] == key
}

// Sentence joins words with one ASCII space, the mnemonic sentence of BIP-39.
func Sentence(words []string) string { return strings.Join(words, " ") }

// Seed returns the 64-byte BIP-39 seed of a sentence; an error never holds the sentence or the passphrase.
func Seed(sentence, passphrase string) ([]byte, error) {
	// BIP-39, section "From mnemonic to seed". NFKD is the identity for the English list and an ASCII passphrase, so none is done.
	for i := 0; i < len(passphrase); i++ {
		if passphrase[i] >= 0x80 {
			return nil, ErrPassphrase
		}
	}
	seed, err := pbkdf2.Key(sha512.New, sentence, []byte("mnemonic"+passphrase), 2048, 64)
	if err != nil {
		return nil, fmt.Errorf("koloid: the phrase seed is not available in this build: %w: %w", errors.ErrUnsupported, err)
	}
	return seed, nil
}
