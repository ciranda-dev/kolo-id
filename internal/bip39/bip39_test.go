package bip39

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
)

func TestWordlistPinned(t *testing.T) {
	raw, err := os.ReadFile("english.txt")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if got := hex.EncodeToString(sum[:]); got != "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda" {
		t.Fatalf("english.txt sha256 = %s", got)
	}
	if len(wordlist) != 2048 || wordlist[0] != "abandon" || wordlist[2047] != "zoo" {
		t.Fatalf("list: %d words, first %q, last %q", len(wordlist), wordlist[0], wordlist[2047])
	}
	if !sort.StringsAreSorted(wordlist) {
		t.Fatal("list is not sorted")
	}
	prefixes := map[string]bool{}
	for _, w := range wordlist {
		if len(w) < 3 || len(w) > 8 {
			t.Fatalf("word length %d", len(w))
		}
		prefixes[w[:min(4, len(w))]] = true
	}
	if len(prefixes) != 2048 {
		t.Fatalf("%d distinct 4-letter prefixes, want 2048", len(prefixes))
	}
}

// Every word is ASCII a-z, so NFKD is the identity on every sentence the library accepts.
func TestNFKDInvariantWordlist(t *testing.T) {
	for _, w := range wordlist {
		for i := 0; i < len(w); i++ {
			if w[i] < 'a' || w[i] > 'z' {
				t.Fatalf("word %q has a byte outside a-z", w)
			}
		}
	}
}

type vector struct{ entropy, mnemonic, seed string }

func loadVectors(t *testing.T) []vector {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var file map[string][][]string
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var out []vector
	for _, v := range file["english"] {
		out = append(out, vector{v[0], v[1], v[2]})
	}
	if len(out) != 24 {
		t.Fatalf("%d english vectors, want 24", len(out))
	}
	return out
}

// The official vectors: 8 each of 12, 18 and 24 words; the passphrase of every seed is "TREZOR".
func TestBIP39Vectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		entropy, _ := hex.DecodeString(v.entropy)
		words, err := Encode(entropy)
		if err != nil || strings.Join(words, " ") != v.mnemonic {
			t.Fatalf("Encode(%s) = %q, %v", v.entropy, words, err)
		}
		back, err := Decode(strings.Fields(v.mnemonic))
		if err != nil || !bytes.Equal(back, entropy) {
			t.Fatalf("Decode(%q) = %x, %v", v.mnemonic, back, err)
		}
		seed, err := Seed(v.mnemonic, "TREZOR")
		if err != nil || hex.EncodeToString(seed) != v.seed {
			t.Fatalf("Seed(%q) = %x, %v", v.mnemonic, seed, err)
		}
	}
}

func TestEncodeSizes(t *testing.T) {
	for n := 0; n <= 40; n++ {
		words, err := Encode(make([]byte, n))
		valid := n >= 16 && n <= 32 && n%4 == 0
		if valid != (err == nil) || (!valid && !errors.Is(err, ErrEntropySize)) {
			t.Fatalf("Encode(%d bytes) = %v", n, err)
		}
		if valid && len(words) != (n*8+n/4)/11 {
			t.Fatalf("Encode(%d bytes) gave %d words", n, len(words))
		}
	}
}

func TestDecodeErrors(t *testing.T) {
	good := strings.Fields("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
	if _, err := Decode(good); err != nil {
		t.Fatal(err)
	}
	for _, n := range []int{0, 1, 11, 13, 14, 25, 27} {
		if _, err := Decode(make([]string, n)); !errors.Is(err, ErrWordCount) {
			t.Fatalf("%d words: %v", n, err)
		}
	}
	bad := append([]string(nil), good...)
	bad[11] = "abandon" // valid word, wrong checksum
	if _, err := Decode(bad); !errors.Is(err, ErrChecksum) {
		t.Fatalf("checksum: %v", err)
	}
	for _, w := range []string{"", "ab", "abandonn", "abandom", "abandon ", "aband\u00f3n", "abandon\x00", "ABANDON1"} {
		bad = append([]string(nil), good...)
		bad[3] = w
		_, err := Decode(bad)
		var u *UnknownWordError
		if !errors.Is(err, ErrUnknownWord) || !errors.As(err, &u) || u.Position != 4 {
			t.Fatalf("word %q: %v", w, err)
		}
		if strings.Contains(err.Error(), w) && w != "" {
			t.Fatalf("error echoes %q: %v", w, err)
		}
	}
	bad = append([]string(nil), good...)
	bad[0], bad[1] = "AbAnDoN", "ZOO"
	if _, err := Decode(bad); !errors.Is(err, ErrChecksum) {
		t.Fatalf("case folding should find the words: %v", err)
	}
}

// A checksum of CS bits must catch every single-bit change of one word's index in a sample, and the last word carries the checksum.
func TestDecodeChecksumBits(t *testing.T) {
	for _, n := range []int{16, 20, 24, 28, 32} {
		entropy := bytes.Repeat([]byte{0xa5}, n)
		words, _ := Encode(entropy)
		last := wordlist[sort.SearchStrings(wordlist, words[len(words)-1])]
		bad := 0
		for _, w := range wordlist {
			if w == last {
				continue
			}
			trial := append(append([]string(nil), words[:len(words)-1]...), w)
			if _, err := Decode(trial); err != nil {
				bad++
			}
		}
		cs := len(words) / 3
		if want := 2047 - (1<<(11-cs) - 1); bad != want {
			t.Fatalf("%d bytes: %d of 2047 other last words rejected, want %d", n, bad, want)
		}
	}
}

func TestSeedPassphrase(t *testing.T) {
	for _, p := range []string{"caf\u00e9", "\x80", "x\x80", "\xff", "\u3000"} {
		if _, err := Seed("abandon", p); !errors.Is(err, ErrPassphrase) {
			t.Fatalf("non-ASCII passphrase %q: %v", p, err)
		}
	}
	if _, err := Seed("abandon", "\x7f ~"); err != nil {
		t.Fatalf("ASCII passphrase: %v", err)
	}
	a, _ := Seed("abandon abandon", "")
	b, _ := Seed("abandon abandon", "x")
	if len(a) != 64 || bytes.Equal(a, b) {
		t.Fatal("passphrase must change the seed")
	}
}

func TestLookup(t *testing.T) {
	for i, w := range wordlist {
		if got, ok := lookup(w); !ok || got != i {
			t.Fatalf("lookup(%q) = %d, %v", w, got, ok)
		}
		if got, ok := lookup(strings.ToUpper(w)); !ok || got != i {
			t.Fatalf("lookup(%q) = %d, %v", strings.ToUpper(w), got, ok)
		}
	}
	for _, w := range []string{"", "zzz", "aaa", "zoos", "abandon1", "ab\x80", "abc d"} {
		if _, ok := lookup(w); ok {
			t.Fatalf("lookup(%q) found", w)
		}
	}
}

// FuzzWordsEntropy: any valid entropy size round-trips through words, and Decode never panics on any words.
func FuzzWordsEntropy(f *testing.F) {
	f.Add([]byte("0123456789abcdef0123456789abcdef"), "abandon ability")
	f.Add(make([]byte, 16), "")
	f.Fuzz(func(t *testing.T, entropy []byte, junk string) {
		if len(entropy) >= 16 && len(entropy) <= 32 && len(entropy)%4 == 0 {
			words, err := Encode(entropy)
			if err != nil {
				t.Fatal(err)
			}
			back, err := Decode(words)
			if err != nil || !bytes.Equal(back, entropy) {
				t.Fatalf("round trip of %x: %x, %v", entropy, back, err)
			}
		}
		_, _ = Decode(strings.Fields(junk))
	})
}

// A corrupt embedded list makes every list function return an error, never panic.
func TestCorruptWordlist(t *testing.T) {
	good, raw := append([]string(nil), wordlist...), englishRaw
	if err := verifyWordlist(raw, good); err != nil {
		t.Fatalf("the real list: %v", err)
	}
	if err := verifyWordlist(strings.Replace(raw, "abandon", "abandom", 1), good); !errors.Is(err, ErrWordlist) {
		t.Errorf("changed word: %v", err)
	}
	if err := verifyWordlist(raw, good[:2047]); !errors.Is(err, ErrWordlist) {
		t.Errorf("short list: %v", err)
	}
	if err := verifyWordlist(raw, append(good[:2048:2048], "zzz")); !errors.Is(err, ErrWordlist) {
		t.Errorf("long list: %v", err)
	}
	if err := verifyWordlist("", nil); !errors.Is(err, ErrWordlist) || !strings.HasPrefix(err.Error(), "koloid: ") {
		t.Errorf("empty list: %v", err)
	}
	// The embedded list itself is what gets checked, once.
	t.Cleanup(func() { wordlist, wordlistOnce, wordlistErr = good, sync.Once{}, nil })
	wordlist, wordlistOnce, wordlistErr = good[:10], sync.Once{}, nil
	if w, err := Encode(make([]byte, 32)); w != nil || !errors.Is(err, ErrWordlist) {
		t.Errorf("Encode: %v, %v", w, err)
	}
	if e, err := Decode(make([]string, 24)); e != nil || !errors.Is(err, ErrWordlist) {
		t.Errorf("Decode: %v, %v", e, err)
	}
	wordlist, wordlistOnce, wordlistErr = good, sync.Once{}, nil
	if _, err := Encode(make([]byte, 32)); err != nil {
		t.Errorf("Encode with the real list: %v", err)
	}
}
