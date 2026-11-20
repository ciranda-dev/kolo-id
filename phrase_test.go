package koloid

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"testing"
)

const legalPhrase = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title"

const abandonPhrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"

func mustPhrase(t testing.TB, s string) *Phrase {
	t.Helper()
	p, err := ParsePhrase(s)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPersonKeyPath(t *testing.T) {
	for _, k := range personKnownAnswers {
		id, err := mustPhrase(t, k.phrase).Person()
		if err != nil {
			t.Fatal(err)
		}
		if got := id.PublicKeyString(); got != k.person {
			t.Errorf("person key of %.20s... = %s, want %s", k.phrase, got, k.person)
		}
	}
}

func TestPhraseRoundTrip(t *testing.T) {
	for i := range 100 {
		p, err := GeneratePhrase()
		if err != nil {
			t.Fatal(err)
		}
		words := p.Words()
		if len(words) != 24 {
			t.Fatalf("%d words", len(words))
		}
		if e := p.state().entropy; [16]byte(e[:16]) == [16]byte{} || [16]byte(e[16:]) == [16]byte{} {
			t.Fatalf("round %d: a half of the entropy is zero", i)
		}
		want, err := p.Person()
		if err != nil {
			t.Fatal(err)
		}
		q, err := ParseWords(words)
		if err != nil {
			t.Fatalf("round %d: %v", i, err)
		}
		r, err := ParsePhrase(strings.Join(words, " "))
		if err != nil {
			t.Fatal(err)
		}
		for _, x := range []*Phrase{q, r} {
			got, err := x.Person()
			if err != nil || got.PublicKeyString() != want.PublicKeyString() {
				t.Fatalf("round %d: person key differs: %v", i, err)
			}
			if !equalStrings(x.Words(), words) {
				t.Fatalf("round %d: words differ", i)
			}
		}
	}
}

func equalStrings(a, b []string) bool {
	return strings.Join(a, " ") == strings.Join(b, " ")
}

func TestGeneratePhraseIsRandom(t *testing.T) {
	a, _ := GeneratePhrase()
	b, _ := GeneratePhrase()
	if equalStrings(a.Words(), b.Words()) {
		t.Fatal("two generated phrases are equal")
	}
}

func TestGeneratePhraseReaderError(t *testing.T) {
	old := rand.Reader
	t.Cleanup(func() { rand.Reader = old })
	want := errors.New("no entropy")
	rand.Reader = failingReader{want}
	if p, err := GeneratePhrase(); p != nil || !errors.Is(err, want) {
		t.Fatalf("GeneratePhrase = %v, %v", p, err)
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestParseAccepts(t *testing.T) {
	want, _ := mustPhrase(t, abandonPhrase).Person()
	words := strings.Fields(abandonPhrase)
	for name, in := range map[string]string{
		"upper case":       strings.ToUpper(abandonPhrase),
		"mixed case":       strings.Replace(abandonPhrase, "abandon", "AbAnDoN", 5),
		"tabs and CRLF":    strings.Join(words, "\t\r\n"),
		"extra whitespace": "  \n" + strings.Join(words, "   ") + " \t\n",
		"1024 bytes":       abandonPhrase + strings.Repeat(" ", 1024-len(abandonPhrase)),
	} {
		p, err := ParsePhrase(in)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if got, _ := p.Person(); got.PublicKeyString() != want.PublicKeyString() {
			t.Errorf("%s: different key", name)
		}
	}
}

func TestParseRejects(t *testing.T) {
	good := strings.Fields(abandonPhrase)
	with := func(i int, w string) string {
		c := append([]string(nil), good...)
		c[i] = w
		return strings.Join(c, " ")
	}
	cases := []struct {
		name string
		in   string
		want error
		pos  int
	}{
		{"empty", "", ErrPhraseLength, 0},
		{"blank", " \t\r\n ", ErrPhraseLength, 0},
		{"12 words", strings.Join(good[:12], " "), ErrPhraseLength, 0},
		{"23 words", strings.Join(good[:23], " "), ErrPhraseLength, 0},
		{"25 words", abandonPhrase + " art", ErrPhraseLength, 0},
		{"1025 bytes", abandonPhrase + strings.Repeat(" ", 1025-len(abandonPhrase)), ErrPhraseLength, 0},
		{"wrong checksum", with(23, "abandon"), ErrPhraseChecksum, 0},
		{"unknown word", with(6, "abandoned"), ErrUnknownWord, 7},
		{"typo", with(0, "abandpn"), ErrUnknownWord, 1},
		{"last word unknown", with(23, "zzzz"), ErrUnknownWord, 24},
		{"too short word", with(5, "ab"), ErrUnknownWord, 6},
		{"digit", with(2, "ab4ndon"), ErrUnknownWord, 3},
		{"accent", with(4, "aband\u00f3n"), ErrUnknownWord, 5},
		{"NBSP after a word", with(10, "abandon\u00a0"), ErrUnknownWord, 11},
		{"NBSP as separator", strings.Join(good[:10], " ") + "\u00a0" + strings.Join(good[10:], " "), ErrPhraseLength, 0},
		{"ideographic space as separator", strings.Join(good[:10], " ") + "\u3000" + strings.Join(good[10:], " "), ErrPhraseLength, 0},
		{"ideographic space after a word", with(12, "abandon\u3000"), ErrUnknownWord, 13},
		{"zero-width space", with(7, "aban\u200bdon"), ErrUnknownWord, 8},
		{"NUL", with(8, "abandon\x00"), ErrUnknownWord, 9},
		{"hyphen", with(9, "aban-don"), ErrUnknownWord, 10},
		{"comma", strings.Replace(abandonPhrase, " ", ", ", 1), ErrUnknownWord, 1},
		{"invalid UTF-8", with(3, "aba\xffdon"), ErrUnknownWord, 4},
	}
	for _, c := range cases {
		p, err := ParsePhrase(c.in)
		if p != nil || !errors.Is(err, c.want) {
			t.Errorf("%s: ParsePhrase = %v, %v; want %v", c.name, p, err, c.want)
			continue
		}
		if c.pos != 0 {
			var u *UnknownWordError
			if !errors.As(err, &u) || u.Position != c.pos {
				t.Errorf("%s: error %v, want position %d", c.name, err, c.pos)
			}
		}
		if !strings.HasPrefix(err.Error(), "koloid: ") {
			t.Errorf("%s: error text %q does not start with koloid:", c.name, err)
		}
	}
}

func TestParseWordsRejects(t *testing.T) {
	good := strings.Fields(abandonPhrase)
	if _, err := ParseWords(good); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseWords(nil); !errors.Is(err, ErrPhraseLength) {
		t.Fatalf("nil: %v", err)
	}
	bad := append([]string(nil), good...)
	bad[2] = "abandon abandon" // a word holding a space is unknown
	if _, err := ParseWords(bad); !errors.Is(err, ErrUnknownWord) {
		t.Fatalf("space inside a word: %v", err)
	}
	bad[2] = strings.Repeat("a", 1<<20)
	if _, err := ParseWords(bad); !errors.Is(err, ErrUnknownWord) {
		t.Fatalf("huge word: %v", err)
	}
}

// No error text holds a word of the input; the vocabulary of the fixed messages is avoided by the test phrase.
func TestParseErrorsNeverEchoInput(t *testing.T) {
	words := strings.Fields("zebra zone yellow wrestle wine voyage void vital umbrella twist ticket tackle sudden spirit simple rival rifle quote quiz pulse prosper orbit nuclear mango")
	inputs := []string{strings.Join(words, " "), strings.Join(words[:20], " "), strings.Join(words, "  ") + " zoo", strings.Replace(strings.Join(words, " "), "mango", "mangx", 1)}
	for _, in := range inputs {
		_, err := ParsePhrase(in)
		if err == nil {
			t.Fatalf("%q parsed", in)
		}
		for _, w := range append(words, "mangx") {
			if strings.Contains(err.Error(), w) {
				t.Errorf("error %q echoes %q", err, w)
			}
		}
	}
}

func TestPhraseNeverPrinted(t *testing.T) {
	p := mustPhrase(t, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title")
	check := func(how, out string) {
		t.Helper()
		for _, w := range []string{"legal winner", "sausage", "thank year", "worth useful", "title"} {
			if strings.Contains(out, w) {
				t.Errorf("%s prints the phrase: %s", how, out)
			}
		}
		if strings.Contains(out, hex.EncodeToString(p.state().entropy[:8])) {
			t.Errorf("%s prints the entropy: %s", how, out)
		}
	}
	values := map[string]any{"*Phrase": p, "Phrase": *p, "struct field": struct{ P *Phrase }{p}, "value field": struct{ P Phrase }{*p}, "slice": []*Phrase{p}, "map": map[string]Phrase{"k": *p}}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q"} {
			check(fmt.Sprintf("fmt %s of %s", verb, name), fmt.Sprintf(verb, v))
		}
		check("Sprint of "+name, fmt.Sprint(v))
	}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%d"} {
		if out := fmt.Sprintf(verb, p); out != "koloid.Phrase{redacted}" {
			t.Errorf("fmt %s of *Phrase = %q", verb, out)
		}
	}
	var buf bytes.Buffer
	for _, h := range []slog.Handler{slog.NewTextHandler(&buf, nil), slog.NewJSONHandler(&buf, nil)} {
		slog.New(h).Info("phrase", "p", p, "group", slog.GroupValue(slog.Any("p", p)))
	}
	check("slog", buf.String())
	for _, e := range []error{errors.Join(ErrInvalidPhrase, ErrPhraseLength), ErrNotEncodable, ErrPhraseChecksum, &UnknownWordError{Position: 3}} {
		check("error text", e.Error())
	}
}

func TestPhraseNotEncodable(t *testing.T) {
	p := mustPhrase(t, abandonPhrase)
	if b, err := p.MarshalText(); b != nil || !errors.Is(err, ErrNotEncodable) {
		t.Fatalf("MarshalText = %q, %v", b, err)
	}
	if b, err := p.MarshalJSON(); b != nil || !errors.Is(err, ErrNotEncodable) {
		t.Fatalf("MarshalJSON = %q, %v", b, err)
	}
	if _, err := json.Marshal(struct{ P *Phrase }{p}); !errors.Is(err, ErrNotEncodable) {
		t.Fatalf("json.Marshal: %v", err)
	}
	var q Phrase
	if err := json.Unmarshal([]byte(`"abandon"`), &q); !errors.Is(err, ErrNotEncodable) {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if err := q.UnmarshalText([]byte("abandon")); !errors.Is(err, ErrNotEncodable) {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if q.valid() {
		t.Fatal("a decoded Phrase is valid")
	}
}

func TestPhraseClear(t *testing.T) {
	p := mustPhrase(t, legalPhrase)
	st := p.state()
	if st.entropy == [32]byte{} {
		t.Fatal("setup: the entropy must not be zero")
	}
	p.Clear()
	if st.entropy != [32]byte{} {
		t.Fatal("entropy not zeroed")
	}
	if p.Words() != nil {
		t.Fatal("Words after Clear")
	}
	if id, err := p.Person(); id != nil || !errors.Is(err, ErrInvalidPhrase) {
		t.Fatalf("Person after Clear = %v, %v", id, err)
	}
	p.Clear()
	var nilPhrase *Phrase
	nilPhrase.Clear()
	for name, q := range map[string]*Phrase{"nil": nil, "zero": {}} {
		if q.Words() != nil {
			t.Errorf("%s: Words", name)
		}
		if id, err := q.Person(); id != nil || !errors.Is(err, ErrInvalidPhrase) {
			t.Errorf("%s: Person = %v, %v", name, id, err)
		}
		if q.String() != "koloid.Phrase{redacted}" {
			t.Errorf("%s: String", name)
		}
	}
	(&Phrase{}).Clear()
}

// Words returns a fresh slice each time: changing it does not change the phrase.
func TestWordsIsACopy(t *testing.T) {
	p := mustPhrase(t, abandonPhrase)
	w := p.Words()
	w[0] = "zoo"
	if p.Words()[0] != "abandon" {
		t.Fatal("Words shares its slice")
	}
}

// Under GODEBUG=fips140=only PBKDF2 refuses the 8-byte BIP-39 salt; Person must return an error, never panic.
func TestSeedFIPSOnly(t *testing.T) {
	if os.Getenv("KOLO_ID_FIPS_CHILD") == "1" {
		_, err := mustPhrase(t, abandonPhrase).Person()
		if err == nil || !errors.Is(err, errors.ErrUnsupported) || !strings.HasPrefix(err.Error(), "koloid: ") {
			t.Fatalf("Person under fips140=only = %v", err)
		}
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSeedFIPSOnly$", "-test.v")
	cmd.Env = append(os.Environ(), "KOLO_ID_FIPS_CHILD=1", "GODEBUG=fips140=only")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestSeedFIPSOnly") {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
}
