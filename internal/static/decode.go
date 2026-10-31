package static

import (
	"encoding/base64"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Long base64-looking string literals. Short ones are everywhere (ids, tiny icons) and
// carry no meaningful payload, so the minimum length keeps noise down.
var base64Literal = regexp.MustCompile(`["'\x60]([A-Za-z0-9+/_-]{60,}={0,2})["'\x60]`)

// Hidden is a payload recovered from an encoded string.
type Hidden struct {
	Encoding string // "base64", "charcode", "hex-escape"...
	Text     string
}

// RevealHidden decodes the encodings attackers use to hide code from a casual read,
// and returns only results that look like text (binary blobs, images and fonts are skipped).
func RevealHidden(code string) []Hidden {
	var out []Hidden
	for _, m := range base64Literal.FindAllStringSubmatch(code, 50) {
		if t, ok := decodeBase64Text(m[1]); ok {
			out = append(out, Hidden{"base64", t})
		}
	}
	if t := decodeCharCodes(code); t != "" {
		out = append(out, Hidden{"String.fromCharCode", t})
	}
	if t := decodeEscapes(code); t != "" {
		out = append(out, Hidden{"hex/unicode escapes", t})
	}
	return out
}

func decodeBase64Text(s string) (string, bool) {
	encodings := []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding}
	for _, enc := range encodings {
		b, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if looksLikeText(b) {
			return string(b), true
		}
	}
	return "", false
}

func looksLikeText(b []byte) bool {
	if len(b) < 16 || !utf8.Valid(b) {
		return false
	}
	printable := 0
	for _, r := range string(b) {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	return float64(printable)/float64(utf8.RuneCount(b)) > 0.95
}

var charCodeCall = regexp.MustCompile(`fromCharCode\s*\(\s*((?:\d{1,5}\s*,\s*){8,}\d{1,5})\s*\)`)

// decodeCharCodes turns String.fromCharCode(104,116,116,112,...) back into text.
func decodeCharCodes(code string) string {
	var b strings.Builder
	for _, m := range charCodeCall.FindAllStringSubmatch(code, 20) {
		for _, n := range strings.Split(m[1], ",") {
			v, err := strconv.Atoi(strings.TrimSpace(n))
			if err == nil && v > 0 && v < 0x110000 {
				b.WriteRune(rune(v))
			}
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

var escapeRun = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}){12,}`)

// decodeEscapes expands long runs of \x68\x74... or h... into readable text.
func decodeEscapes(code string) string {
	var b strings.Builder
	for _, run := range escapeRun.FindAllString(code, 20) {
		for i := 0; i < len(run); {
			if run[i+1] == 'x' {
				v, _ := strconv.ParseUint(run[i+2:i+4], 16, 32)
				b.WriteRune(rune(v))
				i += 4
			} else {
				v, _ := strconv.ParseUint(run[i+2:i+6], 16, 32)
				b.WriteRune(rune(v))
				i += 6
			}
		}
		b.WriteByte('\n')
	}
	return strings.TrimSpace(b.String())
}

// Entropy is the Shannon entropy in bits per character. English prose sits around 4,
// minified code around 5, and random or encrypted blobs approach 6.
func Entropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := map[rune]int{}
	n := 0
	for _, r := range s {
		counts[r]++
		n++
	}
	var h float64
	for _, c := range counts {
		p := float64(c) / float64(n)
		h -= p * math.Log2(p)
	}
	return h
}

var longStringLiteral = regexp.MustCompile(`["'\x60]([^"'\x60\s]{200,})["'\x60]`)

// HighEntropyStrings returns string literals that look encrypted or packed.
func HighEntropyStrings(code string) []string {
	var out []string
	for _, m := range longStringLiteral.FindAllStringSubmatch(code, 20) {
		if Entropy(m[1]) > 5.3 {
			out = append(out, m[1])
		}
	}
	return out
}
