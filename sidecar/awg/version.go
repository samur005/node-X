// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// This file is ported from samur005/3s-ui wgserver/version.go (GPL-3.0).
// Do not copy LucX / PolyForm Noncommercial sources.

package awg

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

// AWGVersions are the AmneziaWG generations the inbound form offers. "1.0" is
// the original (junk packets, S1/S2, magic headers) and is kept for old
// clients; there is no separate 2.5 specification, so "2.5" carries exactly
// the 2.0 field set.
var AWGVersions = []string{"1.0", "1.5", "2.0", "2.5", "3.0", "3.1"}

// ValidVersion reports whether v is one of AWGVersions.
func ValidVersion(v string) bool {
	for _, x := range AWGVersions {
		if x == v {
			return true
		}
	}
	return false
}

// level maps a version to the feature tier it has: 0 base, 1 CPS chains (I1-I5),
// 2 S3/S4 and header ranges, 3 header protection and timers, 4 random trailers
// and disable-cookies.
func level(v string) int {
	switch v {
	case "1.0":
		return 0
	case "1.5":
		return 1
	case "2.0", "2.5":
		return 2
	case "3.0":
		return 3
	case "3.1":
		return 4
	}
	return 2
}

// FieldSet names which obfuscation fields a version has, for the form and for
// pruning stored values.
type FieldSet struct {
	Base           bool `json:"base"`           // Jc Jmin Jmax S1 S2 H1-H4
	CPS            bool `json:"cps"`            // I1-I5
	S34            bool `json:"s34"`            // S3 S4
	HRange         bool `json:"hRange"`         // H1-H4 may be ranges
	Protection     bool `json:"protection"`     // header protection key, content padding, timers
	TrailersCookie bool `json:"trailersCookie"` // RandomTrailers, DisableCookies
}

// Fields returns the field set of a version.
func Fields(v string) FieldSet {
	l := level(v)
	return FieldSet{
		Base:           true,
		CPS:            l >= 1,
		S34:            l >= 2,
		HRange:         l >= 2 && l < 3,
		Protection:     l >= 3,
		TrailersCookie: l >= 4,
	}
}

// Prune zeroes every field the version does not have.
func (o Obfuscation) Prune(version string) Obfuscation {
	f := Fields(version)
	if !f.CPS {
		o.I1, o.I2, o.I3, o.I4, o.I5 = "", "", "", "", ""
	}
	if !f.S34 {
		o.S3, o.S4 = 0, 0
	}
	if !f.Protection {
		o.HeaderProtectionKey, o.ContentPaddingAddition = "", ""
		o.RekeyAfterTime, o.RekeyTimeout, o.RejectAfterTime = "", "", ""
		o.KeepaliveTimeout, o.MaxHandshakeAttempts = "", ""
	}
	if !f.TrailersCookie {
		o.RandomTrailers, o.DisableCookies = false, false
	}
	return o
}

// hMax caps generated magic headers at 2^31-1: the protocol allows the full
// uint32, but some clients' editors reject anything above.
const hMax = 2147483647

func randInt(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(hi-lo)+1))
	if err != nil {
		return lo
	}
	return lo + int(n.Int64())
}

// GenerateKey returns a base64 32-byte random key (header protection key).
func GenerateKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

// Generate makes a random, valid parameter set for a version. A fixed set
// would be fingerprinted by DPI, which is the thing the protocol is for.
func Generate(version string) Obfuscation {
	f := Fields(version)
	var o Obfuscation
	o.Jc = randInt(3, 6)
	o.Jmin = randInt(40, 89)
	o.Jmax = o.Jmin + randInt(50, 250)
	o.S1 = randInt(15, 150)
	o.S2 = randInt(15, 150)
	// Equal sizes of the init and response packet is the fingerprint S1/S2 exist
	// to remove.
	for o.S1+56 == o.S2 {
		o.S2 = randInt(15, 150)
	}
	if f.S34 {
		o.S3 = randInt(12, 55)
		o.S4 = randInt(12, 27)
	}
	// Four non-overlapping bands over the header space; the low bound stays
	// above 4, which is where plain WireGuard's message types live.
	const lo = 5
	band := (hMax - lo + 1) / 4
	hs := [4]string{}
	for i := range 4 {
		bandLo := lo + i*band
		bandHi := bandLo + band - 1
		if f.HRange {
			a := randInt(bandLo, bandHi-1000000)
			b := a + randInt(1000, 900000)
			hs[i] = fmt.Sprintf("%d-%d", a, b)
		} else {
			hs[i] = strconv.Itoa(randInt(bandLo, bandHi))
		}
	}
	o.H1, o.H2, o.H3, o.H4 = hs[0], hs[1], hs[2], hs[3]
	if f.CPS {
		o.I1 = fmt.Sprintf("<r %d>", randInt(32, 256))
	}
	if f.Protection {
		// Header protection uses the S padding as its nonce: every S is >= 12.
		o.S3 = max(o.S3, 12)
		o.S4 = max(o.S4, 12)
		o.HeaderProtectionKey = GenerateKey()
		cp := randInt(8, 24)
		o.ContentPaddingAddition = fmt.Sprintf("%d-%d", cp, cp+randInt(8, 40))
		rk := randInt(100, 120)
		rkHi := rk + randInt(10, 40)
		o.RekeyAfterTime = fmt.Sprintf("%d-%d", rk, rkHi)
		rj := rkHi + randInt(30, 60)
		o.RejectAfterTime = fmt.Sprintf("%d-%d", rj, rj+randInt(30, 90))
		rt := randInt(3, 6)
		o.RekeyTimeout = fmt.Sprintf("%d-%d", rt, rt+randInt(1, 4))
		ka := randInt(8, 12)
		o.KeepaliveTimeout = fmt.Sprintf("%d-%d", ka, ka+randInt(2, 8))
		ha := randInt(15, 25)
		o.MaxHandshakeAttempts = fmt.Sprintf("%d-%d", ha, ha+randInt(5, 25))
	}
	if f.TrailersCookie {
		o.RandomTrailers = true
		o.DisableCookies = true
	}
	return o.Prune(version)
}

// FillMissing keeps what o has and generates the rest of the fields the
// version needs. A form that switches version, or saves an inbound created
// before a field existed, gets a complete set instead of an error.
func (o Obfuscation) FillMissing(version string) Obfuscation {
	o = o.Prune(version)
	g := Generate(version)
	f := Fields(version)
	if o.Jc == 0 && o.Jmin == 0 && o.Jmax == 0 {
		o.Jc, o.Jmin, o.Jmax = g.Jc, g.Jmin, g.Jmax
	}
	if o.S1 == 0 && o.S2 == 0 {
		o.S1, o.S2 = g.S1, g.S2
	}
	if f.S34 && o.S3 == 0 && o.S4 == 0 {
		o.S3, o.S4 = g.S3, g.S4
	}
	if o.H1 == "" && o.H2 == "" && o.H3 == "" && o.H4 == "" {
		o.H1, o.H2, o.H3, o.H4 = g.H1, g.H2, g.H3, g.H4
	}
	// A version without ranges must not keep a range from a newer one.
	if !f.HRange {
		for _, h := range []*string{&o.H1, &o.H2, &o.H3, &o.H4} {
			if lo, _, ok := parseRange(*h); ok && strings.Contains(*h, "-") {
				*h = strconv.FormatInt(lo, 10)
			}
		}
	}
	if f.CPS && o.I1 == "" && o.I2 == "" && o.I3 == "" && o.I4 == "" && o.I5 == "" {
		o.I1 = g.I1
	}
	if f.Protection {
		if o.HeaderProtectionKey == "" {
			o.HeaderProtectionKey = g.HeaderProtectionKey
		}
		// Header protection needs every S >= 12.
		if o.S1 < 12 || o.S2 < 12 || o.S3 < 12 || o.S4 < 12 {
			o.S1, o.S2 = max(o.S1, 12), max(o.S2, 12)
			o.S3, o.S4 = max(o.S3, 12), max(o.S4, 12)
			for o.S1+56 == o.S2 {
				o.S2++
			}
		}
		fill := func(dst *string, v string) {
			if *dst == "" {
				*dst = v
			}
		}
		fill(&o.ContentPaddingAddition, g.ContentPaddingAddition)
		fill(&o.RekeyAfterTime, g.RekeyAfterTime)
		fill(&o.RekeyTimeout, g.RekeyTimeout)
		fill(&o.RejectAfterTime, g.RejectAfterTime)
		fill(&o.KeepaliveTimeout, g.KeepaliveTimeout)
		fill(&o.MaxHandshakeAttempts, g.MaxHandshakeAttempts)
	}
	return o
}

const hMaxValid int64 = 4294967295

// Padded handshake packets (148+S1, 92+S2, 64+S3 bytes) have to fit the
// smallest receive buffer the engine has (1700 bytes on iOS).
const (
	maxS1 = 1700 - 148
	maxS2 = 1700 - 92
	maxS3 = 1700 - 64
)

// parseRange reads "N" or "low-high".
func parseRange(v string) (lo, hi int64, ok bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, 0, false
	}
	if a, b, isRange := strings.Cut(v, "-"); isRange {
		l, e1 := strconv.ParseInt(strings.TrimSpace(a), 10, 64)
		h, e2 := strconv.ParseInt(strings.TrimSpace(b), 10, 64)
		if e1 != nil || e2 != nil {
			return 0, 0, false
		}
		return l, h, true
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	return n, n, true
}

func noControl(name, v string) error {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%s must not contain control characters", name)
		}
	}
	return nil
}

func checkRange(name, v string, minAllowed int64, singleOnly bool) error {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	if err := noControl(name, v); err != nil {
		return err
	}
	lo, hi, ok := parseRange(v)
	if !ok {
		return fmt.Errorf("%s: %q must be a number or a low-high range", name, v)
	}
	if singleOnly && strings.Contains(v, "-") {
		return fmt.Errorf("%s: %q must be a single number in this version", name, v)
	}
	if lo < minAllowed || hi > hMaxValid || lo > hi {
		return fmt.Errorf("%s: %q must satisfy %d <= low <= high <= %d", name, v, minAllowed, hMaxValid)
	}
	return nil
}

var chainTags = map[string]bool{"b": true, "t": true, "r": true, "rc": true, "rd": true, "d": true, "ds": true, "dz": true}

var (
	negativeCount = regexp.MustCompile(`<\s*(r|rc|rd|dz)\s+-\d+\s*>?`)
	kernelOnlyTag = regexp.MustCompile(`<\s*c\s*>?`)
)

// checkChain validates one I1-I5 descriptor. Two shapes are refused because
// they hurt the engine, not merely fail to obfuscate: a negative count panics
// in a timer goroutine minutes after the save, and the kernel-only <c> tag
// aborts the config apply after the peers were already dropped.
func checkChain(name, spec string) error {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	if err := noControl(name, spec); err != nil {
		return err
	}
	if m := negativeCount.FindString(spec); m != "" {
		return fmt.Errorf("%s: %s has a negative count", name, m)
	}
	if m := kernelOnlyTag.FindString(spec); m != "" {
		return fmt.Errorf("%s: %s is a kernel-only tag", name, m)
	}
	rest := spec
	for {
		start := strings.IndexByte(rest, '<')
		if start == -1 {
			return nil
		}
		end := strings.IndexByte(rest[start:], '>')
		if end == -1 {
			return fmt.Errorf("%s: %q is missing a closing '>'", name, spec)
		}
		fields := strings.Fields(rest[start+1 : start+end])
		if len(fields) == 0 {
			return fmt.Errorf("%s: %q has an empty <> tag", name, spec)
		}
		if !chainTags[fields[0]] {
			return fmt.Errorf("%s: %q uses unknown tag <%s>", name, spec, fields[0])
		}
		rest = rest[start+end+1:]
	}
}

// Validate checks a parameter set for a version.
func (o Obfuscation) Validate(version string) error {
	f := Fields(version)
	if o.Jc < 0 || o.Jc > 128 {
		return fmt.Errorf("Jc %d must be 0..128", o.Jc)
	}
	if o.Jmin < 0 || o.Jmax < 0 || o.Jmax > 1280 || o.Jmin > o.Jmax {
		return fmt.Errorf("Jmin/Jmax: need 0 <= Jmin (%d) <= Jmax (%d) <= 1280", o.Jmin, o.Jmax)
	}
	for _, c := range []struct {
		n    string
		v, m int
	}{{"S1", o.S1, maxS1}, {"S2", o.S2, maxS2}, {"S3", o.S3, maxS3}} {
		if c.v < 0 || c.v > c.m {
			return fmt.Errorf("%s %d must be 0..%d", c.n, c.v, c.m)
		}
	}
	if o.S4 < 0 || o.S4 > 32 {
		return fmt.Errorf("S4 %d must be 0..32", o.S4)
	}
	if o.S1+56 == o.S2 {
		return fmt.Errorf("S1+56 must not equal S2 (%d+56 == %d)", o.S1, o.S2)
	}
	hs := [4]string{o.H1, o.H2, o.H3, o.H4}
	var los, his [4]int64
	for i, h := range hs {
		if err := checkRange(fmt.Sprintf("H%d", i+1), h, 1, !f.HRange); err != nil {
			return err
		}
		l, u, ok := parseRange(h)
		if !ok {
			// A blank header keeps WireGuard's own type number.
			l, u = int64(i+1), int64(i+1)
		}
		los[i], his[i] = l, u
	}
	for i := range 4 {
		for j := i + 1; j < 4; j++ {
			if los[i] <= his[j] && los[j] <= his[i] {
				return fmt.Errorf("H%d and H%d overlap", i+1, j+1)
			}
		}
	}
	for i, c := range []string{o.I1, o.I2, o.I3, o.I4, o.I5} {
		if err := checkChain(fmt.Sprintf("I%d", i+1), c); err != nil {
			return err
		}
	}
	if o.HeaderProtectionKey != "" {
		if err := noControl("headerProtectionKey", o.HeaderProtectionKey); err != nil {
			return err
		}
		k, err := base64.StdEncoding.DecodeString(o.HeaderProtectionKey)
		if err != nil || len(k) != 32 {
			return fmt.Errorf("headerProtectionKey must be a base64 32-byte key")
		}
		for i, s := range []int{o.S1, o.S2, o.S3, o.S4} {
			if s < 12 {
				return fmt.Errorf("S%d %d: header protection needs S1-S4 >= 12", i+1, s)
			}
		}
	}
	if err := checkRange("contentPaddingAddition", o.ContentPaddingAddition, 0, false); err != nil {
		return err
	}
	for _, t := range []struct{ n, v string }{
		{"rekeyAfterTime", o.RekeyAfterTime}, {"rekeyTimeout", o.RekeyTimeout},
		{"rejectAfterTime", o.RejectAfterTime}, {"keepaliveTimeout", o.KeepaliveTimeout},
		{"maxHandshakeAttempts", o.MaxHandshakeAttempts},
	} {
		if err := checkRange(t.n, t.v, 1, false); err != nil {
			return err
		}
	}
	// A session has to renew before it is dropped: every rekey time below every
	// reject time. A blank side means WireGuard's own 120s / 180s.
	if o.RekeyAfterTime != "" || o.RejectAfterTime != "" {
		rekeyHi, rejectLo := int64(120), int64(180)
		if o.RekeyAfterTime != "" {
			_, rekeyHi, _ = parseRange(o.RekeyAfterTime)
		}
		if o.RejectAfterTime != "" {
			rejectLo, _, _ = parseRange(o.RejectAfterTime)
		}
		if rekeyHi >= rejectLo {
			return fmt.Errorf("rekeyAfterTime max %d must be below rejectAfterTime min %d", rekeyHi, rejectLo)
		}
	}
	return nil
}
