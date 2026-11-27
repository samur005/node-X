// Copyright (C) 2026 Remnawave X contributors.
//
// Combined Remnawave X work is AGPL-3.0-only.
// This file is ported from samur005/3s-ui wgserver/version.go (GPL-3.0).
// Do not copy LucX / PolyForm Noncommercial sources.

package awg

import (
	"strings"
	"testing"
)

func TestEveryVersionGeneratesAValidSet(t *testing.T) {
	for _, v := range AWGVersions {
		for i := 0; i < 50; i++ {
			o := Generate(v)
			if err := o.Validate(v); err != nil {
				t.Fatalf("%s: generated set invalid: %v (%+v)", v, err, o)
			}
			if o != o.Prune(v) {
				t.Fatalf("%s: generated a field the version does not have: %+v", v, o)
			}
		}
	}
}

func TestFieldsPerVersion(t *testing.T) {
	cases := []struct {
		v                                      string
		cps, s34, hrange, protection, trailers bool
	}{
		{"1.0", false, false, false, false, false},
		{"1.5", true, false, false, false, false},
		{"2.0", true, true, true, false, false},
		{"2.5", true, true, true, false, false},
		{"3.0", true, true, false, true, false},
		{"3.1", true, true, false, true, true},
	}
	for _, c := range cases {
		f := Fields(c.v)
		if f.CPS != c.cps || f.S34 != c.s34 || f.HRange != c.hrange || f.Protection != c.protection || f.TrailersCookie != c.trailers {
			t.Errorf("%s: %+v", c.v, f)
		}
	}
}

func TestGeneratedHeadersAreRangesOnlyWhereAllowed(t *testing.T) {
	if h := Generate("2.0").H1; !strings.Contains(h, "-") {
		t.Errorf("2.0 should get a range, got %q", h)
	}
	for _, v := range []string{"1.0", "1.5", "3.0", "3.1"} {
		if h := Generate(v).H1; strings.Contains(h, "-") {
			t.Errorf("%s should get a single number, got %q", v, h)
		}
	}
	g := Generate("3.0")
	for _, s := range []int{g.S1, g.S2, g.S3, g.S4} {
		if s < 12 {
			t.Errorf("3.0 needs every S >= 12: %+v", g)
		}
	}
	if g.HeaderProtectionKey == "" {
		t.Error("3.0 needs a header protection key")
	}
}

func TestFillMissingKeepsWhatIsThereAndCompletesTheRest(t *testing.T) {
	o := Generate("2.0")
	o.S3, o.S4, o.I1 = 0, 0, ""
	keep := o
	up := o.FillMissing("3.1")
	if up.Jc != keep.Jc || up.H1 != keep.H1 && strings.Contains(keep.H1, "-") == false {
		// ranges are collapsed to a single number when the version has none
	}
	if up.HeaderProtectionKey == "" || up.S3 < 12 || up.S4 < 12 || up.ContentPaddingAddition == "" {
		t.Errorf("3.1 set incomplete: %+v", up)
	}
	if strings.Contains(up.H1, "-") {
		t.Errorf("3.1 must not keep a range header: %q", up.H1)
	}
	if err := up.Validate("3.1"); err != nil {
		t.Errorf("filled set invalid: %v", err)
	}
	down := up.FillMissing("1.0")
	if down.S3 != 0 || down.HeaderProtectionKey != "" || down.I1 != "" || down.RandomTrailers {
		t.Errorf("1.0 must drop the newer fields: %+v", down)
	}
	if err := down.Validate("1.0"); err != nil {
		t.Errorf("1.0 set invalid: %v", err)
	}
}

func TestValidateRefusesBadSets(t *testing.T) {
	good := Generate("3.1")
	cases := map[string]func(o *Obfuscation){
		"S1+56=S2":         func(o *Obfuscation) { o.S1, o.S2 = 20, 76 },
		"H overlap":        func(o *Obfuscation) { o.H1, o.H2 = "100", "100" },
		"H not a number":   func(o *Obfuscation) { o.H1 = "abc" },
		"negative count":   func(o *Obfuscation) { o.I1 = "<r -5>" },
		"kernel only tag":  func(o *Obfuscation) { o.I1 = "<c>" },
		"unknown tag":      func(o *Obfuscation) { o.I1 = "<zz 1>" },
		"unterminated":     func(o *Obfuscation) { o.I1 = "<r 5" },
		"newline in I":     func(o *Obfuscation) { o.I2 = "<r 5>\nPostUp=x" },
		"hpk with small S": func(o *Obfuscation) { o.S1 = 5 },
		"bad hpk":          func(o *Obfuscation) { o.HeaderProtectionKey = "short" },
		"jmin>jmax":        func(o *Obfuscation) { o.Jmin, o.Jmax = 200, 100 },
		"S4 too big":       func(o *Obfuscation) { o.S4 = 40 },
		"rekey >= reject":  func(o *Obfuscation) { o.RekeyAfterTime, o.RejectAfterTime = "100-200", "150-250" },
		"timer zero":       func(o *Obfuscation) { o.RekeyTimeout = "0" },
		"range reversed":   func(o *Obfuscation) { o.ContentPaddingAddition = "20-10" },
	}
	for name, mut := range cases {
		o := good
		mut(&o)
		if err := o.Validate("3.1"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A range is not allowed where the version has none.
	o := Generate("1.5")
	o.H1 = "100-200"
	if err := o.Validate("1.5"); err == nil {
		t.Error("1.5 accepted a header range")
	}
	// ...and is where it has them.
	o = Generate("2.0")
	if err := o.Validate("2.0"); err != nil {
		t.Error(err)
	}
}

func TestVersions(t *testing.T) {
	for _, want := range []string{"1.5", "2.0", "2.5", "3.0", "3.1"} {
		if !ValidVersion(want) {
			t.Errorf("%s must be selectable", want)
		}
	}
	if ValidVersion("4.0") || ValidVersion("") {
		t.Error("unknown versions accepted")
	}
}
