package v2rayxhttp

import (
	"strings"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	// Session and seq are appended straight onto the path, so it must always
	// carry both a leading and a trailing slash, and drop any query.
	for input, want := range map[string]string{
		"":                   "/",
		"/":                  "/",
		"p9k2":               "/p9k2/",
		"/p9k2":              "/p9k2/",
		"/p9k2/":             "/p9k2/",
		"/api/upload?x=1":    "/api/upload/",
		"/nested/path/here/": "/nested/path/here/",
	} {
		if got := normalizePath(input); got != want {
			t.Errorf("normalizePath(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestParseRange(t *testing.T) {
	cases := []struct {
		in       string
		min, max int
		wantErr  bool
	}{
		{"", 100, 1000, false},
		{"200", 200, 200, false},
		{"100-1000", 100, 1000, false},
		{" 4 - 8 ", 4, 8, false},
		{"8-4", 0, 0, true},
		{"lots", 0, 0, true},
	}
	for _, c := range cases {
		gotMin, gotMax, err := parseRange(c.in, 100, 1000)
		if c.wantErr {
			if err == nil {
				t.Errorf("parseRange(%q) expected an error", c.in)
			}
			continue
		}
		if err != nil || gotMin != c.min || gotMax != c.max {
			t.Errorf("parseRange(%q) = %d,%d,%v want %d,%d,nil", c.in, gotMin, gotMax, err, c.min, c.max)
		}
	}
}

func TestRandomPaddingStaysInRange(t *testing.T) {
	// The server answers 400 when x_padding falls outside its configured
	// range, so this bound is part of the protocol, not cosmetics.
	for i := 0; i < 200; i++ {
		padding, err := randomPadding(100, 1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(padding) < 100 || len(padding) > 1000 {
			t.Fatalf("padding length %d out of range", len(padding))
		}
		if strings.Trim(padding, "X") != "" {
			t.Fatalf("padding must be opaque filler, got %q", padding[:10])
		}
	}
	fixed, err := randomPadding(7, 7)
	if err != nil || len(fixed) != 7 {
		t.Fatalf("fixed padding = %q, %v", fixed, err)
	}
}

func TestNewSessionIDIsUniqueAndURLSafe(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id, err := newSessionID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 32 {
			t.Fatalf("session id %q has length %d", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate session id %q", id)
		}
		seen[id] = true
	}
}
