package util

import "testing"

func TestNormalizeDomain(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://WWW.Example.com/path", "example.com"},
		{"example.com:443", "example.com"},
		{"sub.example.com", "sub.example.com"},
	}

	for _, tt := range tests {
		got, err := NormalizeDomain(tt.input)
		if err != nil {
			t.Fatalf("NormalizeDomain(%q) returned error: %v", tt.input, err)
		}
		if got != tt.want {
			t.Fatalf("NormalizeDomain(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}
