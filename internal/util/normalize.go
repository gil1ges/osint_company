package util

import (
	"fmt"
	"html"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var multiSpace = regexp.MustCompile(`\s+`)

func NormalizeDomain(input string) (string, error) {
	raw := strings.TrimSpace(strings.ToLower(input))
	if raw == "" {
		return "", fmt.Errorf("empty domain")
	}
	if strings.Contains(raw, "://") {
		parsed, err := url.Parse(raw)
		if err != nil {
			return "", err
		}
		raw = parsed.Host
	}
	if strings.Contains(raw, "/") {
		parts := strings.Split(raw, "/")
		raw = parts[0]
	}
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		raw = host
		if port == "" {
			return "", fmt.Errorf("empty port in domain")
		}
	}
	raw = strings.TrimPrefix(raw, "www.")
	raw = strings.Trim(raw, ". ")
	if raw == "" {
		return "", fmt.Errorf("empty domain")
	}
	return raw, nil
}

func NormalizeURL(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	if strings.HasPrefix(input, "//") {
		return "https:" + input
	}
	if !strings.Contains(input, "://") {
		return "https://" + input
	}
	return input
}

func ExtractDomainFromURL(input string) string {
	normalized := NormalizeURL(input)
	parsed, err := url.Parse(normalized)
	if err != nil {
		return ""
	}
	host := parsed.Hostname()
	host, err = NormalizeDomain(host)
	if err != nil {
		return ""
	}
	return host
}

func NormalizeWhitespace(value string) string {
	value = html.UnescapeString(value)
	value = strings.TrimSpace(value)
	return multiSpace.ReplaceAllString(value, " ")
}

func NormalizeDigits(value string) string {
	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func ClipString(value string, limit int) string {
	if limit <= 0 || len(value) <= limit {
		return value
	}
	return strings.TrimSpace(value[:limit]) + "..."
}

func UniqueStrings(values []string) []string {
	set := make(map[string]string)
	for _, value := range values {
		normalized := strings.TrimSpace(value)
		if normalized == "" {
			continue
		}
		key := strings.ToLower(normalized)
		if _, exists := set[key]; !exists {
			set[key] = normalized
		}
	}
	out := make([]string, 0, len(set))
	for _, value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func UniqueLowerStrings(values []string) []string {
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.ToLower(strings.TrimSpace(value))
		if value != "" {
			normalized = append(normalized, value)
		}
	}
	return UniqueStrings(normalized)
}

func JoinHeaderValues(values []string) string {
	return strings.Join(values, "; ")
}
