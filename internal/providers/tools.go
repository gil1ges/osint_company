package providers

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

type ToolStatus struct {
	Name      string `json:"name"`
	Path      string `json:"path,omitempty"`
	Available bool   `json:"available"`
}

func LookupTool(name string) ToolStatus {
	path, err := exec.LookPath(name)
	if err != nil {
		return ToolStatus{Name: name, Available: false}
	}
	return ToolStatus{Name: name, Path: path, Available: true}
}

func ToolUnavailableError(name string) models.SourceError {
	return models.SourceError{
		SourceName:  name,
		SourceType:  "tool",
		Operation:   "lookup",
		Error:       "tool not installed",
		Temporary:   false,
		CollectedAt: time.Now().UTC(),
	}
}

func WrapError(sourceName, sourceType, operation, sourceURL string, err error) models.SourceError {
	return models.SourceError{
		SourceName:  sourceName,
		SourceType:  sourceType,
		Operation:   operation,
		SourceURL:   sourceURL,
		Error:       err.Error(),
		Temporary:   true,
		CollectedAt: time.Now().UTC(),
	}
}

func ParseJSONLines[T any](data []byte) ([]T, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	out := make([]T, 0)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var item T
		if err := json.Unmarshal([]byte(line), &item); err != nil {
			return nil, fmt.Errorf("parse json line %q: %w", util.ClipString(line, 160), err)
		}
		out = append(out, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func NormalizeHosts(domain string, hosts []string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	set := make(map[string]struct{})
	for _, host := range hosts {
		host = strings.ToLower(strings.TrimSpace(host))
		host = strings.TrimPrefix(host, "*.")
		host = strings.TrimSuffix(host, ".")
		if host == "" {
			continue
		}
		if domain != "" && host != domain && !strings.HasSuffix(host, "."+domain) {
			continue
		}
		set[host] = struct{}{}
	}

	out := make([]string, 0, len(set))
	for host := range set {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func NormalizeSubdomains(domain string, hosts []string) []string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}

	normalized := NormalizeHosts(domain, hosts)
	out := make([]string, 0, len(normalized))
	for _, host := range normalized {
		if host == domain {
			continue
		}
		out = append(out, host)
	}
	return out
}

func runConfiguredTextProvider(ctx context.Context, name, command string, placeholders map[string]string) ([]string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return nil, fmt.Errorf("provider command is not configured")
	}

	fields := strings.Fields(command)
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty provider command")
	}
	for idx, field := range fields {
		for key, value := range placeholders {
			field = strings.ReplaceAll(field, "{{"+key+"}}", value)
		}
		fields[idx] = field
	}

	result, err := util.RunCommand(ctx, fields[0], fields[1:]...)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	lines := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(result.Stdout))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lines, nil
}
