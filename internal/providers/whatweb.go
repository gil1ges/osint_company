package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

type whatwebEntry struct {
	Target  string                         `json:"target"`
	Plugins map[string]map[string][]string `json:"plugins"`
}

func ParseWhatWebJSON(data []byte) ([]string, error) {
	var entries []whatwebEntry
	if err := json.Unmarshal(data, &entries); err == nil {
		return extractWhatWebTechnologies(entries), nil
	}

	var single whatwebEntry
	if err := json.Unmarshal(data, &single); err == nil {
		return extractWhatWebTechnologies([]whatwebEntry{single}), nil
	}

	return nil, fmt.Errorf("unrecognized WhatWeb JSON")
}

func extractWhatWebTechnologies(entries []whatwebEntry) []string {
	set := make(map[string]struct{})
	for _, entry := range entries {
		for plugin := range entry.Plugins {
			name := strings.TrimSpace(plugin)
			if name == "" {
				continue
			}
			set[name] = struct{}{}
		}
	}

	out := make([]string, 0, len(set))
	for tech := range set {
		out = append(out, tech)
	}
	sort.Strings(out)
	return out
}

func RunWhatWeb(ctx context.Context, targetURL string) ([]string, *models.SourceError) {
	if !util.CommandExists("whatweb") {
		err := ToolUnavailableError("whatweb")
		return nil, &err
	}

	tmpFile, err := os.CreateTemp("", "whatweb-*.json")
	if err != nil {
		sourceErr := WrapError("whatweb", "tool", "tempfile", "", err)
		return nil, &sourceErr
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	_, err = util.RunCommand(ctx, "whatweb", "--quiet", fmt.Sprintf("--log-json=%s", tmpFile.Name()), targetURL)
	if err != nil {
		sourceErr := WrapError("whatweb", "tool", "detect_technologies", targetURL, err)
		return nil, &sourceErr
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		sourceErr := WrapError("whatweb", "tool", "read_output", targetURL, err)
		return nil, &sourceErr
	}

	tech, err := ParseWhatWebJSON(data)
	if err != nil {
		sourceErr := WrapError("whatweb", "tool", "parse_json", targetURL, err)
		return nil, &sourceErr
	}
	return tech, nil
}
