package report

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
)

type aggregatedSourceError struct {
	SourceName string `json:"source"`
	Operation  string `json:"operation,omitempty"`
	Error      string `json:"error"`
	Count      int    `json:"count,omitempty"`
}

func aggregateWarnings(values []string) []string {
	set := make(map[string]struct{})
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := set[key]; ok {
			continue
		}
		set[key] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func aggregateErrors(items []models.SourceError) []aggregatedSourceError {
	grouped := make(map[string]aggregatedSourceError)
	for _, item := range items {
		key := strings.ToLower(item.SourceName + "|" + item.Operation + "|" + item.Error)
		current := grouped[key]
		current.SourceName = item.SourceName
		current.Operation = item.Operation
		current.Error = item.Error
		current.Count++
		grouped[key] = current
	}

	out := make([]aggregatedSourceError, 0, len(grouped))
	for _, item := range grouped {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].SourceName == out[j].SourceName {
			if out[i].Operation == out[j].Operation {
				return out[i].Error < out[j].Error
			}
			return out[i].Operation < out[j].Operation
		}
		return out[i].SourceName < out[j].SourceName
	})
	return out
}

func formatAggregatedError(item aggregatedSourceError) string {
	if item.Count > 1 {
		return fmt.Sprintf("%s (x%d)", item.Error, item.Count)
	}
	return item.Error
}

func stringPtr(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
