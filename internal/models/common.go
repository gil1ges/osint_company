package models

import "time"

type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

type Evidence struct {
	SourceName  string    `json:"source_name"`
	SourceURL   string    `json:"source_url,omitempty"`
	SourceType  string    `json:"source_type"`
	RetrievedAt time.Time `json:"retrieved_at"`
	Method      string    `json:"method"`
	Snippet     string    `json:"snippet,omitempty"`
}

type Conflict struct {
	FieldName       string     `json:"field_name"`
	Value           string     `json:"value"`
	NormalizedValue string     `json:"normalized_value,omitempty"`
	Notes           []string   `json:"notes,omitempty"`
	Evidence        []Evidence `json:"evidence,omitempty"`
}

type Finding struct {
	FieldName       string     `json:"field_name"`
	Value           string     `json:"value"`
	NormalizedValue string     `json:"normalized_value,omitempty"`
	Module          string     `json:"module"`
	Verified        bool       `json:"verified"`
	Confidence      Confidence `json:"confidence"`
	CollectedAt     time.Time  `json:"collected_at"`
	Notes           []string   `json:"notes,omitempty"`
	Evidence        []Evidence `json:"evidence,omitempty"`
	Conflicts       []Conflict `json:"conflicts,omitempty"`
}

type SourceError struct {
	SourceName  string    `json:"source_name"`
	SourceURL   string    `json:"source_url,omitempty"`
	SourceType  string    `json:"source_type,omitempty"`
	Operation   string    `json:"operation,omitempty"`
	Error       string    `json:"error"`
	Temporary   bool      `json:"temporary"`
	CollectedAt time.Time `json:"collected_at"`
}

type ModuleResult struct {
	Name     string        `json:"name"`
	Findings []Finding     `json:"findings"`
	Warnings []string      `json:"warnings,omitempty"`
	Errors   []SourceError `json:"errors,omitempty"`
}
