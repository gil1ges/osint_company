package models

import "time"

type TargetInput struct {
	Company string `json:"company,omitempty"`
	INN     string `json:"inn,omitempty"`
	Domain  string `json:"domain,omitempty"`
}

type Report struct {
	GeneratedAt      time.Time                     `json:"generated_at"`
	Inputs           TargetInput                   `json:"inputs"`
	Profile          *ProfileModuleResult          `json:"profile,omitempty"`
	DigitalFootprint *DigitalFootprintModuleResult `json:"digital_footprint,omitempty"`
	Warnings         []string                      `json:"warnings,omitempty"`
	Errors           []SourceError                 `json:"errors,omitempty"`
}
