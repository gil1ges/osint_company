package report

import (
	"encoding/json"

	"github.com/gorcher/osint_company/internal/models"
)

func GenerateJSON(report models.Report) ([]byte, string, error) {
	data, err := json.MarshalIndent(buildCompactJSONReport(report), "", "  ")
	return data, "json", err
}

type compactJSONReport struct {
	GeneratedAt      string                  `json:"generated_at"`
	Inputs           models.TargetInput      `json:"inputs"`
	BasicProfile     *compactProfileSection  `json:"basic_profile,omitempty"`
	DigitalFootprint *compactDigitalSection  `json:"digital_footprint,omitempty"`
	Warnings         []string                `json:"warnings,omitempty"`
	Errors           []aggregatedSourceError `json:"errors,omitempty"`
}

type compactProfileSection struct {
	OfficialWebsite  *string                    `json:"official_website"`
	FullLegalName    *string                    `json:"full_legal_name"`
	INN              *string                    `json:"inn"`
	OGRN             *string                    `json:"ogrn"`
	RegistrationData *string                    `json:"registration_data"`
	RegistrationDate *string                    `json:"registration_date"`
	OfficeAddresses  []string                   `json:"office_addresses"`
	Branches         []string                   `json:"branches"`
	Subsidiaries     []string                   `json:"subsidiaries"`
	Activities       compactProfileActivities   `json:"activities"`
	Licenses         []string                   `json:"licenses"`
	Certificates     []string                   `json:"certificates"`
	PagesScanned     []string                   `json:"pages_scanned"`
	DocumentsScanned []models.DocumentReference `json:"documents_scanned"`
}

type compactDigitalSection struct {
	OfficialWebsite *string                  `json:"official_website"`
	Domain          *string                  `json:"domain"`
	DomainDiscovery *string                  `json:"domain_discovery"`
	ProvidersUsed   []string                 `json:"providers_used"`
	Subdomains      []string                 `json:"subdomains"`
	IPs             []string                 `json:"ips"`
	CDN             *string                  `json:"cdn"`
	Technologies    []string                 `json:"technologies"`
	ProviderHints   []string                 `json:"provider_hints"`
	Ports           []models.PortFinding     `json:"ports"`
	Wayback         []models.WaybackSnapshot `json:"wayback"`
}

type compactProfileActivities struct {
	Services   []string `json:"services"`
	Industries []string `json:"industries"`
}

func buildCompactJSONReport(report models.Report) compactJSONReport {
	out := compactJSONReport{
		GeneratedAt: report.GeneratedAt.Format("2006-01-02T15:04:05Z07:00"),
		Inputs:      report.Inputs,
		Warnings:    aggregateWarnings(report.Warnings),
		Errors:      aggregateErrors(report.Errors),
	}

	if report.Profile != nil {
		out.BasicProfile = &compactProfileSection{
			OfficialWebsite:  stringPtr(report.Profile.Data.OfficialWebsite),
			FullLegalName:    stringPtr(report.Profile.Data.FullLegalName),
			INN:              stringPtr(report.Profile.Data.INN),
			OGRN:             stringPtr(report.Profile.Data.OGRN),
			RegistrationData: stringPtr(report.Profile.Data.RegistrationData),
			RegistrationDate: stringPtr(report.Profile.Data.RegistrationDate),
			OfficeAddresses:  cloneStringSlice(report.Profile.Data.OfficeAddresses),
			Branches:         cloneStringSlice(report.Profile.Data.Branches),
			Subsidiaries:     cloneStringSlice(report.Profile.Data.Subsidiaries),
			Activities: compactProfileActivities{
				Services:   cloneStringSlice(report.Profile.Data.Activities.Services),
				Industries: cloneStringSlice(report.Profile.Data.Activities.Industries),
			},
			Licenses:         cloneStringSlice(report.Profile.Data.Licenses),
			Certificates:     cloneStringSlice(report.Profile.Data.Certificates),
			PagesScanned:     cloneStringSlice(report.Profile.Data.PagesScanned),
			DocumentsScanned: cloneDocumentSlice(report.Profile.Data.DocumentsScanned),
		}
	}

	if report.DigitalFootprint != nil {
		out.DigitalFootprint = &compactDigitalSection{
			OfficialWebsite: stringPtr(report.DigitalFootprint.Data.OfficialWebsite),
			Domain:          stringPtr(report.DigitalFootprint.Data.Domain),
			DomainDiscovery: stringPtr(report.DigitalFootprint.Data.DomainDiscovery),
			ProvidersUsed:   cloneStringSlice(report.DigitalFootprint.Data.ProvidersUsed),
			Subdomains:      cloneStringSlice(report.DigitalFootprint.Data.Subdomains),
			IPs:             cloneStringSlice(report.DigitalFootprint.Data.IPs),
			CDN:             stringPtr(report.DigitalFootprint.Data.CDN),
			Technologies:    cloneStringSlice(report.DigitalFootprint.Data.Technologies),
			ProviderHints:   cloneStringSlice(report.DigitalFootprint.Data.ProviderHints),
			Ports:           clonePortSlice(report.DigitalFootprint.Data.Ports),
			Wayback:         cloneWaybackSlice(report.DigitalFootprint.Data.Wayback),
		}
	}

	return out
}

func cloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
	return append([]string{}, values...)
}

func cloneDocumentSlice(values []models.DocumentReference) []models.DocumentReference {
	if len(values) == 0 {
		return []models.DocumentReference{}
	}
	return append([]models.DocumentReference{}, values...)
}

func clonePortSlice(values []models.PortFinding) []models.PortFinding {
	if len(values) == 0 {
		return []models.PortFinding{}
	}
	return append([]models.PortFinding{}, values...)
}

func cloneWaybackSlice(values []models.WaybackSnapshot) []models.WaybackSnapshot {
	if len(values) == 0 {
		return []models.WaybackSnapshot{}
	}
	return append([]models.WaybackSnapshot{}, values...)
}
