package report

import (
	"fmt"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
)

func GenerateMarkdown(report models.Report) ([]byte, string, error) {
	var b strings.Builder
	b.WriteString("# Company OSINT Report\n\n")
	b.WriteString(fmt.Sprintf("- Generated at: `%s`\n", report.GeneratedAt.Format("2006-01-02 15:04:05Z07:00")))
	b.WriteString(fmt.Sprintf("- Company: `%s`\n", orFallback(report.Inputs.Company, "not provided")))
	b.WriteString(fmt.Sprintf("- INN: `%s`\n", orFallback(report.Inputs.INN, "not provided")))
	b.WriteString(fmt.Sprintf("- Domain: `%s`\n\n", orFallback(report.Inputs.Domain, "not provided")))

	if report.Profile != nil {
		writeProfileMarkdown(&b, *report.Profile)
	}
	if report.DigitalFootprint != nil {
		writeDigitalMarkdown(&b, *report.DigitalFootprint)
	}
	if len(report.Warnings) > 0 {
		b.WriteString("## Warnings\n\n")
		for _, warning := range aggregateWarnings(report.Warnings) {
			b.WriteString("- " + warning + "\n")
		}
		b.WriteString("\n")
	}
	if len(report.Errors) > 0 {
		b.WriteString("## Errors\n\n")
		for _, err := range aggregateErrors(report.Errors) {
			b.WriteString(fmt.Sprintf("- `%s` / `%s`: %s\n", err.SourceName, err.Operation, formatAggregatedError(err)))
		}
	}
	return []byte(b.String()), "md", nil
}

func writeProfileMarkdown(b *strings.Builder, profile models.ProfileModuleResult) {
	b.WriteString("## 1. Basic Company Profile\n\n")
	b.WriteString(fmt.Sprintf("- Official website: `%s`\n", orFallback(profile.Data.OfficialWebsite, "Not found")))
	b.WriteString(fmt.Sprintf("- Full legal name: `%s`\n", orFallback(profile.Data.FullLegalName, "Not found")))
	b.WriteString(fmt.Sprintf("- INN: `%s`\n", orFallback(profile.Data.INN, "Not found")))
	b.WriteString(fmt.Sprintf("- OGRN: `%s`\n", orFallback(profile.Data.OGRN, "Not found")))
	b.WriteString(fmt.Sprintf("- Registration date: `%s`\n", orFallback(profile.Data.RegistrationDate, "Not found")))
	b.WriteString(fmt.Sprintf("- Registration details: `%s`\n", orFallback(profile.Data.RegistrationData, "Not found")))
	b.WriteString(fmt.Sprintf("- Office addresses: %s\n", joinOrFallback(profile.Data.OfficeAddresses, "Not found")))
	b.WriteString(fmt.Sprintf("- Branches: %s\n", joinOrFallback(profile.Data.Branches, "Not found")))
	b.WriteString(fmt.Sprintf("- Subsidiaries: %s\n", joinOrFallback(profile.Data.Subsidiaries, "Not found")))
	b.WriteString(fmt.Sprintf("- Services: %s\n", joinOrFallback(profile.Data.Activities.Services, "Not found")))
	b.WriteString(fmt.Sprintf("- Industries: %s\n", joinOrFallback(profile.Data.Activities.Industries, "Not found")))
	b.WriteString(fmt.Sprintf("- Licenses: %s\n", joinOrFallback(profile.Data.Licenses, "Not found")))
	b.WriteString(fmt.Sprintf("- Certificates: %s\n", joinOrFallback(profile.Data.Certificates, "Not found")))
	b.WriteString(fmt.Sprintf("- Documents scanned: %s\n\n", joinDocuments(profile.Data.DocumentsScanned)))
}

func writeDigitalMarkdown(b *strings.Builder, footprint models.DigitalFootprintModuleResult) {
	b.WriteString("## 2. Digital Footprint\n\n")
	b.WriteString(fmt.Sprintf("- Official website: `%s`\n", orFallback(footprint.Data.OfficialWebsite, "Not found")))
	b.WriteString(fmt.Sprintf("- Domain: `%s`\n", orFallback(footprint.Data.Domain, "Not found")))
	b.WriteString(fmt.Sprintf("- Discovery: `%s`\n", orFallback(footprint.Data.DomainDiscovery, "Not found")))
	b.WriteString(fmt.Sprintf("- Providers used: %s\n", joinOrFallback(footprint.Data.ProvidersUsed, "Not found")))
	b.WriteString(fmt.Sprintf("- CDN: `%s`\n", orFallback(footprint.Data.CDN, "Not found")))
	b.WriteString(fmt.Sprintf("- IPs: %s\n", joinOrFallback(footprint.Data.IPs, "Not found")))
	b.WriteString(fmt.Sprintf("- Technologies: %s\n", joinOrFallback(footprint.Data.Technologies, "Not found")))
	b.WriteString(fmt.Sprintf("- Subdomains: %s\n\n", joinOrFallback(footprint.Data.Subdomains, "Not found")))
}

func orFallback(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func joinOrFallback(values []string, fallback string) string {
	if len(values) == 0 {
		return fallback
	}
	return strings.Join(values, ", ")
}

func joinDocuments(values []models.DocumentReference) string {
	if len(values) == 0 {
		return "Not found"
	}
	items := make([]string, 0, len(values))
	for _, item := range values {
		label := item.Label
		if strings.TrimSpace(label) == "" {
			label = item.URL
		}
		items = append(items, label)
	}
	return strings.Join(items, ", ")
}
