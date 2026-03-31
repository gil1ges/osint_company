package report

import (
	"fmt"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
)

func GenerateText(report models.Report) ([]byte, string, error) {
	var b strings.Builder
	b.WriteString("COMPANY OSINT REPORT\n")
	b.WriteString("====================\n\n")
	b.WriteString(fmt.Sprintf("Generated at: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05Z07:00")))
	b.WriteString(fmt.Sprintf("Company: %s\n", orFallback(report.Inputs.Company, "not provided")))
	b.WriteString(fmt.Sprintf("INN: %s\n", orFallback(report.Inputs.INN, "not provided")))
	b.WriteString(fmt.Sprintf("Domain: %s\n\n", orFallback(report.Inputs.Domain, "not provided")))

	if report.Profile != nil {
		b.WriteString("1. BASIC COMPANY PROFILE\n")
		b.WriteString("------------------------\n")
		b.WriteString(fmt.Sprintf("Official website: %s\n", orFallback(report.Profile.Data.OfficialWebsite, "Not found")))
		b.WriteString(fmt.Sprintf("Full legal name: %s\n", orFallback(report.Profile.Data.FullLegalName, "Not found")))
		b.WriteString(fmt.Sprintf("INN: %s\n", orFallback(report.Profile.Data.INN, "Not found")))
		b.WriteString(fmt.Sprintf("OGRN: %s\n", orFallback(report.Profile.Data.OGRN, "Not found")))
		b.WriteString(fmt.Sprintf("Registration details: %s\n", orFallback(report.Profile.Data.RegistrationData, "Not found")))
		b.WriteString(fmt.Sprintf("Registration date: %s\n", orFallback(report.Profile.Data.RegistrationDate, "Not found")))
		b.WriteString(fmt.Sprintf("Office addresses: %s\n", joinOrFallback(report.Profile.Data.OfficeAddresses, "Not found")))
		b.WriteString(fmt.Sprintf("Branches: %s\n", joinOrFallback(report.Profile.Data.Branches, "Not found")))
		b.WriteString(fmt.Sprintf("Subsidiaries: %s\n", joinOrFallback(report.Profile.Data.Subsidiaries, "Not found")))
		b.WriteString(fmt.Sprintf("Services: %s\n", joinOrFallback(report.Profile.Data.Activities.Services, "Not found")))
		b.WriteString(fmt.Sprintf("Industries: %s\n", joinOrFallback(report.Profile.Data.Activities.Industries, "Not found")))
		b.WriteString(fmt.Sprintf("Licenses: %s\n", joinOrFallback(report.Profile.Data.Licenses, "Not found")))
		b.WriteString(fmt.Sprintf("Certificates: %s\n", joinOrFallback(report.Profile.Data.Certificates, "Not found")))
		b.WriteString(fmt.Sprintf("Documents scanned: %s\n\n", joinDocuments(report.Profile.Data.DocumentsScanned)))
	}

	if report.DigitalFootprint != nil {
		b.WriteString("2. DIGITAL FOOTPRINT\n")
		b.WriteString("--------------------\n")
		b.WriteString(fmt.Sprintf("Official website: %s\n", orFallback(report.DigitalFootprint.Data.OfficialWebsite, "Not found")))
		b.WriteString(fmt.Sprintf("Domain: %s\n", orFallback(report.DigitalFootprint.Data.Domain, "Not found")))
		b.WriteString(fmt.Sprintf("Providers used: %s\n", joinOrFallback(report.DigitalFootprint.Data.ProvidersUsed, "Not found")))
		b.WriteString(fmt.Sprintf("CDN: %s\n", orFallback(report.DigitalFootprint.Data.CDN, "Not found")))
		b.WriteString(fmt.Sprintf("IPs: %s\n", joinOrFallback(report.DigitalFootprint.Data.IPs, "Not found")))
		b.WriteString(fmt.Sprintf("Technologies: %s\n", joinOrFallback(report.DigitalFootprint.Data.Technologies, "Not found")))
		b.WriteString(fmt.Sprintf("Subdomains: %s\n\n", joinOrFallback(report.DigitalFootprint.Data.Subdomains, "Not found")))
	}

	if len(report.Warnings) > 0 {
		b.WriteString("WARNINGS\n")
		b.WriteString("--------\n")
		for _, warning := range aggregateWarnings(report.Warnings) {
			b.WriteString("- " + warning + "\n")
		}
		b.WriteString("\n")
	}

	if len(report.Errors) > 0 {
		b.WriteString("ERRORS\n")
		b.WriteString("------\n")
		for _, err := range aggregateErrors(report.Errors) {
			b.WriteString(fmt.Sprintf("- %s / %s: %s\n", err.SourceName, err.Operation, formatAggregatedError(err)))
		}
	}

	return []byte(b.String()), "txt", nil
}
