package profile

import (
	"testing"

	"github.com/gorcher/osint_company/internal/models"
)

func TestConfidenceRules(t *testing.T) {
	high := BuildFinalFindings([]models.NormalizedCandidate{
		{
			FieldName:       "full_legal_name",
			Value:           `ООО "ЗАЗЕКС"`,
			NormalizedValue: `ООО "ЗАЗЕКС"`,
			PageType:        "legal",
			PageURL:         "https://example.com/legal",
			Source:          "text",
			Official:        true,
			Authoritative:   true,
			Clean:           true,
		},
	})
	if len(high) != 1 || !high[0].Verified || high[0].Confidence != models.ConfidenceHigh {
		t.Fatalf("expected authoritative clean finding to be high verified, got %#v", high)
	}

	low := BuildFinalFindings([]models.NormalizedCandidate{
		{
			FieldName:       "full_legal_name",
			Value:           `{"slug":"corp"}`,
			NormalizedValue: `{"slug":"corp"}`,
			PageType:        "company",
			PageURL:         "https://example.com/company",
			Source:          "text",
			Official:        true,
			Authoritative:   false,
			Clean:           false,
		},
	})
	if len(low) != 0 {
		t.Fatalf("expected garbage candidate to be dropped, got %#v", low)
	}
}
