package digitalfootprint

import (
	"slices"
	"testing"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/providers"
)

func TestMergeScalarKeepsOldWhenNewEmpty(t *testing.T) {
	if got := mergeScalar("Cloudflare", ""); got != "Cloudflare" {
		t.Fatalf("mergeScalar should keep old non-empty value, got %q", got)
	}
	if got := mergeScalar("Cloudflare", "Fastly"); got != "Fastly" {
		t.Fatalf("mergeScalar should prefer new non-empty value, got %q", got)
	}
}

func TestMergeStringListsPreservesOldAndAddsNew(t *testing.T) {
	got := mergeStringLists(
		[]string{"spiderfoot", "203.0.113.10", "Nginx"},
		[]string{"", "203.0.113.10", "Fastly"},
	)
	want := []string{"203.0.113.10", "Fastly", "Nginx", "spiderfoot"}
	if !slices.Equal(got, want) {
		t.Fatalf("mergeStringLists() = %#v, want %#v", got, want)
	}
}

func TestMergeWaybackSnapshotsKeepsOldWhenNewEmpty(t *testing.T) {
	oldValues := []models.WaybackSnapshot{
		{Timestamp: "20240101000000", OriginalURL: "https://example.com", ArchiveURL: "https://web.archive.org/example"},
	}
	got := mergeWaybackSnapshots(oldValues, nil)
	if !slices.Equal(got, oldValues) {
		t.Fatalf("mergeWaybackSnapshots() = %#v, want %#v", got, oldValues)
	}
}

func TestMergePortFindingsKeepsOldWhenNewEmpty(t *testing.T) {
	oldValues := []models.PortFinding{
		{IP: "203.0.113.10", Port: 443, Transport: "tcp", Source: "shodan", Product: "nginx"},
	}
	got := mergePortFindings(oldValues, nil)
	if !slices.Equal(got, oldValues) {
		t.Fatalf("mergePortFindings() = %#v, want %#v", got, oldValues)
	}
}

func TestApplyExternalEnrichmentRetainsEarlierValues(t *testing.T) {
	result := models.DigitalFootprintModuleResult{
		Data: models.DigitalFootprintData{
			IPs:           []string{"203.0.113.10"},
			Technologies:  []string{"Nginx"},
			ProviderHints: []string{"asn: AS64500"},
			Subdomains:    []string{"api.example.com"},
		},
	}

	applyExternalEnrichment(&result, providers.EnrichmentResult{})

	if !slices.Equal(result.Data.IPs, []string{"203.0.113.10"}) {
		t.Fatalf("expected IPs to survive empty enrichment, got %#v", result.Data.IPs)
	}
	if !slices.Equal(result.Data.Technologies, []string{"Nginx"}) {
		t.Fatalf("expected technologies to survive empty enrichment, got %#v", result.Data.Technologies)
	}
	if !slices.Equal(result.Data.ProviderHints, []string{"asn: AS64500"}) {
		t.Fatalf("expected provider hints to survive empty enrichment, got %#v", result.Data.ProviderHints)
	}
	if !slices.Equal(result.Data.Subdomains, []string{"api.example.com"}) {
		t.Fatalf("expected subdomains to survive empty enrichment, got %#v", result.Data.Subdomains)
	}
}
