package digitalfootprint

import (
	"strings"
	"testing"

	"github.com/gorcher/osint_company/internal/models"
)

func TestSummarizeProviderHints(t *testing.T) {
	hints := summarizeProviderHints([]string{
		`PROVIDER_DNS | ns1.yandexcloud.net | zuzex.ru | sfp_dnsraw`,
		`BGP_AS_MEMBER | 200350 | 89.169.128.0/18 | sfp_ripe`,
		`RAW_RIR_DATA | {"asname":"YandexCloud","bgproute":"89.169.128.0/18"} | 89.169.178.50 | sfp_ripe`,
	})

	joined := strings.Join(hints, " | ")
	for _, expected := range []string{
		"hosting/provider: Yandex Cloud",
		"asn: AS200350",
		"netblock: 89.169.128.0/18",
		"nameserver: ns1.yandexcloud.net",
	} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("expected %q in summarized hints, got %#v", expected, hints)
		}
	}
}

func TestCondenseSpiderFootErrors(t *testing.T) {
	errors := []models.SourceError{
		{SourceName: "spiderfoot", Operation: "scan_error", Error: "You enabled sfp_abuseipdb but did not set an API key!"},
		{SourceName: "spiderfoot", Operation: "scan_error", Error: "Failed to connect to https://api.bgpview.io/asn/200350"},
		{SourceName: "http", Operation: "fetch_page", Error: "http status 404"},
	}

	filtered, warnings := condenseSpiderFootErrors(errors, nil)
	if len(filtered) != 1 || filtered[0].SourceName != "http" {
		t.Fatalf("expected non-spiderfoot error to remain, got %#v", filtered)
	}
	if !containsWarningText(warnings, "SpiderFoot completed with partial third-party module failures and missing optional API-key integrations") {
		t.Fatalf("expected condensed spiderfoot warning, got %#v", warnings)
	}
}

func containsWarningText(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
