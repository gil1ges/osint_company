package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/gorcher/osint_company/internal/models"
)

func TestGenerateAllReportFormats(t *testing.T) {
	report := models.Report{
		GeneratedAt: time.Unix(1710000000, 0).UTC(),
		Inputs: models.TargetInput{
			Company: "Acme Corp",
			INN:     "7700000000",
			Domain:  "example.com",
		},
		Warnings: []string{"passive source unavailable", "passive source unavailable"},
		Errors: []models.SourceError{
			{SourceName: "dns", Operation: "lookup_ip", Error: "timeout"},
			{SourceName: "dns", Operation: "lookup_ip", Error: "timeout"},
		},
		Profile: &models.ProfileModuleResult{
			ModuleResult: models.ModuleResult{
				Name: "profile",
				Findings: []models.Finding{
					{FieldName: "full_legal_name", Value: "ООО ACME", Confidence: models.ConfidenceMedium},
				},
			},
			Data: models.ProfileData{
				OfficialWebsite: "https://example.com",
				FullLegalName:   "ООО ACME",
				INN:             "7700000000",
				OGRN:            "1027700000000",
				OfficeAddresses: []string{"Moscow, Example street, 1"},
				Activities: models.ProfileActivities{
					Services:   []string{"web development"},
					Industries: []string{"fintech"},
				},
			},
		},
		DigitalFootprint: &models.DigitalFootprintModuleResult{
			ModuleResult: models.ModuleResult{
				Name: "digitalfootprint",
				Findings: []models.Finding{
					{FieldName: "technology", Value: "Nginx", Confidence: models.ConfidenceMedium},
				},
			},
			Data: models.DigitalFootprintData{
				OfficialWebsite: "https://example.com",
				Domain:          "example.com",
				ProvidersUsed:   []string{"spiderfoot"},
				IPs:             []string{"1.2.3.4"},
				ProviderHints: []string{
					"hosting/provider: Example Cloud",
					"nameserver: ns1.example.com",
					"netblock: 1.2.3.0/24",
					"asn: AS64500",
				},
				Technologies: []string{"Next.js", "Nginx"},
			},
		},
	}

	formats := []struct {
		name string
		fn   func(models.Report) ([]byte, string, error)
		want string
	}{
		{"json", GenerateJSON, "Acme Corp"},
		{"html", GenerateHTML, "OSINT-отчет по компании"},
	}

	for _, tt := range formats {
		data, _, err := tt.fn(report)
		if err != nil {
			t.Fatalf("%s returned error: %v", tt.name, err)
		}
		if !strings.Contains(string(data), tt.want) {
			t.Fatalf("%s output did not contain %q", tt.name, tt.want)
		}
	}
}

func TestGenerateHTMLIncludesKeyBoundFields(t *testing.T) {
	report := models.Report{
		GeneratedAt: time.Unix(1710000000, 0).UTC(),
		Inputs: models.TargetInput{
			Company: "Acme Corp",
			Domain:  "example.com",
		},
		Profile: &models.ProfileModuleResult{
			Data: models.ProfileData{
				FullLegalName:   "ООО ACME",
				INN:             "7700000000",
				OGRN:            "1027700000000",
				OfficeAddresses: []string{"Moscow, Example street, 1"},
			},
		},
		DigitalFootprint: &models.DigitalFootprintModuleResult{
			Data: models.DigitalFootprintData{
				Domain:        "example.com",
				ProvidersUsed: []string{"spiderfoot"},
				IPs:           []string{"84.201.185.208", "89.169.178.50"},
				ProviderHints: []string{
					"hosting/provider: Yandex Cloud",
					"nameserver: ns1.yandexcloud.net",
					"nameserver: ns2.yandexcloud.net",
					"netblock: 89.169.128.0/18",
					"asn: AS119021",
					"asn: AS169",
					"asn: AS200350",
				},
				Technologies: []string{"Next.js", "Nginx"},
			},
		},
	}

	data, _, err := GenerateHTML(report)
	if err != nil {
		t.Fatalf("GenerateHTML returned error: %v", err)
	}
	output := string(data)
	for _, want := range []string{
		"7700000000",
		"1027700000000",
		"84.201.185.208",
		"89.169.178.50",
		"Yandex Cloud",
		"ns1.yandexcloud.net",
		"ns2.yandexcloud.net",
		"89.169.128.0/18",
		"AS119021",
		"AS169",
		"AS200350",
		"spiderfoot",
		"Next.js",
		"Nginx",
		"Профиль компании",
		"Цифровой след",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected HTML report to contain %q, got %s", want, output)
		}
	}
}

func TestGenerateHTMLMatchesDigitalFootprintSample(t *testing.T) {
	report := models.Report{
		GeneratedAt: time.Unix(1710000000, 0).UTC(),
		Inputs: models.TargetInput{
			Company: "ЗАЗЕКС",
			Domain:  "zuzex.ru",
		},
		DigitalFootprint: &models.DigitalFootprintModuleResult{
			Data: models.DigitalFootprintData{
				OfficialWebsite: "https://www.zuzex.ru/",
				Domain:          "zuzex.ru",
				DomainDiscovery: "provided via CLI input",
				ProvidersUsed:   []string{"spiderfoot"},
				IPs: []string{
					"2a0d:d6c1:0:1a::1b4",
					"2a0d:d6c1:0:1a::2c9",
					"84.201.185.208",
					"84.201.189.229",
					"89.169.178.50",
				},
				Technologies: []string{"Next.js", "Nginx"},
				ProviderHints: []string{
					"asn: AS119021",
					"asn: AS169",
					"asn: AS200350",
					"hosting/provider: Yandex Cloud",
					"nameserver: ns1.yandexcloud.net",
					"nameserver: ns2.yandexcloud.net",
					"netblock: 89.169.128.0/18",
				},
			},
		},
	}

	data, _, err := GenerateHTML(report)
	if err != nil {
		t.Fatalf("GenerateHTML returned error: %v", err)
	}
	output := string(data)
	for _, want := range []string{
		"spiderfoot",
		"2a0d:d6c1:0:1a::1b4",
		"2a0d:d6c1:0:1a::2c9",
		"84.201.185.208",
		"84.201.189.229",
		"89.169.178.50",
		"Next.js",
		"Nginx",
		"ns1.yandexcloud.net",
		"ns2.yandexcloud.net",
		"Yandex Cloud",
		"89.169.128.0/18",
		"AS119021",
		"AS169",
		"AS200350",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("expected HTML report to contain %q, got %s", want, output)
		}
	}
}

func TestGenerateHTMLMatchesJSONForSameReportObject(t *testing.T) {
	report := models.Report{
		GeneratedAt: time.Unix(1710000000, 0).UTC(),
		Inputs: models.TargetInput{
			Company: "ЗАЗЕКС",
			Domain:  "zuzex.ru",
		},
		DigitalFootprint: &models.DigitalFootprintModuleResult{
			Data: models.DigitalFootprintData{
				OfficialWebsite: "https://www.zuzex.ru/",
				Domain:          "zuzex.ru",
				DomainDiscovery: "provided via CLI input",
				ProvidersUsed:   []string{"spiderfoot"},
				IPs: []string{
					"2a0d:d6c1:0:1a::1b4",
					"2a0d:d6c1:0:1a::2c9",
					"84.201.185.208",
					"84.201.189.229",
					"89.169.178.50",
				},
				Technologies: []string{"Next.js", "Nginx"},
				ProviderHints: []string{
					"asn: AS119021",
					"asn: AS169",
					"asn: AS200350",
					"hosting/provider: Yandex Cloud",
					"nameserver: ns1.yandexcloud.net",
					"nameserver: ns2.yandexcloud.net",
					"netblock: 89.169.128.0/18",
				},
			},
		},
	}

	jsonData, _, err := GenerateJSON(report)
	if err != nil {
		t.Fatalf("GenerateJSON returned error: %v", err)
	}
	htmlData, _, err := GenerateHTML(report)
	if err != nil {
		t.Fatalf("GenerateHTML returned error: %v", err)
	}

	var compact compactJSONReport
	if err := json.Unmarshal(jsonData, &compact); err != nil {
		t.Fatalf("unmarshal compact JSON: %v", err)
	}
	if compact.DigitalFootprint == nil {
		t.Fatal("expected digital_footprint in compact JSON")
	}

	html := string(htmlData)
	for _, value := range compact.DigitalFootprint.ProvidersUsed {
		if !strings.Contains(html, value) {
			t.Fatalf("expected HTML to contain provider %q, got %s", value, html)
		}
	}
	for _, value := range compact.DigitalFootprint.IPs {
		if !strings.Contains(html, value) {
			t.Fatalf("expected HTML to contain IP %q, got %s", value, html)
		}
	}
	for _, value := range compact.DigitalFootprint.Technologies {
		if !strings.Contains(html, value) {
			t.Fatalf("expected HTML to contain technology %q, got %s", value, html)
		}
	}
	for _, value := range []string{
		"ns1.yandexcloud.net",
		"ns2.yandexcloud.net",
		"Yandex Cloud",
		"89.169.128.0/18",
		"AS119021",
		"AS169",
		"AS200350",
	} {
		if !strings.Contains(html, value) {
			t.Fatalf("expected HTML to contain parsed provider hint %q, got %s", value, html)
		}
	}
}

func TestGenerateJSONUsesNullAndEmptyCollections(t *testing.T) {
	report := models.Report{
		GeneratedAt: time.Unix(1710000000, 0).UTC(),
		Inputs: models.TargetInput{
			Company: "Acme Corp",
		},
		Profile: &models.ProfileModuleResult{
			Data: models.ProfileData{},
		},
	}

	data, _, err := GenerateJSON(report)
	if err != nil {
		t.Fatalf("GenerateJSON returned error: %v", err)
	}
	output := string(data)
	if !strings.Contains(output, `"full_legal_name": null`) {
		t.Fatalf("expected null legal name in json, got %s", output)
	}
	if !strings.Contains(output, `"office_addresses": []`) {
		t.Fatalf("expected empty office_addresses array in json, got %s", output)
	}
}

func TestGroupedErrorsInJSON(t *testing.T) {
	report := models.Report{
		GeneratedAt: time.Unix(1710000000, 0).UTC(),
		Errors: []models.SourceError{
			{SourceName: "http", Operation: "fetch_page", Error: "http status 404"},
			{SourceName: "http", Operation: "fetch_page", Error: "http status 404"},
		},
	}

	data, _, err := GenerateJSON(report)
	if err != nil {
		t.Fatalf("GenerateJSON returned error: %v", err)
	}
	output := string(data)
	if !strings.Contains(output, `"error": "http status 404"`) || !strings.Contains(output, `"count": 2`) {
		t.Fatalf("expected grouped error in json report, got %s", output)
	}
}
