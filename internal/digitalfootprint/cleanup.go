package digitalfootprint

import (
	"regexp"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

var (
	reHintASN  = regexp.MustCompile(`(?i)\b(?:AS)?(\d{3,10})\b`)
	reHintCIDR = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b`)
	reHintNS   = regexp.MustCompile(`(?i)\bns\d+\.[a-z0-9.-]+\.[a-z]{2,}\b`)
)

func cleanupResult(result *models.DigitalFootprintModuleResult) {
	result.Data.ProviderHints = summarizeProviderHints(result.Data.ProviderHints)
	result.Errors, result.Warnings = condenseSpiderFootErrors(result.Errors, result.Warnings)
}

func summarizeProviderHints(values []string) []string {
	summaries := make([]string, 0)
	for _, value := range values {
		lower := strings.ToLower(strings.TrimSpace(value))
		if lower == "" {
			continue
		}

		if provider := inferProviderName(lower); provider != "" {
			summaries = append(summaries, "hosting/provider: "+provider)
		}
		if match := reHintASN.FindStringSubmatch(value); len(match) > 1 {
			summaries = append(summaries, "asn: AS"+match[1])
		}
		if cidr := reHintCIDR.FindString(value); cidr != "" {
			summaries = append(summaries, "netblock: "+cidr)
		}
		if ns := reHintNS.FindString(lower); ns != "" {
			summaries = append(summaries, "nameserver: "+ns)
			continue
		}
		if strings.HasPrefix(lower, "ns") && strings.Contains(lower, ".") && !strings.Contains(lower, " ") {
			summaries = append(summaries, "nameserver: "+lower)
		}
	}
	return util.UniqueStrings(summaries)
}

func inferProviderName(lower string) string {
	switch {
	case strings.Contains(lower, "yandexcloud"), strings.Contains(lower, "yandex.cloud"):
		return "Yandex Cloud"
	case strings.Contains(lower, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(lower, "amazon"), strings.Contains(lower, "aws"), strings.Contains(lower, "cloudfront"):
		return "Amazon"
	case strings.Contains(lower, "google"), strings.Contains(lower, "gcp"):
		return "Google Cloud"
	case strings.Contains(lower, "azure"), strings.Contains(lower, "microsoft"):
		return "Microsoft Azure"
	case strings.Contains(lower, "digitalocean"):
		return "DigitalOcean"
	case strings.Contains(lower, "fastly"):
		return "Fastly"
	case strings.Contains(lower, "akamai"):
		return "Akamai"
	default:
		return ""
	}
}

func condenseSpiderFootErrors(errors []models.SourceError, warnings []string) ([]models.SourceError, []string) {
	filtered := make([]models.SourceError, 0, len(errors))
	var apiKeyFailures int
	var thirdPartyFailures int

	for _, item := range errors {
		if strings.EqualFold(item.SourceName, "spiderfoot") && strings.EqualFold(item.Operation, "scan_error") {
			lower := strings.ToLower(item.Error)
			switch {
			case strings.Contains(lower, "did not set an api key"), strings.Contains(lower, "did not set an api key/password"):
				apiKeyFailures++
				continue
			case strings.Contains(lower, "failed to connect"), strings.Contains(lower, "unexpected http response"), strings.Contains(lower, "unexpected reply"):
				thirdPartyFailures++
				continue
			}
		}
		filtered = append(filtered, item)
	}

	switch {
	case apiKeyFailures > 0 && thirdPartyFailures > 0:
		warnings = append(warnings, "SpiderFoot completed with partial third-party module failures and missing optional API-key integrations")
	case thirdPartyFailures > 0:
		warnings = append(warnings, "SpiderFoot completed with partial third-party module failures")
	case apiKeyFailures > 0:
		warnings = append(warnings, "SpiderFoot completed with missing optional API-key integrations")
	}

	return filtered, util.UniqueStrings(warnings)
}
