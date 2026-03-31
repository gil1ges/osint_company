package digitalfootprint

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"time"

	"github.com/gorcher/osint_company/internal/config"
	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/providers"
	"github.com/gorcher/osint_company/internal/util"
)

type Service struct {
	httpClient *util.HTTPClient
	config     config.Config
	logger     *slog.Logger
}

func NewService(httpClient *util.HTTPClient, cfg config.Config, logger *slog.Logger) *Service {
	return &Service{
		httpClient: httpClient,
		config:     cfg,
		logger:     logger,
	}
}

func (s *Service) Collect(ctx context.Context, inputs models.TargetInput) models.DigitalFootprintModuleResult {
	result := models.DigitalFootprintModuleResult{
		ModuleResult: models.ModuleResult{Name: "digitalfootprint"},
	}

	domain, officialWebsite, discovery, discoveryEvidence, discoveryErrors := determineDomain(ctx, s.httpClient, s.logger, inputs)
	result.Errors = append(result.Errors, discoveryErrors...)
	result.Data.Domain = domain
	result.Data.OfficialWebsite = officialWebsite
	result.Data.DomainDiscovery = discovery

	if domain == "" {
		result.Warnings = append(result.Warnings, "official domain could not be confidently determined")
		return result
	}

	result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "domain", domain, true, models.ConfidenceMedium, discoveryEvidence...))
	if officialWebsite != "" {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "official_website", officialWebsite, true, models.ConfidenceMedium, append(discoveryEvidence, httpEvidence(officialWebsite, officialWebsite))...))
	}

	spiderFoot := providers.CollectSpiderFootEnrichment(ctx, s.httpClient, s.config.SpiderFootCommand, s.config.SpiderFootURL, s.config.SpiderFootResultsPath, domain, inputs.Company)
	result.Warnings = append(result.Warnings, spiderFoot.Warnings...)
	result.Errors = append(result.Errors, spiderFoot.Errors...)
	result.Data.ProvidersUsed = mergeStringLists(result.Data.ProvidersUsed, providers.ProvidersUsed(spiderFoot))
	applyExternalEnrichment(&result, spiderFoot)

	dnsRecords, dnsErrors := collectDNS(ctx, domain)
	result.Errors = append(result.Errors, dnsErrors...)
	result.Data.DNS = mergeDNSRecords(result.Data.DNS, dnsRecords)
	result.Data.IPs = mergeStringLists(result.Data.IPs, dnsRecords.A)
	result.Data.IPs = mergeStringLists(result.Data.IPs, dnsRecords.AAAA)
	appendDNSFindings(&result, domain, dnsRecords)

	httpCapture := fetchHTTP(ctx, s.httpClient, domain)
	result.Errors = append(result.Errors, httpCapture.Errors...)
	if httpCapture.Details != nil {
		result.Data.HTTP = httpCapture.Details
		result.Data.OfficialWebsite = mergeScalar(result.Data.OfficialWebsite, httpCapture.Details.FinalURL)
		if httpCapture.Details.Title != "" {
			result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "http_title", httpCapture.Details.Title, false, models.ConfidenceMedium, httpCapture.Evidence...))
		}
		if httpCapture.Details.Description != "" {
			result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "http_description", httpCapture.Details.Description, false, models.ConfidenceLow, httpCapture.Evidence...))
		}
	} else {
		result.Warnings = append(result.Warnings, buildHTTPNotFoundWarning(domain))
	}

	tlsInfo, tlsErrors := collectTLS(ctx, domain)
	result.Errors = append(result.Errors, tlsErrors...)
	result.Data.TLS = mergeTLSCertificate(result.Data.TLS, tlsInfo)
	if tlsInfo != nil {
		if tlsInfo.Issuer != "" {
			result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "tls_issuer", tlsInfo.Issuer, true, models.ConfidenceMedium, tlsEvidence(domain, tlsInfo.Issuer)))
		}
		if tlsInfo.Subject != "" {
			result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "tls_subject", tlsInfo.Subject, true, models.ConfidenceMedium, tlsEvidence(domain, tlsInfo.Subject)))
		}
	}

	rdapHints, rdapErrors := lookupRDAP(ctx, s.httpClient, result.Data.IPs)
	result.Errors = append(result.Errors, rdapErrors...)
	result.Data.ProviderHints = mergeStringLists(result.Data.ProviderHints, rdapHints)
	for _, hint := range rdapHints {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "provider_hint", hint, false, models.ConfidenceMedium, models.Evidence{
			SourceName:  "rdap",
			SourceType:  "rdap",
			RetrievedAt: nowUTC(),
			Method:      "rdap lookup",
			Snippet:     hint,
		}))
	}

	fallbackSubdomains, dnsErrors := collectSubdomains(ctx, s.httpClient, s.config, domain, subdomainSeeds(httpCapture))
	result.Errors = append(result.Errors, dnsErrors...)
	result.Data.Subdomains = mergeStringLists(result.Data.Subdomains, fallbackSubdomains)
	for _, host := range result.Data.Subdomains {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "subdomain", host, false, models.ConfidenceMedium, models.Evidence{
			SourceName:  "passive_sources",
			SourceType:  "aggregate",
			RetrievedAt: nowUTC(),
			Method:      "ct/wayback/provider aggregation",
			Snippet:     host,
		}))
	}

	tech := append([]string{}, result.Data.Technologies...)
	tech = append(tech, detectBuiltInTechnologies(httpCapture)...)
	if httpCapture != nil && httpCapture.Details != nil && httpCapture.Details.FinalURL != "" {
		if detected, err := providers.RunWhatWeb(ctx, httpCapture.Details.FinalURL); err == nil {
			tech = append(tech, detected...)
		} else if err != nil && err.Error != "tool not installed" {
			result.Errors = append(result.Errors, *err)
		}
	}
	result.Data.Technologies = mergeStringLists(result.Data.Technologies, tech)
	for _, item := range result.Data.Technologies {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "technology", item, false, models.ConfidenceMedium, models.Evidence{
			SourceName:  "http",
			SourceType:  "http",
			RetrievedAt: nowUTC(),
			Method:      "headers/cookies/body/signature analysis",
			Snippet:     item,
		}))
	}

	waybackSnapshots, dnsErrors := collectWaybackSnapshots(ctx, s.httpClient, domain)
	result.Errors = append(result.Errors, dnsErrors...)
	result.Data.Wayback = mergeWaybackSnapshots(result.Data.Wayback, waybackSnapshots)
	for _, item := range result.Data.Wayback {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "wayback_snapshot", item.ArchiveURL, false, models.ConfidenceMedium, models.Evidence{
			SourceName:  "wayback",
			SourceURL:   item.ArchiveURL,
			SourceType:  "archive",
			RetrievedAt: nowUTC(),
			Method:      "cdx api",
			Snippet:     item.Timestamp + " " + item.OriginalURL,
		}))
	}

	result.Data.CDN = mergeScalar(result.Data.CDN, inferCDN(result.Data.HTTP, result.Data.DNS, result.Data.ProviderHints, result.Data.TLS))
	if result.Data.CDN != "" {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "cdn", result.Data.CDN, false, models.ConfidenceMedium, models.Evidence{
			SourceName:  "inference",
			SourceType:  "heuristic",
			RetrievedAt: nowUTC(),
			Method:      "headers/cname/asn hints",
			Snippet:     result.Data.CDN,
		}))
	}

	ports, discovery, dnsErrors := collectPassivePorts(ctx, s.httpClient, s.config, result.Data.IPs)
	result.Errors = append(result.Errors, dnsErrors...)
	result.Data.Ports = mergePortFindings(result.Data.Ports, ports)
	if discovery != "" {
		result.Warnings = append(result.Warnings, discovery)
	}
	for _, port := range result.Data.Ports {
		value := fmt.Sprintf("%s:%d/%s", port.IP, port.Port, port.Transport)
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "passive_port", value, false, models.ConfidenceMedium, models.Evidence{
			SourceName:  port.Source,
			SourceType:  "api",
			RetrievedAt: nowUTC(),
			Method:      "passive host intelligence",
			Snippet:     value,
		}))
	}

	cleanupResult(&result)
	return result
}

func applyExternalEnrichment(result *models.DigitalFootprintModuleResult, enrichment providers.EnrichmentResult) {
	result.Data.Subdomains = mergeStringLists(result.Data.Subdomains, enrichment.Subdomains)
	result.Data.IPs = mergeStringLists(result.Data.IPs, enrichment.IPs)
	result.Data.ProviderHints = mergeStringLists(result.Data.ProviderHints, enrichment.ProviderHints)
	result.Data.Technologies = mergeStringLists(result.Data.Technologies, enrichment.Technologies)

	for _, value := range enrichment.Subdomains {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "subdomain", value, false, models.ConfidenceMedium, providerEvidence(enrichment, "subdomain", value)...))
	}
	for _, value := range enrichment.IPs {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "provider_ip", value, false, models.ConfidenceMedium, providerEvidence(enrichment, "ip", value)...))
	}
	for _, value := range enrichment.ProviderHints {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "provider_hint", value, false, models.ConfidenceMedium, providerEvidence(enrichment, "provider_hint", value)...))
	}
	for _, value := range enrichment.Technologies {
		result.Findings = append(result.Findings, simpleFinding("digitalfootprint", "technology", value, false, models.ConfidenceMedium, providerEvidence(enrichment, "technology", value)...))
	}
}

func providerEvidence(enrichment providers.EnrichmentResult, method, value string) []models.Evidence {
	evidence := make([]models.Evidence, 0)
	for _, item := range enrichment.Evidence {
		if item.Method == method && item.Snippet == util.ClipString(util.NormalizeWhitespace(value), 180) {
			evidence = append(evidence, item)
		}
	}
	if len(evidence) == 0 {
		evidence = append(evidence, models.Evidence{
			SourceName:  enrichment.Provider,
			SourceType:  "provider",
			RetrievedAt: nowUTC(),
			Method:      method,
			Snippet:     value,
		})
	}
	return evidence
}

func appendDNSFindings(result *models.DigitalFootprintModuleResult, domain string, records models.DNSRecords) {
	add := func(field string, values []string) {
		for _, value := range values {
			result.Findings = append(result.Findings, simpleFinding("digitalfootprint", field, value, true, models.ConfidenceMedium, models.Evidence{
				SourceName:  "dns",
				SourceURL:   domain,
				SourceType:  "dns",
				RetrievedAt: nowUTC(),
				Method:      "resolver lookup",
				Snippet:     value,
			}))
		}
	}
	add("dns_a", records.A)
	add("dns_aaaa", records.AAAA)
	add("dns_mx", records.MX)
	add("dns_ns", records.NS)
	add("dns_txt", records.TXT)
	add("dns_cname", records.CNAME)
}

func simpleFinding(module, field, value string, verified bool, confidence models.Confidence, evidence ...models.Evidence) models.Finding {
	return models.Finding{
		FieldName:       field,
		Value:           value,
		NormalizedValue: value,
		Module:          module,
		Verified:        verified,
		Confidence:      confidence,
		CollectedAt:     time.Now().UTC(),
		Evidence:        evidence,
	}
}

func subdomainSeeds(capture *HTTPCapture) []string {
	if capture == nil {
		return nil
	}
	seeds := append([]string{}, capture.Links...)
	seeds = append(seeds, capture.Scripts...)
	return util.UniqueStrings(seeds)
}

func nowUTC() time.Time {
	return time.Now().UTC()
}

func portDedupKey(item models.PortFinding) string {
	return item.IP + "|" + strconv.Itoa(item.Port) + "|" + item.Transport + "|" + item.Source
}

func mergeScalar(oldValue, newValue string) string {
	newValue = util.NormalizeWhitespace(newValue)
	if newValue != "" {
		return newValue
	}
	return util.NormalizeWhitespace(oldValue)
}

func mergeStringLists(oldValues, newValues []string) []string {
	return util.UniqueStrings(append(append([]string{}, oldValues...), newValues...))
}

func mergeWaybackSnapshots(oldValues, newValues []models.WaybackSnapshot) []models.WaybackSnapshot {
	if len(oldValues) == 0 && len(newValues) == 0 {
		return nil
	}
	merged := make(map[string]models.WaybackSnapshot)
	for _, item := range append(append([]models.WaybackSnapshot{}, oldValues...), newValues...) {
		key := util.NormalizeWhitespace(item.Timestamp + "|" + item.OriginalURL + "|" + item.ArchiveURL)
		if key == "||" {
			continue
		}
		merged[key] = item
	}
	out := make([]models.WaybackSnapshot, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		left := out[i].Timestamp + "|" + out[i].OriginalURL + "|" + out[i].ArchiveURL
		right := out[j].Timestamp + "|" + out[j].OriginalURL + "|" + out[j].ArchiveURL
		return left < right
	})
	return out
}

func mergePortFindings(oldValues, newValues []models.PortFinding) []models.PortFinding {
	if len(oldValues) == 0 && len(newValues) == 0 {
		return nil
	}
	merged := make(map[string]models.PortFinding)
	for _, item := range append(append([]models.PortFinding{}, oldValues...), newValues...) {
		merged[portDedupKey(item)] = item
	}
	out := make([]models.PortFinding, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return portDedupKey(out[i]) < portDedupKey(out[j])
	})
	return out
}

func mergeDNSRecords(oldValue, newValue models.DNSRecords) models.DNSRecords {
	return models.DNSRecords{
		A:     mergeStringLists(oldValue.A, newValue.A),
		AAAA:  mergeStringLists(oldValue.AAAA, newValue.AAAA),
		MX:    mergeStringLists(oldValue.MX, newValue.MX),
		NS:    mergeStringLists(oldValue.NS, newValue.NS),
		TXT:   mergeStringLists(oldValue.TXT, newValue.TXT),
		CNAME: mergeStringLists(oldValue.CNAME, newValue.CNAME),
	}
}

func mergeTLSCertificate(oldValue, newValue *models.TLSCertificate) *models.TLSCertificate {
	switch {
	case oldValue == nil:
		return newValue
	case newValue == nil:
		return oldValue
	default:
		return &models.TLSCertificate{
			Issuer:       mergeScalar(oldValue.Issuer, newValue.Issuer),
			Subject:      mergeScalar(oldValue.Subject, newValue.Subject),
			SerialNumber: mergeScalar(oldValue.SerialNumber, newValue.SerialNumber),
			SANs:         mergeStringLists(oldValue.SANs, newValue.SANs),
			ValidFrom:    mergeScalar(oldValue.ValidFrom, newValue.ValidFrom),
			ValidTo:      mergeScalar(oldValue.ValidTo, newValue.ValidTo),
		}
	}
}
