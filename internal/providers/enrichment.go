package providers

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

var (
	reIPv4          = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	reHostnameToken = regexp.MustCompile(`(?i)\b[a-z0-9][a-z0-9._-]*\.[a-z]{2,}\b`)
	reASNToken      = regexp.MustCompile(`(?i)\bAS\d+\b`)
)

type EnrichmentResult struct {
	Provider      string
	Used          bool
	Warnings      []string
	Errors        []models.SourceError
	Subdomains    []string
	IPs           []string
	ProviderHints []string
	Technologies  []string
	Evidence      []models.Evidence
}

type graphML struct {
	XMLName xml.Name       `xml:"graphml"`
	Graphs  []graphMLGraph `xml:"graph"`
}

type graphMLGraph struct {
	Nodes []graphMLNode `xml:"node"`
}

type graphMLNode struct {
	Data []graphMLData `xml:"data"`
}

type graphMLData struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type spiderFootScan struct {
	ID     string
	Name   string
	Target string
	Status string
}

type spiderFootExportRow struct {
	Data          string `json:"data"`
	EventType     string `json:"event_type"`
	Module        string `json:"module"`
	SourceData    string `json:"source_data"`
	FalsePositive bool   `json:"false_positive"`
	LastSeen      string `json:"last_seen"`
	ScanName      string `json:"scan_name"`
	ScanTarget    string `json:"scan_target"`
}

func CollectSpiderFootEnrichment(ctx context.Context, client *util.HTTPClient, configuredCommand, configuredURL, configuredPath, domain, company string) EnrichmentResult {
	result := EnrichmentResult{Provider: "spiderfoot"}
	urlErrors := make([]models.SourceError, 0)

	urlCandidates := spiderFootURLCandidates(configuredURL)
	for _, candidate := range urlCandidates {
		enrichment, attempted, err := collectSpiderFootFromURL(ctx, client, candidate, domain, company)
		if err == nil && attempted {
			result.merge(enrichment)
			result.Used = result.Used || enrichment.Used
			if enrichment.Used {
				break
			}
		} else if attempted && err != nil {
			urlErrors = append(urlErrors, WrapError("spiderfoot", "api", "fetch_results", candidate, err))
		}
	}

	if !result.Used {
		if enrichment, ok, err := loadProviderPath("spiderfoot", configuredPath, spiderFootDefaultPaths(), domain); err == nil && ok {
			result.merge(enrichment)
			result.Used = result.Used || enrichment.Used
		} else if err != nil {
			result.Errors = append(result.Errors, WrapError("spiderfoot", "file", "load_results", configuredPath, err))
		}
	}

	if !result.Used {
		if lines, used, err := RunSpiderFootAuto(ctx, configuredCommand, domain, company); err == nil && used {
			result.merge(classifyProviderLines("spiderfoot", "", lines, domain))
			result.Used = true
		} else if used && err != nil {
			result.Errors = append(result.Errors, WrapError("spiderfoot", "tool", "run", "", err))
		}
	}

	if !result.Used && len(result.Errors) == 0 {
		result.Errors = append(result.Errors, urlErrors...)
	}
	switch {
	case hasWarning(result.Warnings, "SpiderFoot timed out with no usable results"):
	case result.Used && hasWarning(result.Warnings, "SpiderFoot returned partial results due to timeout"):
	case result.Used:
		result.Warnings = append(result.Warnings, "SpiderFoot used successfully")
	case spiderFootHasTimeout(urlErrors, result.Errors):
		result.Warnings = append(result.Warnings, "SpiderFoot timed out")
	default:
		result.Warnings = append(result.Warnings, "SpiderFoot unavailable")
	}
	result.normalize(domain)
	return result
}

func CollectMaltegoEnrichment(ctx context.Context, configuredCommand, configuredPath, domain, company string) EnrichmentResult {
	result := EnrichmentResult{Provider: "maltego"}

	if lines, used, err := RunMaltegoAuto(ctx, configuredCommand, domain, company); err == nil && used {
		result.merge(classifyProviderLines("maltego", "", lines, domain))
		result.Used = true
	} else if used && err != nil {
		result.Errors = append(result.Errors, WrapError("maltego", "tool", "run", "", err))
	}

	if enrichment, ok, err := loadProviderPath("maltego", configuredPath, maltegoDefaultPaths(), domain); err == nil && ok {
		result.merge(enrichment)
		result.Used = result.Used || enrichment.Used
	} else if err != nil {
		result.Errors = append(result.Errors, WrapError("maltego", "file", "load_results", configuredPath, err))
	}

	if !result.Used && len(result.Errors) == 0 {
		result.Warnings = append(result.Warnings, "maltego: no local CLI or export results found")
	}
	result.normalize(domain)
	return result
}

func (r *EnrichmentResult) merge(other EnrichmentResult) {
	r.Subdomains = append(r.Subdomains, other.Subdomains...)
	r.IPs = append(r.IPs, other.IPs...)
	r.ProviderHints = append(r.ProviderHints, other.ProviderHints...)
	r.Technologies = append(r.Technologies, other.Technologies...)
	r.Evidence = append(r.Evidence, other.Evidence...)
	r.Warnings = append(r.Warnings, other.Warnings...)
	r.Errors = append(r.Errors, other.Errors...)
	r.Used = r.Used || other.Used
}

func (r *EnrichmentResult) normalize(domain string) {
	r.Subdomains = NormalizeSubdomains(domain, r.Subdomains)
	r.IPs = util.UniqueStrings(r.IPs)
	r.ProviderHints = util.UniqueStrings(r.ProviderHints)
	r.Technologies = util.UniqueStrings(r.Technologies)
	r.Warnings = util.UniqueStrings(r.Warnings)
}

func spiderFootDefaultPaths() []string {
	return []string{
		"./spiderfoot-results",
		"./spiderfoot-results.json",
		"./exports/spiderfoot",
		"./exports/spiderfoot.json",
		"./testdata/spiderfoot",
		"./testdata/spiderfoot.json",
		"./testdata/spiderfoot.csv",
	}
}

func spiderFootURLCandidates(configuredURL string) []string {
	candidates := make([]string, 0, 2)
	if strings.TrimSpace(configuredURL) != "" {
		candidates = append(candidates, configuredURL)
	}
	candidates = append(candidates, "http://127.0.0.1:5001")
	seen := make(map[string]struct{})
	out := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidate = strings.TrimSpace(candidate)
		if candidate == "" {
			continue
		}
		key := strings.ToLower(candidate)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, candidate)
	}
	return out
}

func maltegoDefaultPaths() []string {
	return []string{
		"./maltego-results",
		"./maltego-results.json",
		"./exports/maltego",
		"./exports/maltego.json",
		"./testdata/maltego",
		"./testdata/maltego.json",
		"./testdata/maltego.csv",
		"./testdata/maltego.graphml",
	}
}

func loadProviderURL(ctx context.Context, client *util.HTTPClient, provider, sourceURL, domain string) (EnrichmentResult, error) {
	page, err := client.Get(ctx, sourceURL)
	if err != nil {
		return EnrichmentResult{}, err
	}
	return parseProviderContent(provider, sourceURL, page.Body, domain)
}

func collectSpiderFootFromURL(ctx context.Context, client *util.HTTPClient, baseURL, domain, company string) (EnrichmentResult, bool, error) {
	target := spiderFootTarget(domain, company)
	if target == "" {
		return EnrichmentResult{Provider: "spiderfoot"}, false, nil
	}

	baseURL = normalizeSpiderFootBaseURL(baseURL)
	if baseURL == "" {
		return EnrichmentResult{Provider: "spiderfoot"}, false, nil
	}

	scan, err := spiderFootFindExistingScan(ctx, client, baseURL, target)
	if err != nil {
		return EnrichmentResult{Provider: "spiderfoot"}, true, err
	}
	if scan.ID == "" {
		scan, err = spiderFootStartScan(ctx, client, baseURL, target)
		if err != nil {
			return EnrichmentResult{Provider: "spiderfoot"}, true, err
		}
	}

	_, partial, err := spiderFootWaitForResults(ctx, client, baseURL, scan.ID)
	if err != nil {
		if isTimeoutError(err) {
			enrichment, ok := spiderFootCollectUsablePartialResult(client, baseURL, scan.ID, domain)
			if ok {
				enrichment.Warnings = append(enrichment.Warnings, "SpiderFoot returned partial results due to timeout")
				return enrichment, true, nil
			}
			return EnrichmentResult{Provider: "spiderfoot", Warnings: []string{"SpiderFoot timed out with no usable results"}}, true, nil
		}
		return EnrichmentResult{Provider: "spiderfoot"}, true, err
	}

	fetchCtx := ctx
	if partial {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
	}

	exportRows, err := spiderFootFetchExport(fetchCtx, client, baseURL, scan.ID)
	if err != nil {
		if partial || isTimeoutError(err) {
			enrichment, ok := spiderFootCollectUsablePartialResult(client, baseURL, scan.ID, domain)
			if ok {
				enrichment.Warnings = append(enrichment.Warnings, "SpiderFoot returned partial results due to timeout")
				return enrichment, true, nil
			}
			return EnrichmentResult{Provider: "spiderfoot", Warnings: []string{"SpiderFoot timed out with no usable results"}}, true, nil
		}
		return EnrichmentResult{Provider: "spiderfoot"}, true, err
	}

	enrichment := parseSpiderFootExportRows(baseURL, scan.ID, exportRows, domain)
	if len(exportRows) > 0 {
		enrichment.Used = true
	}
	if partial {
		enrichment.Warnings = append(enrichment.Warnings, "SpiderFoot returned partial results due to timeout")
	}

	scanErrors, err := spiderFootFetchErrors(fetchCtx, client, baseURL, scan.ID)
	if err == nil && len(scanErrors) > 0 {
		for _, item := range scanErrors {
			enrichment.Errors = append(enrichment.Errors, models.SourceError{
				SourceName:  "spiderfoot",
				SourceURL:   spiderFootScanURL(baseURL, scan.ID),
				SourceType:  "provider",
				Operation:   "scan_error",
				Error:       item,
				Temporary:   true,
				CollectedAt: time.Now().UTC(),
			})
		}
	}

	return enrichment, true, nil
}

func loadProviderPath(provider, configured string, defaults []string, domain string) (EnrichmentResult, bool, error) {
	candidates := make([]string, 0, len(defaults)+1)
	if strings.TrimSpace(configured) != "" {
		candidates = append(candidates, configured)
	}
	candidates = append(candidates, defaults...)

	for _, candidate := range candidates {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		info, err := os.Stat(candidate)
		if err != nil {
			continue
		}
		if info.IsDir() {
			enrichment, used, err := loadProviderDirectory(provider, candidate, domain)
			return enrichment, used, err
		}
		body, err := os.ReadFile(candidate)
		if err != nil {
			return EnrichmentResult{}, false, err
		}
		enrichment, err := parseProviderContent(provider, candidate, body, domain)
		return enrichment, true, err
	}
	return EnrichmentResult{}, false, nil
}

func loadProviderDirectory(provider, dir, domain string) (EnrichmentResult, bool, error) {
	patterns := []string{"*.json", "*.csv", "*.txt", "*.graphml"}
	files := make([]string, 0)
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			return EnrichmentResult{}, false, err
		}
		files = append(files, matches...)
	}
	if len(files) == 0 {
		return EnrichmentResult{}, false, nil
	}

	result := EnrichmentResult{Provider: provider}
	for _, file := range files {
		body, err := os.ReadFile(file)
		if err != nil {
			return EnrichmentResult{}, true, err
		}
		enrichment, err := parseProviderContent(provider, file, body, domain)
		if err != nil {
			return EnrichmentResult{}, true, err
		}
		result.merge(enrichment)
	}
	return result, true, nil
}

func parseProviderContent(provider, source string, body []byte, domain string) (EnrichmentResult, error) {
	switch strings.ToLower(filepath.Ext(source)) {
	case ".csv":
		return parseProviderCSV(provider, source, body, domain)
	case ".graphml":
		return parseProviderGraphML(provider, source, body, domain)
	case ".txt", ".log":
		lines := strings.Split(string(body), "\n")
		return classifyProviderLines(provider, source, lines, domain), nil
	default:
		if result, err := parseProviderJSON(provider, source, body, domain); err == nil {
			return result, nil
		}
		lines := strings.Split(string(body), "\n")
		return classifyProviderLines(provider, source, lines, domain), nil
	}
}

func spiderFootTarget(domain, company string) string {
	if strings.TrimSpace(domain) != "" {
		return strings.TrimSpace(domain)
	}
	return strings.TrimSpace(company)
}

func normalizeSpiderFootBaseURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/")
}

func spiderFootEndpoint(baseURL, path string, params url.Values) string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return baseURL + path
	}
	ref := &url.URL{Path: path, RawQuery: params.Encode()}
	return base.ResolveReference(ref).String()
}

func spiderFootScanURL(baseURL, scanID string) string {
	return spiderFootEndpoint(baseURL, "/scaninfo", url.Values{"id": []string{scanID}})
}

func spiderFootJSONGet[T any](ctx context.Context, client *util.HTTPClient, endpoint string, dest *T) error {
	page, err := client.GetWithHeaders(ctx, endpoint, map[string]string{
		"Accept": "application/json",
	})
	if err != nil {
		return err
	}
	if page.StatusCode >= 400 {
		return fmt.Errorf("http status %d", page.StatusCode)
	}
	if err := json.Unmarshal(page.Body, dest); err != nil {
		return fmt.Errorf("decode json from %s: %w", endpoint, err)
	}
	return nil
}

func spiderFootFindExistingScan(ctx context.Context, client *util.HTTPClient, baseURL, target string) (spiderFootScan, error) {
	endpoint := spiderFootEndpoint(baseURL, "/scanlist", nil)
	var rows [][]any
	if err := spiderFootJSONGet(ctx, client, endpoint, &rows); err != nil {
		return spiderFootScan{}, err
	}

	target = strings.ToLower(strings.TrimSpace(target))
	best := spiderFootScan{}
	bestScore := -1
	for _, row := range rows {
		if len(row) < 7 {
			continue
		}
		scan := spiderFootScan{
			ID:     anyToString(row[0]),
			Name:   anyToString(row[1]),
			Target: strings.ToLower(anyToString(row[2])),
			Status: strings.ToUpper(anyToString(row[6])),
		}
		if scan.ID == "" || scan.Target == "" {
			continue
		}
		score := spiderFootScanMatchScore(scan, target)
		if score > bestScore {
			best = scan
			bestScore = score
		}
	}
	if bestScore <= 0 {
		return spiderFootScan{}, nil
	}
	return best, nil
}

func spiderFootScanMatchScore(scan spiderFootScan, target string) int {
	if scan.Target == target {
		switch scan.Status {
		case "RUNNING", "STARTING":
			return 4
		case "FINISHED":
			return 3
		default:
			return 2
		}
	}
	if strings.Contains(scan.Name, target) {
		return 1
	}
	return 0
}

func spiderFootStartScan(ctx context.Context, client *util.HTTPClient, baseURL, target string) (spiderFootScan, error) {
	if strings.TrimSpace(target) == "" {
		return spiderFootScan{}, fmt.Errorf("empty spiderfoot target")
	}

	baseParams := url.Values{
		"scanname":   []string{fmt.Sprintf("osintcli-%s", sanitizeSpiderFootName(target))},
		"scantarget": []string{target},
		"modulelist": []string{""},
		"typelist":   []string{""},
	}

	for _, usecase := range []string{"Passive", "Footprint", "all"} {
		params := cloneValues(baseParams)
		params.Set("usecase", usecase)
		if scan, err := spiderFootStartScanRequest(ctx, client, baseURL, params, target); err == nil {
			return scan, nil
		}
	}

	modules, err := spiderFootListModules(ctx, client, baseURL)
	if err != nil {
		return spiderFootScan{}, err
	}
	if len(modules) == 0 {
		return spiderFootScan{}, fmt.Errorf("startscan failed: spiderfoot returned no modules")
	}
	params := cloneValues(baseParams)
	params.Set("modulelist", strings.Join(modules, ","))
	params.Set("usecase", "")
	return spiderFootStartScanRequest(ctx, client, baseURL, params, target)
}

func spiderFootStartScanRequest(ctx context.Context, client *util.HTTPClient, baseURL string, params url.Values, target string) (spiderFootScan, error) {
	endpoint := spiderFootEndpoint(baseURL, "/startscan", params)
	var response []any
	if err := spiderFootJSONGet(ctx, client, endpoint, &response); err != nil {
		return spiderFootScan{}, err
	}
	if len(response) < 2 || !strings.EqualFold(anyToString(response[0]), "SUCCESS") {
		return spiderFootScan{}, fmt.Errorf("startscan failed: %v", response)
	}
	return spiderFootScan{
		ID:     anyToString(response[1]),
		Target: strings.ToLower(target),
		Status: "STARTING",
	}, nil
}

func spiderFootListModules(ctx context.Context, client *util.HTTPClient, baseURL string) ([]string, error) {
	endpoint := spiderFootEndpoint(baseURL, "/modules", nil)
	var rows []map[string]any
	if err := spiderFootJSONGet(ctx, client, endpoint, &rows); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		name := strings.TrimSpace(anyToString(row["name"]))
		if name == "" || strings.Contains(name, "__") || strings.HasPrefix(name, "sfp__stor_") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return util.UniqueStrings(out), nil
}

func sanitizeSpiderFootName(value string) string {
	value = strings.ToLower(util.NormalizeWhitespace(value))
	replacer := strings.NewReplacer(" ", "-", "/", "-", "\\", "-", ":", "-", ".", "-", ",", "-")
	value = replacer.Replace(value)
	value = strings.Trim(value, "-")
	if value == "" {
		return "scan"
	}
	return value
}

func spiderFootWaitForResults(ctx context.Context, client *util.HTTPClient, baseURL, scanID string) (string, bool, error) {
	waitBudget := spiderFootWaitBudget(ctx)
	deadline := time.Now().Add(waitBudget)
	status := ""

	for {
		current, err := spiderFootScanStatus(ctx, client, baseURL, scanID)
		if err != nil {
			return status, false, err
		}
		status = current
		switch status {
		case "FINISHED":
			return status, false, nil
		case "ABORTED":
			return status, false, fmt.Errorf("scan aborted")
		}
		if time.Now().After(deadline) {
			return status, true, nil
		}

		select {
		case <-ctx.Done():
			return status, true, nil
		case <-time.After(2 * time.Second):
		}
	}
}

func spiderFootWaitBudget(ctx context.Context) time.Duration {
	waitBudget := 8 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline) - 3*time.Second
		if remaining <= time.Second {
			return time.Second
		}
		if remaining < waitBudget {
			return remaining
		}
	}
	return waitBudget
}

func spiderFootScanStatus(ctx context.Context, client *util.HTTPClient, baseURL, scanID string) (string, error) {
	endpoint := spiderFootEndpoint(baseURL, "/scanstatus", url.Values{"id": []string{scanID}})
	var row []any
	if err := spiderFootJSONGet(ctx, client, endpoint, &row); err != nil {
		return "", err
	}
	if len(row) < 6 {
		return "", nil
	}
	return strings.ToUpper(anyToString(row[5])), nil
}

func spiderFootFetchExport(ctx context.Context, client *util.HTTPClient, baseURL, scanID string) ([]spiderFootExportRow, error) {
	endpoint := spiderFootEndpoint(baseURL, "/scanexportjsonmulti", url.Values{"ids": []string{scanID}})
	var rows []spiderFootExportRow
	if err := spiderFootJSONGet(ctx, client, endpoint, &rows); err == nil {
		return rows, nil
	}

	fallbackEndpoint := spiderFootEndpoint(baseURL, "/scaneventresults", url.Values{"id": []string{scanID}})
	var fallback [][]any
	if err := spiderFootJSONGet(ctx, client, fallbackEndpoint, &fallback); err != nil {
		return nil, err
	}
	rows = make([]spiderFootExportRow, 0, len(fallback))
	for _, item := range fallback {
		if len(item) < 11 {
			continue
		}
		rows = append(rows, spiderFootExportRow{
			LastSeen:   anyToString(item[0]),
			Data:       anyToString(item[1]),
			SourceData: anyToString(item[2]),
			Module:     anyToString(item[3]),
			EventType:  anyToString(item[10]),
		})
	}
	return rows, nil
}

func spiderFootFetchErrors(ctx context.Context, client *util.HTTPClient, baseURL, scanID string) ([]string, error) {
	endpoint := spiderFootEndpoint(baseURL, "/scanerrors", url.Values{
		"id":    []string{scanID},
		"limit": []string{"20"},
	})
	var rows [][]any
	if err := spiderFootJSONGet(ctx, client, endpoint, &rows); err != nil {
		return nil, err
	}

	out := make([]string, 0, len(rows))
	for _, row := range rows {
		if len(row) == 0 {
			continue
		}
		text := anyToString(row[len(row)-1])
		text = util.NormalizeWhitespace(text)
		if text != "" {
			out = append(out, text)
		}
	}
	return util.UniqueStrings(out), nil
}

func parseSpiderFootExportRows(baseURL, scanID string, rows []spiderFootExportRow, domain string) EnrichmentResult {
	result := EnrichmentResult{Provider: "spiderfoot", Used: len(rows) > 0}
	sourceURL := spiderFootScanURL(baseURL, scanID)

	for _, row := range rows {
		if row.FalsePositive {
			continue
		}
		data := util.NormalizeWhitespace(row.Data)
		sourceData := util.NormalizeWhitespace(row.SourceData)
		eventType := strings.ToLower(util.NormalizeWhitespace(row.EventType))
		module := strings.ToLower(util.NormalizeWhitespace(row.Module))
		contextLine := util.NormalizeWhitespace(strings.Join(compactStrings([]string{row.EventType, data, sourceData, row.Module}), " | "))

		if ip := net.ParseIP(strings.TrimSpace(data)); ip != nil {
			result.IPs = append(result.IPs, ip.String())
			result.Evidence = append(result.Evidence, providerEvidence("spiderfoot", sourceURL, "ip", ip.String()))
		}
		if ip := net.ParseIP(strings.TrimSpace(sourceData)); ip != nil {
			result.IPs = append(result.IPs, ip.String())
			result.Evidence = append(result.Evidence, providerEvidence("spiderfoot", sourceURL, "ip", ip.String()))
		}

		for _, host := range []string{extractHost(data), extractHost(sourceData)} {
			if host == "" || domain == "" {
				continue
			}
			if host == domain || !strings.HasSuffix(host, "."+domain) {
				continue
			}
			result.Subdomains = append(result.Subdomains, host)
			result.Evidence = append(result.Evidence, providerEvidence("spiderfoot", sourceURL, "subdomain", host))
		}

		if spiderFootLooksLikeProviderHint(eventType, module, contextLine) {
			result.ProviderHints = append(result.ProviderHints, util.ClipString(contextLine, 180))
			result.Evidence = append(result.Evidence, providerEvidence("spiderfoot", sourceURL, "provider_hint", contextLine))
		}
		if spiderFootLooksLikeTechnology(eventType, module, data) {
			result.Technologies = append(result.Technologies, util.NormalizeWhitespace(data))
			result.Evidence = append(result.Evidence, providerEvidence("spiderfoot", sourceURL, "technology", data))
		}

		classifyStructuredString(eventType, data, &result)
		classifyStructuredString(module, data, &result)
		classifyStructuredString("source_data", sourceData, &result)
	}

	result.normalize(domain)
	return result
}

func spiderFootLooksLikeProviderHint(eventType, module, value string) bool {
	text := strings.ToLower(strings.Join([]string{eventType, module, value}, " | "))
	return strings.Contains(text, "asn") ||
		strings.Contains(text, "netblock") ||
		strings.Contains(text, "bgp") ||
		strings.Contains(text, "provider") ||
		strings.Contains(text, "network") ||
		strings.Contains(text, "hosting") ||
		strings.Contains(text, "owner")
}

func spiderFootLooksLikeTechnology(eventType, module, value string) bool {
	text := strings.ToLower(strings.Join([]string{eventType, module, value}, " | "))
	return strings.Contains(text, "technology") ||
		strings.Contains(text, "weblogic") ||
		strings.Contains(text, "banner") ||
		strings.Contains(text, "http_header") ||
		strings.Contains(text, "nginx") ||
		strings.Contains(text, "apache") ||
		strings.Contains(text, "cloudflare") ||
		strings.Contains(text, "next.js")
}

func compactStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}

func cloneValues(in url.Values) url.Values {
	out := make(url.Values, len(in))
	for key, values := range in {
		out[key] = append([]string{}, values...)
	}
	return out
}

func anyToString(value any) string {
	if value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		if typed == float64(int64(typed)) {
			return strconv.FormatInt(int64(typed), 10)
		}
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case int:
		return strconv.Itoa(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprint(value)
	}
}

func parseProviderJSON(provider, source string, body []byte, domain string) (EnrichmentResult, error) {
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return EnrichmentResult{}, err
	}
	values := make([]string, 0)
	result := EnrichmentResult{Provider: provider, Used: true}
	walkProviderJSON(payload, &values, &result)
	result.merge(classifyProviderLines(provider, source, values, domain))
	result.normalize(domain)
	return result, nil
}

func walkProviderJSON(value any, values *[]string, result *EnrichmentResult) {
	switch typed := value.(type) {
	case map[string]any:
		typeValue, _ := typed["type"].(string)
		entityValue, _ := typed["value"].(string)
		if typeValue != "" && entityValue != "" {
			*values = append(*values, typeValue+": "+entityValue)
		}
		for key, item := range typed {
			lower := strings.ToLower(key)
			if text, ok := item.(string); ok {
				classifyStructuredString(lower, text, result)
				*values = append(*values, text)
			}
			walkProviderJSON(item, values, result)
		}
	case []any:
		for _, item := range typed {
			walkProviderJSON(item, values, result)
		}
	}
}

func parseProviderCSV(provider, source string, body []byte, domain string) (EnrichmentResult, error) {
	reader := csv.NewReader(strings.NewReader(string(body)))
	rows, err := reader.ReadAll()
	if err != nil {
		return EnrichmentResult{}, err
	}
	if len(rows) == 0 {
		return EnrichmentResult{Provider: provider}, nil
	}

	headers := make([]string, 0)
	for _, column := range rows[0] {
		headers = append(headers, strings.ToLower(strings.TrimSpace(column)))
	}

	lines := make([]string, 0, len(rows))
	for idx, row := range rows {
		if idx == 0 {
			continue
		}
		lineParts := make([]string, 0, len(row))
		for colIdx, value := range row {
			name := fmt.Sprintf("col%d", colIdx)
			if colIdx < len(headers) {
				name = headers[colIdx]
			}
			value = strings.TrimSpace(value)
			if value == "" {
				continue
			}
			lineParts = append(lineParts, name+": "+value)
		}
		if len(lineParts) > 0 {
			lines = append(lines, strings.Join(lineParts, " | "))
		}
	}
	return classifyProviderLines(provider, source, lines, domain), nil
}

func parseProviderGraphML(provider, source string, body []byte, domain string) (EnrichmentResult, error) {
	var payload graphML
	if err := xml.Unmarshal(body, &payload); err != nil {
		return EnrichmentResult{}, err
	}
	lines := make([]string, 0)
	for _, graph := range payload.Graphs {
		for _, node := range graph.Nodes {
			for _, data := range node.Data {
				text := strings.TrimSpace(data.Value)
				if text != "" {
					lines = append(lines, text)
				}
			}
		}
	}
	return classifyProviderLines(provider, source, lines, domain), nil
}

func classifyProviderLines(provider, source string, lines []string, domain string) EnrichmentResult {
	result := EnrichmentResult{Provider: provider}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result.Used = true
		classifyStructuredString("", line, &result)
		for _, ip := range reIPv4.FindAllString(line, -1) {
			if parsed := net.ParseIP(ip); parsed != nil {
				result.IPs = append(result.IPs, parsed.String())
				result.Evidence = append(result.Evidence, providerEvidence(provider, source, "ip", ip))
			}
		}
		for _, host := range reHostnameToken.FindAllString(line, -1) {
			host = strings.ToLower(strings.TrimSuffix(host, "."))
			if domain != "" && (host == domain || strings.HasSuffix(host, "."+domain)) {
				if host != domain {
					result.Subdomains = append(result.Subdomains, host)
					result.Evidence = append(result.Evidence, providerEvidence(provider, source, "subdomain", host))
				}
			}
		}
		if reASNToken.MatchString(line) || strings.Contains(strings.ToLower(line), "asn") || strings.Contains(strings.ToLower(line), "provider") || strings.Contains(strings.ToLower(line), "network") {
			result.ProviderHints = append(result.ProviderHints, util.ClipString(util.NormalizeWhitespace(line), 180))
			result.Evidence = append(result.Evidence, providerEvidence(provider, source, "provider_hint", line))
		}
	}
	result.normalize(domain)
	return result
}

func classifyStructuredString(field, value string, result *EnrichmentResult) {
	lowerField := strings.ToLower(field)
	lowerValue := strings.ToLower(strings.TrimSpace(value))
	if lowerValue == "" {
		return
	}

	switch {
	case strings.Contains(lowerField, "ip"):
		if ip := net.ParseIP(strings.TrimSpace(value)); ip != nil {
			result.IPs = append(result.IPs, ip.String())
		}
	case strings.Contains(lowerField, "domain"), strings.Contains(lowerField, "host"), strings.Contains(lowerField, "fqdn"), strings.Contains(lowerField, "hostname"):
		host := extractHost(value)
		if host != "" {
			result.Subdomains = append(result.Subdomains, host)
		}
	case strings.Contains(lowerField, "asn"), strings.Contains(lowerField, "provider"), strings.Contains(lowerField, "netname"), strings.Contains(lowerField, "network"):
		result.ProviderHints = append(result.ProviderHints, util.ClipString(util.NormalizeWhitespace(value), 180))
	case strings.Contains(lowerField, "tech"), strings.Contains(lowerField, "product"), strings.Contains(lowerField, "service"):
		result.Technologies = append(result.Technologies, util.NormalizeWhitespace(value))
	}

	if strings.Contains(lowerValue, "nginx") || strings.Contains(lowerValue, "wordpress") || strings.Contains(lowerValue, "cloudflare") || strings.Contains(lowerValue, "next.js") {
		result.Technologies = append(result.Technologies, util.NormalizeWhitespace(value))
	}
}

func extractHost(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.Contains(value, "://") {
		if parsed, err := url.Parse(value); err == nil {
			value = parsed.Hostname()
		}
	}
	value = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(value), "."))
	if value == "" {
		return ""
	}
	if net.ParseIP(value) != nil {
		return ""
	}
	return value
}

func providerEvidence(provider, source, method, snippet string) models.Evidence {
	return models.Evidence{
		SourceName:  provider,
		SourceURL:   source,
		SourceType:  "provider",
		RetrievedAt: time.Now().UTC(),
		Method:      method,
		Snippet:     util.ClipString(util.NormalizeWhitespace(snippet), 180),
	}
}

func ProvidersUsed(results ...EnrichmentResult) []string {
	out := make([]string, 0)
	for _, result := range results {
		if result.Used {
			out = append(out, result.Provider)
		}
	}
	sort.Strings(out)
	return util.UniqueStrings(out)
}

func spiderFootCollectUsablePartialResult(client *util.HTTPClient, baseURL, scanID, domain string) (EnrichmentResult, bool) {
	fetchCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	rows, err := spiderFootFetchExport(fetchCtx, client, baseURL, scanID)
	if err != nil || len(rows) == 0 {
		return EnrichmentResult{Provider: "spiderfoot"}, false
	}
	enrichment := parseSpiderFootExportRows(baseURL, scanID, rows, domain)
	enrichment.Used = len(rows) > 0
	if scanErrors, err := spiderFootFetchErrors(fetchCtx, client, baseURL, scanID); err == nil && len(scanErrors) > 0 {
		for _, item := range scanErrors {
			enrichment.Errors = append(enrichment.Errors, models.SourceError{
				SourceName:  "spiderfoot",
				SourceURL:   spiderFootScanURL(baseURL, scanID),
				SourceType:  "provider",
				Operation:   "scan_error",
				Error:       item,
				Temporary:   true,
				CollectedAt: time.Now().UTC(),
			})
		}
	}
	return enrichment, enrichment.Used
}

func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	lower := strings.ToLower(err.Error())
	return strings.Contains(lower, "timeout") || strings.Contains(lower, "deadline exceeded") || strings.Contains(lower, "context canceled")
}

func hasWarning(warnings []string, target string) bool {
	for _, warning := range warnings {
		if strings.EqualFold(strings.TrimSpace(warning), target) {
			return true
		}
	}
	return false
}

func spiderFootHasTimeout(groups ...[]models.SourceError) bool {
	for _, items := range groups {
		for _, item := range items {
			if strings.Contains(strings.ToLower(item.Error), "timeout") || strings.Contains(strings.ToLower(item.Error), "deadline exceeded") {
				return true
			}
		}
	}
	return false
}
