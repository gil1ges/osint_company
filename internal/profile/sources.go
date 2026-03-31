package profile

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"html"
	"log/slog"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

var (
	reTitle           = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	reMetaDescription = regexp.MustCompile(`(?is)<meta[^>]+name=["']description["'][^>]+content=["'](.*?)["']`)
	reMetaGenerator   = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["'](.*?)["']`)
	reJSONLDScript    = regexp.MustCompile(`(?is)<script[^>]+type=["']application/ld\+json["'][^>]*>(.*?)</script>`)
	reAnchor          = regexp.MustCompile(`(?is)<a[^>]+href=["'](.*?)["'][^>]*>(.*?)</a>`)
	reSearchResult    = regexp.MustCompile(`(?is)<a[^>]+class=["'][^"']*result__a[^"']*["'][^>]+href=["'](.*?)["'][^>]*>(.*?)</a>`)
	reStripTags       = regexp.MustCompile(`(?is)<[^>]+>`)
	reBlockBreaks     = regexp.MustCompile(`(?i)</?(?:p|div|section|article|li|ul|ol|tr|td|th|br|h[1-6]|footer|header|main|aside)[^>]*>`)
	reWhitespace      = regexp.MustCompile(`\s+`)
	reSitemapLine     = regexp.MustCompile(`(?im)^sitemap:\s*(https?://\S+)\s*$`)
	reInlineLegalName = regexp.MustCompile(`(?i)(?:полное наименование|юридическое наименование|наименование юридического лица|legal name|registered name|organization name)\s*[:\-]?\s*([^\n]{4,220})`)
	reInlineOGRN      = regexp.MustCompile(`(?i)(?:огрн|ogrn)\D{0,20}(\d{13})`)
	reInlineINN       = regexp.MustCompile(`(?i)(?:инн|tax id|tin)\D{0,20}(\d{10,12})`)
	reInlineAddress   = regexp.MustCompile(`(?i)(?:адрес(?: офиса| регистрации| местонахождения)?|registered address|legal address|office address|head office)\s*[:\-]?\s*([^\n]{10,220})`)
)

var publicRegistryDomains = []string{
	"rusprofile.ru",
	"checko.ru",
	"sbis.ru",
	"list-org.com",
	"b2b.house",
	"audit-it.ru",
	"companies.rbc.ru",
	"vbankcenter.ru",
}

type searchHit struct {
	URL   string
	Title string
}

type LinkRef struct {
	URL  string
	Text string
}

type PageData struct {
	URL         string
	PageType    string
	Title       string
	Description string
	BodyText    string
	Lines       []string
	Links       []LinkRef
	JSONLD      []map[string]any
	RetrievedAt time.Time
	SourceType  string
}

type urlSet struct {
	URLs []struct {
		Loc string `xml:"loc"`
	} `xml:"url"`
}

type sitemapIndex struct {
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
}

func DiscoverOfficialWebsite(ctx context.Context, client *util.HTTPClient, company, inn string, logger *slog.Logger) (string, []models.Evidence, []models.SourceError) {
	queryParts := make([]string, 0, 3)
	if strings.TrimSpace(company) != "" {
		queryParts = append(queryParts, company)
	}
	if strings.TrimSpace(inn) != "" {
		queryParts = append(queryParts, "ИНН "+inn)
	}
	queryParts = append(queryParts, "official site")
	query := strings.Join(queryParts, " ")

	endpoint := "https://duckduckgo.com/html/?q=" + url.QueryEscape(query)
	page, err := client.Get(ctx, endpoint)
	if err != nil {
		return "", nil, []models.SourceError{{
			SourceName:  "duckduckgo",
			SourceURL:   endpoint,
			SourceType:  "search",
			Operation:   "discover_website",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: time.Now().UTC(),
		}}
	}

	hits := parseSearchResults(string(page.Body))
	tokens := companyTokens(company)
	bestURL := ""
	bestScore := 0
	bestTitle := ""
	for _, hit := range hits {
		domain := util.ExtractDomainFromURL(hit.URL)
		if domain == "" || ignoredDiscoveryDomain(domain) {
			continue
		}
		score := scoreDomainCandidate(domain, tokens)
		if score > bestScore {
			bestScore = score
			bestURL = util.NormalizeURL(domain)
			bestTitle = hit.Title
		}
	}

	if bestScore < 2 {
		logger.Debug("official website not confidently detected", "query", query)
		return "", nil, nil
	}

	return bestURL, []models.Evidence{{
		SourceName:  "duckduckgo",
		SourceURL:   endpoint,
		SourceType:  "search",
		RetrievedAt: time.Now().UTC(),
		Method:      "html search result parsing",
		Snippet:     util.ClipString(bestTitle, 200),
	}}, nil
}

func FetchCandidatePages(ctx context.Context, client *util.HTTPClient, officialWebsite string, logger *slog.Logger) ([]PageData, []models.SourceError) {
	if strings.TrimSpace(officialWebsite) == "" {
		return nil, nil
	}

	domain := util.ExtractDomainFromURL(officialWebsite)
	if domain == "" {
		return nil, []models.SourceError{{
			SourceName:  "profile",
			SourceURL:   officialWebsite,
			SourceType:  "internal",
			Operation:   "normalize_domain",
			Error:       "invalid official website",
			CollectedAt: time.Now().UTC(),
		}}
	}

	baseURL := util.NormalizeURL(domain)
	seedURLs := []string{
		baseURL,
		baseURL + "/about",
		baseURL + "/about-us",
		baseURL + "/company",
		baseURL + "/contacts",
		baseURL + "/contact",
		baseURL + "/legal",
		baseURL + "/requisites",
		baseURL + "/rekvizity",
		baseURL + "/disclosure",
		baseURL + "/licenses",
		baseURL + "/licences",
		baseURL + "/certificates",
		baseURL + "/documents",
		baseURL + "/docs",
		baseURL + "/compliance",
		baseURL + "/privacy",
		baseURL + "/terms",
	}

	pages := make([]PageData, 0)
	errors := make([]models.SourceError, 0)
	seen := make(map[string]struct{})

	robotsURLs, robotErrs := fetchRobotsAndSitemaps(ctx, client, baseURL)
	errors = append(errors, robotErrs...)
	sitemapURLs := append([]string{baseURL + "/sitemap.xml"}, robotsURLs...)
	sitemapCandidates, sitemapErrors := fetchSitemapCandidates(ctx, client, domain, sitemapURLs)
	errors = append(errors, sitemapErrors...)

	queue := make([]string, 0, len(seedURLs)+len(sitemapCandidates))
	queue = append(queue, seedURLs...)
	queue = append(queue, sitemapCandidates...)

	for len(queue) > 0 && len(pages) < 18 {
		target := queue[0]
		queue = queue[1:]
		target = normalizeCandidateURL(target, baseURL)
		if target == "" {
			continue
		}
		if _, ok := seen[target]; ok {
			continue
		}
		seen[target] = struct{}{}

		page, err := client.Get(ctx, target)
		if err != nil {
			errors = append(errors, models.SourceError{
				SourceName:  "http",
				SourceURL:   target,
				SourceType:  "official_site",
				Operation:   "fetch_page",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: time.Now().UTC(),
			})
			continue
		}
		if page.StatusCode >= 400 {
			errors = append(errors, models.SourceError{
				SourceName:  "http",
				SourceURL:   target,
				SourceType:  "official_site",
				Operation:   "fetch_page",
				Error:       fmt.Sprintf("http status %d", page.StatusCode),
				CollectedAt: time.Now().UTC(),
			})
			continue
		}

		parsed := parseHTMLPage(page.FinalURL, string(page.Body), page.RetrievedAt, domain)
		pages = append(pages, parsed)

		if len(pages) <= 4 {
			for _, link := range relevantInternalLinks(parsed.Links, domain) {
				if _, ok := seen[link]; !ok {
					queue = append(queue, link)
				}
			}
		}
	}

	logger.Debug("profile pages fetched", "count", len(pages), "domain", domain)
	return pages, errors
}

func FetchPublicRegistryPages(ctx context.Context, client *util.HTTPClient, company, inn, domain string, logger *slog.Logger) ([]PageData, []models.SourceError) {
	urls, errors := discoverPublicRegistryURLs(ctx, client, company, inn, domain)
	pages := make([]PageData, 0, len(urls))
	for _, target := range urls {
		page, err := client.Get(ctx, target)
		if err != nil {
			errors = append(errors, models.SourceError{
				SourceName:  "http",
				SourceURL:   target,
				SourceType:  "public_registry",
				Operation:   "fetch_public_card",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: time.Now().UTC(),
			})
			continue
		}
		if page.StatusCode >= 400 {
			errors = append(errors, models.SourceError{
				SourceName:  "http",
				SourceURL:   target,
				SourceType:  "public_registry",
				Operation:   "fetch_public_card",
				Error:       fmt.Sprintf("http status %d", page.StatusCode),
				CollectedAt: time.Now().UTC(),
			})
			continue
		}

		parsed := parseHTMLPage(page.FinalURL, string(page.Body), page.RetrievedAt, util.ExtractDomainFromURL(page.FinalURL))
		parsed.PageType = "public_card"
		parsed.SourceType = "public_registry"
		pages = append(pages, parsed)
	}
	logger.Debug("public registry pages fetched", "count", len(pages))
	return pages, errors
}

func discoverPublicRegistryURLs(ctx context.Context, client *util.HTTPClient, company, inn, domain string) ([]string, []models.SourceError) {
	queries := make([]string, 0, 3)
	if strings.TrimSpace(inn) != "" {
		queries = append(queries, inn+" компания ОГРН")
	}
	if strings.TrimSpace(domain) != "" {
		queries = append(queries, domain+" ИНН ОГРН компания")
	}
	if strings.TrimSpace(company) != "" {
		queries = append(queries, company+" ИНН ОГРН")
	}

	urls := make([]string, 0)
	errors := make([]models.SourceError, 0)
	seen := make(map[string]struct{})

	for _, query := range util.UniqueStrings(queries) {
		endpoint := "https://duckduckgo.com/html/?q=" + url.QueryEscape(query)
		page, err := client.Get(ctx, endpoint)
		if err != nil {
			errors = append(errors, models.SourceError{
				SourceName:  "duckduckgo",
				SourceURL:   endpoint,
				SourceType:  "search",
				Operation:   "discover_public_cards",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: time.Now().UTC(),
			})
			continue
		}
		for _, hit := range parseSearchResults(string(page.Body)) {
			host := util.ExtractDomainFromURL(hit.URL)
			if !isPublicRegistryDomain(host) {
				continue
			}
			if _, ok := seen[hit.URL]; ok {
				continue
			}
			seen[hit.URL] = struct{}{}
			urls = append(urls, hit.URL)
			if len(urls) >= 5 {
				return urls, errors
			}
		}
	}

	return urls, errors
}

func fetchRobotsAndSitemaps(ctx context.Context, client *util.HTTPClient, baseURL string) ([]string, []models.SourceError) {
	robotsURL := strings.TrimRight(baseURL, "/") + "/robots.txt"
	page, err := client.Get(ctx, robotsURL)
	if err != nil || page.StatusCode >= 400 {
		if err == nil {
			err = fmt.Errorf("http status %d", page.StatusCode)
		}
		return nil, []models.SourceError{{
			SourceName:  "http",
			SourceURL:   robotsURL,
			SourceType:  "official_site",
			Operation:   "fetch_robots",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: time.Now().UTC(),
		}}
	}

	matches := reSitemapLine.FindAllStringSubmatch(string(page.Body), -1)
	urls := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) > 1 {
			urls = append(urls, strings.TrimSpace(match[1]))
		}
	}
	return util.UniqueStrings(urls), nil
}

func fetchSitemapCandidates(ctx context.Context, client *util.HTTPClient, domain string, sitemapURLs []string) ([]string, []models.SourceError) {
	errors := make([]models.SourceError, 0)
	candidates := make([]string, 0)
	seen := make(map[string]struct{})

	for _, sitemapURL := range util.UniqueStrings(sitemapURLs) {
		if sitemapURL == "" {
			continue
		}
		page, err := client.Get(ctx, sitemapURL)
		if err != nil {
			errors = append(errors, models.SourceError{
				SourceName:  "http",
				SourceURL:   sitemapURL,
				SourceType:  "sitemap",
				Operation:   "fetch_sitemap",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: time.Now().UTC(),
			})
			continue
		}

		urls, err := parseSitemapXML(page.Body)
		if err != nil {
			errors = append(errors, models.SourceError{
				SourceName:  "http",
				SourceURL:   sitemapURL,
				SourceType:  "sitemap",
				Operation:   "parse_sitemap",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: time.Now().UTC(),
			})
			continue
		}

		for _, item := range urls {
			host := util.ExtractDomainFromURL(item)
			if host != domain {
				continue
			}
			if !looksLikeProfileURL(item) {
				continue
			}
			if _, ok := seen[item]; ok {
				continue
			}
			seen[item] = struct{}{}
			candidates = append(candidates, item)
		}
	}

	return util.UniqueStrings(candidates), errors
}

func parseSitemapXML(data []byte) ([]string, error) {
	var urls urlSet
	if err := xml.Unmarshal(data, &urls); err == nil && len(urls.URLs) > 0 {
		out := make([]string, 0, len(urls.URLs))
		for _, item := range urls.URLs {
			out = append(out, strings.TrimSpace(item.Loc))
		}
		return util.UniqueStrings(out), nil
	}

	var index sitemapIndex
	if err := xml.Unmarshal(data, &index); err == nil && len(index.Sitemaps) > 0 {
		out := make([]string, 0, len(index.Sitemaps))
		for _, item := range index.Sitemaps {
			out = append(out, strings.TrimSpace(item.Loc))
		}
		return util.UniqueStrings(out), nil
	}

	return nil, fmt.Errorf("unsupported sitemap format")
}

func parseHTMLPage(targetURL, rawHTML string, retrievedAt time.Time, domain string) PageData {
	title := firstSubmatch(reTitle, rawHTML)
	description := firstSubmatch(reMetaDescription, rawHTML)
	bodyText := htmlToText(rawHTML)

	return PageData{
		URL:         targetURL,
		PageType:    classifyPageType(targetURL),
		Title:       util.NormalizeWhitespace(title),
		Description: util.NormalizeWhitespace(description),
		BodyText:    bodyText,
		Lines:       splitTextLines(bodyText),
		Links:       extractLinks(rawHTML, targetURL, domain),
		JSONLD:      extractJSONLD(rawHTML),
		RetrievedAt: retrievedAt,
		SourceType:  "official_site",
	}
}

func parseSearchResults(rawHTML string) []searchHit {
	matches := reSearchResult.FindAllStringSubmatch(rawHTML, 10)
	out := make([]searchHit, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		target := normalizeSearchResultURL(match[1])
		title := util.NormalizeWhitespace(reStripTags.ReplaceAllString(match[2], " "))
		if target == "" {
			continue
		}
		out = append(out, searchHit{
			URL:   target,
			Title: title,
		})
	}
	return out
}

func extractJSONLD(rawHTML string) []map[string]any {
	matches := reJSONLDScript.FindAllStringSubmatch(rawHTML, -1)
	out := make([]map[string]any, 0)
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		block := html.UnescapeString(strings.TrimSpace(match[1]))
		var payload any
		if err := json.Unmarshal([]byte(block), &payload); err != nil {
			continue
		}
		switch value := payload.(type) {
		case map[string]any:
			out = append(out, value)
		case []any:
			for _, item := range value {
				if object, ok := item.(map[string]any); ok {
					out = append(out, object)
				}
			}
		}
	}
	return out
}

func extractLinks(rawHTML, baseURL, domain string) []LinkRef {
	matches := reAnchor.FindAllStringSubmatch(rawHTML, -1)
	base, _ := url.Parse(baseURL)
	out := make([]LinkRef, 0, len(matches))
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		href := html.UnescapeString(strings.TrimSpace(match[1]))
		if href == "" || strings.HasPrefix(href, "#") || strings.HasPrefix(strings.ToLower(href), "javascript:") {
			continue
		}
		parsed, err := url.Parse(href)
		if err != nil {
			continue
		}
		if base != nil {
			parsed = base.ResolveReference(parsed)
		}
		resolved := parsed.String()
		text := util.NormalizeWhitespace(reStripTags.ReplaceAllString(match[2], " "))
		if host := util.ExtractDomainFromURL(resolved); host != "" && host == domain {
			out = append(out, LinkRef{URL: resolved, Text: text})
			continue
		}
		if strings.HasSuffix(strings.ToLower(resolved), ".pdf") || strings.HasSuffix(strings.ToLower(resolved), ".doc") || strings.HasSuffix(strings.ToLower(resolved), ".docx") {
			out = append(out, LinkRef{URL: resolved, Text: text})
		}
	}
	return uniqueLinks(out)
}

func relevantInternalLinks(links []LinkRef, domain string) []string {
	out := make([]string, 0)
	for _, link := range links {
		host := util.ExtractDomainFromURL(link.URL)
		if host != domain {
			continue
		}
		if looksLikeProfileURL(link.URL) || looksLikeProfileText(link.Text) {
			out = append(out, link.URL)
		}
	}
	return util.UniqueStrings(out)
}

func htmlToText(rawHTML string) string {
	withBreaks := reBlockBreaks.ReplaceAllString(rawHTML, "\n")
	text := reStripTags.ReplaceAllString(withBreaks, " ")
	text = html.UnescapeString(text)
	text = strings.ReplaceAll(text, "\u00a0", " ")
	text = strings.ReplaceAll(text, "\r", "\n")
	lines := strings.Split(text, "\n")
	cleanLines := make([]string, 0, len(lines))
	for _, line := range lines {
		line = util.NormalizeWhitespace(reWhitespace.ReplaceAllString(line, " "))
		if line != "" {
			cleanLines = append(cleanLines, line)
		}
	}
	return strings.Join(cleanLines, "\n")
}

func splitTextLines(text string) []string {
	parts := strings.FieldsFunc(text, func(r rune) bool {
		return r == '\n' || r == ';'
	})
	lines := make([]string, 0, len(parts))
	for _, part := range parts {
		part = util.NormalizeWhitespace(part)
		if part != "" {
			lines = append(lines, part)
		}
	}
	return util.UniqueStrings(lines)
}

func companyTokens(company string) []string {
	company = strings.ToLower(company)
	replacer := strings.NewReplacer(`"`, " ", `'`, " ", ",", " ", ".", " ", "(", " ", ")", " ")
	company = replacer.Replace(company)
	stopWords := map[string]bool{
		"ооо": true, "ао": true, "пао": true, "zao": true, "oao": true,
		"llc": true, "inc": true, "corp": true, "corporation": true, "company": true,
	}
	parts := strings.Fields(company)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) < 3 || stopWords[part] {
			continue
		}
		out = append(out, part)
	}
	return util.UniqueStrings(out)
}

func scoreDomainCandidate(domain string, tokens []string) int {
	score := 0
	labels := strings.FieldsFunc(domain, func(r rune) bool {
		return r == '.' || r == '-' || r == '_'
	})
	for _, token := range tokens {
		for _, label := range labels {
			if token == label {
				score += 2
				continue
			}
			if strings.Contains(label, token) || strings.Contains(token, label) {
				score++
			}
		}
	}
	return score
}

func ignoredDiscoveryDomain(domain string) bool {
	blocked := []string{
		"linkedin.com", "facebook.com", "instagram.com", "x.com", "twitter.com", "wikipedia.org",
		"crunchbase.com", "bloomberg.com", "glassdoor.com", "youtube.com", "yandex.ru", "mapquest.com",
	}
	for _, suffix := range blocked {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	return false
}

func isPublicRegistryDomain(domain string) bool {
	for _, candidate := range publicRegistryDomains {
		if domain == candidate || strings.HasSuffix(domain, "."+candidate) {
			return true
		}
	}
	return false
}

func normalizeSearchResultURL(raw string) string {
	raw = html.UnescapeString(strings.TrimSpace(raw))
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	if parsed.Host == "duckduckgo.com" {
		if target := parsed.Query().Get("uddg"); target != "" {
			return html.UnescapeString(target)
		}
	}
	return raw
}

func classifyPageType(targetURL string) string {
	lower := strings.ToLower(targetURL)
	switch {
	case lower == "", lower == "/":
		return "homepage"
	case strings.Contains(lower, "requisite"), strings.Contains(lower, "rekviz"):
		return "requisites"
	case strings.Contains(lower, "legal"):
		return "legal"
	case strings.Contains(lower, "contact"):
		return "contacts"
	case strings.Contains(lower, "about"), strings.Contains(lower, "company"):
		return "company"
	case strings.Contains(lower, "license"), strings.Contains(lower, "licence"):
		return "licenses"
	case strings.Contains(lower, "certificate"):
		return "certificates"
	case strings.Contains(lower, "document"), strings.Contains(lower, "/docs"), strings.Contains(lower, "/doc"):
		return "documents"
	case strings.Contains(lower, "compliance"), strings.Contains(lower, "quality"):
		return "compliance"
	case strings.Contains(lower, "privacy"):
		return "privacy"
	case strings.Contains(lower, "terms"):
		return "terms"
	default:
		return "generic"
	}
}

func looksLikeProfileURL(candidate string) bool {
	lower := strings.ToLower(candidate)
	keywords := []string{
		"/about", "/company", "/contact", "/contacts", "/legal", "/requisites", "/rekviz",
		"/disclosure", "/license", "/licence", "/certificate", "/documents", "/docs",
		"/compliance", "/privacy", "/terms", "/quality",
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func looksLikeProfileText(text string) bool {
	lower := strings.ToLower(text)
	keywords := []string{
		"about", "company", "contacts", "contact", "legal", "requisites", "rekviz", "disclosure",
		"license", "licence", "certificate", "documents", "docs", "compliance", "privacy", "terms",
		"контак", "о компании", "реквизит", "лиценз", "сертификат", "документ",
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func normalizeCandidateURL(candidate, baseURL string) string {
	if strings.TrimSpace(candidate) == "" {
		return ""
	}
	base, _ := url.Parse(baseURL)
	parsed, err := url.Parse(candidate)
	if err != nil {
		return ""
	}
	if base != nil {
		parsed = base.ResolveReference(parsed)
	}
	return parsed.String()
}

func uniqueLinks(items []LinkRef) []LinkRef {
	set := make(map[string]LinkRef)
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item.URL))
		if key == "" {
			continue
		}
		if existing, ok := set[key]; ok {
			if existing.Text == "" && item.Text != "" {
				set[key] = item
			}
			continue
		}
		set[key] = item
	}
	out := make([]LinkRef, 0, len(set))
	for _, item := range set {
		out = append(out, item)
	}
	slices.SortFunc(out, func(a, b LinkRef) int {
		return strings.Compare(a.URL, b.URL)
	})
	return out
}

func firstSubmatch(expr *regexp.Regexp, input string) string {
	match := expr.FindStringSubmatch(input)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}
