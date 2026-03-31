package digitalfootprint

import (
	"context"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

var (
	httpTitleRe     = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	httpMetaDescRe  = regexp.MustCompile(`(?is)<meta[^>]+name=["']description["'][^>]+content=["'](.*?)["']`)
	httpMetaGenRe   = regexp.MustCompile(`(?is)<meta[^>]+name=["']generator["'][^>]+content=["'](.*?)["']`)
	httpLinkRe      = regexp.MustCompile(`(?is)<a[^>]+href=["'](.*?)["']`)
	httpScriptSrcRe = regexp.MustCompile(`(?is)<script[^>]+src=["'](.*?)["']`)
)

type HTTPCapture struct {
	Details    *models.HTTPDetails
	Body       string
	Links      []string
	Scripts    []string
	Errors     []models.SourceError
	Evidence   []models.Evidence
	FinalHost  string
	StatusCode int
}

func fetchHTTP(ctx context.Context, client *util.HTTPClient, domain string) *HTTPCapture {
	targets := []string{"https://" + domain, "http://" + domain}
	capture := &HTTPCapture{Errors: make([]models.SourceError, 0)}

	for _, target := range targets {
		page, err := client.Get(ctx, target)
		if err != nil {
			capture.Errors = append(capture.Errors, models.SourceError{
				SourceName:  "http",
				SourceURL:   target,
				SourceType:  "http",
				Operation:   "fetch_homepage",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: nowUTC(),
			})
			continue
		}

		body := string(page.Body)
		headers := make(map[string]string)
		for key, values := range page.Headers {
			headers[key] = util.JoinHeaderValues(values)
		}
		cookies := make([]string, 0)
		for _, cookie := range page.Headers.Values("Set-Cookie") {
			name := strings.SplitN(cookie, "=", 2)[0]
			if strings.TrimSpace(name) != "" {
				cookies = append(cookies, name)
			}
		}
		finalURL := page.FinalURL
		if finalURL == "" {
			finalURL = target
		}

		details := &models.HTTPDetails{
			HomepageURL:   target,
			FinalURL:      finalURL,
			Title:         util.NormalizeWhitespace(firstSubmatch(httpTitleRe, body)),
			Description:   util.NormalizeWhitespace(firstSubmatch(httpMetaDescRe, body)),
			Headers:       headers,
			Cookies:       util.UniqueStrings(cookies),
			MetaGenerator: util.NormalizeWhitespace(firstSubmatch(httpMetaGenRe, body)),
		}

		base, _ := url.Parse(finalURL)
		details.RobotsURL = resolveURL(base, "/robots.txt")
		details.SitemapURL = resolveURL(base, "/sitemap.xml")
		if robots, err := client.Get(ctx, details.RobotsURL); err == nil && robots.StatusCode < 400 {
			details.RobotsPreview = util.ClipString(util.NormalizeWhitespace(string(robots.Body)), 300)
		}

		capture.Details = details
		capture.Body = body
		capture.Links = extractAbsoluteURLs(body, finalURL, httpLinkRe)
		capture.Scripts = extractAbsoluteURLs(body, finalURL, httpScriptSrcRe)
		capture.StatusCode = page.StatusCode
		capture.FinalHost = util.ExtractDomainFromURL(finalURL)
		capture.Evidence = append(capture.Evidence, models.Evidence{
			SourceName:  "http",
			SourceURL:   finalURL,
			SourceType:  "http",
			RetrievedAt: page.RetrievedAt,
			Method:      "http homepage fetch",
			Snippet:     util.ClipString(details.Title+" "+details.Description, 220),
		})
		return capture
	}

	return capture
}

func extractAbsoluteURLs(rawHTML, baseURL string, expr *regexp.Regexp) []string {
	base, _ := url.Parse(baseURL)
	matches := expr.FindAllStringSubmatch(rawHTML, -1)
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		href := html.UnescapeString(strings.TrimSpace(match[1]))
		if href == "" || strings.HasPrefix(href, "javascript:") {
			continue
		}
		parsed, err := url.Parse(href)
		if err != nil {
			continue
		}
		if base != nil {
			parsed = base.ResolveReference(parsed)
		}
		out = append(out, parsed.String())
	}
	return util.UniqueStrings(out)
}

func firstSubmatch(expr *regexp.Regexp, input string) string {
	match := expr.FindStringSubmatch(input)
	if len(match) < 2 {
		return ""
	}
	return match[1]
}

func resolveURL(base *url.URL, ref string) string {
	if base == nil {
		return ref
	}
	parsed, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(parsed).String()
}

func httpEvidence(targetURL, snippet string) models.Evidence {
	return models.Evidence{
		SourceName:  "http",
		SourceURL:   targetURL,
		SourceType:  "http",
		RetrievedAt: nowUTC(),
		Method:      "http fetch",
		Snippet:     util.ClipString(snippet, 200),
	}
}

func buildHTTPNotFoundWarning(domain string) string {
	return fmt.Sprintf("homepage fetch for %s returned no usable content", domain)
}
