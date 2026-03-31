package digitalfootprint

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gorcher/osint_company/internal/config"
	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/providers"
	"github.com/gorcher/osint_company/internal/util"
)

type crtshRecord struct {
	NameValue string `json:"name_value"`
}

func collectSubdomains(ctx context.Context, client *util.HTTPClient, cfg config.Config, domain string, homepageLinks []string) ([]string, []models.SourceError) {
	set := make([]string, 0)
	errors := make([]models.SourceError, 0)

	if hosts, err := lookupCRTSh(ctx, client, domain); err == nil {
		set = append(set, hosts...)
	} else {
		errors = append(errors, *err)
	}
	if hosts, err := collectWaybackHosts(ctx, client, domain); err == nil {
		set = append(set, hosts...)
	} else if err != nil {
		errors = append(errors, *err)
	}
	if hosts, err := providers.RunSubfinder(ctx, domain); err == nil {
		set = append(set, hosts...)
	} else if err != nil && err.Error != "tool not installed" {
		errors = append(errors, *err)
	}
	if hosts, err := providers.RunAmassPassive(ctx, domain); err == nil {
		set = append(set, hosts...)
	} else if err != nil && err.Error != "tool not installed" {
		errors = append(errors, *err)
	}
	if hosts, err := providers.LookupSecurityTrailsSubdomains(ctx, client, domain, cfg.SecurityTrailsAPIKey); err == nil {
		set = append(set, hosts...)
	} else if err != nil {
		errors = append(errors, *err)
	}
	if lines, attempted, err := providers.RunSpiderFootAuto(ctx, cfg.SpiderFootCommand, domain, ""); err == nil {
		set = append(set, normalizeProviderLinesToHosts(domain, lines)...)
	} else if attempted {
		errors = append(errors, models.SourceError{
			SourceName:  "spiderfoot",
			SourceType:  "tool",
			Operation:   "run",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		})
	}
	if lines, attempted, err := providers.RunMaltegoAuto(ctx, cfg.MaltegoCommand, domain, ""); err == nil {
		set = append(set, normalizeProviderLinesToHosts(domain, lines)...)
	} else if attempted {
		errors = append(errors, models.SourceError{
			SourceName:  "maltego",
			SourceType:  "tool",
			Operation:   "run",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		})
	}

	for _, link := range homepageLinks {
		if host := util.ExtractDomainFromURL(link); host != "" && host != domain {
			set = append(set, host)
		}
	}

	return providers.NormalizeSubdomains(domain, set), errors
}

func lookupCRTSh(ctx context.Context, client *util.HTTPClient, domain string) ([]string, *models.SourceError) {
	endpoint := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", domain)
	page, err := client.Get(ctx, endpoint)
	if err != nil {
		sourceErr := models.SourceError{
			SourceName:  "crt.sh",
			SourceURL:   endpoint,
			SourceType:  "certificate_transparency",
			Operation:   "fetch_subdomains",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		}
		return nil, &sourceErr
	}

	var rows []crtshRecord
	if err := json.Unmarshal(page.Body, &rows); err != nil {
		sourceErr := models.SourceError{
			SourceName:  "crt.sh",
			SourceURL:   endpoint,
			SourceType:  "certificate_transparency",
			Operation:   "parse_json",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		}
		return nil, &sourceErr
	}

	hosts := make([]string, 0)
	for _, row := range rows {
		for _, item := range strings.Split(row.NameValue, "\n") {
			item = strings.TrimSpace(strings.TrimPrefix(item, "*."))
			if item != "" {
				hosts = append(hosts, item)
			}
		}
	}
	return providers.NormalizeSubdomains(domain, hosts), nil
}

func normalizeProviderLinesToHosts(domain string, lines []string) []string {
	hosts := make([]string, 0, len(lines))
	for _, line := range lines {
		host := util.ExtractDomainFromURL(line)
		if host == "" {
			host = strings.ToLower(strings.TrimSpace(line))
		}
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return providers.NormalizeSubdomains(domain, hosts)
}
