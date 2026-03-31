package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

type securityTrailsSubdomainsResponse struct {
	Subdomains []string `json:"subdomains"`
}

func LookupSecurityTrailsSubdomains(ctx context.Context, client *util.HTTPClient, domain, apiKey string) ([]string, *models.SourceError) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("https://api.securitytrails.com/v1/domain/%s/subdomains", url.PathEscape(domain))
	page, err := client.GetWithHeaders(ctx, endpoint, map[string]string{
		"APIKEY": apiKey,
	})
	if err != nil {
		sourceErr := WrapError("securitytrails", "api", "lookup_subdomains", endpoint, err)
		return nil, &sourceErr
	}

	var payload securityTrailsSubdomainsResponse
	if err := json.Unmarshal(page.Body, &payload); err != nil {
		sourceErr := WrapError("securitytrails", "api", "parse_json", endpoint, err)
		return nil, &sourceErr
	}

	hosts := make([]string, 0, len(payload.Subdomains))
	for _, item := range payload.Subdomains {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		hosts = append(hosts, item+"."+domain)
	}
	return NormalizeHosts(domain, hosts), nil
}
