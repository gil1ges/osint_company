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

type shodanHostResponse struct {
	Ports []int `json:"ports"`
	Data  []struct {
		Port      int    `json:"port"`
		Transport string `json:"transport"`
		Product   string `json:"product"`
	} `json:"data"`
}

func LookupShodanHost(ctx context.Context, client *util.HTTPClient, ip, apiKey string) ([]models.PortFinding, *models.SourceError) {
	if strings.TrimSpace(apiKey) == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("https://api.shodan.io/shodan/host/%s?key=%s", url.PathEscape(ip), url.QueryEscape(apiKey))
	page, err := client.Get(ctx, endpoint)
	if err != nil {
		sourceErr := WrapError("shodan", "api", "lookup_host", endpoint, err)
		return nil, &sourceErr
	}

	var payload shodanHostResponse
	if err := json.Unmarshal(page.Body, &payload); err != nil {
		sourceErr := WrapError("shodan", "api", "parse_json", endpoint, err)
		return nil, &sourceErr
	}

	out := make([]models.PortFinding, 0, len(payload.Data))
	for _, entry := range payload.Data {
		out = append(out, models.PortFinding{
			IP:        ip,
			Port:      entry.Port,
			Transport: entry.Transport,
			Product:   entry.Product,
			Source:    "shodan",
		})
	}
	return out, nil
}
