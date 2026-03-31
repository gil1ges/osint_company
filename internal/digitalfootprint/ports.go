package digitalfootprint

import (
	"context"
	"strconv"
	"strings"

	"github.com/gorcher/osint_company/internal/config"
	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/providers"
	"github.com/gorcher/osint_company/internal/util"
)

func collectPassivePorts(ctx context.Context, client *util.HTTPClient, cfg config.Config, ips []string) ([]models.PortFinding, string, []models.SourceError) {
	if strings.TrimSpace(cfg.ShodanAPIKey) == "" {
		return nil, "active scanning intentionally not performed; passive source unavailable", nil
	}

	out := make([]models.PortFinding, 0)
	errors := make([]models.SourceError, 0)
	for _, ip := range ips {
		ports, err := providers.LookupShodanHost(ctx, client, ip, cfg.ShodanAPIKey)
		if err != nil {
			errors = append(errors, *err)
			continue
		}
		out = append(out, ports...)
	}

	seen := make(map[string]models.PortFinding)
	for _, item := range out {
		key := item.IP + "|" + item.Source + "|" + item.Product + "|" + item.Transport + "|" + strconv.Itoa(item.Port)
		seen[key] = item
	}
	deduped := make([]models.PortFinding, 0, len(seen))
	for _, item := range seen {
		deduped = append(deduped, item)
	}
	return deduped, "", errors
}
