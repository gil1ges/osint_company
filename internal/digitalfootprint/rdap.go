package digitalfootprint

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

func lookupRDAP(ctx context.Context, client *util.HTTPClient, ips []string) ([]string, []models.SourceError) {
	hints := make([]string, 0)
	errors := make([]models.SourceError, 0)

	for _, ip := range ips {
		endpoint := fmt.Sprintf("https://rdap.org/ip/%s", ip)
		page, err := client.Get(ctx, endpoint)
		if err != nil {
			errors = append(errors, models.SourceError{
				SourceName:  "rdap",
				SourceURL:   endpoint,
				SourceType:  "rdap",
				Operation:   "lookup_ip",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: nowUTC(),
			})
			continue
		}

		var payload map[string]any
		if err := json.Unmarshal(page.Body, &payload); err != nil {
			errors = append(errors, models.SourceError{
				SourceName:  "rdap",
				SourceURL:   endpoint,
				SourceType:  "rdap",
				Operation:   "parse_json",
				Error:       err.Error(),
				Temporary:   true,
				CollectedAt: nowUTC(),
			})
			continue
		}

		parts := make([]string, 0)
		for _, key := range []string{"name", "handle", "country"} {
			if value, ok := payload[key].(string); ok && strings.TrimSpace(value) != "" {
				parts = append(parts, value)
			}
		}
		if len(parts) > 0 {
			hints = append(hints, strings.Join(parts, " | "))
		}
	}

	return util.UniqueStrings(hints), errors
}
