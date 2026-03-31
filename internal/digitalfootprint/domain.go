package digitalfootprint

import (
	"context"
	"log/slog"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/profile"
	"github.com/gorcher/osint_company/internal/util"
)

func determineDomain(ctx context.Context, client *util.HTTPClient, logger *slog.Logger, inputs models.TargetInput) (string, string, string, []models.Evidence, []models.SourceError) {
	if strings.TrimSpace(inputs.Domain) != "" {
		domain, err := util.NormalizeDomain(inputs.Domain)
		if err == nil {
			return domain, util.NormalizeURL(domain), "provided via CLI input", []models.Evidence{{
				SourceName:  "user_input",
				SourceType:  "input",
				RetrievedAt: nowUTC(),
				Method:      "cli flag",
				Snippet:     inputs.Domain,
			}}, nil
		}
	}

	officialWebsite, evidence, errors := profile.DiscoverOfficialWebsite(ctx, client, inputs.Company, inputs.INN, logger)
	if officialWebsite == "" {
		return "", "", "", evidence, errors
	}

	domain := util.ExtractDomainFromURL(officialWebsite)
	return domain, officialWebsite, "discovered from search results", evidence, errors
}
