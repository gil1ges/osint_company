package digitalfootprint

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

func collectWaybackSnapshots(ctx context.Context, client *util.HTTPClient, domain string) ([]models.WaybackSnapshot, []models.SourceError) {
	if domain == "" {
		return nil, nil
	}

	endpoint := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=%s/*&output=json&fl=timestamp,original,statuscode&collapse=digest&limit=20", domain)
	page, err := client.Get(ctx, endpoint)
	if err != nil {
		return nil, []models.SourceError{{
			SourceName:  "wayback",
			SourceURL:   endpoint,
			SourceType:  "archive",
			Operation:   "fetch_snapshots",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		}}
	}

	var rows [][]string
	if err := json.Unmarshal(page.Body, &rows); err != nil {
		return nil, []models.SourceError{{
			SourceName:  "wayback",
			SourceURL:   endpoint,
			SourceType:  "archive",
			Operation:   "parse_json",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		}}
	}

	snapshots := make([]models.WaybackSnapshot, 0)
	for idx, row := range rows {
		if idx == 0 || len(row) < 3 {
			continue
		}
		archiveURL := fmt.Sprintf("https://web.archive.org/web/%s/%s", row[0], row[1])
		snapshots = append(snapshots, models.WaybackSnapshot{
			Timestamp:   row[0],
			OriginalURL: row[1],
			ArchiveURL:  archiveURL,
			StatusCode:  row[2],
		})
	}
	return snapshots, nil
}

func collectWaybackHosts(ctx context.Context, client *util.HTTPClient, domain string) ([]string, *models.SourceError) {
	endpoint := fmt.Sprintf("https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey&limit=200", domain)
	page, err := client.Get(ctx, endpoint)
	if err != nil {
		sourceErr := models.SourceError{
			SourceName:  "wayback",
			SourceURL:   endpoint,
			SourceType:  "archive",
			Operation:   "fetch_hosts",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		}
		return nil, &sourceErr
	}

	var rows [][]string
	if err := json.Unmarshal(page.Body, &rows); err != nil {
		sourceErr := models.SourceError{
			SourceName:  "wayback",
			SourceURL:   endpoint,
			SourceType:  "archive",
			Operation:   "parse_json",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: nowUTC(),
		}
		return nil, &sourceErr
	}

	hosts := make([]string, 0)
	for idx, row := range rows {
		if idx == 0 || len(row) == 0 {
			continue
		}
		host := util.ExtractDomainFromURL(row[0])
		if host != "" {
			hosts = append(hosts, host)
		}
	}
	return util.UniqueStrings(hosts), nil
}
