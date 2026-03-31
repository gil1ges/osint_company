package digitalfootprint

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

func collectDNS(ctx context.Context, domain string) (models.DNSRecords, []models.SourceError) {
	records := models.DNSRecords{}
	errors := make([]models.SourceError, 0)

	if domain == "" {
		return records, errors
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		errors = append(errors, models.SourceError{
			SourceName:  "dns",
			SourceURL:   domain,
			SourceType:  "dns",
			Operation:   "lookup_ip",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: time.Now().UTC(),
		})
	} else {
		for _, ip := range ips {
			if ip.To4() != nil {
				records.A = append(records.A, ip.String())
			} else {
				records.AAAA = append(records.AAAA, ip.String())
			}
		}
	}

	if mx, err := net.DefaultResolver.LookupMX(ctx, domain); err == nil {
		for _, item := range mx {
			records.MX = append(records.MX, fmt.Sprintf("%d %s", item.Pref, strings.TrimSuffix(item.Host, ".")))
		}
	} else {
		errors = append(errors, wrapDNSError(domain, "lookup_mx", err))
	}

	if ns, err := net.DefaultResolver.LookupNS(ctx, domain); err == nil {
		for _, item := range ns {
			records.NS = append(records.NS, strings.TrimSuffix(item.Host, "."))
		}
	} else {
		errors = append(errors, wrapDNSError(domain, "lookup_ns", err))
	}

	if txt, err := net.DefaultResolver.LookupTXT(ctx, domain); err == nil {
		records.TXT = append(records.TXT, txt...)
	} else {
		errors = append(errors, wrapDNSError(domain, "lookup_txt", err))
	}

	if cname, err := net.DefaultResolver.LookupCNAME(ctx, domain); err == nil {
		cname = strings.TrimSuffix(cname, ".")
		if cname != "" && cname != domain {
			records.CNAME = append(records.CNAME, cname)
		}
	} else {
		errors = append(errors, wrapDNSError(domain, "lookup_cname", err))
	}

	records.A = util.UniqueStrings(records.A)
	records.AAAA = util.UniqueStrings(records.AAAA)
	records.MX = util.UniqueStrings(records.MX)
	records.NS = util.UniqueStrings(records.NS)
	records.TXT = util.UniqueStrings(records.TXT)
	records.CNAME = util.UniqueStrings(records.CNAME)

	if len(records.CNAME) == 0 && util.CommandExists("dig") {
		if values, err := digLookup(ctx, domain, "CNAME"); err == nil {
			records.CNAME = util.UniqueStrings(values)
		}
	}

	return records, errors
}

func digLookup(ctx context.Context, domain, rrType string) ([]string, error) {
	result, err := util.RunCommand(ctx, "dig", "+short", domain, rrType)
	if err != nil {
		return nil, err
	}
	lines := strings.Split(result.Stdout, "\n")
	values := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(strings.TrimSuffix(line, "."))
		if line != "" {
			values = append(values, line)
		}
	}
	return util.UniqueStrings(values), nil
}

func wrapDNSError(domain, operation string, err error) models.SourceError {
	return models.SourceError{
		SourceName:  "dns",
		SourceURL:   domain,
		SourceType:  "dns",
		Operation:   operation,
		Error:       err.Error(),
		Temporary:   true,
		CollectedAt: time.Now().UTC(),
	}
}
