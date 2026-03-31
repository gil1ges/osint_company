package providers

import (
	"context"
	"strings"

	"github.com/gorcher/osint_company/internal/util"
)

func RunSpiderFoot(ctx context.Context, command string, domain string, company string) ([]string, error) {
	return runConfiguredTextProvider(ctx, "spiderfoot", command, map[string]string{
		"domain":  domain,
		"company": company,
	})
}

func RunSpiderFootAuto(ctx context.Context, configuredCommand, domain, company string) ([]string, bool, error) {
	placeholders := map[string]string{
		"domain":  domain,
		"company": company,
	}
	candidates := []string{}
	if strings.TrimSpace(configuredCommand) != "" {
		candidates = append(candidates, configuredCommand)
	}
	for _, candidate := range []string{
		"spiderfoot-cli -s {{domain}}",
		"spiderfoot -s {{domain}}",
		"sf.py -s {{domain}}",
	} {
		fields := strings.Fields(candidate)
		if len(fields) > 0 && util.CommandExists(fields[0]) {
			candidates = append(candidates, candidate)
		}
	}

	var attempted bool
	var lastErr error
	for _, candidate := range candidates {
		attempted = true
		lines, err := runConfiguredTextProvider(ctx, "spiderfoot", candidate, placeholders)
		if err == nil {
			return lines, true, nil
		}
		lastErr = err
	}
	if !attempted {
		return nil, false, nil
	}
	return nil, true, lastErr
}
