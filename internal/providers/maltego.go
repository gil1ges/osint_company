package providers

import (
	"context"
	"strings"

	"github.com/gorcher/osint_company/internal/util"
)

func RunMaltego(ctx context.Context, command string, domain string, company string) ([]string, error) {
	return runConfiguredTextProvider(ctx, "maltego", command, map[string]string{
		"domain":  domain,
		"company": company,
	})
}

func RunMaltegoAuto(ctx context.Context, configuredCommand, domain, company string) ([]string, bool, error) {
	placeholders := map[string]string{
		"domain":  domain,
		"company": company,
	}
	candidates := []string{}
	if strings.TrimSpace(configuredCommand) != "" {
		candidates = append(candidates, configuredCommand)
	}
	for _, candidate := range []string{
		"maltego {{domain}}",
		"maltego-ce {{domain}}",
		"maltego-classic {{domain}}",
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
		lines, err := runConfiguredTextProvider(ctx, "maltego", candidate, placeholders)
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
