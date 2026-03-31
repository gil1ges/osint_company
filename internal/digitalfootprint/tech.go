package digitalfootprint

import (
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

func detectBuiltInTechnologies(capture *HTTPCapture) []string {
	if capture == nil || capture.Details == nil {
		return nil
	}

	set := make([]string, 0)
	headers := capture.Details.Headers
	body := strings.ToLower(capture.Body)

	add := func(name string) {
		if strings.TrimSpace(name) != "" {
			set = append(set, name)
		}
	}

	server := strings.ToLower(headers["Server"])
	switch {
	case strings.Contains(server, "cloudflare"):
		add("Cloudflare")
	case strings.Contains(server, "nginx"):
		add("Nginx")
	case strings.Contains(server, "apache"):
		add("Apache HTTP Server")
	case strings.Contains(server, "caddy"):
		add("Caddy")
	case strings.Contains(server, "iis"):
		add("Microsoft IIS")
	}

	poweredBy := strings.ToLower(headers["X-Powered-By"])
	switch {
	case strings.Contains(poweredBy, "php"):
		add("PHP")
	case strings.Contains(poweredBy, "express"):
		add("Express")
	case strings.Contains(poweredBy, "asp.net"):
		add("ASP.NET")
	}

	generator := strings.ToLower(capture.Details.MetaGenerator)
	switch {
	case strings.Contains(generator, "wordpress"):
		add("WordPress")
	case strings.Contains(generator, "drupal"):
		add("Drupal")
	case strings.Contains(generator, "joomla"):
		add("Joomla")
	}

	for _, cookie := range capture.Details.Cookies {
		lower := strings.ToLower(cookie)
		switch {
		case strings.Contains(lower, "wordpress"):
			add("WordPress")
		case strings.Contains(lower, "phpsessid"):
			add("PHP")
		case strings.Contains(lower, "_shopify"):
			add("Shopify")
		case strings.Contains(lower, "_ga"):
			add("Google Analytics")
		case strings.Contains(lower, "cf_"):
			add("Cloudflare")
		}
	}

	switch {
	case strings.Contains(body, "wp-content"):
		add("WordPress")
	case strings.Contains(body, "__next_data__"):
		add("Next.js")
	case strings.Contains(body, "drupal-settings-json"):
		add("Drupal")
	case strings.Contains(body, "data-reactroot") || strings.Contains(body, "react-dom"):
		add("React")
	case strings.Contains(body, "googletagmanager.com"):
		add("Google Tag Manager")
	case strings.Contains(body, "www.googletagmanager.com/gtag/js"):
		add("Google Analytics")
	case strings.Contains(body, "cdn.jsdelivr.net"):
		add("jsDelivr")
	}

	for _, script := range capture.Scripts {
		lower := strings.ToLower(script)
		switch {
		case strings.Contains(lower, "gtm.js"):
			add("Google Tag Manager")
		case strings.Contains(lower, "analytics.js"), strings.Contains(lower, "gtag/js"):
			add("Google Analytics")
		case strings.Contains(lower, "cdn.shopify.com"):
			add("Shopify")
		case strings.Contains(lower, "wp-includes"):
			add("WordPress")
		}
	}

	return util.UniqueStrings(set)
}

func inferCDN(httpDetails *models.HTTPDetails, dns models.DNSRecords, providerHints []string, tlsInfo *models.TLSCertificate) string {
	values := make([]string, 0)
	if httpDetails != nil {
		values = append(values, strings.ToLower(httpDetails.Headers["Server"]))
		values = append(values, strings.ToLower(httpDetails.Headers["Via"]))
		values = append(values, strings.ToLower(httpDetails.Headers["CF-Cache-Status"]))
	}
	values = append(values, strings.ToLower(strings.Join(dns.CNAME, " ")))
	values = append(values, strings.ToLower(strings.Join(providerHints, " ")))
	if tlsInfo != nil {
		values = append(values, strings.ToLower(tlsInfo.Issuer))
	}

	text := strings.Join(values, " | ")
	switch {
	case strings.Contains(text, "cloudflare"):
		return "Cloudflare"
	case strings.Contains(text, "cloudfront"):
		return "Amazon CloudFront"
	case strings.Contains(text, "akamai"):
		return "Akamai"
	case strings.Contains(text, "fastly"):
		return "Fastly"
	}
	return ""
}
