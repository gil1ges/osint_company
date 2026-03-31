package report

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/models"
)

type htmlViewData struct {
	GeneratedAt      time.Time
	Summary          htmlSummaryView
	Profile          *htmlProfileView
	DigitalFootprint *htmlDigitalView
	Providers        htmlProvidersView
	Warnings         []string
	Errors           []aggregatedSourceError
}

type htmlSummaryView struct {
	Company          string
	FullLegalName    string
	Domain           string
	INN              string
	OGRN             string
	RegistrationDate string
	MainAddress      string
	ProvidersUsed    []string
	OverallStatus    string
}

type htmlProfileView struct {
	OfficialWebsite  string
	FullLegalName    string
	INN              string
	OGRN             string
	RegistrationData string
	RegistrationDate string
	OfficeAddresses  []string
	Branches         []string
	Subsidiaries     []string
	Services         []string
	Industries       []string
	Licenses         []string
	Certificates     []string
	PagesScanned     []string
	DocumentsScanned []models.DocumentReference
}

type htmlDigitalView struct {
	OfficialWebsite  string
	Domain           string
	DomainDiscovery  string
	ProvidersUsed    []string
	IPs              []string
	Nameservers      []string
	HostingProviders []string
	Netblocks        []string
	ASNs             []string
	AdditionalHints  []string
	CDN              string
	Technologies     []string
	Subdomains       []string
	Wayback          []models.WaybackSnapshot
	Ports            []string
}

type htmlProvidersView struct {
	ProvidersUsed   []string
	PrimaryProvider string
	SpiderFootState string
	ProfileSources  []string
}

const fallbackTemplate = `<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <title>OSINT-отчет по компании</title>
</head>
<body>
  <h1>OSINT-отчет по компании</h1>
  <p>Сформирован: {{ fmtTime .GeneratedAt }}</p>
  <p>Компания: {{ with .Summary.Company }}{{ . }}{{ else }}Не найдено{{ end }}</p>
  <p>Домен: {{ with .Summary.Domain }}{{ . }}{{ else }}Не найдено{{ end }}</p>
</body>
</html>`

func GenerateHTML(report models.Report) ([]byte, string, error) {
	tpl, err := template.New("report").Funcs(template.FuncMap{
		"fmtTime": func(value time.Time) string {
			return value.Format("02 Jan 2006 15:04 MST")
		},
		"orValue": func(value string) string {
			value = strings.TrimSpace(value)
			if value == "" {
				return "Не найдено"
			}
			return value
		},
		"orJoined": func(values []string) string {
			if len(values) == 0 {
				return "Не найдено"
			}
			return strings.Join(values, ", ")
		},
		"hasItems": func(values []string) bool {
			return len(values) > 0
		},
		"portLabel": func(item string) string {
			if strings.TrimSpace(item) == "" {
				return "Неизвестно"
			}
			return item
		},
	}).Parse(loadHTMLTemplate())
	if err != nil {
		return nil, "", err
	}

	var buf bytes.Buffer
	compact := buildCompactJSONReport(report)
	view := htmlViewData{
		GeneratedAt:      report.GeneratedAt,
		Summary:          buildHTMLSummary(compact),
		Profile:          buildHTMLProfile(compact.BasicProfile),
		DigitalFootprint: buildHTMLDigital(compact.DigitalFootprint),
		Providers:        buildHTMLProviders(compact, report),
		Warnings:         compact.Warnings,
		Errors:           compact.Errors,
	}
	if err := tpl.Execute(&buf, view); err != nil {
		return nil, "", err
	}
	return buf.Bytes(), "html", nil
}

func loadHTMLTemplate() string {
	candidates := []string{
		filepath.Join("templates", "report.html.tmpl"),
		filepath.Join("..", "..", "templates", "report.html.tmpl"),
		filepath.Join("..", "templates", "report.html.tmpl"),
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "templates", "report.html.tmpl"))
	}
	for _, candidate := range candidates {
		data, err := os.ReadFile(candidate)
		if err == nil {
			return string(data)
		}
	}
	return fallbackTemplate
}

func buildHTMLSummary(report compactJSONReport) htmlSummaryView {
	summary := htmlSummaryView{
		Company: pickFirstNonEmpty(
			report.Inputs.Company,
			ptrValueOrEmpty(valueOrNil(report.BasicProfile, func(p *compactProfileSection) *string { return p.FullLegalName })),
		),
		FullLegalName: pickFirstNonEmpty(
			ptrValueOrEmpty(valueOrNil(report.BasicProfile, func(p *compactProfileSection) *string { return p.FullLegalName })),
		),
		Domain: pickFirstNonEmpty(
			ptrValueOrEmpty(valueOrNil(report.DigitalFootprint, func(d *compactDigitalSection) *string { return d.Domain })),
			report.Inputs.Domain,
		),
		INN: pickFirstNonEmpty(
			ptrValueOrEmpty(valueOrNil(report.BasicProfile, func(p *compactProfileSection) *string { return p.INN })),
			report.Inputs.INN,
		),
		OGRN: ptrValueOrEmpty(valueOrNil(report.BasicProfile, func(p *compactProfileSection) *string { return p.OGRN })),
		RegistrationDate: ptrValueOrEmpty(valueOrNil(report.BasicProfile, func(p *compactProfileSection) *string {
			return p.RegistrationDate
		})),
		MainAddress: firstOrEmpty(valueOrEmptySlice(report.BasicProfile, func(p *compactProfileSection) []string {
			return p.OfficeAddresses
		})),
		ProvidersUsed: valueOrEmptySlice(report.DigitalFootprint, func(d *compactDigitalSection) []string {
			return d.ProvidersUsed
		}),
	}
	summary.OverallStatus = deriveOverallStatusFromCompact(report)
	return summary
}

func buildHTMLProfile(profile *compactProfileSection) *htmlProfileView {
	if profile == nil {
		return nil
	}
	return &htmlProfileView{
		OfficialWebsite:  ptrValueOrEmpty(profile.OfficialWebsite),
		FullLegalName:    ptrValueOrEmpty(profile.FullLegalName),
		INN:              ptrValueOrEmpty(profile.INN),
		OGRN:             ptrValueOrEmpty(profile.OGRN),
		RegistrationData: ptrValueOrEmpty(profile.RegistrationData),
		RegistrationDate: ptrValueOrEmpty(profile.RegistrationDate),
		OfficeAddresses:  append([]string{}, profile.OfficeAddresses...),
		Branches:         append([]string{}, profile.Branches...),
		Subsidiaries:     append([]string{}, profile.Subsidiaries...),
		Services:         append([]string{}, profile.Activities.Services...),
		Industries:       append([]string{}, profile.Activities.Industries...),
		Licenses:         append([]string{}, profile.Licenses...),
		Certificates:     append([]string{}, profile.Certificates...),
		PagesScanned:     append([]string{}, profile.PagesScanned...),
		DocumentsScanned: append([]models.DocumentReference{}, profile.DocumentsScanned...),
	}
}

func buildHTMLDigital(digital *compactDigitalSection) *htmlDigitalView {
	if digital == nil {
		return nil
	}
	hints := classifyProviderHints(digital.ProviderHints, nil)
	return &htmlDigitalView{
		OfficialWebsite:  ptrValueOrEmpty(digital.OfficialWebsite),
		Domain:           ptrValueOrEmpty(digital.Domain),
		DomainDiscovery:  ptrValueOrEmpty(digital.DomainDiscovery),
		ProvidersUsed:    append([]string{}, digital.ProvidersUsed...),
		IPs:              append([]string{}, digital.IPs...),
		Nameservers:      hints.Nameservers,
		HostingProviders: hints.HostingProviders,
		Netblocks:        hints.Netblocks,
		ASNs:             hints.ASNs,
		AdditionalHints:  hints.AdditionalHints,
		CDN:              ptrValueOrEmpty(digital.CDN),
		Technologies:     append([]string{}, digital.Technologies...),
		Subdomains:       append([]string{}, digital.Subdomains...),
		Wayback:          append([]models.WaybackSnapshot{}, digital.Wayback...),
		Ports:            formatPorts(digital.Ports),
	}
}

func buildHTMLProviders(compact compactJSONReport, report models.Report) htmlProvidersView {
	providersUsed := valueOrEmptySlice(compact.DigitalFootprint, func(d *compactDigitalSection) []string {
		return d.ProvidersUsed
	})
	return htmlProvidersView{
		ProvidersUsed:   providersUsed,
		PrimaryProvider: derivePrimaryProvider(providersUsed),
		SpiderFootState: deriveSpiderFootState(report.Warnings),
		ProfileSources:  deriveProfileSources(report),
	}
}

type classifiedHints struct {
	Nameservers      []string
	HostingProviders []string
	Netblocks        []string
	ASNs             []string
	AdditionalHints  []string
}

func classifyProviderHints(hints []string, dnsNS []string) classifiedHints {
	out := classifiedHints{
		Nameservers:      append([]string{}, dnsNS...),
		HostingProviders: []string{},
		Netblocks:        []string{},
		ASNs:             []string{},
		AdditionalHints:  []string{},
	}
	for _, hint := range hints {
		hint = strings.TrimSpace(hint)
		lower := strings.ToLower(hint)
		switch {
		case strings.HasPrefix(lower, "nameserver:"):
			out.Nameservers = append(out.Nameservers, strings.TrimSpace(strings.TrimPrefix(hint, "nameserver:")))
		case strings.HasPrefix(lower, "hosting/provider:"):
			out.HostingProviders = append(out.HostingProviders, strings.TrimSpace(strings.TrimPrefix(hint, "hosting/provider:")))
		case strings.HasPrefix(lower, "netblock:"):
			out.Netblocks = append(out.Netblocks, strings.TrimSpace(strings.TrimPrefix(hint, "netblock:")))
		case strings.HasPrefix(lower, "asn:"):
			out.ASNs = append(out.ASNs, strings.TrimSpace(strings.TrimPrefix(hint, "asn:")))
		default:
			out.AdditionalHints = append(out.AdditionalHints, hint)
		}
	}
	out.Nameservers = uniqueSorted(out.Nameservers)
	out.HostingProviders = uniqueSorted(out.HostingProviders)
	out.Netblocks = uniqueSorted(out.Netblocks)
	out.ASNs = uniqueSorted(out.ASNs)
	out.AdditionalHints = uniqueSorted(out.AdditionalHints)
	return out
}

func uniqueSorted(values []string) []string {
	set := make(map[string]string)
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		set[key] = value
	}
	out := make([]string, 0, len(set))
	for _, value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func formatPorts(items []models.PortFinding) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		label := fmt.Sprintf("%s:%d", item.IP, item.Port)
		if item.Transport != "" {
			label += "/" + item.Transport
		}
		if item.Product != "" {
			label += " - " + item.Product
		}
		out = append(out, label)
	}
	return uniqueSorted(out)
}

func deriveOverallStatus(report models.Report) string {
	hasErrors := len(aggregateErrors(report.Errors)) > 0
	hasWarnings := len(aggregateWarnings(report.Warnings)) > 0
	return deriveOverallStatusFlags(hasWarnings, hasErrors)
}

func deriveOverallStatusFromCompact(report compactJSONReport) string {
	return deriveOverallStatusFlags(len(report.Warnings) > 0, len(report.Errors) > 0)
}

func deriveOverallStatusFlags(hasWarnings, hasErrors bool) string {
	switch {
	case hasErrors && hasWarnings:
		return "Выполнено с предупреждениями и ошибками"
	case hasErrors:
		return "Выполнено с ошибками"
	case hasWarnings:
		return "Выполнено с предупреждениями"
	default:
		return "Выполнено успешно"
	}
}

func derivePrimaryProvider(providers []string) string {
	for _, provider := range providers {
		if strings.EqualFold(provider, "spiderfoot") {
			return "SpiderFoot"
		}
	}
	if len(providers) > 0 {
		return providers[0]
	}
	return "Пассивные fallback-источники"
}

func deriveSpiderFootState(warnings []string) string {
	for _, warning := range warnings {
		lower := strings.ToLower(strings.TrimSpace(warning))
		switch {
		case strings.Contains(lower, "spiderfoot used successfully"):
			return "SpiderFoot использован успешно"
		case strings.Contains(lower, "spiderfoot returned partial results"):
			return "SpiderFoot вернул частичные результаты"
		case strings.Contains(lower, "spiderfoot timed out"):
			return "SpiderFoot превысил время ожидания"
		case strings.Contains(lower, "spiderfoot unavailable"):
			return "SpiderFoot недоступен"
		}
	}
	return "Статус SpiderFoot не определен"
}

func deriveProfileSources(report models.Report) []string {
	set := make([]string, 0, 4)
	if report.Profile != nil {
		if strings.TrimSpace(report.Profile.Data.OfficialWebsite) != "" {
			set = append(set, "Официальный сайт")
		}
		for _, page := range report.Profile.Data.PagesScanned {
			lower := strings.ToLower(page)
			switch {
			case strings.Contains(lower, "rusprofile"), strings.Contains(lower, "rbc.ru"), strings.Contains(lower, "companies.rbc.ru"), strings.Contains(lower, "checko"), strings.Contains(lower, "list-org"), strings.Contains(lower, "audit-it"):
				set = append(set, "Публичные карточки компании")
			}
		}
	}
	if report.DigitalFootprint != nil {
		for _, provider := range report.DigitalFootprint.Data.ProvidersUsed {
			if strings.EqualFold(provider, "spiderfoot") {
				set = append(set, "SpiderFoot")
			}
		}
	}
	return uniqueSorted(set)
}

func pickFirstNonEmpty(values ...string) string {
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			return value
		}
	}
	return ""
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return strings.TrimSpace(values[0])
}

func valueOrEmpty[T any](value *T, getter func(*T) string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(getter(value))
}

func valueOrEmptySlice[T any](value *T, getter func(*T) []string) []string {
	if value == nil {
		return nil
	}
	return append([]string{}, getter(value)...)
}

func valueOrNil[T any, V any](value *T, getter func(*T) *V) *V {
	if value == nil {
		return nil
	}
	return getter(value)
}

func ptrValueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}
