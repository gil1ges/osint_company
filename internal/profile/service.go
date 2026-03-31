package profile

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/config"
	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

type Service struct {
	httpClient *util.HTTPClient
	config     config.Config
	logger     *slog.Logger
}

func NewService(httpClient *util.HTTPClient, cfg config.Config, logger *slog.Logger) *Service {
	return &Service{
		httpClient: httpClient,
		config:     cfg,
		logger:     logger,
	}
}

func (s *Service) Collect(ctx context.Context, inputs models.TargetInput) models.ProfileModuleResult {
	result := models.ProfileModuleResult{
		ModuleResult: models.ModuleResult{Name: "profile"},
	}

	officialWebsite := strings.TrimSpace(inputs.Domain)
	if officialWebsite != "" {
		if normalized, err := util.NormalizeDomain(officialWebsite); err == nil {
			officialWebsite = util.NormalizeURL(normalized)
		}
	}

	if officialWebsite == "" && (strings.TrimSpace(inputs.Company) != "" || strings.TrimSpace(inputs.INN) != "") {
		discovered, evidence, errors := DiscoverOfficialWebsite(ctx, s.httpClient, inputs.Company, inputs.INN, s.logger)
		officialWebsite = discovered
		result.Errors = append(result.Errors, errors...)
		if discovered != "" {
			result.Findings = append(result.Findings, models.Finding{
				FieldName:       "official_website",
				Value:           discovered,
				NormalizedValue: util.NormalizeURL(discovered),
				Module:          "profile",
				Verified:        true,
				Confidence:      models.ConfidenceMedium,
				CollectedAt:     time.Now().UTC(),
				Notes:           []string{"discovered via search result parsing"},
				Evidence:        evidence,
			})
		}
	}

	result.Data.OfficialWebsite = officialWebsite
	pages, pageErrors := FetchCandidatePages(ctx, s.httpClient, officialWebsite, s.logger)
	result.Errors = append(result.Errors, pageErrors...)
	publicPages, publicErrors := FetchPublicRegistryPages(ctx, s.httpClient, inputs.Company, inputs.INN, util.ExtractDomainFromURL(officialWebsite), s.logger)
	result.Errors = append(result.Errors, publicErrors...)
	pages = append(pages, publicPages...)
	for _, page := range pages {
		result.Data.PagesScanned = append(result.Data.PagesScanned, page.URL)
	}
	result.Data.PagesScanned = util.UniqueStrings(result.Data.PagesScanned)

	rawCandidates, documents := s.extractRawCandidates(inputs, pages)
	result.Debug.RawCandidates = rawCandidates
	result.Data.DocumentsScanned = dedupeDocuments(documents)

	normalized := NormalizeRawCandidates(rawCandidates)
	result.Debug.NormalizedCandidates = normalized

	result.Findings = append(result.Findings, BuildFinalFindings(normalized)...)
	s.applyFindings(&result)
	fillDerivedRegistrationData(&result)

	if result.Data.OfficialWebsite == "" {
		result.Warnings = append(result.Warnings, "official website could not be confidently determined")
	}
	if len(result.Data.PagesScanned) == 0 {
		result.Warnings = append(result.Warnings, "no official HTML pages were scanned")
	}
	if result.Data.FullLegalName == "" {
		result.Warnings = append(result.Warnings, "full legal name: not found")
	}
	if result.Data.OGRN == "" {
		result.Warnings = append(result.Warnings, "ogrn: not found")
	}
	if result.Data.RegistrationDate == "" {
		result.Warnings = append(result.Warnings, "registration date: not found")
	}
	if result.Data.RegistrationData == "" {
		result.Warnings = append(result.Warnings, "registration data: not found")
	}
	if len(result.Data.Licenses) == 0 {
		result.Warnings = append(result.Warnings, "licenses: not found")
	}
	if len(result.Data.Certificates) == 0 {
		result.Warnings = append(result.Warnings, "certificates: not found")
	}

	return result
}

func (s *Service) extractRawCandidates(inputs models.TargetInput, pages []PageData) ([]models.RawCandidate, []models.DocumentReference) {
	raw := make([]models.RawCandidate, 0)
	documents := make([]models.DocumentReference, 0)

	if inn, ok := normalizeINN(inputs.INN); ok {
		raw = append(raw, models.RawCandidate{
			FieldName: "inn",
			Value:     inn,
			Source:    "user_input",
			Flags:     []string{"input"},
		})
	}

	for _, page := range pages {
		raw = append(raw, extractRawFromPage(page)...)
		docRaw, docs := detectDocumentCandidates(page)
		raw = append(raw, docRaw...)
		documents = append(documents, docs...)
	}

	return raw, documents
}

func extractRawFromPage(page PageData) []models.RawCandidate {
	raw := make([]models.RawCandidate, 0)
	authoritative := page.PageType == "legal" || page.PageType == "requisites" || page.PageType == "privacy" || page.PageType == "terms"

	add := func(field, value, source string, flags ...string) {
		value = cleanCandidateString(value)
		if value == "" {
			return
		}
		raw = append(raw, models.RawCandidate{
			FieldName: field,
			Value:     value,
			PageURL:   page.URL,
			PageType:  page.PageType,
			Source:    source,
			Flags:     flags,
		})
	}

	if legalNames := extractLegalNames(page.Title); len(legalNames) > 0 {
		for _, item := range legalNames {
			add("full_legal_name", item, "title")
		}
	}

	if page.Description != "" && authoritative {
		for _, item := range extractLegalNames(page.Description) {
			add("full_legal_name", item, "meta")
		}
	}

	for _, block := range page.JSONLD {
		extractFromJSONLD(block, page, &raw)
	}

	for _, line := range extractINNCandidates(page) {
		add("inn", line, "text")
	}
	for _, line := range extractOGRNCandidates(page) {
		add("ogrn", line, "text")
	}
	for _, line := range extractLegalNameLines(page) {
		add("full_legal_name", line, "text")
	}
	for _, line := range extractRegistrationDateCandidates(page) {
		add("registration_date", line, "text")
	}
	for _, line := range extractRegistrationDataCandidates(page) {
		add("registration_data", line, "text")
	}
	for _, line := range extractAddressCandidates(page) {
		add("office_address", line, "text")
	}
	for _, line := range extractBranchCandidates(page) {
		add("branch", line, "text")
	}
	for _, line := range extractSubsidiaryCandidates(page) {
		add("subsidiary", line, "text")
	}
	for _, line := range extractActivityCandidates(page) {
		add("activity", line, "text")
	}
	for _, line := range extractComplianceTextCandidates(page) {
		add("certificate", line, "text")
	}
	for _, line := range extractLicenseTextCandidates(page) {
		add("license", line, "text")
	}

	return raw
}

func extractFromJSONLD(block map[string]any, page PageData, raw *[]models.RawCandidate) {
	add := func(field, value string) {
		value = cleanCandidateString(value)
		if value == "" {
			return
		}
		*raw = append(*raw, models.RawCandidate{
			FieldName: field,
			Value:     value,
			PageURL:   page.URL,
			PageType:  page.PageType,
			Source:    "jsonld",
		})
	}

	for _, key := range []string{"legalName", "name", "alternateName"} {
		if value, ok := block[key].(string); ok {
			add("full_legal_name", value)
		}
	}
	for _, key := range []string{"taxID", "vatID"} {
		if value, ok := block[key].(string); ok {
			add("inn", value)
		}
	}
	for _, key := range []string{"foundingDate", "foundingdate"} {
		if value, ok := block[key].(string); ok {
			add("registration_date", value)
		}
	}
	if value, ok := block["description"].(string); ok && looksLikeActivityText(value) {
		add("activity", value)
	}
	if address, ok := block["address"].(map[string]any); ok {
		addressParts := make([]string, 0)
		for _, key := range []string{"streetAddress", "postalCode", "addressLocality", "addressRegion", "addressCountry"} {
			if value, ok := address[key].(string); ok && strings.TrimSpace(value) != "" {
				addressParts = append(addressParts, value)
			}
		}
		if len(addressParts) > 0 {
			add("office_address", strings.Join(addressParts, ", "))
		}
	}
}

func extractLegalNameLines(page PageData) []string {
	lines := make([]string, 0)
	for _, line := range append([]string{page.Title, page.Description}, page.Lines...) {
		if match := reInlineLegalName.FindStringSubmatch(line); len(match) > 1 {
			lines = append(lines, match[1])
		}
		for _, item := range extractLegalNames(line) {
			lines = append(lines, item)
		}
	}
	return util.UniqueStrings(lines)
}

func extractINNCandidates(page PageData) []string {
	out := make([]string, 0)
	for _, line := range page.Lines {
		if match := reInlineINN.FindStringSubmatch(line); len(match) > 1 {
			out = append(out, match[1])
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "инн") || page.SourceType == "public_registry" {
			out = append(out, reLikelyINN.FindAllString(line, -1)...)
		}
	}
	return util.UniqueStrings(out)
}

func extractOGRNCandidates(page PageData) []string {
	out := make([]string, 0)
	for _, line := range page.Lines {
		if match := reInlineOGRN.FindStringSubmatch(line); len(match) > 1 {
			out = append(out, match[1])
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "огрн") || page.SourceType == "public_registry" {
			out = append(out, reLikelyOGRN.FindAllString(line, -1)...)
		}
	}
	return util.UniqueStrings(out)
}

func extractRegistrationDateCandidates(page PageData) []string {
	keywords := []string{"основан", "зарегистр", "дата регистрации", "founded", "established", "since"}
	out := make([]string, 0)
	for _, line := range append([]string{page.BodyText}, page.Lines...) {
		lower := strings.ToLower(line)
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				if match := reDateValue.FindString(line); match != "" {
					out = append(out, match)
				}
			}
		}
	}
	return util.UniqueStrings(out)
}

func extractRegistrationDataCandidates(page PageData) []string {
	keywords := []string{"реквизит", "legal details", "company details", "registration details", "кпп", "ogrn", "огрн", "инн"}
	out := make([]string, 0)
	for _, line := range page.Lines {
		lower := strings.ToLower(line)
		matchCount := 0
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				matchCount++
			}
		}
		if matchCount >= 2 {
			out = append(out, line)
		}
	}
	return util.UniqueStrings(out)
}

func extractAddressCandidates(page PageData) []string {
	out := make([]string, 0)
	for _, line := range page.Lines {
		if match := reInlineAddress.FindStringSubmatch(line); len(match) > 1 {
			out = append(out, match[1])
			continue
		}
		if reAddressKeywords.MatchString(line) && reAddressSignals.MatchString(line) {
			out = append(out, line)
		}
	}
	for _, link := range page.Links {
		lower := strings.ToLower(link.Text + " " + link.URL)
		if strings.Contains(lower, "map") || strings.Contains(lower, "maps") || strings.Contains(lower, "карта") {
			if reAddressKeywords.MatchString(link.Text) {
				out = append(out, link.Text)
			}
		}
	}
	return util.UniqueStrings(out)
}

func extractBranchCandidates(page PageData) []string {
	keywords := []string{"branch", "office", "филиал", "представительство"}
	return filterEntityCandidates(extractKeywordLines(page.Lines, keywords))
}

func extractSubsidiaryCandidates(page PageData) []string {
	keywords := []string{"subsidiary", "affiliate", "дочерн", "group company", "группа компаний"}
	return filterEntityCandidates(extractKeywordLines(page.Lines, keywords))
}

func extractActivityCandidates(page PageData) []string {
	out := make([]string, 0)
	for _, candidate := range append([]string{page.Title, page.Description, page.BodyText}, page.Lines...) {
		if looksLikeActivityText(candidate) {
			out = append(out, candidate)
		}
	}
	for _, link := range page.Links {
		if looksLikeActivityText(link.Text) {
			out = append(out, link.Text)
		}
		if strings.Contains(strings.ToLower(link.URL), "/services/") || strings.Contains(strings.ToLower(link.URL), "/industr") {
			out = append(out, link.Text)
		}
	}
	return util.UniqueStrings(out)
}

func extractComplianceTextCandidates(page PageData) []string {
	keywords := []string{"certificate", "сертификат", "iso", "accredit", "аккредита"}
	return filterDocumentSummaryCandidates(extractKeywordLines(page.Lines, keywords))
}

func extractLicenseTextCandidates(page PageData) []string {
	keywords := []string{"license", "licence", "лиценз", "quality"}
	return filterDocumentSummaryCandidates(extractKeywordLines(page.Lines, keywords))
}

func extractKeywordLines(lines []string, keywords []string) []string {
	out := make([]string, 0)
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "client") || strings.Contains(lower, "partner") || strings.Contains(lower, "portfolio") || strings.Contains(lower, "клиент") || strings.Contains(lower, "партнер") {
			continue
		}
		for _, keyword := range keywords {
			if strings.Contains(lower, keyword) {
				out = append(out, line)
				break
			}
		}
	}
	return util.UniqueStrings(out)
}

func filterEntityCandidates(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		lower := strings.ToLower(value)
		if isLabelOnly(value) ||
			strings.Contains(lower, "client") ||
			strings.Contains(lower, "partner") ||
			strings.Contains(lower, "portfolio") ||
			strings.Contains(lower, "project") ||
			strings.Contains(lower, "еще ") ||
			strings.Contains(lower, "ещё ") {
			continue
		}
		if !(reLegalEntity.MatchString(value) || reAddressSignals.MatchString(value) || strings.Contains(lower, "branch") || strings.Contains(lower, "subsidiary") || strings.Contains(lower, "филиал") || strings.Contains(lower, "дочер")) {
			continue
		}
		out = append(out, value)
	}
	return util.UniqueStrings(out)
}

func filterDocumentSummaryCandidates(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		lower := strings.ToLower(value)
		if isLabelOnly(value) ||
			strings.Contains(lower, "отсутств") ||
			strings.Contains(lower, "не найден") ||
			strings.Contains(lower, "сведения") ||
			strings.Contains(lower, "детально") ||
			strings.Contains(lower, "подробнее") ||
			strings.Contains(lower, "javascript") {
			continue
		}
		out = append(out, value)
	}
	return util.UniqueStrings(out)
}

func looksLikeActivityText(value string) bool {
	services, industries := classifyActivities(value)
	return len(services) > 0 || len(industries) > 0
}

func extractLegalNames(value string) []string {
	value = cleanCandidateString(value)
	if value == "" {
		return nil
	}

	lower := strings.ToLower(value)
	if idx := strings.Index(lower, "полное наименование"); idx >= 0 {
		if colon := strings.Index(value[idx:], ":"); colon >= 0 {
			value = cleanCandidateString(value[idx+colon+1:])
		}
	}

	candidates := make([]string, 0)
	patterns := []string{
		`(?i)\b(?:ООО|АО|ПАО|ОАО|ЗАО|ИП)\s+[«"][^"»]{2,140}[»"]`,
		`(?i)\b(?:ООО|АО|ПАО|ОАО|ЗАО|ИП)\s+[A-ZА-Я0-9][^|]{2,160}`,
		`(?i)\b(?:LLC|LTD|INC|CORP(?:ORATION)?)\s+[A-Z0-9][^|]{2,160}`,
	}
	for _, pattern := range patterns {
		re := regexp.MustCompile(pattern)
		candidates = append(candidates, re.FindAllString(value, -1)...)
	}
	if len(candidates) == 0 {
		for _, prefix := range []string{"ООО ", "АО ", "ПАО ", "ОАО ", "ЗАО ", "ИП ", "LLC ", "LTD ", "INC "} {
			if strings.Contains(strings.ToUpper(value), prefix) {
				candidates = append(candidates, value)
				break
			}
		}
	}
	if len(candidates) == 0 && reLegalEntity.MatchString(value) {
		candidates = append(candidates, value)
	}
	return util.UniqueStrings(candidates)
}

func (s *Service) applyFindings(result *models.ProfileModuleResult) {
	for _, finding := range result.Findings {
		switch finding.FieldName {
		case "full_legal_name":
			if result.Data.FullLegalName == "" {
				result.Data.FullLegalName = finding.Value
			}
		case "inn":
			if result.Data.INN == "" {
				result.Data.INN = finding.Value
			}
		case "ogrn":
			if result.Data.OGRN == "" {
				result.Data.OGRN = finding.Value
			}
		case "registration_data":
			if result.Data.RegistrationData == "" {
				result.Data.RegistrationData = finding.Value
			}
		case "registration_date":
			if result.Data.RegistrationDate == "" {
				result.Data.RegistrationDate = finding.Value
			}
		case "office_address":
			result.Data.OfficeAddresses = append(result.Data.OfficeAddresses, finding.Value)
		case "branch":
			result.Data.Branches = append(result.Data.Branches, finding.Value)
		case "subsidiary":
			result.Data.Subsidiaries = append(result.Data.Subsidiaries, finding.Value)
		case "activity_service":
			result.Data.Activities.Services = append(result.Data.Activities.Services, finding.Value)
		case "activity_industry":
			result.Data.Activities.Industries = append(result.Data.Activities.Industries, finding.Value)
		case "license":
			result.Data.Licenses = append(result.Data.Licenses, finding.Value)
		case "certificate":
			result.Data.Certificates = append(result.Data.Certificates, finding.Value)
		}
	}

	result.Data.OfficeAddresses = util.UniqueStrings(result.Data.OfficeAddresses)
	result.Data.Branches = util.UniqueStrings(result.Data.Branches)
	result.Data.Subsidiaries = util.UniqueStrings(result.Data.Subsidiaries)
	result.Data.Activities.Services = util.UniqueStrings(result.Data.Activities.Services)
	result.Data.Activities.Industries = util.UniqueStrings(result.Data.Activities.Industries)
	result.Data.Licenses = util.UniqueStrings(result.Data.Licenses)
	result.Data.Certificates = util.UniqueStrings(result.Data.Certificates)

	result.Data.OfficeAddresses = sanitizeAddresses(result.Data.OfficeAddresses)
	result.Data.Branches = sanitizeEntityList(result.Data.Branches)
	result.Data.Subsidiaries = sanitizeEntityList(result.Data.Subsidiaries)
	result.Data.Licenses = sanitizeDocumentList(result.Data.Licenses)
	result.Data.Certificates = sanitizeDocumentList(result.Data.Certificates)
}

func dedupeDocuments(items []models.DocumentReference) []models.DocumentReference {
	set := make(map[string]models.DocumentReference)
	for _, item := range items {
		key := strings.ToLower(strings.TrimSpace(item.URL))
		if key == "" {
			continue
		}
		if existing, ok := set[key]; ok {
			if existing.Label == "" && item.Label != "" {
				set[key] = item
			}
			continue
		}
		set[key] = item
	}
	out := make([]models.DocumentReference, 0, len(set))
	for _, item := range set {
		out = append(out, item)
	}
	return out
}

func (s *Service) String() string {
	return fmt.Sprintf("profile service with timeout %s", s.config.Timeout)
}

func fillDerivedRegistrationData(result *models.ProfileModuleResult) {
	if normalized, ok := normalizeRegistrationData(result.Data.RegistrationData); ok {
		result.Data.RegistrationData = normalized
		return
	}
	result.Data.RegistrationData = ""
}

func sanitizeAddresses(values []string) []string {
	set := make(map[string]string)
	for _, value := range values {
		if normalized, ok := normalizeAddress(value); ok {
			key := canonicalAddressKey(normalized)
			if existing, ok := set[key]; ok {
				if len(normalized) < len(existing) {
					set[key] = normalized
				}
				continue
			}
			set[key] = normalized
		}
	}
	out := make([]string, 0, len(set))
	for _, value := range set {
		out = append(out, value)
	}
	return util.UniqueStrings(out)
}

func canonicalAddressKey(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(
		",", " ",
		".", " ",
		"-", " ",
		`"`, " ",
		`'`, " ",
		"«", " ",
		"»", " ",
		"(", " ",
		")", " ",
	)
	value = replacer.Replace(value)
	tokens := strings.Fields(value)
	filtered := make([]string, 0, len(tokens))
	stopwords := map[string]struct{}{
		"обл": {}, "область": {}, "г": {}, "город": {}, "ru": {}, "россия": {}, "russia": {},
		"ростовская": {}, // drop region adjectives so same street/building form collapses
	}
	for _, token := range tokens {
		if _, ok := stopwords[token]; ok {
			continue
		}
		filtered = append(filtered, token)
	}
	sort.Strings(filtered)
	return strings.Join(filtered, "|")
}

func sanitizeEntityList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if normalized, ok := normalizeBranchOrSubsidiary(value); ok {
			out = append(out, normalized)
		}
	}
	return util.UniqueStrings(out)
}

func sanitizeDocumentList(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if normalized, ok := normalizeDocumentLabel(value); ok {
			out = append(out, normalized)
		}
	}
	return util.UniqueStrings(out)
}
