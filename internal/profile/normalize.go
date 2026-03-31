package profile

import (
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

var (
	reJSONLike          = regexp.MustCompile(`[{}` + "`" + `]|"\s*:|:\s*[\[{"]`)
	reHTMLLeftovers     = regexp.MustCompile(`(?i)<script|</script|<style|</style|<div|</div|<span|</span|<img|</img`)
	reLegalEntity       = regexp.MustCompile(`(?i)\b(?:ооо|ао|пао|оао|зао|ип|llc|ltd|inc|corp(?:oration)?)\b`)
	reLikelyOGRN        = regexp.MustCompile(`\b\d{13}\b`)
	reLikelyINN         = regexp.MustCompile(`\b\d{10,12}\b`)
	reLikelyKPP         = regexp.MustCompile(`\b\d{9}\b`)
	reDateValue         = regexp.MustCompile(`\b(?:\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})\b`)
	reAddressKeywords   = regexp.MustCompile(`(?i)\b(?:address|office|офис|адрес|street|st\.|ул\.|улица|проспект|пр-кт|avenue|road|rd\.|бульвар|бул\.|building|дом|д\.|suite|оф\.)\b`)
	reFrontMatterNoise  = regexp.MustCompile(`(?i)\b(?:slug|attributes|previewdescription|skillimage|hydration|payload|frontend|webpack|__next|apollo|gatsby|uploads|services/|image":|title":|description":|data":|id":|webvisor|window\.location|const\s+[a-z_]+|function\s*\(|match\(/)\b`)
	reDocumentExtension = regexp.MustCompile(`(?i)\.(pdf|docx?|rtf)$`)
	reAddressSignals    = regexp.MustCompile(`(?i)\b(?:\d{5,6}|г\.|город|city|ул\.|улица|проспект|пр-кт|бульвар|бул\.|дом|д\.|building|suite|оф\.|office|street|road|avenue)\b`)
	reCapitalValue      = regexp.MustCompile(`(?i)(?:уставный капитал|authorized capital)[^0-9]{0,20}([0-9 ]+(?:[.,][0-9]+)?)`)
)

var exactLabelNoise = map[string]struct{}{
	"адрес":             {},
	"юридический адрес": {},
	"почтовый адрес":    {},
	"адрес офиса":       {},
	"адреса":            {},
	"address":           {},
	"office address":    {},
	"branches":          {},
	"branch":            {},
	"subsidiaries":      {},
	"subsidiary":        {},
	"филиалы":           {},
	"филиал":            {},
	"филиалы и представительства": {},
	"дочерние":          {},
	"дочерние компании": {},
	"дочерняя компания": {},
	"лицензии":          {},
	"лицензия":          {},
	"сертификаты":       {},
	"сертификат":        {},
	"licenses":          {},
	"license":           {},
	"certificates":      {},
	"certificate":       {},
	"сведения о лицензиях отсутствуют": {},
}

var serviceDictionary = map[string][]string{
	"mobile development":          {"mobile development", "mobile app", "ios", "android", "мобильн"},
	"web development":             {"web development", "web app", "frontend", "backend", "веб-разработ", "web-разработ"},
	"desktop development":         {"desktop development", "desktop app", "desktop"},
	"mvp / poc":                   {"mvp", "poc", "proof of concept"},
	"dedicated team":              {"dedicated team", "team extension", "выделенн", "команда"},
	"ui/ux design":                {"ui/ux", "ux/ui", "product design", "дизайн интерфейсов", "ui design", "ux design"},
	"data science":                {"data science", "data analytics", "аналитика данных"},
	"machine learning":            {"machine learning", "ml", "artificial intelligence", "ai", "машинн"},
	"custom software development": {"custom software", "software development", "разработка по", "кастомн"},
	"e-commerce solutions":        {"e-commerce", "ecommerce", "интернет-магазин"},
	"qa / testing":                {"qa", "testing", "тестирован"},
	"devops / cloud":              {"devops", "cloud", "aws", "azure", "kubernetes"},
}

var industryDictionary = map[string][]string{
	"fintech":       {"fintech", "finance", "банков", "payment", "payments"},
	"medtech":       {"medtech", "healthcare", "medical", "медицин"},
	"education":     {"education", "edtech", "обучен", "education tech"},
	"entertainment": {"entertainment", "media", "gaming", "игр"},
	"real estate":   {"real estate", "property", "недвижим"},
	"tourism":       {"tourism", "travel", "tour"},
	"oil & gas":     {"oil", "gas", "нефт", "газ"},
	"e-commerce":    {"e-commerce", "retail", "marketplace"},
	"logistics":     {"logistics", "supply chain", "доставк", "логист"},
}

func NormalizeRawCandidates(raw []models.RawCandidate) []models.NormalizedCandidate {
	out := make([]models.NormalizedCandidate, 0)
	for _, candidate := range raw {
		out = append(out, normalizeRawCandidate(candidate)...)
	}
	return dedupeNormalizedCandidates(out)
}

func normalizeRawCandidate(candidate models.RawCandidate) []models.NormalizedCandidate {
	value := cleanCandidateString(candidate.Value)
	if value == "" {
		return nil
	}
	if isGarbageCandidate(value) {
		return nil
	}

	switch candidate.FieldName {
	case "full_legal_name":
		if normalized, ok := normalizeLegalName(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, normalized, true)}
		}
	case "inn":
		if normalized, ok := normalizeINN(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, normalized, true)}
		}
	case "ogrn":
		if normalized, ok := normalizeOGRN(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, normalized, true)}
		}
	case "registration_date":
		if normalized, ok := normalizeDate(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, value, normalized, true)}
		}
	case "office_address":
		if normalized, ok := normalizeAddress(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, strings.ToLower(normalized), true)}
		}
	case "branch":
		if normalized, ok := normalizeBranchOrSubsidiary(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, strings.ToLower(normalized), true)}
		}
	case "subsidiary":
		if normalized, ok := normalizeBranchOrSubsidiary(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, strings.ToLower(normalized), true)}
		}
	case "license":
		if normalized, ok := normalizeDocumentLabel(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, strings.ToLower(normalized), true)}
		}
	case "certificate":
		if normalized, ok := normalizeDocumentLabel(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, strings.ToLower(normalized), true)}
		}
	case "registration_data":
		if normalized, ok := normalizeRegistrationData(value); ok {
			return []models.NormalizedCandidate{buildNormalized(candidate, normalized, strings.ToLower(normalized), true)}
		}
	case "activity":
		services, industries := classifyActivities(value)
		out := make([]models.NormalizedCandidate, 0, len(services)+len(industries))
		for _, item := range services {
			cloned := candidate
			cloned.FieldName = "activity_service"
			out = append(out, buildNormalized(cloned, item, strings.ToLower(item), true))
		}
		for _, item := range industries {
			cloned := candidate
			cloned.FieldName = "activity_industry"
			out = append(out, buildNormalized(cloned, item, strings.ToLower(item), true))
		}
		return out
	}

	return nil
}

func buildNormalized(raw models.RawCandidate, value, normalized string, clean bool) models.NormalizedCandidate {
	authoritative := raw.PageType == "legal" || raw.PageType == "requisites" || raw.PageType == "privacy" || raw.PageType == "terms" || raw.PageType == "licenses" || raw.PageType == "certificates" || raw.Source == "document"
	official := raw.PageURL != "" && raw.PageType != "public_card"
	return models.NormalizedCandidate{
		FieldName:       raw.FieldName,
		Value:           value,
		NormalizedValue: normalized,
		PageURL:         raw.PageURL,
		PageType:        raw.PageType,
		Source:          raw.Source,
		Official:        official,
		Authoritative:   authoritative,
		Clean:           clean,
	}
}

func cleanCandidateString(value string) string {
	value = util.NormalizeWhitespace(value)
	value = strings.Trim(value, " ,;|:-")
	return value
}

func isGarbageCandidate(value string) bool {
	lower := strings.ToLower(cleanCandidateString(value))
	switch {
	case value == "":
		return true
	case isLabelOnly(lower):
		return true
	case reJSONLike.MatchString(value):
		return true
	case reHTMLLeftovers.MatchString(lower):
		return true
	case reFrontMatterNoise.MatchString(lower):
		return true
	case strings.Contains(lower, "/uploads/"), strings.Contains(lower, "services/"):
		return true
	case strings.Contains(lower, "window.location"), strings.Contains(lower, "webvisor:true"), strings.HasPrefix(lower, "const "):
		return true
	case len(value) > 220 && strings.Count(value, ":") >= 2:
		return true
	case strings.Count(value, "/") >= 4 && !strings.Contains(value, "http"):
		return true
	}
	return false
}

func isLabelOnly(value string) bool {
	value = cleanCandidateString(value)
	value = strings.Trim(value, ".:;,- ")
	if value == "" {
		return true
	}
	if _, ok := exactLabelNoise[strings.ToLower(value)]; ok {
		return true
	}
	if strings.HasPrefix(strings.ToLower(value), "еще ") || strings.HasPrefix(strings.ToLower(value), "ещё ") {
		return true
	}
	return false
}

func normalizeLegalName(value string) (string, bool) {
	value = cleanCandidateString(value)
	lower := strings.ToLower(value)
	if !(strings.Contains(lower, "ооо") ||
		strings.Contains(lower, "ао") ||
		strings.Contains(lower, "пао") ||
		strings.Contains(lower, "оао") ||
		strings.Contains(lower, "зао") ||
		strings.Contains(lower, "ип") ||
		strings.Contains(lower, "llc") ||
		strings.Contains(lower, "ltd") ||
		strings.Contains(lower, "inc")) {
		return "", false
	}
	if isGarbageCandidate(value) || len(value) < 5 || len(value) > 180 {
		return "", false
	}
	return value, true
}

func normalizeINN(value string) (string, bool) {
	value = util.NormalizeDigits(value)
	if len(value) != 10 && len(value) != 12 {
		return "", false
	}
	if !validateINN(value) {
		return "", false
	}
	return value, true
}

func normalizeOGRN(value string) (string, bool) {
	value = util.NormalizeDigits(value)
	if len(value) != 13 {
		return "", false
	}
	if !validateOGRN(value) {
		return "", false
	}
	return value, true
}

func normalizeDate(value string) (string, bool) {
	value = cleanCandidateString(value)
	match := reDateValue.FindString(value)
	if match == "" {
		match = value
	}
	layouts := []string{
		"2006-01-02",
		"02.01.2006",
		"2.1.2006",
		"02-01-2006",
		"2-1-2006",
		"02/01/2006",
		"2/1/2006",
	}
	for _, layout := range layouts {
		if ts, err := time.Parse(layout, match); err == nil {
			return ts.Format("2006-01-02"), true
		}
	}
	return "", false
}

func normalizeAddress(value string) (string, bool) {
	value = cleanCandidateString(value)
	if len(value) < 10 || len(value) > 220 {
		return "", false
	}
	lower := strings.ToLower(value)
	if isGarbageCandidate(value) || isLabelOnly(value) {
		return "", false
	}
	if !(reAddressKeywords.MatchString(value) || reAddressSignals.MatchString(value) || strings.Contains(lower, "адрес")) {
		return "", false
	}
	cleaned := stripFieldPrefix(value, []string{"адрес", "юридический адрес", "почтовый адрес", "office address", "registered address", "legal address", "address"})
	cleaned = strings.Trim(cleaned, `'"`)
	if isLabelOnly(cleaned) {
		return "", false
	}
	cleanLower := strings.ToLower(cleaned)
	if strings.Contains(cleanLower, "для переписки") || strings.Contains(cleanLower, "correspondence") {
		return "", false
	}
	if regexp.MustCompile(`(?i)^[a-zа-я]:`).MatchString(cleaned) {
		return "", false
	}
	cleaned = strings.TrimSuffix(cleaned, ", RU")
	cleaned = strings.TrimSuffix(cleaned, ", ru")
	if !reAddressSignals.MatchString(cleaned) || (!strings.ContainsAny(cleaned, "0123456789") && !strings.Contains(cleanLower, ",") && !strings.Contains(cleanLower, "ростов") && !strings.Contains(cleanLower, "moscow") && !strings.Contains(cleanLower, "санкт") && !strings.Contains(cleanLower, "city")) {
		return "", false
	}
	return cleaned, true
}

func normalizeBranchOrSubsidiary(value string) (string, bool) {
	value = cleanCandidateString(value)
	if len(value) < 5 || len(value) > 180 || isGarbageCandidate(value) || isLabelOnly(value) {
		return "", false
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "client") || strings.Contains(lower, "partner") || strings.Contains(lower, "portfolio") || strings.Contains(lower, "project") || strings.Contains(lower, "смотреть все") || strings.Contains(lower, "все филиалы") || strings.Contains(lower, "в регионе") || regexp.MustCompile(`(?i)\b\d+\s+филиал`).MatchString(value) {
		return "", false
	}
	cleaned := stripFieldPrefix(value, []string{"branch", "branches", "subsidiary", "subsidiaries", "филиал", "филиалы", "дочерняя компания", "дочерние компании", "филиалы и представительства"})
	if isLabelOnly(cleaned) {
		return "", false
	}
	cleanLower := strings.ToLower(cleaned)
	if !(reLegalEntity.MatchString(cleaned) || reAddressSignals.MatchString(cleaned) || strings.Contains(cleanLower, "branch office") || strings.Contains(cleanLower, "subsidiary") || strings.Contains(cleanLower, "дочер")) {
		return "", false
	}
	return cleaned, true
}

func normalizeDocumentLabel(value string) (string, bool) {
	value = cleanCandidateString(value)
	if value == "" || isGarbageCandidate(value) || isLabelOnly(value) {
		return "", false
	}
	if strings.HasPrefix(strings.ToLower(value), "http") {
		u := strings.TrimSpace(value)
		base := path.Base(u)
		base = strings.TrimSuffix(base, path.Ext(base))
		base = strings.ReplaceAll(base, "-", " ")
		base = strings.ReplaceAll(base, "_", " ")
		value = util.NormalizeWhitespace(base)
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "отсутств") || strings.Contains(lower, "not found") || strings.Contains(lower, "сведения") {
		return "", false
	}
	value = stripFieldPrefix(value, []string{"license", "licenses", "licence", "certificate", "certificates", "лицензия", "лицензии", "сертификат", "сертификаты"})
	if isLabelOnly(value) {
		return "", false
	}
	if len(value) < 3 || len(value) > 180 {
		return "", false
	}
	return value, true
}

func normalizeRegistrationData(value string) (string, bool) {
	value = cleanCandidateString(value)
	if isGarbageCandidate(value) || len(value) < 8 || len(value) > 220 {
		return "", false
	}
	lower := strings.ToLower(value)
	if strings.Contains(lower, "official website") || isLabelOnly(value) {
		return "", false
	}
	requiredTokens := 0
	for _, token := range []string{"инн", "огрн", "кпп", "ogrn", "tax", "registration"} {
		if strings.Contains(lower, token) {
			requiredTokens++
		}
	}
	if requiredTokens == 0 && len(reLikelyINN.FindAllString(value, -1)) == 0 && len(reLikelyOGRN.FindAllString(value, -1)) == 0 {
		return "", false
	}
	if requiredTokens < 2 && len(reLikelyINN.FindAllString(value, -1)) == 0 && len(reLikelyOGRN.FindAllString(value, -1)) == 0 {
		return "", false
	}
	parts := make([]string, 0, 4)
	if inns := reLikelyINN.FindAllString(value, -1); len(inns) > 0 {
		parts = append(parts, "ИНН "+inns[0])
	}
	if kpps := reLikelyKPP.FindAllString(value, -1); len(kpps) > 0 {
		parts = append(parts, "КПП "+kpps[len(kpps)-1])
	}
	if ogrns := reLikelyOGRN.FindAllString(value, -1); len(ogrns) > 0 {
		parts = append(parts, "ОГРН "+ogrns[0])
	}
	if capital := reCapitalValue.FindStringSubmatch(value); len(capital) > 1 {
		parts = append(parts, "уставный капитал "+util.NormalizeWhitespace(capital[1])+" руб.")
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(util.UniqueStrings(parts), "; "), true
}

func stripFieldPrefix(value string, prefixes []string) string {
	value = cleanCandidateString(value)
	lower := strings.ToLower(value)
	for _, prefix := range prefixes {
		prefixLower := strings.ToLower(prefix)
		if strings.HasPrefix(lower, prefixLower+":") {
			return cleanCandidateString(value[len(prefix)+1:])
		}
		if strings.HasPrefix(lower, prefixLower+" -") {
			return cleanCandidateString(value[len(prefix)+2:])
		}
		if strings.EqualFold(value, prefix) {
			return ""
		}
	}
	return value
}

func classifyActivities(value string) ([]string, []string) {
	lower := strings.ToLower(cleanCandidateString(value))
	if lower == "" || isGarbageCandidate(lower) {
		return nil, nil
	}
	services := make([]string, 0)
	industries := make([]string, 0)
	for canonical, patterns := range serviceDictionary {
		for _, pattern := range patterns {
			if strings.Contains(lower, pattern) {
				services = append(services, canonical)
				break
			}
		}
	}
	for canonical, patterns := range industryDictionary {
		for _, pattern := range patterns {
			if strings.Contains(lower, pattern) {
				industries = append(industries, canonical)
				break
			}
		}
	}
	return util.UniqueStrings(services), util.UniqueStrings(industries)
}

func detectDocumentCandidates(page PageData) ([]models.RawCandidate, []models.DocumentReference) {
	raw := make([]models.RawCandidate, 0)
	docs := make([]models.DocumentReference, 0)
	for _, link := range page.Links {
		lowerURL := strings.ToLower(link.URL)
		lowerText := strings.ToLower(link.Text)
		if !reDocumentExtension.MatchString(lowerURL) && !looksLikeDocumentLink(lowerText, lowerURL) {
			continue
		}

		docType := "document"
		fieldName := ""
		switch {
		case strings.Contains(lowerText, "license"), strings.Contains(lowerText, "licence"), strings.Contains(lowerText, "лиценз"):
			docType = "license"
			fieldName = "license"
		case strings.Contains(lowerText, "certificate"), strings.Contains(lowerText, "сертификат"), strings.Contains(lowerText, "iso"), strings.Contains(lowerText, "accredit"):
			docType = "certificate"
			fieldName = "certificate"
		case page.PageType == "licenses":
			docType = "license"
			fieldName = "license"
		case page.PageType == "certificates" || page.PageType == "compliance":
			docType = "certificate"
			fieldName = "certificate"
		}

		label := link.Text
		if label == "" {
			label = link.URL
		}
		docs = append(docs, models.DocumentReference{
			URL:    link.URL,
			Label:  cleanCandidateString(label),
			Type:   docType,
			Source: page.URL,
		})
		if fieldName != "" {
			raw = append(raw, models.RawCandidate{
				FieldName: fieldName,
				Value:     label,
				PageURL:   page.URL,
				PageType:  page.PageType,
				Source:    "document_link",
			})
		}
	}
	return raw, docs
}

func looksLikeDocumentLink(text, target string) bool {
	lower := strings.ToLower(text + " " + target)
	keywords := []string{
		"license", "licence", "certificate", "iso", "accredit", "compliance",
		"лиценз", "сертификат", "аккред", "документ",
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return false
}

func dedupeNormalizedCandidates(items []models.NormalizedCandidate) []models.NormalizedCandidate {
	set := make(map[string]models.NormalizedCandidate)
	for _, item := range items {
		key := strings.ToLower(item.FieldName + "|" + item.NormalizedValue + "|" + item.PageType + "|" + item.PageURL)
		if _, exists := set[key]; !exists {
			set[key] = item
		}
	}
	out := make([]models.NormalizedCandidate, 0, len(set))
	for _, item := range set {
		out = append(out, item)
	}
	return out
}

func validateOGRN(value string) bool {
	if len(value) != 13 {
		return false
	}
	base, err := strconv.ParseInt(value[:12], 10, 64)
	if err != nil {
		return false
	}
	check := base % 11 % 10
	return int(value[12]-'0') == int(check)
}

func validateINN(value string) bool {
	digits := make([]int, 0, len(value))
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
		digits = append(digits, int(r-'0'))
	}

	if len(digits) == 10 {
		weights := []int{2, 4, 10, 3, 5, 9, 4, 6, 8}
		sum := 0
		for i, weight := range weights {
			sum += digits[i] * weight
		}
		return digits[9] == (sum%11)%10
	}
	if len(digits) == 12 {
		weightsA := []int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		weightsB := []int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
		sumA := 0
		for i, weight := range weightsA {
			sumA += digits[i] * weight
		}
		sumB := 0
		for i, weight := range weightsB {
			sumB += digits[i] * weight
		}
		return digits[10] == (sumA%11)%10 && digits[11] == (sumB%11)%10
	}
	return false
}
