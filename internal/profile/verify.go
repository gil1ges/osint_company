package profile

import (
	"sort"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

type candidateGroup struct {
	FieldName       string
	Value           string
	NormalizedValue string
	Evidence        []models.Evidence
	Official        bool
	Authoritative   bool
	Clean           bool
	Notes           []string
}

func BuildFinalFindings(normalized []models.NormalizedCandidate) []models.Finding {
	findings := make([]models.Finding, 0)
	singleFields := []string{
		"full_legal_name",
		"inn",
		"ogrn",
		"registration_date",
		"registration_data",
	}
	for _, field := range singleFields {
		if finding := consolidateSingleField("profile", field, filterField(normalized, field)); finding != nil {
			findings = append(findings, *finding)
		}
	}

	listFields := []string{
		"office_address",
		"branch",
		"subsidiary",
		"activity_service",
		"activity_industry",
		"license",
		"certificate",
	}
	for _, field := range listFields {
		findings = append(findings, consolidateListField("profile", field, filterField(normalized, field))...)
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].FieldName == findings[j].FieldName {
			return findings[i].Value < findings[j].Value
		}
		return findings[i].FieldName < findings[j].FieldName
	})
	return findings
}

func filterField(items []models.NormalizedCandidate, field string) []models.NormalizedCandidate {
	out := make([]models.NormalizedCandidate, 0)
	for _, item := range items {
		if item.FieldName == field {
			out = append(out, item)
		}
	}
	return out
}

func consolidateSingleField(module, field string, items []models.NormalizedCandidate) *models.Finding {
	groups := groupCandidates(items)
	if len(groups) == 0 {
		return nil
	}
	sortGroups(groups)
	primary := groups[0]
	verified, confidence := determineConfidence(primary)
	conflicts := make([]models.Conflict, 0)
	for _, item := range groups[1:] {
		conflicts = append(conflicts, models.Conflict{
			FieldName:       field,
			Value:           item.Value,
			NormalizedValue: item.NormalizedValue,
			Notes:           util.UniqueStrings(item.Notes),
			Evidence:        item.Evidence,
		})
	}

	return &models.Finding{
		FieldName:       field,
		Value:           primary.Value,
		NormalizedValue: primary.NormalizedValue,
		Module:          module,
		Verified:        verified,
		Confidence:      confidence,
		CollectedAt:     time.Now().UTC(),
		Notes:           util.UniqueStrings(primary.Notes),
		Evidence:        primary.Evidence,
		Conflicts:       conflicts,
	}
}

func consolidateListField(module, field string, items []models.NormalizedCandidate) []models.Finding {
	groups := groupCandidates(items)
	if len(groups) == 0 {
		return nil
	}
	sortGroups(groups)
	out := make([]models.Finding, 0, len(groups))
	for _, group := range groups {
		verified, confidence := determineConfidence(group)
		out = append(out, models.Finding{
			FieldName:       field,
			Value:           group.Value,
			NormalizedValue: group.NormalizedValue,
			Module:          module,
			Verified:        verified,
			Confidence:      confidence,
			CollectedAt:     time.Now().UTC(),
			Notes:           util.UniqueStrings(group.Notes),
			Evidence:        group.Evidence,
		})
	}
	return out
}

func groupCandidates(items []models.NormalizedCandidate) []candidateGroup {
	grouped := make(map[string]*candidateGroup)
	for _, item := range items {
		if !item.Clean || item.NormalizedValue == "" || isGarbageCandidate(item.Value) {
			continue
		}
		key := strings.ToLower(item.FieldName + "|" + item.NormalizedValue)
		group, exists := grouped[key]
		if !exists {
			group = &candidateGroup{
				FieldName:       item.FieldName,
				Value:           item.Value,
				NormalizedValue: item.NormalizedValue,
				Clean:           item.Clean,
			}
			grouped[key] = group
		}
		group.Official = group.Official || item.Official
		group.Authoritative = group.Authoritative || item.Authoritative
		group.Notes = append(group.Notes, item.PageType, item.Source)
		group.Evidence = append(group.Evidence, models.Evidence{
			SourceName:  "profile",
			SourceURL:   item.PageURL,
			SourceType:  item.Source,
			RetrievedAt: time.Now().UTC(),
			Method:      item.PageType,
			Snippet:     util.ClipString(item.Value, 180),
		})
	}

	out := make([]candidateGroup, 0, len(grouped))
	for _, item := range grouped {
		item.Evidence = uniqueEvidence(item.Evidence)
		item.Notes = util.UniqueStrings(item.Notes)
		out = append(out, *item)
	}
	return out
}

func determineConfidence(group candidateGroup) (bool, models.Confidence) {
	if !group.Clean || isGarbageCandidate(group.Value) {
		return false, models.ConfidenceLow
	}

	independent := independentEvidenceCount(group.Evidence)
	hasPublicCard := containsNote(group.Notes, "public_card")
	switch {
	case group.FieldName == "ogrn" && group.Authoritative:
		if independent >= 1 {
			return true, models.ConfidenceHigh
		}
		return true, models.ConfidenceMedium
	case group.FieldName == "full_legal_name" && group.Authoritative:
		if independent >= 1 {
			return true, models.ConfidenceHigh
		}
		return true, models.ConfidenceMedium
	case (group.FieldName == "license" || group.FieldName == "certificate") && (group.Authoritative || hasPublicCard):
		return true, models.ConfidenceMedium
	case (group.FieldName == "office_address" || group.FieldName == "branch" || group.FieldName == "subsidiary") && (group.Authoritative || independent >= 2):
		if independent >= 2 {
			return true, models.ConfidenceHigh
		}
		return true, models.ConfidenceMedium
	case group.Official && independent >= 2:
		return true, models.ConfidenceHigh
	case group.Official:
		return true, models.ConfidenceMedium
	case hasPublicCard:
		return false, models.ConfidenceMedium
	case independent >= 2:
		return false, models.ConfidenceMedium
	default:
		return false, models.ConfidenceLow
	}
}

func independentEvidenceCount(evidence []models.Evidence) int {
	set := make(map[string]struct{})
	for _, item := range evidence {
		pageType := strings.ToLower(item.Method)
		origin := strings.ToLower(item.SourceType)
		key := origin + "|" + pageType
		set[key] = struct{}{}
	}
	return len(set)
}

func uniqueEvidence(items []models.Evidence) []models.Evidence {
	set := make(map[string]models.Evidence)
	for _, item := range items {
		key := strings.ToLower(item.SourceURL + "|" + item.SourceType + "|" + item.Method + "|" + item.Snippet)
		if _, ok := set[key]; !ok {
			set[key] = item
		}
	}
	out := make([]models.Evidence, 0, len(set))
	for _, item := range set {
		out = append(out, item)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].SourceURL < out[j].SourceURL
	})
	return out
}

func sortGroups(items []candidateGroup) {
	sort.Slice(items, func(i, j int) bool {
		left := independentEvidenceCount(items[i].Evidence)
		right := independentEvidenceCount(items[j].Evidence)
		if left == right {
			if items[i].Authoritative != items[j].Authoritative {
				return items[i].Authoritative
			}
			if items[i].Official != items[j].Official {
				return items[i].Official
			}
			return items[i].NormalizedValue < items[j].NormalizedValue
		}
		return left > right
	})
}

func containsNote(notes []string, target string) bool {
	for _, note := range notes {
		if strings.EqualFold(note, target) {
			return true
		}
	}
	return false
}
