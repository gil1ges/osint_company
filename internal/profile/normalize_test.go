package profile

import (
	"testing"

	"github.com/gorcher/osint_company/internal/models"
)

func TestGarbageFiltering(t *testing.T) {
	values := []string{
		`{"slug":"mobile-dev","attributes":{"title":"x"}}`,
		`previewDescription: "text"`,
		`/uploads/docs/license.pdf`,
	}
	for _, value := range values {
		if !isGarbageCandidate(value) {
			t.Fatalf("expected %q to be detected as garbage", value)
		}
	}
}

func TestLegalNameExtractionAndNormalization(t *testing.T) {
	names := extractLegalNames(`Полное наименование: ООО "ЗАЗЕКС"`)
	if len(names) == 0 {
		t.Fatal("expected legal name candidate")
	}
	if normalized, ok := normalizeLegalName(names[0]); !ok || normalized == "" {
		t.Fatalf("expected normalized legal name, got %q ok=%t", normalized, ok)
	}
	if normalized, _ := normalizeLegalName(`ООО "ЗАЗЕКС"`); normalized != `ООО "ЗАЗЕКС"` {
		t.Fatalf("expected closing quote to be preserved, got %q", normalized)
	}
}

func TestOGRNExtractionAndValidation(t *testing.T) {
	if normalized, ok := normalizeOGRN("1027700132195"); !ok || normalized != "1027700132195" {
		t.Fatalf("expected valid ogrn, got %q ok=%t", normalized, ok)
	}
	if _, ok := normalizeOGRN("1234567890123"); ok {
		t.Fatal("expected invalid ogrn to be rejected")
	}
}

func TestAddressNormalization(t *testing.T) {
	value := "Адрес: 344113, Ростовская область, г. Ростов-на-Дону, б-р Комарова, зд. 28/2, оф. 32"
	normalized, ok := normalizeAddress(value)
	if !ok || normalized == "" {
		t.Fatalf("expected normalized address, got %q ok=%t", normalized, ok)
	}
}

func TestActivityNormalization(t *testing.T) {
	services, industries := classifyActivities("We provide mobile development, web development and fintech products for healthcare")
	if len(services) == 0 || len(industries) == 0 {
		t.Fatalf("expected services and industries, got %v / %v", services, industries)
	}
}

func TestDocumentDetection(t *testing.T) {
	page := PageData{
		URL:      "https://example.com/certificates",
		PageType: "certificates",
		Links: []LinkRef{
			{URL: "https://example.com/docs/iso-9001.pdf", Text: "ISO 9001 Certificate"},
			{URL: "https://example.com/docs/license.pdf", Text: "Лицензия"},
		},
	}

	raw, docs := detectDocumentCandidates(page)
	if len(raw) != 2 {
		t.Fatalf("expected 2 raw document candidates, got %d", len(raw))
	}
	if len(docs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docs))
	}
}

func TestNormalizeRawCandidates(t *testing.T) {
	raw := []models.RawCandidate{
		{FieldName: "activity", Value: `{"slug":"bad"}`},
		{FieldName: "activity", Value: "mobile development for fintech"},
	}
	normalized := NormalizeRawCandidates(raw)
	if len(normalized) == 0 {
		t.Fatal("expected non-garbage activity to survive normalization")
	}
	for _, item := range normalized {
		if isGarbageCandidate(item.Value) {
			t.Fatalf("garbage survived normalization: %#v", item)
		}
	}
}

func TestBranchSubsidiaryFiltering(t *testing.T) {
	values := filterEntityCandidates([]string{
		"Branch office in Moscow",
		"Client portfolio for partner companies",
		"Subsidiary ООО Ромашка",
	})
	if len(values) != 2 {
		t.Fatalf("expected 2 filtered values, got %v", values)
	}
}

func TestRegistrationDataNormalizationRejectsFakeWebsiteValue(t *testing.T) {
	if _, ok := normalizeRegistrationData("official website https://zuzex.ru"); ok {
		t.Fatal("expected fake registration data to be rejected")
	}
	if normalized, ok := normalizeRegistrationData("ИНН/КПП 6161057898 616101001 Уставный капитал 10 000 руб."); !ok || normalized == "" {
		t.Fatalf("expected real registration data to survive, got %q ok=%t", normalized, ok)
	}
}

func TestLabelOnlyValuesAreRejected(t *testing.T) {
	if _, ok := normalizeBranchOrSubsidiary("Филиалы"); ok {
		t.Fatal("expected branch label to be rejected")
	}
	if _, ok := normalizeDocumentLabel("Лицензии"); ok {
		t.Fatal("expected document label to be rejected")
	}
	if _, ok := normalizeDocumentLabel("Сведения о лицензиях отсутствуют"); ok {
		t.Fatal("expected absence summary to be rejected")
	}
}

func TestAddressRequiresRealSignals(t *testing.T) {
	if _, ok := normalizeAddress("Адрес"); ok {
		t.Fatal("expected address label to be rejected")
	}
	if _, ok := normalizeAddress("Office address"); ok {
		t.Fatal("expected weak office label to be rejected")
	}
}

func TestRejectJSAndSummaryDocumentNoise(t *testing.T) {
	if _, ok := normalizeDocumentLabel("const isOurSite = window.location.hostname.match(/\\.rusprofile\\.ru$/)"); ok {
		t.Fatal("expected js fragment to be rejected")
	}
	if _, ok := normalizeDocumentLabel("webvisor:true"); ok {
		t.Fatal("expected tracking fragment to be rejected")
	}
}

func TestRejectBranchSummaryPhrases(t *testing.T) {
	values := []string{
		"Смотреть все филиалы и представительства",
		"У ООО \"Зазекс\" 1 филиал в 1 регионе России.",
		"Филиалы и представительства",
	}
	for _, value := range values {
		if _, ok := normalizeBranchOrSubsidiary(value); ok {
			t.Fatalf("expected branch summary to be rejected: %q", value)
		}
	}
}

func TestAddressCleanupRejectsMalformedFragments(t *testing.T) {
	values := []string{
		"'344113, Ростовская область, г Ростов-На-Дону, б-р Комарова, зд. 28/2, ком. 32д'",
		"обл. Ростовская, г. Ростов-На-Дону, б-р Комарова, зд. 28/2, ком. 32д, 344113, RU",
		"для переписки 420021, Республика Татарстан, г. Казань, а/я 263, ООО «БизБренд»",
		"у: 344092, Ростовская область, город Ростов-на-Дону, пр-кт Королева, д.5 к.3, кв.7б.",
	}

	got := sanitizeAddresses(values)
	if len(got) != 1 {
		t.Fatalf("expected one cleaned company address, got %#v", got)
	}
}
