package models

type DocumentReference struct {
	URL    string `json:"url"`
	Label  string `json:"label,omitempty"`
	Type   string `json:"type,omitempty"`
	Source string `json:"source,omitempty"`
}

type RawCandidate struct {
	FieldName string   `json:"field_name"`
	Value     string   `json:"value"`
	PageURL   string   `json:"page_url,omitempty"`
	PageType  string   `json:"page_type,omitempty"`
	Source    string   `json:"source,omitempty"`
	Flags     []string `json:"flags,omitempty"`
}

type NormalizedCandidate struct {
	FieldName       string   `json:"field_name"`
	Value           string   `json:"value"`
	NormalizedValue string   `json:"normalized_value,omitempty"`
	PageURL         string   `json:"page_url,omitempty"`
	PageType        string   `json:"page_type,omitempty"`
	Source          string   `json:"source,omitempty"`
	Official        bool     `json:"official"`
	Authoritative   bool     `json:"authoritative"`
	Clean           bool     `json:"clean"`
	Notes           []string `json:"notes,omitempty"`
}

type ProfileActivities struct {
	Services   []string `json:"services,omitempty"`
	Industries []string `json:"industries,omitempty"`
}

type ProfileDebug struct {
	RawCandidates        []RawCandidate        `json:"raw_candidates,omitempty"`
	NormalizedCandidates []NormalizedCandidate `json:"normalized_candidates,omitempty"`
}

type ProfileData struct {
	OfficialWebsite  string              `json:"official_website,omitempty"`
	FullLegalName    string              `json:"full_legal_name,omitempty"`
	INN              string              `json:"inn,omitempty"`
	OGRN             string              `json:"ogrn,omitempty"`
	RegistrationData string              `json:"registration_data,omitempty"`
	RegistrationDate string              `json:"registration_date,omitempty"`
	OfficeAddresses  []string            `json:"office_addresses,omitempty"`
	Branches         []string            `json:"branches,omitempty"`
	Subsidiaries     []string            `json:"subsidiaries,omitempty"`
	Activities       ProfileActivities   `json:"activities"`
	Licenses         []string            `json:"licenses,omitempty"`
	Certificates     []string            `json:"certificates,omitempty"`
	PagesScanned     []string            `json:"pages_scanned,omitempty"`
	DocumentsScanned []DocumentReference `json:"documents_scanned,omitempty"`
}

type ProfileModuleResult struct {
	ModuleResult
	Data  ProfileData  `json:"data"`
	Debug ProfileDebug `json:"debug,omitempty"`
}
