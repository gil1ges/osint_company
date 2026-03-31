package models

type DNSRecords struct {
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	MX    []string `json:"mx,omitempty"`
	NS    []string `json:"ns,omitempty"`
	TXT   []string `json:"txt,omitempty"`
	CNAME []string `json:"cname,omitempty"`
}

type TLSCertificate struct {
	Issuer       string   `json:"issuer,omitempty"`
	Subject      string   `json:"subject,omitempty"`
	SerialNumber string   `json:"serial_number,omitempty"`
	SANs         []string `json:"sans,omitempty"`
	ValidFrom    string   `json:"valid_from,omitempty"`
	ValidTo      string   `json:"valid_to,omitempty"`
}

type HTTPDetails struct {
	HomepageURL   string            `json:"homepage_url,omitempty"`
	FinalURL      string            `json:"final_url,omitempty"`
	Title         string            `json:"title,omitempty"`
	Description   string            `json:"description,omitempty"`
	Headers       map[string]string `json:"headers,omitempty"`
	Cookies       []string          `json:"cookies,omitempty"`
	MetaGenerator string            `json:"meta_generator,omitempty"`
	RobotsURL     string            `json:"robots_url,omitempty"`
	RobotsPreview string            `json:"robots_preview,omitempty"`
	SitemapURL    string            `json:"sitemap_url,omitempty"`
}

type WaybackSnapshot struct {
	Timestamp   string `json:"timestamp"`
	OriginalURL string `json:"original_url"`
	ArchiveURL  string `json:"archive_url"`
	StatusCode  string `json:"status_code,omitempty"`
}

type PortFinding struct {
	IP        string `json:"ip"`
	Port      int    `json:"port"`
	Transport string `json:"transport,omitempty"`
	Product   string `json:"product,omitempty"`
	Source    string `json:"source"`
	Notes     string `json:"notes,omitempty"`
}

type DigitalFootprintData struct {
	OfficialWebsite string            `json:"official_website,omitempty"`
	Domain          string            `json:"domain,omitempty"`
	DomainDiscovery string            `json:"domain_discovery,omitempty"`
	ProvidersUsed   []string          `json:"providers_used,omitempty"`
	Subdomains      []string          `json:"subdomains,omitempty"`
	IPs             []string          `json:"ips,omitempty"`
	ProviderHints   []string          `json:"provider_hints,omitempty"`
	CDN             string            `json:"cdn,omitempty"`
	DNS             DNSRecords        `json:"dns"`
	Technologies    []string          `json:"technologies,omitempty"`
	TLS             *TLSCertificate   `json:"tls,omitempty"`
	HTTP            *HTTPDetails      `json:"http,omitempty"`
	Wayback         []WaybackSnapshot `json:"wayback,omitempty"`
	Ports           []PortFinding     `json:"ports,omitempty"`
}

type DigitalFootprintModuleResult struct {
	ModuleResult
	Data DigitalFootprintData `json:"data"`
}
