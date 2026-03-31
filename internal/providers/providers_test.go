package providers

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/gorcher/osint_company/internal/util"
)

func TestParseExternalToolJSON(t *testing.T) {
	root := filepath.Join("..", "..", "testdata")

	subfinderData, err := os.ReadFile(filepath.Join(root, "subfinder.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	amassData, err := os.ReadFile(filepath.Join(root, "amass.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	whatwebData, err := os.ReadFile(filepath.Join(root, "whatweb.json"))
	if err != nil {
		t.Fatal(err)
	}

	subfinderHosts, err := ParseSubfinderJSON(subfinderData)
	if err != nil {
		t.Fatalf("ParseSubfinderJSON returned error: %v", err)
	}
	amassHosts, err := ParseAmassJSON(amassData)
	if err != nil {
		t.Fatalf("ParseAmassJSON returned error: %v", err)
	}
	whatwebTech, err := ParseWhatWebJSON(whatwebData)
	if err != nil {
		t.Fatalf("ParseWhatWebJSON returned error: %v", err)
	}

	if !slices.Equal(subfinderHosts, []string{"api.example.com", "www.example.com"}) {
		t.Fatalf("unexpected subfinder hosts: %#v", subfinderHosts)
	}
	if !slices.Equal(amassHosts, []string{"mail.example.com", "vpn.example.com"}) {
		t.Fatalf("unexpected amass hosts: %#v", amassHosts)
	}
	if !slices.Equal(whatwebTech, []string{"Cloudflare", "Nginx", "WordPress"}) {
		t.Fatalf("unexpected whatweb technologies: %#v", whatwebTech)
	}
}

func TestNormalizeHosts(t *testing.T) {
	got := NormalizeHosts("example.com", []string{
		"api.example.com",
		"API.example.com",
		"*.cdn.example.com",
		"other.net",
	})

	want := []string{"api.example.com", "cdn.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("NormalizeHosts() = %#v, want %#v", got, want)
	}
}

func TestNormalizeSubdomains(t *testing.T) {
	got := NormalizeSubdomains("example.com", []string{
		"example.com",
		"www.example.com",
		"API.example.com.",
		"other.net",
	})

	want := []string{"api.example.com", "www.example.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("NormalizeSubdomains() = %#v, want %#v", got, want)
	}
}

func TestParseProviderJSONEnrichment(t *testing.T) {
	body := []byte(`[
	  {"type":"domain","value":"api.example.com"},
	  {"ip":"203.0.113.10"},
	  {"asn":"AS12345 Example Network"},
	  {"technology":"Cloudflare"}
	]`)

	result, err := parseProviderContent("spiderfoot", "spiderfoot.json", body, "example.com")
	if err != nil {
		t.Fatalf("parseProviderContent returned error: %v", err)
	}
	if !slices.Equal(result.Subdomains, []string{"api.example.com"}) {
		t.Fatalf("unexpected subdomains: %#v", result.Subdomains)
	}
	if !slices.Equal(result.IPs, []string{"203.0.113.10"}) {
		t.Fatalf("unexpected ips: %#v", result.IPs)
	}
	if !slices.Equal(result.Technologies, []string{"Cloudflare"}) {
		t.Fatalf("unexpected technologies: %#v", result.Technologies)
	}
}

func TestParseProviderCSVEnrichment(t *testing.T) {
	body := []byte("type,value\nhost,www.example.com\nprovider,AS321 Example ISP\n")
	result, err := parseProviderContent("maltego", "maltego.csv", body, "example.com")
	if err != nil {
		t.Fatalf("parseProviderContent returned error: %v", err)
	}
	if !slices.Equal(result.Subdomains, []string{"www.example.com"}) {
		t.Fatalf("unexpected subdomains: %#v", result.Subdomains)
	}
	if len(result.ProviderHints) == 0 {
		t.Fatalf("expected provider hints, got %#v", result.ProviderHints)
	}
}

func TestParseSpiderFootExportRows(t *testing.T) {
	rows := []spiderFootExportRow{
		{
			Data:       "api.example.com",
			EventType:  "INTERNET_NAME",
			Module:     "sfp_dnsresolve",
			SourceData: "example.com",
		},
		{
			Data:       "203.0.113.10",
			EventType:  "IP_ADDRESS",
			Module:     "sfp_dnsresolve",
			SourceData: "api.example.com",
		},
		{
			Data:       "AS12345 Example Hosting Network",
			EventType:  "BGP_AS_MEMBER",
			Module:     "sfp_ir",
			SourceData: "203.0.113.10",
		},
		{
			Data:       "nginx",
			EventType:  "WEBSERVER_BANNER",
			Module:     "sfp_httpheaders",
			SourceData: "https://api.example.com",
		},
		{
			Data:       "example.com",
			EventType:  "INTERNET_NAME",
			Module:     "sfp_dnsresolve",
			SourceData: "example.com",
		},
	}

	result := parseSpiderFootExportRows("http://127.0.0.1:5001", "scan123", rows, "example.com")
	if !result.Used {
		t.Fatalf("expected spiderfoot result to be marked used")
	}
	if !slices.Equal(result.Subdomains, []string{"api.example.com"}) {
		t.Fatalf("unexpected subdomains: %#v", result.Subdomains)
	}
	if !slices.Equal(result.IPs, []string{"203.0.113.10"}) {
		t.Fatalf("unexpected ips: %#v", result.IPs)
	}
	if len(result.ProviderHints) == 0 {
		t.Fatalf("expected provider hints, got %#v", result.ProviderHints)
	}
	if !slices.Equal(result.Technologies, []string{"nginx"}) {
		t.Fatalf("unexpected technologies: %#v", result.Technologies)
	}
}

func TestCollectSpiderFootEnrichmentFromAPI(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scanlist", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/startscan", func(w http.ResponseWriter, r *http.Request) {
		usecase := r.URL.Query().Get("usecase")
		modulelist := r.URL.Query().Get("modulelist")
		if usecase == "Passive" || modulelist != "" {
			_, _ = w.Write([]byte(`["SUCCESS","scan123"]`))
			return
		}
		_, _ = w.Write([]byte(`["ERROR","Incorrect usage: no modules specified for scan."]`))
	})
	mux.HandleFunc("/scanstatus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["scan123","example.com","","","","FINISHED",{}]`))
	})
	mux.HandleFunc("/scanexportjsonmulti", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"data":"api.example.com","event_type":"INTERNET_NAME","module":"sfp_dnsresolve","source_data":"example.com","false_positive":false,"last_seen":"2026-03-31 00:00:00","scan_name":"scan","scan_target":"example.com"},{"data":"203.0.113.10","event_type":"IP_ADDRESS","module":"sfp_dnsresolve","source_data":"api.example.com","false_positive":false,"last_seen":"2026-03-31 00:00:00","scan_name":"scan","scan_target":"example.com"}]`))
	})
	mux.HandleFunc("/scanerrors", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/modules", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"name":"sfp_dnsresolve","descr":"DNS resolver"}]`))
	})

	server := newTCP4TestServer(t, mux)
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := util.NewHTTPClient(3*time.Second, "osintcli-test", logger)
	result := CollectSpiderFootEnrichment(context.Background(), client, "", server.URL, "", "example.com", "")

	if !result.Used {
		t.Fatalf("expected spiderfoot enrichment to be used")
	}
	if !slices.Equal(result.Subdomains, []string{"api.example.com"}) {
		t.Fatalf("unexpected subdomains: %#v", result.Subdomains)
	}
	if !slices.Equal(result.IPs, []string{"203.0.113.10"}) {
		t.Fatalf("unexpected ips: %#v", result.IPs)
	}
	if !hasWarning(result.Warnings, "SpiderFoot used successfully") {
		t.Fatalf("expected success warning, got %#v", result.Warnings)
	}
}

func TestCollectSpiderFootEnrichmentPartialResults(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scanlist", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/startscan", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["SUCCESS","scan123"]`))
	})
	mux.HandleFunc("/scanstatus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["scan123","example.com","","","","RUNNING",{}]`))
	})
	mux.HandleFunc("/scanexportjsonmulti", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[{"data":"api.example.com","event_type":"INTERNET_NAME","module":"sfp_dnsresolve","source_data":"example.com","false_positive":false,"last_seen":"2026-03-31 00:00:00","scan_name":"scan","scan_target":"example.com"}]`))
	})
	mux.HandleFunc("/scanerrors", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})

	server := newTCP4TestServer(t, mux)
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := util.NewHTTPClient(2*time.Second, "osintcli-test", logger)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result := CollectSpiderFootEnrichment(ctx, client, "", server.URL, "", "example.com", "")
	if !result.Used {
		t.Fatalf("expected partial spiderfoot result to be used")
	}
	if !slices.Equal(result.Subdomains, []string{"api.example.com"}) {
		t.Fatalf("expected partial spiderfoot subdomains to survive timeout, got %#v", result.Subdomains)
	}
	if !hasWarning(result.Warnings, "SpiderFoot returned partial results due to timeout") {
		t.Fatalf("expected partial warning, got %#v", result.Warnings)
	}
}

func TestCollectSpiderFootEnrichmentTimeoutWithNoUsableResults(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/scanlist", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/startscan", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["SUCCESS","scan123"]`))
	})
	mux.HandleFunc("/scanstatus", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`["scan123","example.com","","","","RUNNING",{}]`))
	})
	mux.HandleFunc("/scanexportjsonmulti", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		_, _ = w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/scanerrors", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`[]`))
	})

	server := newTCP4TestServer(t, mux)
	defer server.Close()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	client := util.NewHTTPClient(500*time.Millisecond, "osintcli-test", logger)
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	result := CollectSpiderFootEnrichment(ctx, client, "", server.URL, "", "example.com", "")
	if result.Used {
		t.Fatalf("expected no usable spiderfoot result, got %#v", result)
	}
	if !hasWarning(result.Warnings, "SpiderFoot timed out with no usable results") {
		t.Fatalf("expected timeout-with-no-results warning, got %#v", result.Warnings)
	}
}

func newTCP4TestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(handler)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on tcp4 loopback: %v", err)
	}
	server.Listener = listener
	server.Start()
	return server
}
