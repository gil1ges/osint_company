package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

type subfinderRecord struct {
	Host    string   `json:"host"`
	Input   string   `json:"input"`
	Sources []string `json:"sources"`
}

func ParseSubfinderJSON(data []byte) ([]string, error) {
	records, err := ParseJSONLines[subfinderRecord](data)
	if err != nil {
		return nil, err
	}

	hosts := make([]string, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.Host) != "" {
			hosts = append(hosts, record.Host)
		}
	}
	return NormalizeHosts("", hosts), nil
}

func RunSubfinder(ctx context.Context, domain string) ([]string, *models.SourceError) {
	if !util.CommandExists("subfinder") {
		err := ToolUnavailableError("subfinder")
		return nil, &err
	}

	result, err := util.RunCommand(ctx, "subfinder", "-silent", "-all", "-d", domain, "-oJ")
	if err != nil {
		sourceErr := WrapError("subfinder", "tool", "enumerate_subdomains", "", err)
		return nil, &sourceErr
	}

	hosts, err := ParseSubfinderJSON([]byte(result.Stdout))
	if err != nil {
		sourceErr := WrapError("subfinder", "tool", "parse_json", "", err)
		return nil, &sourceErr
	}

	return NormalizeHosts(domain, hosts), nil
}

func MarshalSubfinderRecord(record subfinderRecord) ([]byte, error) {
	return json.Marshal(record)
}

func ExampleSubfinderJSON(host string) string {
	record := subfinderRecord{Host: host}
	data, _ := json.Marshal(record)
	return fmt.Sprintf("%s\n", data)
}
