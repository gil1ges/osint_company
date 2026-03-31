package providers

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/util"
)

type amassRecord struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

func ParseAmassJSON(data []byte) ([]string, error) {
	records, err := ParseJSONLines[amassRecord](data)
	if err != nil {
		return nil, err
	}
	hosts := make([]string, 0, len(records))
	for _, record := range records {
		if strings.TrimSpace(record.Name) != "" {
			hosts = append(hosts, record.Name)
		}
	}
	return NormalizeHosts("", hosts), nil
}

func RunAmassPassive(ctx context.Context, domain string) ([]string, *models.SourceError) {
	if !util.CommandExists("amass") {
		err := ToolUnavailableError("amass")
		return nil, &err
	}

	tmpFile, err := os.CreateTemp("", "amass-*.json")
	if err != nil {
		sourceErr := WrapError("amass", "tool", "tempfile", "", err)
		return nil, &sourceErr
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	_, err = util.RunCommand(ctx, "amass", "enum", "-passive", "-norecursive", "-noalts", "-d", domain, "-json", tmpFile.Name())
	if err != nil {
		sourceErr := WrapError("amass", "tool", "enumerate_subdomains", "", err)
		return nil, &sourceErr
	}

	data, err := os.ReadFile(tmpFile.Name())
	if err != nil {
		sourceErr := WrapError("amass", "tool", "read_output", "", err)
		return nil, &sourceErr
	}

	hosts, err := ParseAmassJSON(data)
	if err != nil {
		sourceErr := WrapError("amass", "tool", "parse_json", "", err)
		return nil, &sourceErr
	}
	return NormalizeHosts(domain, hosts), nil
}

func MarshalAmassRecord(record amassRecord) ([]byte, error) {
	return json.Marshal(record)
}
