package report

import (
	"fmt"

	"github.com/gorcher/osint_company/internal/models"
)

type Service struct{}

func NewService() *Service {
	return &Service{}
}

func (s *Service) Generate(report models.Report, format string) ([]byte, string, error) {
	switch format {
	case "json":
		return GenerateJSON(report)
	case "html":
		return GenerateHTML(report)
	default:
		return nil, "", fmt.Errorf("unsupported report format %q", format)
	}
}
