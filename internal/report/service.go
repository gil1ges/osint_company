package report

import (
	"fmt"
	"log/slog"

	"github.com/gorcher/osint_company/internal/models"
)

type Service struct {
	logger *slog.Logger
}

func NewService(logger *slog.Logger) *Service {
	return &Service{logger: logger}
}

func (s *Service) Generate(report models.Report, format string) ([]byte, string, error) {
	switch format {
	case "json":
		return GenerateJSON(report)
	case "html":
		return GenerateHTML(report)
	case "md":
		return GenerateMarkdown(report)
	case "txt":
		return GenerateText(report)
	default:
		return nil, "", fmt.Errorf("unsupported report format %q", format)
	}
}
