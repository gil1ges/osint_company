package app

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gorcher/osint_company/internal/config"
	"github.com/gorcher/osint_company/internal/digitalfootprint"
	"github.com/gorcher/osint_company/internal/models"
	"github.com/gorcher/osint_company/internal/profile"
	reportsvc "github.com/gorcher/osint_company/internal/report"
	"github.com/gorcher/osint_company/internal/util"
)

type Options struct {
	Company    string
	INN        string
	Domain     string
	Module     string
	Format     string
	Output     string
	ConfigPath string
	Timeout    time.Duration
	Verbose    bool
}

func (o Options) Validate() error {
	validModules := map[string]bool{
		"profile":          true,
		"digitalfootprint": true,
		"all":              true,
	}
	validFormats := map[string]bool{
		"json": true,
		"html": true,
	}

	if !validModules[o.Module] {
		return fmt.Errorf("unsupported module %q", o.Module)
	}
	if !validFormats[o.Format] {
		return fmt.Errorf("unsupported format %q", o.Format)
	}

	return nil
}

type runtimeConfig struct {
	Config config.Config
	Inputs models.TargetInput
	Module string
	Format string
	Output string
}

func Run(ctx context.Context, opts Options) (string, error) {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return "", fmt.Errorf("load config: %w", err)
	}

	runCfg := mergeConfig(cfg, opts)
	ctx, cancel := context.WithTimeout(ctx, runCfg.Config.Timeout)
	defer cancel()

	logger := newLogger(runCfg.Config.Verbose)
	httpClient := util.NewHTTPClient(runCfg.Config.Timeout, runCfg.Config.UserAgent, logger)

	report := models.Report{
		GeneratedAt: time.Now().UTC(),
		Inputs:      runCfg.Inputs,
	}

	if runCfg.Module == "profile" || runCfg.Module == "all" {
		service := profile.NewService(httpClient, runCfg.Config, logger)
		result := service.Collect(ctx, runCfg.Inputs)
		report.Profile = &result
		report.Warnings = append(report.Warnings, result.Warnings...)
		report.Errors = append(report.Errors, result.Errors...)
	}

	if runCfg.Module == "digitalfootprint" || runCfg.Module == "all" {
		service := digitalfootprint.NewService(httpClient, runCfg.Config, logger)
		result := service.Collect(ctx, runCfg.Inputs)
		report.DigitalFootprint = &result
		report.Warnings = append(report.Warnings, result.Warnings...)
		report.Errors = append(report.Errors, result.Errors...)
	}

	generator := reportsvc.NewService()
	content, ext, err := generator.Generate(report, runCfg.Format)
	if err != nil {
		return "", fmt.Errorf("generate report: %w", err)
	}

	outputPath, err := util.ResolveOutputPath(runCfg.Output, ext)
	if err != nil {
		return "", fmt.Errorf("resolve output path: %w", err)
	}

	if err := util.WriteFile(outputPath, content); err != nil {
		return "", fmt.Errorf("write report: %w", err)
	}

	logger.Info("report written", "path", outputPath)
	return outputPath, nil
}

func mergeConfig(cfg config.Config, opts Options) runtimeConfig {
	merged := cfg

	if opts.Timeout > 0 {
		merged.Timeout = opts.Timeout
	}
	if strings.TrimSpace(opts.Output) != "" {
		merged.Output = opts.Output
	}
	if opts.Verbose {
		merged.Verbose = true
	}
	if merged.Timeout <= 0 {
		merged.Timeout = 15 * time.Second
	}
	if strings.TrimSpace(merged.Output) == "" {
		merged.Output = "./reports"
	}
	if strings.TrimSpace(merged.UserAgent) == "" {
		merged.UserAgent = "osintcli/1.0"
	}

	return runtimeConfig{
		Config: merged,
		Inputs: models.TargetInput{
			Company: strings.TrimSpace(opts.Company),
			INN:     util.NormalizeDigits(opts.INN),
			Domain:  strings.TrimSpace(opts.Domain),
		},
		Module: opts.Module,
		Format: opts.Format,
		Output: merged.Output,
	}
}

func newLogger(verbose bool) *slog.Logger {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}

	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})
	return slog.New(handler)
}
