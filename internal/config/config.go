package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Timeout               time.Duration
	Output                string
	UserAgent             string
	Verbose               bool
	ShodanAPIKey          string
	SecurityTrailsAPIKey  string
	SpiderFootCommand     string
	SpiderFootURL         string
	SpiderFootResultsPath string
	MaltegoCommand        string
	MaltegoResultsPath    string
}

func Default() Config {
	return Config{
		Timeout:   15 * time.Second,
		Output:    "./reports",
		UserAgent: "osintcli/1.0",
	}
}

func Load(path string) (Config, error) {
	cfg := Default()

	if strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return cfg, fmt.Errorf("read config file: %w", err)
		}
		if err := applySimpleYAML(&cfg, string(data)); err != nil {
			return cfg, fmt.Errorf("parse config file: %w", err)
		}
	}

	applyEnvOverrides(&cfg)
	return cfg, nil
}

func applySimpleYAML(cfg *Config, data string) error {
	scanner := bufio.NewScanner(strings.NewReader(data))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			return fmt.Errorf("line %d: expected key: value", lineNo)
		}
		key := strings.TrimSpace(line[:idx])
		value := strings.Trim(strings.TrimSpace(line[idx+1:]), `"'`)
		if err := setConfigValue(cfg, key, value); err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	return scanner.Err()
}

func setConfigValue(cfg *Config, key, value string) error {
	switch strings.ToLower(key) {
	case "timeout":
		if value == "" {
			return nil
		}
		d, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("invalid timeout %q: %w", value, err)
		}
		cfg.Timeout = d
	case "output":
		cfg.Output = value
	case "user_agent":
		cfg.UserAgent = value
	case "verbose":
		b, err := strconv.ParseBool(value)
		if err != nil {
			return fmt.Errorf("invalid verbose value %q: %w", value, err)
		}
		cfg.Verbose = b
	case "shodan_api_key":
		cfg.ShodanAPIKey = value
	case "securitytrails_api_key":
		cfg.SecurityTrailsAPIKey = value
	case "spiderfoot_command":
		cfg.SpiderFootCommand = value
	case "spiderfoot_url":
		cfg.SpiderFootURL = value
	case "spiderfoot_results_path":
		cfg.SpiderFootResultsPath = value
	case "maltego_command":
		cfg.MaltegoCommand = value
	case "maltego_results_path":
		cfg.MaltegoResultsPath = value
	default:
		return nil
	}
	return nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("OSINTCLI_TIMEOUT"); strings.TrimSpace(v) != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Timeout = d
		}
	}
	if v := os.Getenv("OSINTCLI_OUTPUT"); strings.TrimSpace(v) != "" {
		cfg.Output = v
	}
	if v := os.Getenv("OSINTCLI_USER_AGENT"); strings.TrimSpace(v) != "" {
		cfg.UserAgent = v
	}
	if v := os.Getenv("OSINTCLI_SHODAN_API_KEY"); strings.TrimSpace(v) != "" {
		cfg.ShodanAPIKey = v
	}
	if v := os.Getenv("OSINTCLI_SECURITYTRAILS_API_KEY"); strings.TrimSpace(v) != "" {
		cfg.SecurityTrailsAPIKey = v
	}
	if v := os.Getenv("OSINTCLI_SPIDERFOOT_COMMAND"); strings.TrimSpace(v) != "" {
		cfg.SpiderFootCommand = v
	}
	if v := os.Getenv("OSINTCLI_SPIDERFOOT_URL"); strings.TrimSpace(v) != "" {
		cfg.SpiderFootURL = v
	}
	if v := os.Getenv("OSINTCLI_SPIDERFOOT_RESULTS_PATH"); strings.TrimSpace(v) != "" {
		cfg.SpiderFootResultsPath = v
	}
	if v := os.Getenv("OSINTCLI_MALTEGO_COMMAND"); strings.TrimSpace(v) != "" {
		cfg.MaltegoCommand = v
	}
	if v := os.Getenv("OSINTCLI_MALTEGO_RESULTS_PATH"); strings.TrimSpace(v) != "" {
		cfg.MaltegoResultsPath = v
	}
	if v := os.Getenv("OSINTCLI_VERBOSE"); strings.TrimSpace(v) != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Verbose = b
		}
	}
}
