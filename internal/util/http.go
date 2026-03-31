package util

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

type HTTPClient struct {
	client    *http.Client
	logger    *slog.Logger
	userAgent string
	retries   int
}

type FetchedPage struct {
	URL         string
	StatusCode  int
	Headers     http.Header
	Body        []byte
	RetrievedAt time.Time
	FinalURL    string
}

func NewHTTPClient(timeout time.Duration, userAgent string, logger *slog.Logger) *HTTPClient {
	return &HTTPClient{
		client: &http.Client{
			Timeout: timeout,
		},
		logger:    logger,
		userAgent: userAgent,
		retries:   2,
	}
}

func (c *HTTPClient) Get(ctx context.Context, targetURL string) (*FetchedPage, error) {
	return c.GetWithHeaders(ctx, targetURL, nil)
}

func (c *HTTPClient) GetWithHeaders(ctx context.Context, targetURL string, headers map[string]string) (*FetchedPage, error) {
	var lastErr error
	for attempt := 0; attempt <= c.retries; attempt++ {
		page, err := c.doGet(ctx, targetURL, headers)
		if err == nil {
			return page, nil
		}
		lastErr = err
		if attempt < c.retries {
			backoff := time.Duration(attempt+1) * 400 * time.Millisecond
			c.logger.Debug("http retry", "url", targetURL, "attempt", attempt+1, "backoff", backoff.String(), "error", err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(backoff):
			}
		}
	}
	return nil, lastErr
}

func (c *HTTPClient) doGet(ctx context.Context, targetURL string, headers map[string]string) (*FetchedPage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.userAgent)
	req.Header.Set("Accept", "*/*")
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, 2<<20)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
		return nil, fmt.Errorf("http status %d", resp.StatusCode)
	}

	page := &FetchedPage{
		URL:         targetURL,
		StatusCode:  resp.StatusCode,
		Headers:     resp.Header.Clone(),
		Body:        body,
		RetrievedAt: time.Now().UTC(),
	}
	if resp.Request != nil && resp.Request.URL != nil {
		page.FinalURL = resp.Request.URL.String()
	}

	return page, nil
}
