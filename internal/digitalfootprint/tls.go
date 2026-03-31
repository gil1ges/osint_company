package digitalfootprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/gorcher/osint_company/internal/models"
)

func collectTLS(ctx context.Context, domain string) (*models.TLSCertificate, []models.SourceError) {
	if domain == "" {
		return nil, nil
	}

	dialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS12,
		},
	}

	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(domain, "443"))
	if err != nil {
		return nil, []models.SourceError{{
			SourceName:  "tls",
			SourceURL:   domain,
			SourceType:  "tls",
			Operation:   "dial",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: time.Now().UTC(),
		}}
	}
	defer conn.Close()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, []models.SourceError{{
			SourceName:  "tls",
			SourceURL:   domain,
			SourceType:  "tls",
			Operation:   "handshake",
			Error:       "connection is not tls",
			CollectedAt: time.Now().UTC(),
		}}
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, []models.SourceError{{
			SourceName:  "tls",
			SourceURL:   domain,
			SourceType:  "tls",
			Operation:   "handshake",
			Error:       err.Error(),
			Temporary:   true,
			CollectedAt: time.Now().UTC(),
		}}
	}

	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, []models.SourceError{{
			SourceName:  "tls",
			SourceURL:   domain,
			SourceType:  "tls",
			Operation:   "parse_peer_certificates",
			Error:       "no peer certificates presented",
			CollectedAt: time.Now().UTC(),
		}}
	}

	cert := state.PeerCertificates[0]
	return &models.TLSCertificate{
		Issuer:       cert.Issuer.String(),
		Subject:      cert.Subject.String(),
		SerialNumber: cert.SerialNumber.String(),
		SANs:         cert.DNSNames,
		ValidFrom:    cert.NotBefore.Format(time.RFC3339),
		ValidTo:      cert.NotAfter.Format(time.RFC3339),
	}, nil
}

func tlsEvidence(domain string, fieldValue string) models.Evidence {
	return models.Evidence{
		SourceName:  "tls",
		SourceURL:   fmt.Sprintf("https://%s", domain),
		SourceType:  "tls",
		RetrievedAt: nowUTC(),
		Method:      "tls handshake",
		Snippet:     fieldValue,
	}
}
