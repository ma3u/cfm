/*
 *  Copyright (c) 2026 Metaform Systems, Inc.
 *
 *  This program and the accompanying materials are made available under the
 *  terms of the Apache License, Version 2.0 which is available at
 *  https://www.apache.org/licenses/LICENSE-2.0
 *
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Contributors:
 *       Metaform Systems, Inc. - initial API and implementation
 *       Matthias Buchhorn - configurable subject token type and client credentials
 *
 */

package tokenexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/eclipse-cfm/cfm/common/system"
	"github.com/eclipse-cfm/cfm/common/token"
)

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
	Scope           string `json:"scope"`
	IssuedTokenType string `json:"issued_token_type"`
}

// TokenExchangeProvider reads a token from a file share and exchanges it for a resource-bound token. The initial token is a
// projected token bound to the workload ID (in Kubernetes: ServiceAccount), and the second token is a token bound to the
// participant context
type TokenExchangeProvider struct {
	filePath              string
	tokenExchangeUrl      string
	tokenExchangeAudience string
	subjectTokenType      string
	clientID              string
	clientSecret          string
	httpClient            *http.Client
	monitor               system.LogMonitor
}

const (
	// DefaultSubjectTokenType is the type jwtlet expects for a projected ServiceAccount token.
	DefaultSubjectTokenType = "urn:ietf:params:oauth:token-type:jwt"

	// SubjectTokenTypeKey, ClientIDKey and ClientSecretKey are the configuration keys WithConfig reads.
	SubjectTokenTypeKey = "tokenexchange.subjectTokenType"
	ClientIDKey         = "tokenexchange.clientId"
	ClientSecretKey     = "tokenexchange.clientSecret"
)

// ProviderOption is a functional option for configuring TokenExchangeProvider
type ProviderOption func(*TokenExchangeProvider)

// WithTokenExchangeUrl sets the URL of the token exchange server (jwtlet)
func WithTokenExchangeUrl(url string) ProviderOption {
	return func(t *TokenExchangeProvider) {
		t.tokenExchangeUrl = url
	}
}

// WithTokenExchangeAudience sets the token exchange audience (e.g. "edcv"). all downstream services must validate against this audience
func WithTokenExchangeAudience(audience string) ProviderOption {
	return func(t *TokenExchangeProvider) {
		t.tokenExchangeAudience = audience
	}
}

// WithHttpClient sets the HTTP client
func WithHttpClient(client *http.Client) ProviderOption {
	return func(t *TokenExchangeProvider) {
		t.httpClient = client
	}
}

// WithMonitor sets the log monitor
func WithMonitor(monitor system.LogMonitor) ProviderOption {
	return func(t *TokenExchangeProvider) {
		t.monitor = monitor
	}
}

// WithSubjectTokenType sets the subject_token_type sent with the exchange (RFC 8693, section 3). The default,
// DefaultSubjectTokenType, is what jwtlet expects; an authorization server that accepts only access tokens as subject
// tokens (Keycloak's standard token exchange, for example) needs "urn:ietf:params:oauth:token-type:access_token".
func WithSubjectTokenType(tokenType string) ProviderOption {
	return func(t *TokenExchangeProvider) {
		if tokenType != "" {
			t.subjectTokenType = tokenType
		}
	}
}

// WithClientCredentials makes the provider authenticate as an OAuth2 client (HTTP Basic, RFC 6749, section 2.3.1), for
// an authorization server that requires client authentication on the token exchange. Without a token file path, the
// subject token is then obtained with the client_credentials grant from the same token endpoint.
func WithClientCredentials(clientID string, clientSecret string) ProviderOption {
	return func(t *TokenExchangeProvider) {
		t.clientID = clientID
		t.clientSecret = clientSecret
	}
}

// ConfigGetter is the part of the agent configuration OptionsFromConfig reads.
type ConfigGetter interface {
	GetString(key string) string
}

// WithConfig applies the optional configuration keys SubjectTokenTypeKey, ClientIDKey and ClientSecretKey. None set
// leaves the provider as jwtlet needs it.
func WithConfig(config ConfigGetter) ProviderOption {
	return func(t *TokenExchangeProvider) {
		WithSubjectTokenType(config.GetString(SubjectTokenTypeKey))(t)
		if clientID := config.GetString(ClientIDKey); clientID != "" {
			WithClientCredentials(clientID, config.GetString(ClientSecretKey))(t)
		}
	}
}

// NewTokenExchangeProvider creates a new TokenExchangeProvider with the given token file path and options
// tokenFilePath: the absolute path to the file that contains the token
func NewTokenExchangeProvider(tokenFilePath string, opts ...ProviderOption) TokenExchangeProvider {
	provider := TokenExchangeProvider{
		filePath:         tokenFilePath,
		subjectTokenType: DefaultSubjectTokenType,
		monitor:          system.NoopMonitor{},
	}
	for _, opt := range opts {
		opt(&provider)
	}
	return provider
}

// NewCachingTokenExchangeProvider creates a TokenExchangeProvider and wraps it in a token.CachingTokenProvider, so
// exchanged tokens are reused per scope and participant context until shortly before they expire.
func NewCachingTokenExchangeProvider(tokenFilePath string, opts ...ProviderOption) *token.CachingTokenProvider {
	return token.NewCachingTokenProvider(NewTokenExchangeProvider(tokenFilePath, opts...))
}

func (t TokenExchangeProvider) GetToken(ctx context.Context, scope string, participantContextID string) (string, error) {
	exchanged, err := t.GetExpiringToken(ctx, scope, participantContextID)
	if err != nil {
		return "", err
	}
	return exchanged.Value, nil
}

// GetExpiringToken exchanges the subject token for a token bound to the participant context. The subject token is read
// from the file on every call, because it is rotated on disk. ExpiresAt is nil if the response has no positive
// expires_in.
func (t TokenExchangeProvider) GetExpiringToken(ctx context.Context, scope string, participantContextID string) (*token.ExpiringToken, error) {
	requestedAt := time.Now()
	subjectToken, err := t.subjectToken(ctx)
	if err != nil {
		return nil, err
	}

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", subjectToken)
	formData.Set("subject_token_type", t.subjectTokenType)
	formData.Set("resource", participantContextID)
	formData.Set("scope", scope)
	formData.Set("audience", t.tokenExchangeAudience)

	t.monitor.Debugw("sending token exchange request", "url", t.tokenExchangeUrl, "scope", scope, "resource", participantContextID, "audience", t.tokenExchangeAudience)
	req, err := http.NewRequestWithContext(ctx, "POST", t.tokenExchangeUrl+"/token", strings.NewReader(formData.Encode()))
	if err != nil {
		return nil, fmt.Errorf("error creating token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	t.authenticate(req)
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending token exchange request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.monitor.Debugw("token exchange failed", "status", resp.StatusCode, "body", string(bodyBytes))
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}
	var tokenResponse tokenExchangeResponse
	err = json.Unmarshal(bodyBytes, &tokenResponse)
	if err != nil {
		return nil, fmt.Errorf("error decoding token exchange response: %w", err)
	}

	t.monitor.Debugw("token exchange successful", "scope", scope, "resource", participantContextID, "token_type", tokenResponse.TokenType, "expires_in", tokenResponse.ExpiresIn)
	exchanged := &token.ExpiringToken{Value: tokenResponse.AccessToken}
	if tokenResponse.ExpiresIn > 0 {
		// measured from before the request, so the cached lifetime never exceeds the real one
		expiresAt := requestedAt.Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
		exchanged.ExpiresAt = &expiresAt
	}
	return exchanged, nil
}

// subjectToken reads the subject token from the token file, which is rotated on disk, so on every call. Without a
// token file and with client credentials, it obtains one with the client_credentials grant instead.
func (t TokenExchangeProvider) subjectToken(ctx context.Context) (string, error) {
	if t.filePath == "" && t.clientID != "" {
		return t.clientCredentialsToken(ctx)
	}
	t.monitor.Debugw("reading subject token from file", "path", t.filePath)
	content, err := os.ReadFile(t.filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func (t TokenExchangeProvider) clientCredentialsToken(ctx context.Context) (string, error) {
	formData := url.Values{}
	formData.Set("grant_type", "client_credentials")
	req, err := http.NewRequestWithContext(ctx, "POST", t.tokenExchangeUrl+"/token", strings.NewReader(formData.Encode()))
	if err != nil {
		return "", fmt.Errorf("error creating client credentials request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	t.authenticate(req)
	resp, err := t.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error sending client credentials request: %w", err)
	}
	defer resp.Body.Close()
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading response body: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		t.monitor.Debugw("client credentials grant failed", "status", resp.StatusCode, "body", string(bodyBytes))
		return "", fmt.Errorf("client credentials grant failed with status %d", resp.StatusCode)
	}
	var tokenResponse tokenExchangeResponse
	if err := json.Unmarshal(bodyBytes, &tokenResponse); err != nil {
		return "", fmt.Errorf("error decoding client credentials response: %w", err)
	}
	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("client credentials response carries no access token")
	}
	return tokenResponse.AccessToken, nil
}

// authenticate adds the client credentials, when configured, as HTTP Basic.
func (t TokenExchangeProvider) authenticate(req *http.Request) {
	if t.clientID != "" {
		req.SetBasicAuth(url.QueryEscape(t.clientID), url.QueryEscape(t.clientSecret))
	}
}
