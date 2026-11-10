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
 *
 */

package tokenexchange

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSubjectToken       = "subject-token-value"
	testScope              = "test-scope:read"
	testParticipantContext = "did:web:test-participant"
	testAudience           = "test-audience"
	testAccessToken        = "exchanged-access-token"
)

func writeTokenFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	require.NoError(t, os.WriteFile(path, []byte(content), 0600))
	return path
}

func tokenResponse() tokenExchangeResponse {
	return tokenExchangeResponse{
		AccessToken:     testAccessToken,
		TokenType:       "Bearer",
		ExpiresIn:       3600,
		Scope:           testScope,
		IssuedTokenType: "urn:ietf:params:oauth:token-type:access_token",
	}
}

func TestGetToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/token", r.URL.Path)
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		form, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", form.Get("grant_type"))
		assert.Equal(t, testSubjectToken, form.Get("subject_token"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:jwt", form.Get("subject_token_type"))
		assert.Equal(t, testParticipantContext, form.Get("resource"))
		assert.Equal(t, testScope, form.Get("scope"))
		assert.Equal(t, testAudience, form.Get("audience"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenResponse())
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithTokenExchangeAudience(testAudience),
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
	assert.Equal(t, testAccessToken, token)
}

func TestGetToken_TokenFileNotFound(t *testing.T) {
	provider := NewTokenExchangeProvider("/nonexistent/path/token",
		WithTokenExchangeUrl("http://unused"),
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.Error(t, err)
	assert.Empty(t, token)
}

func TestGetToken_ServerReturns401(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.ErrorContains(t, err, "token exchange failed with status 401")
	assert.Empty(t, token)
}

func TestGetToken_ServerReturns500(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.ErrorContains(t, err, "token exchange failed with status 500")
	assert.Empty(t, token)
}

func TestGetToken_InvalidJsonResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not valid json"))
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.ErrorContains(t, err, "error decoding token exchange response")
	assert.Empty(t, token)
}

func TestGetToken_HttpClientError(t *testing.T) {
	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl("http://127.0.0.1:1"), // nothing listening here
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.ErrorContains(t, err, "error sending token exchange request")
	assert.Empty(t, token)
}

func TestGetToken_InvalidUrl(t *testing.T) {
	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl("://bad url"),
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.ErrorContains(t, err, "error creating token exchange request")
	assert.Empty(t, token)
}

func TestGetToken_FormFieldsForwarded(t *testing.T) {
	var capturedForm url.Values
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		capturedForm, _ = url.ParseQuery(string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{AccessToken: testAccessToken})
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithTokenExchangeAudience("my-audience"),
		WithHttpClient(&http.Client{}),
	)

	_, err := provider.GetToken(t.Context(), "my-scope", "did:web:alice")
	require.NoError(t, err)
	assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", capturedForm.Get("grant_type"))
	assert.Equal(t, testSubjectToken, capturedForm.Get("subject_token"))
	assert.Equal(t, "did:web:alice", capturedForm.Get("resource"))
	assert.Equal(t, "my-scope", capturedForm.Get("scope"))
	assert.Equal(t, "my-audience", capturedForm.Get("audience"))
}

func TestGetToken_EmptyTokenFile(t *testing.T) {
	var capturedSubjectToken string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		capturedSubjectToken = form.Get("subject_token")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{AccessToken: testAccessToken})
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, "")
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	_, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
	assert.Equal(t, "", capturedSubjectToken)
}

func TestGetToken_ContentTypeHeader(t *testing.T) {
	var capturedContentType string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedContentType = r.Header.Get("Content-Type")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{AccessToken: testAccessToken})
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	_, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(capturedContentType, "application/x-www-form-urlencoded"))
}

func TestNewTokenExchangeProvider_DefaultsNoopMonitor(t *testing.T) {
	provider := NewTokenExchangeProvider("/some/path")
	assert.NotNil(t, provider.monitor)
}

func TestGetToken_TokenAppendedToUrl(t *testing.T) {
	var capturedPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{AccessToken: testAccessToken})
	}))
	defer server.Close()

	tokenFile := writeTokenFile(t, testSubjectToken)
	provider := NewTokenExchangeProvider(tokenFile,
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	_, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
	assert.Equal(t, "/token", capturedPath)
}

func TestGetExpiringToken_ExpiryFromExpiresIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse())
	}))
	defer server.Close()

	provider := NewTokenExchangeProvider(writeTokenFile(t, testSubjectToken),
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	before := time.Now()
	token, err := provider.GetExpiringToken(t.Context(), testScope, testParticipantContext)
	after := time.Now()
	require.NoError(t, err)
	assert.Equal(t, testAccessToken, token.Value)
	require.NotNil(t, token.ExpiresAt)
	assert.False(t, token.ExpiresAt.Before(before.Add(time.Hour)))
	assert.False(t, token.ExpiresAt.After(after.Add(time.Hour)))
}

func TestGetExpiringToken_NoExpiryWithoutExpiresIn(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenExchangeResponse{AccessToken: testAccessToken})
	}))
	defer server.Close()

	provider := NewTokenExchangeProvider(writeTokenFile(t, testSubjectToken),
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	token, err := provider.GetExpiringToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
	assert.Nil(t, token.ExpiresAt)
}

func TestCachingTokenExchangeProvider_ExchangesOncePerScopeAndParticipant(t *testing.T) {
	var exchanges atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		exchanges.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse())
	}))
	defer server.Close()

	provider := NewCachingTokenExchangeProvider(writeTokenFile(t, testSubjectToken),
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
	)

	for range 3 {
		token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
		require.NoError(t, err)
		assert.Equal(t, testAccessToken, token)
	}
	_, err := provider.GetToken(t.Context(), "other-scope", testParticipantContext)
	require.NoError(t, err)

	assert.Equal(t, int32(2), exchanges.Load())
}

type mapConfig map[string]string

func (m mapConfig) GetString(key string) string { return m[key] }

func TestGetToken_ConfiguredSubjectTokenTypeAndClientCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		require.True(t, ok, "the client authenticates with HTTP Basic")
		assert.Equal(t, "cfm-agents", user)
		assert.Equal(t, "s3cret", pass)

		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		form, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:token-exchange", form.Get("grant_type"))
		assert.Equal(t, testSubjectToken, form.Get("subject_token"))
		assert.Equal(t, "urn:ietf:params:oauth:token-type:access_token", form.Get("subject_token_type"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse())
	}))
	defer server.Close()

	provider := NewTokenExchangeProvider(writeTokenFile(t, testSubjectToken),
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
		WithConfig(mapConfig{
			SubjectTokenTypeKey: "urn:ietf:params:oauth:token-type:access_token",
			ClientIDKey:         "cfm-agents",
			ClientSecretKey:     "s3cret",
		}),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
	assert.Equal(t, testAccessToken, token)
}

func TestGetToken_ClientCredentialsWithoutTokenFile_ObtainsTheSubjectToken(t *testing.T) {
	var grants []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := r.BasicAuth()
		require.True(t, ok)
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		form, err := url.ParseQuery(string(body))
		require.NoError(t, err)
		grants = append(grants, form.Get("grant_type"))

		w.Header().Set("Content-Type", "application/json")
		if form.Get("grant_type") == "client_credentials" {
			_ = json.NewEncoder(w).Encode(tokenExchangeResponse{AccessToken: "client-token", ExpiresIn: 300})
			return
		}
		assert.Equal(t, "client-token", form.Get("subject_token"))
		_ = json.NewEncoder(w).Encode(tokenResponse())
	}))
	defer server.Close()

	provider := NewTokenExchangeProvider("",
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
		WithClientCredentials("cfm-agents", "s3cret"),
		WithSubjectTokenType("urn:ietf:params:oauth:token-type:access_token"),
	)

	token, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
	assert.Equal(t, testAccessToken, token)
	assert.Equal(t, []string{"client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"}, grants)
}

func TestGetToken_WithoutConfig_KeepsTheJwtletDefaults(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, ok := r.BasicAuth()
		assert.False(t, ok, "no client authentication unless configured")
		body, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(body))
		assert.Equal(t, DefaultSubjectTokenType, form.Get("subject_token_type"))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse())
	}))
	defer server.Close()

	provider := NewTokenExchangeProvider(writeTokenFile(t, testSubjectToken),
		WithTokenExchangeUrl(server.URL),
		WithHttpClient(&http.Client{}),
		WithConfig(mapConfig{}),
	)

	_, err := provider.GetToken(t.Context(), testScope, testParticipantContext)
	require.NoError(t, err)
}
