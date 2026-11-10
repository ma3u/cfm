//  Copyright (c) 2025 Metaform Systems, Inc
//
//  This program and the accompanying materials are made available under the
//  terms of the Apache License, Version 2.0 which is available at
//  https://www.apache.org/licenses/LICENSE-2.0
//
//  SPDX-License-Identifier: Apache-2.0
//
//  Contributors:
//       Metaform Systems, Inc. - initial API and implementation
//

package activity

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/eclipse-cfm/cfm/agent/common"
	"github.com/eclipse-cfm/cfm/agent/common/identityhub"
	"github.com/eclipse-cfm/cfm/common/model"
	"github.com/eclipse-cfm/cfm/common/system"
	"github.com/eclipse-cfm/cfm/pmanager/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type ConfigOption func(*Config)

func WithIdentityHub(client identityhub.IdentityAPIClient) ConfigOption {
	return func(c *Config) {
		c.IdentityAPIClient = client
	}
}

func validConfig(opts ...ConfigOption) *Config {
	c := Config{
		IdentityAPIClient: MockIdentityHubClient{},
		Client:            &http.Client{},
		LogMonitor:        system.NoopMonitor{},
		VaultURL:          "https://vault.example.com:8200",
	}
	for _, opt := range opts {
		opt(&c)
	}
	return &c
}

var processingData = map[string]any{
	model.ParticipantIdentifier:         "did:web:participant-abc",
	"clientID.vaultAccess":              "client-123",
	"participantContextId":              "client-456",
	"cfm.participant.credentialservice": "https://example.com/credentialservice",
	"cfm.participant.protocolservice":   "https://example.com/protocolservice",
	"cfm.participant.dataservice":       "https://example.com/dataservice",
}

func TestIHActivityProcessor_ProcessDeploy_WithValidData(t *testing.T) {
	processor := NewProcessor(validConfig())

	activityContext := api.NewActivityContext(context.Background(), "orch-1", api.Activity{
		ID:            "test-activity",
		Type:          "ih",
		Discriminator: api.DeployDiscriminator,
	}, copyOf(processingData), make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	assert.Equal(t, api.ActivityResultType(api.ActivityResultComplete), result.Result)
	assert.NoError(t, result.Error)
}

func TestIHActivityProcessor_ProcessDeploy_MissingParticipantID(t *testing.T) {
	processor := NewProcessor(validConfig())
	pd := copyOf(processingData)
	delete(pd, model.ParticipantIdentifier)

	activityContext := api.NewActivityContext(context.Background(), "orch-2", api.Activity{
		ID:   "activity-1",
		Type: "ih",
	}, pd, make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	require.Equal(t, api.ActivityResultType(api.ActivityResultFatalError), result.Result)
	assert.Contains(t, result.Error.Error(), "error processing IH activity")
}

func TestIHActivityProcessor_ProcessDeploy_MissingCredentialServiceURL(t *testing.T) {
	processor := NewProcessor(validConfig())
	pd := copyOf(processingData)
	delete(pd, "cfm.participant.credentialservice")

	activityContext := api.NewActivityContext(context.Background(), "orch-3", api.Activity{
		ID:            "activity-2",
		Type:          "ih",
		Discriminator: api.DeployDiscriminator,
	}, pd, make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	require.Equal(t, api.ActivityResultType(api.ActivityResultFatalError), result.Result)
	assert.Contains(t, result.Error.Error(), "CredentialServiceURL is empty")
}

func TestIHActivityProcessor_ProcessDeploy_MissingProtocolServiceURL(t *testing.T) {
	processor := NewProcessor(validConfig())
	pd := copyOf(processingData)
	delete(pd, "cfm.participant.protocolservice")

	activityContext := api.NewActivityContext(context.Background(), "orch-4", api.Activity{
		ID:            "activity-3",
		Type:          "ih",
		Discriminator: api.DeployDiscriminator,
	}, pd, make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	require.Equal(t, api.ActivityResultType(api.ActivityResultFatalError), result.Result)
	assert.Contains(t, result.Error.Error(), "ProtocolServiceURL is empty")
}

func TestIHActivityProcessor_ProcessDeploy_MissingDataServiceURL(t *testing.T) {
	processor := NewProcessor(validConfig())
	pd := copyOf(processingData)
	delete(pd, "cfm.participant.dataservice")

	activityContext := api.NewActivityContext(context.Background(), "orch-4b", api.Activity{
		ID:            "activity-3b",
		Type:          "ih",
		Discriminator: api.DeployDiscriminator,
	}, pd, make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	require.Equal(t, api.ActivityResultType(api.ActivityResultFatalError), result.Result)
	assert.Contains(t, result.Error.Error(), "DataServiceURL is empty")
}

func TestIHActivityProcessor_ProcessDeploy_IdentityHubFailure(t *testing.T) {
	processor := NewProcessor(validConfig(WithIdentityHub(MockIdentityHubClient{expectedError: fmt.Errorf("ih unavailable")})))

	activityContext := api.NewActivityContext(context.Background(), "orch-6", api.Activity{
		ID:            "activity-5",
		Type:          "ih",
		Discriminator: api.DeployDiscriminator,
	}, copyOf(processingData), make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	require.Equal(t, api.ActivityResultType(api.ActivityResultFatalError), result.Result)
	assert.ErrorContains(t, result.Error, "ih unavailable")
}

func TestIHActivityProcessor_ProcessDispose_Success(t *testing.T) {
	processor := NewProcessor(validConfig())

	activityContext := api.NewActivityContext(context.Background(), "orch-7", api.Activity{
		ID:            "activity-6",
		Type:          "ih",
		Discriminator: api.DisposeDiscriminator,
	}, copyOf(processingData), make(map[string]any))

	result := processor.ProcessDispose(activityContext)

	assert.Equal(t, api.ActivityResultType(api.ActivityResultComplete), result.Result)
	assert.NoError(t, result.Error)
}

func TestIHActivityProcessor_ProcessDispose_IdentityHubError(t *testing.T) {
	processor := NewProcessor(validConfig(WithIdentityHub(MockIdentityHubClient{expectedError: fmt.Errorf("some error")})))

	activityContext := api.NewActivityContext(context.Background(), "orch-8", api.Activity{
		ID:            "activity-7",
		Type:          "ih",
		Discriminator: api.DisposeDiscriminator,
	}, copyOf(processingData), make(map[string]any))

	result := processor.ProcessDispose(activityContext)

	// errors during dispose are logged as warnings; always returns Complete to unblock subsequent agents
	assert.Equal(t, api.ActivityResultType(api.ActivityResultComplete), result.Result)
}

// --- mocks ---

type MockIdentityHubClient struct {
	expectedError error
}

func (m MockIdentityHubClient) CreateParticipantContext(_ context.Context, _ identityhub.ParticipantManifest) error {
	return m.expectedError
}

func (m MockIdentityHubClient) DeleteParticipantContext(_ context.Context, _ string) error {
	return m.expectedError
}

func (m MockIdentityHubClient) RequestCredentials(_ context.Context, _ string, _ identityhub.CredentialRequest) (string, error) {
	panic("not implemented")
}

func (m MockIdentityHubClient) GetCredentialRequestState(_ context.Context, _ string, _ string) (string, error) {
	panic("not implemented")
}

func (m MockIdentityHubClient) QueryCredentialByType(_ context.Context, _ string, _ string) ([]common.VerifiableCredentialResource, error) {
	panic("not implemented")
}

func copyOf(m map[string]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		result[k] = v
	}
	return result
}

type capturingIdentityHubClient struct {
	MockIdentityHubClient
	manifest *identityhub.ParticipantManifest
}

func (c capturingIdentityHubClient) CreateParticipantContext(_ context.Context, manifest identityhub.ParticipantManifest) error {
	*c.manifest = manifest
	return nil
}

func TestIHActivityProcessor_ProcessDeploy_STSInIdentityHub(t *testing.T) {
	var manifest identityhub.ParticipantManifest
	config := validConfig(WithIdentityHub(capturingIdentityHubClient{manifest: &manifest}))
	config.STSInIdentityHub = true
	processor := NewProcessor(config)

	activityContext := api.NewActivityContext(context.Background(), "orch-1", api.Activity{
		ID:            "test-activity",
		Type:          "ih",
		Discriminator: api.DeployDiscriminator,
	}, copyOf(processingData), make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	require.Equal(t, api.ActivityResultType(api.ActivityResultComplete), result.Result, "error: %v", result.Error)
	assert.True(t, manifest.ProvisionStsAccount, "IdentityHub provisions the STS account")
	assert.Empty(t, manifest.VaultConfig.VaultURL, "no vault URL, so the client sends no Vault partition")
}

func TestIHActivityProcessor_ProcessDeploy_DefaultKeepsTheVaultPartition(t *testing.T) {
	var manifest identityhub.ParticipantManifest
	processor := NewProcessor(validConfig(WithIdentityHub(capturingIdentityHubClient{manifest: &manifest})))

	activityContext := api.NewActivityContext(context.Background(), "orch-1", api.Activity{
		ID:            "test-activity",
		Type:          "ih",
		Discriminator: api.DeployDiscriminator,
	}, copyOf(processingData), make(map[string]any))

	result := processor.ProcessDeploy(activityContext)

	require.Equal(t, api.ActivityResultType(api.ActivityResultComplete), result.Result, "error: %v", result.Error)
	assert.False(t, manifest.ProvisionStsAccount)
	assert.Equal(t, "https://vault.example.com:8200", manifest.VaultConfig.VaultURL)
	assert.Equal(t, "client-456/identityhub", manifest.VaultConfig.FolderPath)
}
