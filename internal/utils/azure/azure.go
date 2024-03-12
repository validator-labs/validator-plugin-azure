// Package azure implements utilities that relate to more than one thing we want to do with Azure
// for the plugin's validation logic.
package azure

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	armpolicy "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

const TestClientTimeout = 10 * time.Second

type AzureAPI struct {
	DenyAssignments *armauthorization.DenyAssignmentsClient
	RoleAssignments *armauthorization.RoleAssignmentsClient
	RoleDefinitions *armauthorization.RoleDefinitionsClient
}

// NewAzureAPI creates an AzureAPI object that aggregates Azure service clients.
func NewAzureAPI() (*AzureAPI, error) {
	// Get credentials from the three env vars. For more info on default auth, see:
	// https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication
	var cred *azidentity.DefaultAzureCredential
	var err error
	if cred, err = azidentity.NewDefaultAzureCredential(nil); err != nil {
		return nil, fmt.Errorf("failed to prepare default Azure credential: %w", err)
	}

	// Minimize retries/timeouts for tests
	opts := &armpolicy.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Retry: policy.RetryOptions{},
		},
	}
	if os.Getenv("IS_TEST") == "true" {
		httpClient := http.DefaultClient
		httpClient.Timeout = TestClientTimeout

		opts.ClientOptions.Retry.MaxRetries = -1
		opts.ClientOptions.Retry.TryTimeout = TestClientTimeout
		opts.ClientOptions.Transport = policy.Transporter(httpClient)
	}

	// The subscription ID parameter for deny assignment and role assignment clients isn't relevant
	// because the plugin only uses methods where scope is specified for each query. Therefore, an
	// empty string is used for the param.
	daClient, err := armauthorization.NewDenyAssignmentsClient("", cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure deny assignments client: %w", err)
	}
	raClient, err := armauthorization.NewRoleAssignmentsClient("", cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure role assignments client: %w", err)
	}
	rdClient, err := armauthorization.NewRoleDefinitionsClient(cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure role assignments client: %w", err)
	}

	return &AzureAPI{
		DenyAssignments: daClient,
		RoleAssignments: raClient,
		RoleDefinitions: rdClient,
	}, err
}

// AzureDenyAssignmentsClient is a facade over the Azure deny assignments client. Exists to make our
// code easier to test (it handles paging).
type AzureDenyAssignmentsClient struct {
	ctx    context.Context
	client *armauthorization.DenyAssignmentsClient
}

// NewAzureDenyAssignmentsClient creates a new AzureDenyAssignmentsClient (our facade client) from a
// client from the Azure SDK.
func NewAzureDenyAssignmentsClient(ctx context.Context, azClient *armauthorization.DenyAssignmentsClient) *AzureDenyAssignmentsClient {
	return &AzureDenyAssignmentsClient{
		ctx:    ctx,
		client: azClient,
	}
}

// GetDenyAssignmentsForScope gets all the deny assignments matching a scope and an optional filter.
func (c *AzureDenyAssignmentsClient) GetDenyAssignmentsForScope(scope string, filter *string) ([]*armauthorization.DenyAssignment, error) {
	var denyAssignments []*armauthorization.DenyAssignment
	pager := c.client.NewListForScopePager(scope, &armauthorization.DenyAssignmentsClientListForScopeOptions{
		Filter: filter,
	})

	ch := make(chan error)
	go func() {
		defer close(ch)
		for pager.More() {
			nextResult, err := pager.NextPage(c.ctx)
			if err != nil {
				ch <- fmt.Errorf("failed to get next page of results: %w", err)
			}
			if nextResult.Value != nil {
				denyAssignments = append(denyAssignments, nextResult.Value...)
			}
		}
		ch <- nil
	}()

	select {
	case err := <-ch:
		return denyAssignments, err
	case <-c.ctx.Done():
		return denyAssignments, fmt.Errorf("context cancelled")
	}
}

// AzureRoleAssignmentsClient is a facade over the Azure role assignments client. Exists to make our
// code easier to test (it handles paging).
type AzureRoleAssignmentsClient struct {
	ctx    context.Context
	client *armauthorization.RoleAssignmentsClient
}

// NewAzureRoleAssignmentsClient creates a new AzureRoleAssignmentsClient (our facade client) from a
// client from the Azure SDK.
func NewAzureRoleAssignmentsClient(ctx context.Context, azClient *armauthorization.RoleAssignmentsClient) *AzureRoleAssignmentsClient {
	return &AzureRoleAssignmentsClient{
		ctx:    ctx,
		client: azClient,
	}
}

// GetRoleAssignmentsForScope gets all the role assignments matching a scope and an optional filter.
func (c *AzureRoleAssignmentsClient) GetRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error) {
	var roleAssignments []*armauthorization.RoleAssignment
	pager := c.client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: filter,
	})

	ch := make(chan error)
	go func() {
		defer close(ch)
		for pager.More() {
			nextResult, err := pager.NextPage(c.ctx)
			if err != nil {
				ch <- fmt.Errorf("failed to get next page of results: %w", err)
			}
			if nextResult.Value != nil {
				roleAssignments = append(roleAssignments, nextResult.Value...)
			}
		}
		ch <- nil
	}()

	select {
	case err := <-ch:
		return roleAssignments, err
	case <-c.ctx.Done():
		return roleAssignments, fmt.Errorf("context cancelled")
	}
}

// AzureRoleDefinitionsClient is a facade over the Azure role definitions client. Code that uses
// this instead of the actual Azure client is easier to test because it won't need to deal with
// finding the permissions part of the API response.
type AzureRoleDefinitionsClient struct {
	ctx    context.Context
	client *armauthorization.RoleDefinitionsClient
}

// NewAzureRoleDefinitionsClient creates a new AzureRoleDefinitionsClient (our facade client) from a
// client from the Azure SDK.
func NewAzureRoleDefinitionsClient(ctx context.Context, azClient *armauthorization.RoleDefinitionsClient) *AzureRoleDefinitionsClient {
	return &AzureRoleDefinitionsClient{
		ctx:    ctx,
		client: azClient,
	}
}

// GetByID gets the role definition associated with a role assignment because it uses the
// fully-qualified role ID contained within the role assignment data to retrieve it from Azure.
func (c *AzureRoleDefinitionsClient) GetByID(roleID string) (*armauthorization.RoleDefinition, error) {
	roleDefinitionResp, err := c.client.GetByID(c.ctx, roleID, nil)
	if err != nil {
		return &armauthorization.RoleDefinition{}, fmt.Errorf("failed to get role definition for with ID %s: %w", roleID, err)
	}
	return &roleDefinitionResp.RoleDefinition, nil
}

// RoleNameFromRoleDefinitionID extracts the name of a role (aka the non-fully-qualified ID of the
// role) from an Azure role definition ID (aka the fully-qualified ID of the role definition).
func RoleNameFromRoleDefinitionID(roleDefinitionID string) string {
	split := strings.Split(roleDefinitionID, "/")
	roleName := split[len(split)-1]
	return roleName
}
