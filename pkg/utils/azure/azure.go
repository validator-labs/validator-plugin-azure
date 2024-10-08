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
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/quota/armquota"
)

// TestClientTimeout is the timeout used for Azure clients during tests.
const TestClientTimeout = 10 * time.Second

// API is an container that aggregates Azure service clients.
type API struct {
	DenyAssignmentsClient *armauthorization.DenyAssignmentsClient
	RoleAssignmentsClient *armauthorization.RoleAssignmentsClient
	RoleDefinitionsClient *armauthorization.RoleDefinitionsClient
	// Subscription ID is needed per API call for this client, so the client can't be created until
	// right before it's used while reconciling a rule.
	CommunityGalleryImagesClientProducer func(string) (*armcompute.CommunityGalleryImagesClient, error)
	QuotaLimitsClient                    *armquota.Client
	UsagesClient                         *armquota.UsagesClient
}

// NewAzureAPI creates an AzureAPI.
func NewAzureAPI() (*API, error) {
	// Get credentials from the three env vars. For more info on default auth, see:
	// https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication
	var cred *azidentity.DefaultAzureCredential
	var err error
	if cred, err = azidentity.NewDefaultAzureCredential(nil); err != nil {
		return nil, fmt.Errorf("failed to prepare default Azure credential: %w", err)
	}

	// Minimize retries/timeouts for tests and ensure the correct Azure cloud is connected to.
	opts := &armpolicy.ClientOptions{
		ClientOptions: policy.ClientOptions{
			Retry: policy.RetryOptions{},
			Cloud: azureCloudFromEnv(),
		},
	}
	if os.Getenv("IS_TEST") == "true" {
		httpClient := http.DefaultClient
		httpClient.Timeout = TestClientTimeout

		opts.ClientOptions.Retry.MaxRetries = -1
		opts.ClientOptions.Retry.TryTimeout = TestClientTimeout
		opts.ClientOptions.Transport = policy.Transporter(httpClient)
	}

	// For clients we create with empty subscription ID args, these are clients where the
	// subscription ID is only used in some API calls. We don't use those API calls, so we don't
	// need to provide it.
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

	// Some API calls we make require subscription ID, but it's possible to use the validator plugin
	// in a way where more than one subscription is used during validation. For these API calls, we
	// use API client producers which allow the subscription ID to be specified during validation
	// rule reconciliation, at which point a new client with the required subscription ID is
	// produced.
	cgiClientProducer := func(subscriptionID string) (*armcompute.CommunityGalleryImagesClient, error) {
		return armcompute.NewCommunityGalleryImagesClient(subscriptionID, cred, opts)
	}

	quotaLimitsClient, err := armquota.NewClient(cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure quota limits client: %w", err)
	}
	usagesClient, err := armquota.NewUsagesClient(cred, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure usages client: %w", err)
	}

	return &API{
		DenyAssignmentsClient:                daClient,
		RoleAssignmentsClient:                raClient,
		RoleDefinitionsClient:                rdClient,
		CommunityGalleryImagesClientProducer: cgiClientProducer,
		QuotaLimitsClient:                    quotaLimitsClient,
		UsagesClient:                         usagesClient,
	}, err
}

// DenyAssignmentsClient is a facade over the Azure deny assignments client. Exists to make our
// code easier to test (it handles paging).
type DenyAssignmentsClient struct {
	ctx    context.Context
	client *armauthorization.DenyAssignmentsClient
}

// NewDenyAssignmentsClient creates a new AzureDenyAssignmentsClient (our facade client) from a
// client from the Azure SDK.
func NewDenyAssignmentsClient(ctx context.Context, azClient *armauthorization.DenyAssignmentsClient) *DenyAssignmentsClient {
	return &DenyAssignmentsClient{
		ctx:    ctx,
		client: azClient,
	}
}

// GetDenyAssignmentsForScope gets all the deny assignments matching a scope and an optional filter.
func (c *DenyAssignmentsClient) GetDenyAssignmentsForScope(scope string, filter *string) ([]*armauthorization.DenyAssignment, error) {
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

// RoleAssignmentsClient is a facade over the Azure role assignments client. Exists to make our
// code easier to test (it handles paging).
type RoleAssignmentsClient struct {
	ctx    context.Context
	client *armauthorization.RoleAssignmentsClient
}

// NewRoleAssignmentsClient creates a new AzureRoleAssignmentsClient (our facade client) from a
// client from the Azure SDK.
func NewRoleAssignmentsClient(ctx context.Context, azClient *armauthorization.RoleAssignmentsClient) *RoleAssignmentsClient {
	return &RoleAssignmentsClient{
		ctx:    ctx,
		client: azClient,
	}
}

// GetRoleAssignmentsForScope gets all the role assignments matching a scope and an optional filter.
func (c *RoleAssignmentsClient) GetRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error) {
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

// RoleDefinitionsClient is a facade over the Azure role definitions client. Code that uses
// this instead of the actual Azure client is easier to test because it won't need to deal with
// finding the permissions part of the API response.
type RoleDefinitionsClient struct {
	ctx    context.Context
	client *armauthorization.RoleDefinitionsClient
}

// NewRoleDefinitionsClient creates a new AzureRoleDefinitionsClient (our facade client) from a
// client from the Azure SDK.
func NewRoleDefinitionsClient(ctx context.Context, azClient *armauthorization.RoleDefinitionsClient) *RoleDefinitionsClient {
	return &RoleDefinitionsClient{
		ctx:    ctx,
		client: azClient,
	}
}

// GetByID gets the role definition associated with a role assignment because it uses the
// fully-qualified role ID contained within the role assignment data to retrieve it from Azure.
func (c *RoleDefinitionsClient) GetByID(roleID string) (*armauthorization.RoleDefinition, error) {
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

// CommunityGalleryImagesClient is a facade over the Azure community gallery images client.
// Exists to make our code easier to test (it handles paging).
type CommunityGalleryImagesClient struct {
	ctx            context.Context
	clientProducer func(string) (*armcompute.CommunityGalleryImagesClient, error)
}

// NewCommunityGalleryImagesClient creates a new AzureRoleDefinitionsClient (our facade
// client) from a client from the Azure SDK.
func NewCommunityGalleryImagesClient(ctx context.Context, azClientProducer func(subscriptionID string) (*armcompute.CommunityGalleryImagesClient, error)) *CommunityGalleryImagesClient {
	return &CommunityGalleryImagesClient{
		ctx:            ctx,
		clientProducer: azClientProducer,
	}
}

// GetImagesForGallery gets all the images in a community gallery.
func (c *CommunityGalleryImagesClient) GetImagesForGallery(location, name, subscriptionID string) ([]*armcompute.CommunityGalleryImage, error) {
	client, err := c.clientProducer(subscriptionID)
	if err != nil {
		return []*armcompute.CommunityGalleryImage{}, fmt.Errorf("failed to produce client with subscription ID %s: %w", subscriptionID, err)
	}

	var images []*armcompute.CommunityGalleryImage
	pager := client.NewListPager(location, name, &armcompute.CommunityGalleryImagesClientListOptions{})

	ch := make(chan error)
	go func() {
		defer close(ch)
		for pager.More() {
			nextResult, err := pager.NextPage(c.ctx)
			if err != nil {
				ch <- fmt.Errorf("failed to get next page of results: %w", err)
			}
			if nextResult.Value != nil {
				images = append(images, nextResult.Value...)
			}
		}
		ch <- nil
	}()

	select {
	case err := <-ch:
		return images, err
	case <-c.ctx.Done():
		return images, fmt.Errorf("context cancelled")
	}
}

// QuotasClient is a facade over the Azure quotas client role definitions client.
// Exists to make our code easier to test (it handles paging).
type QuotasClient struct {
	ctx          context.Context
	quotasClient *armquota.Client
	usagesClient *armquota.UsagesClient
}

// NewQuotasClient creates a new QuotasClient (our facade client) from a client from the Azure SDK.
func NewQuotasClient(ctx context.Context, azQuotasClient *armquota.Client, azUsagesCient *armquota.UsagesClient) *QuotasClient {
	return &QuotasClient{
		ctx:          ctx,
		quotasClient: azQuotasClient,
		usagesClient: azUsagesCient,
	}
}

// GetQuotasForScope gets the quota limits for a particular scope. Each quota limit describes a
// resource name and a currently set quota.
func (c *QuotasClient) GetQuotasForScope(scope string) ([]*armquota.CurrentQuotaLimitBase, error) {
	var quotaLimits []*armquota.CurrentQuotaLimitBase
	pager := c.quotasClient.NewListPager(scope, nil)

	ch := make(chan error)
	go func() {
		defer close(ch)
		for pager.More() {
			nextResult, err := pager.NextPage(c.ctx)
			if err != nil {
				ch <- fmt.Errorf("failed to get next page of results: %w", err)
			}
			if nextResult.Value != nil {
				quotaLimits = append(quotaLimits, nextResult.Value...)
			}
		}
		ch <- nil
	}()

	select {
	case err := <-ch:
		return quotaLimits, err
	case <-c.ctx.Done():
		return quotaLimits, fmt.Errorf("context cancelled")
	}
}

// GetUsagesForScope gets the quota usages for a particular scope. Each quota usage describes a
// resource name and the currently used amount. There is usually a 1-to-1 pairing of quota limit and
// quota usage that can be retrieved.
func (c *QuotasClient) GetUsagesForScope(scope string) ([]*armquota.CurrentUsagesBase, error) {
	var quotaUsages []*armquota.CurrentUsagesBase
	pager := c.usagesClient.NewListPager(scope, nil)

	ch := make(chan error)
	go func() {
		defer close(ch)
		for pager.More() {
			nextResult, err := pager.NextPage(c.ctx)
			if err != nil {
				ch <- fmt.Errorf("failed to get next page of results: %w", err)
			}
			if nextResult.Value != nil {
				quotaUsages = append(quotaUsages, nextResult.Value...)
			}
		}
		ch <- nil
	}()

	select {
	case err := <-ch:
		return quotaUsages, err
	case <-c.ctx.Done():
		return quotaUsages, fmt.Errorf("context cancelled")
	}
}

// azureCloudFromEnv returns the Azure cloud to use based on the AZURE_ENVIRONMENT environment
// variable.
func azureCloudFromEnv() cloud.Configuration {
	switch os.Getenv("AZURE_ENVIRONMENT") {
	case "AzureUSGovernment":
		return cloud.AzureGovernment
	case "AzureChinaCloud":
		return cloud.AzureChina
	default:
		// Includes the env var being unset and it being set to "AzureCloud" or any other value.
		return cloud.AzurePublic
	}
}
