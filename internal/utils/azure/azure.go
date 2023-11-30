// Package azure implements utilities that relate to more than one thing we want to do with Azure
// for the plugin's validation logic.
package azure

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

var (
	// Regexp used for extracting Subscription IDs from role assignment scope strings.
	re = regexp.MustCompile(`subscriptions/([a-fA-F0-9\-]+)`)
)

type AzureAPI struct {
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

	// SubscriptionID arg value isn't relevant because we won't be using methods from the client
	// that use the subscription ID state. We'll only use scope methods, where subscription ID is
	// provided for each query if relevant for the scope used in the query.
	raClient, err := armauthorization.NewRoleAssignmentsClient("", cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure role assignments client: %w", err)
	}

	rdClient, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure role assignments client: %w", err)
	}

	return &AzureAPI{
		RoleAssignments: raClient,
		RoleDefinitions: rdClient,
	}, err
}

// AzureRoleAssignmentsClient is a facade over the Azure role assignments client. Code that uses
// this instead of the actual Azure client is easier to test because it won't need to deal with
// paging.
type AzureRoleAssignmentsClient struct {
	client *armauthorization.RoleAssignmentsClient
}

// NewAzureRoleAssignmentsClient creates a new AzureRoleAssignmentsClient (our facade client) from a
// client from the Azure SDK.
func NewAzureRoleAssignmentsClient(azClient *armauthorization.RoleAssignmentsClient) *AzureRoleAssignmentsClient {
	return &AzureRoleAssignmentsClient{
		client: azClient,
	}
}

// ListRoleAssignmentsForScope gets all the role assignments matching a scope.
func (c *AzureRoleAssignmentsClient) ListRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error) {
	pager := c.client.NewListForScopePager(scope, &armauthorization.RoleAssignmentsClientListForScopeOptions{
		Filter: filter,
	})

	var roleAssignments []*armauthorization.RoleAssignment
	for pager.More() {
		nextResult, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("failed to get next page of results: %w", err)
		}
		if nextResult.RoleAssignmentListResult.Value != nil {
			roleAssignments = append(roleAssignments, nextResult.Value...)
		}
	}

	return roleAssignments, nil
}

// AzureRoleDefinitionsClient is a facade over the Azure role definitions client. Code that uses
// this instead of the actual Azure client is easier to test because it won't need to deal with
// finding the permissions part of the API response.
type AzureRoleDefinitionsClient struct {
	client *armauthorization.RoleDefinitionsClient
}

// NewAzureRoleDefinitionsClient creates a new AzureRoleDefinitionsClient (our facade client) from a
// client from the Azure SDK.
func NewAzureRoleDefinitionsClient(azClient *armauthorization.RoleDefinitionsClient) *AzureRoleDefinitionsClient {
	return &AzureRoleDefinitionsClient{
		client: azClient,
	}
}

// GetPermissionDataForRoleDefinition gets the permissions data for a role definition, given its
// role definition ID (the short ID, not the fully-qualified one) and its scope.
func (c *AzureRoleDefinitionsClient) GetPermissionDataForRoleDefinition(roleDefinitionID, scope string) (*armauthorization.Permission, error) {
	roleDefinition, err := c.client.Get(context.TODO(), scope, roleDefinitionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get role definition data: %w", err)
	}

	if roleDefinition.Properties == nil || roleDefinition.Properties.Permissions == nil {
		return nil, fmt.Errorf("role definition data from Azure API response malformed (missing permissions property): %w", err)
	}

	// This is intentional. The API response's type is a slice of permissions structs (not just a
	// struct), and as far as we can tell, there will always be only one of them in the slice, no
	// matter how many permissions exist in the data and how often changes are made to the role
	// definition.
	if len(roleDefinition.Properties.Permissions) != 1 {
		return nil, fmt.Errorf("role definition data from Azure API response malformed (not exactly one permissions data struct)")
	}

	return roleDefinition.Properties.Permissions[0], nil
}

// RoleNameFromRoleDefinitionID extracts the name of a role from an Azure role definition ID.
func RoleNameFromRoleDefinitionID(roleDefinitionID string) string {
	split := strings.Split(roleDefinitionID, "/")
	roleName := split[len(split)-1]
	return roleName
}

// RoleAssignmentScopeSubscription extracts the ID of the subscription from a role assignment scope
// string. Returns an error if the string is malformed.
func RoleAssignmentScopeSubscription(scope string) (string, error) {
	matches := re.FindStringSubmatch(scope)

	if len(matches) < 2 {
		return "", fmt.Errorf("no subscription GUID found in the scope string; string may be invalid")
	}

	return matches[1], nil
}
