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

const (
	RoleTypeBuiltInRole = "BuiltInRole"
)

var (
	// Regexp used for extracting Subscription IDs from role assignment scope strings.
	re = regexp.MustCompile(`subscriptions/([a-fA-F0-9\-]+)`)
)

// NewRoleAssignmentsClient creates a RoleAssignmentsClient from the Azure SDK.
func NewRoleAssignmentsClient() (*armauthorization.RoleAssignmentsClient, error) {
	// Get credentials from the three env vars. For more info on default auth, see:
	// https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication
	var cred *azidentity.DefaultAzureCredential
	var err error
	if cred, err = azidentity.NewDefaultAzureCredential(nil); err != nil {
		return nil, fmt.Errorf("failed to prepare default Azure credential: %w", err)
	}

	// SubscriptionID arg value isn't relevant because we won't be using methods from the client
	// that use the subscription ID state. We'll only use scope methods, where subscription ID is
	// provided for each query, if relevant for the scope used in the query.
	client, err := armauthorization.NewRoleAssignmentsClient("", cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	return client, nil
}

// RoleNameFromRoleDefinitionID extracts the name of a role from an Azure role definition ID. See
// test case for example.
func RoleNameFromRoleDefinitionID(roleDefinitionID string) string {
	split := strings.Split(roleDefinitionID, "/")
	roleName := split[len(split)-1]
	return roleName
}

// AzureRoleAssignmentsClient is a facade over the Azure role assignments client. Code that uses
// this instead of the actual Azure client is easier to test because it won't need to deal with
// paging.
type AzureRoleAssignmentsClient struct {
	client *armauthorization.RoleAssignmentsClient
}

// NewAzureRoleAssignmentsClient creates a new AzureRoleAssignmentsClient (our facade client) from
// a client from the Azure SDK.
//   - azClient: A role assignments client from the Azure SDK. Must be non-nil.
func NewAzureRoleAssignmentsClient(azClient *armauthorization.RoleAssignmentsClient) *AzureRoleAssignmentsClient {
	return &AzureRoleAssignmentsClient{
		client: azClient,
	}
}

// ListRoleAssignmentsForScope gets all the role assignments matching a scope.
//   - scope: The scope for the role assignments query. This can be any scope supported by Azure
//     (e.g. subscription scope).
//   - filter: An optional filter to apply, using the Azure Authorization API filter syntax.
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

// RoleAssignmentScopeSubscription extracts the ID of the subscription from a role assignment scope
// string. Returns an error if the string is malformed, so that the error can be displayed in the
// logs and the user knows they didn't configure scope somewhere in the spec correctly.
//   - scope: The scope string to parse. Must be a valid scope string according to Azure API specs.
func RoleAssignmentScopeSubscription(scope string) (string, error) {
	matches := re.FindStringSubmatch(scope)

	if len(matches) < 2 {
		return "", fmt.Errorf("no subscription GUID found in the scope string; string may be invalid")
	}

	return matches[1], nil
}
