package azure

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
)

const (
	RoleTypeBuiltInRole = "BuiltInRole"
)

// NewRoleAssignmentsClient creates a RoleAssignmentsClient from the Azure SDK for working with a
// particular subscription.
func NewRoleAssignmentsClient(subscriptionID string) (*armauthorization.RoleAssignmentsClient, error) {
	clientFactory, err := armAuthClientFactory(subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("could not get armauthorization client factory: %w", err)
	}

	return clientFactory.NewRoleAssignmentsClient(), nil
}

// RoleNameFromRoleDefinitionID extracts the name of a role from an Azure role definition ID. See
// test case for example.
func RoleNameFromRoleDefinitionID(roleDefinitionID string) string {
	split := strings.Split(roleDefinitionID, "/")
	roleName := split[len(split)-1]
	return roleName
}

// BuiltInRoleLookupMap creates a map that can be used to look up the "name" of
// a built-in role (e.g. "b24988ac-6180-42a0-ab88-20f7382dd24c") given the "role
// name" of the role (e.g. "Contributor").
//
// The role definitions retrieved will be the ones in the subscription
// associated with param subscriptionID. Normally, the subcription to query
// would not matter because we're only interested in the built-in roles, not
// roles created by the Azure user, and the built-in roles will exist in every
// subscription. However, this code must be authenticated to read from the
// subscription, so it must be a subscription that the service principal the
// plugin is authenticated as can read from.
func BuiltInRoleLookupMap(subscriptionID string) (map[string]string, error) {
	clientFactory, err := armAuthClientFactory(subscriptionID)
	if err != nil {
		return nil, fmt.Errorf("could not get armauthorization client factory: %w", err)
	}

	client := clientFactory.NewRoleDefinitionsClient()

	pager := client.NewListPager(fmt.Sprintf("/subscriptions/%s", subscriptionID), nil)

	var roleDefinitions []*armauthorization.RoleDefinition
	for pager.More() {
		nextResult, _ := pager.NextPage(context.TODO())
		if nextResult.RoleDefinitionListResult.Value != nil {
			roleDefinitions = append(roleDefinitions, nextResult.RoleDefinitionListResult.Value...)
		}
	}

	builtins := map[string]string{}

	for _, rd := range roleDefinitions {
		if *rd.Properties.RoleType == RoleTypeBuiltInRole {
			builtins[*rd.Properties.RoleName] = *rd.Name
		}
	}

	return builtins, nil
}

// Attempts to retrieve the default Azure credential according to their chained configuration
// pattern, and prepare a client factory for making requests to APIs associated with the
// armauthorization package. Requires subscription ID parameter because the client factory comes
// prepared to make API requests against a particular subscription.
func armAuthClientFactory(subscriptionID string) (*armauthorization.ClientFactory, error) {
	var cred *azidentity.DefaultAzureCredential
	var err error
	if cred, err = azidentity.NewDefaultAzureCredential(nil); err != nil {
		return nil, fmt.Errorf("could not prepare default Azure credential: %w", err)
	}

	clientFactory, err := armauthorization.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create Azure client factory: %w", err)
	}

	return clientFactory, nil
}

// AzureRoleAssignmentsClient is a facade over the Azure role assignments client. Code that uses
// this instead of the actual Azure client is easier to test because it won't need to deal with
// paging.
type AzureRoleAssignmentsClient struct {
	client *armauthorization.RoleAssignmentsClient
}

// NewAzureRoleAssignmentsClient creates a new AzureRoleAssignmentsClient (our facade client) from
// a client from the Azure SDK.
func NewAzureRoleAssignmentsClient(azClient *armauthorization.RoleAssignmentsClient) *AzureRoleAssignmentsClient {
	client := AzureRoleAssignmentsClient{
		client: azClient,
	}
	return &client
}

// ListRoleAssignmentsForSubscription gets all the role assignments in a subscription.
//   - subscriptionID: The subscription to get role assignments for.
//   - filter: An optional filter to apply, using the Azure filter syntax.
func (c *AzureRoleAssignmentsClient) ListRoleAssignmentsForSubscription(subscriptionID string, filter *string) ([]*armauthorization.RoleAssignment, error) {
	pager := c.client.NewListForSubscriptionPager(&armauthorization.RoleAssignmentsClientListForSubscriptionOptions{
		Filter: filter,
	})
	var roleAssignments []*armauthorization.RoleAssignment
	for pager.More() {
		nextResult, err := pager.NextPage(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("failed to get next page of results: %w", err)
		}
		if nextResult.RoleAssignmentListResult.Value != nil {
			roleAssignments = append(roleAssignments, nextResult.RoleAssignmentListResult.Value...)
		}
	}
	return roleAssignments, nil
}
