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

// NewRoleAssignmentsClient creates an Azure role assignments client for working
// with a particular subscription.
func NewRoleAssignmentsClient(subscriptionID string) (*armauthorization.RoleAssignmentsClient, error) {
	var cred *azidentity.DefaultAzureCredential
	var err error
	if cred, err = azidentity.NewDefaultAzureCredential(nil); err != nil {
		return nil, fmt.Errorf("could not prepare default Azure credential: %w", err)
	}

	clientFactory, err := armauthorization.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create Azure client factory: %w", err)
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
	var cred *azidentity.DefaultAzureCredential
	var err error
	if cred, err = azidentity.NewDefaultAzureCredential(nil); err != nil {
		return nil, fmt.Errorf("could not prepare default Azure credential: %w", err)
	}

	clientFactory, err := armauthorization.NewClientFactory(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("could not create Azure client factory: %w", err)
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
