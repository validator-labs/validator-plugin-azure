// Package path implements validation for the rules supported by this validator plugin.
package validators

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

// roleAssignmentAPI contains methods that allow getting all role assignments for a subscription.
// Note that this is the API of our Azure client facade, not a real Azure client.
type roleAssignmentAPI interface {
	ListRoleAssignmentsForSubscription(subscriptionID string, filter *string) ([]*armauthorization.RoleAssignment, error)
}

// roleLookupMapProvider provides a lookup map of role names to names.
type roleLookupMapProvider func(subscriptionID string) (map[string]string, error)
