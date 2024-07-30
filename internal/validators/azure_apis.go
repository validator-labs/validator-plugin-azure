package validators

import "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

// denyAssignmentAPI contains methods that allow getting all deny assignments for a scope and
// optional filter.
type denyAssignmentAPI interface {
	GetDenyAssignmentsForScope(scope string, filter *string) ([]*armauthorization.DenyAssignment, error)
}

// roleAssignmentAPI contains methods that allow getting all role assignments for a scope and
// optional filter.
type roleAssignmentAPI interface {
	GetRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error)
}

// roleDefinitionAPI contains methods that allow getting all the information we need for an existing
// role definition.
type roleDefinitionAPI interface {
	GetByID(roleID string) (*armauthorization.RoleDefinition, error)
	GetRoleDefinitionsForScope(scope string) ([]*armauthorization.RoleDefinition, error)
}
