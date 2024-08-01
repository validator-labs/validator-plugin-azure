package validators

import (
	"fmt"

	corev1 "k8s.io/api/core/v1"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/internal/constants"
	"github.com/validator-labs/validator-plugin-azure/internal/utils/azure"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapiconstants "github.com/validator-labs/validator/pkg/constants"
	vapitypes "github.com/validator-labs/validator/pkg/types"
)

// roleAssignmentAPI contains methods that allow getting all role assignments for a scope and
// optional filter.
type roleAssignmentAPI interface {
	GetRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error)
}

// roleDefinitionAPI contains methods that allow getting all the information we need for an existing
// role definition.
type roleDefinitionAPI interface {
	GetByID(roleID string) (*armauthorization.RoleDefinition, error)
}

// RBACRoleRuleService reconciles RBAC role rules.
type RBACRoleRuleService struct {
	raAPI roleAssignmentAPI
	rdAPI roleDefinitionAPI
}

// NewRBACRoleRuleService creates a new RBACRoleRuleService. Requires Azure client facades that
// support, role assignments, and role definitions.
func NewRBACRoleRuleService(raAPI roleAssignmentAPI, rdAPI roleDefinitionAPI) *RBACRoleRuleService {
	return &RBACRoleRuleService{
		raAPI: raAPI,
		rdAPI: rdAPI,
	}
}

// ReconcileRBACRoleRule reconciles an RBAC role rule.
func (s *RBACRoleRuleService) ReconcileRBACRoleRule(rule v1alpha1.RBACRoleRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default ValidationResult for this role assignment rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Failures = []string{}
	latestCondition.Message = "All role assignments correct. Roles contain permissions and assigned to principal at scopes."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.Name)
	latestCondition.ValidationType = constants.ValidationTypeRBACRole
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	for _, raSpec := range rule.RoleAssignments {
		newFailure, err := s.processRoleAssignment(raSpec, rule.PrincipalID)
		if err != nil {
			// Code this is returning to will take care of changing the validation result to a
			// failed validation, using the error returned.
			return validationResult, err
		}
		if newFailure != "" {
			latestCondition.Failures = append(latestCondition.Failures, newFailure)
		}
	}

	if len(latestCondition.Failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Message = "Principal lacks required permissions. See failures for details."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}

// processRoleAssignment processes one role assignment in the rule. Returns a string for a new
// failure to append to the rule's failures or an error is something stopped it from validating the
// role assignment.
func (s *RBACRoleRuleService) processRoleAssignment(raSpec v1alpha1.RoleAssignment, principalID string) (string, error) {
	// Get all role assignments for principal at scope.
	raFilter := azure.RoleAssignmentRequestFilter(principalID)
	roleAssignments, err := s.raAPI.GetRoleAssignmentsForScope(raSpec.Scope, &raFilter)
	if err != nil {
		return "", fmt.Errorf("failed to get role assignments for principal '%s' at scope '%s': %w", principalID, principalID, err)
	}

	// Optimization for better failure message. If there are no role assignments, the principal
	// definitely isn't assigned an appropriate role.
	if len(roleAssignments) == 0 {
		return fmt.Sprintf("No role assignments found for principal '%s' at scope '%s'.", principalID, raSpec.Scope), nil
	}

	// For each role assignment, use its role definition ID to fetch the corresponding role
	// definition. If the role definition's role type, role name, and permissions match, and the
	// role assignment's scope matches the scope defined in the rule (meaning the role isn't
	// assigned at a scope greater than required), validation passes.
	for _, ra := range roleAssignments {
		// Check role assignment API response for nils. Not expected, but theoretically possible.
		if ra == nil || ra.ID == nil || ra.Properties == nil || ra.Properties.RoleDefinitionID == nil || ra.Properties.Scope == nil {
			return "", fmt.Errorf("role assignment from API response missing expected properties")
		}

		// Get role definition for role assignment.
		//
		// This happens within the loop, so it results in sequential API calls (until a suitable
		// role is found), and it would be nice to be able to get all role definitions we need at
		// once so that it finishes making API calls sooner. But, that won't work for our use case.
		// To list role definitions, we need to know their scope (which means whether they're at the
		// subscription or tenant level, and which subscriptions or tenants those are). It's
		// impossible to know all of the roles that could be assigned to the principal, but it's
		// possible to start from the role assignments and use the role definition IDs in them to
		// see which roles are assigned. So, we do it that way instead. In the real world, Azure
		// users typically assign fewer, larger roles instead of many, smaller roles, so the issue
		// of time to complete sequential API calls should be negligible.
		roleDef, err := s.rdAPI.GetByID(*ra.Properties.RoleDefinitionID)
		if err != nil {
			return "", fmt.Errorf("failed to get role definition '%s' (for role assignment '%s'): %w",
				*ra.Properties.RoleDefinitionID, *ra.ID, err)
		}

		// Check role def API response for nils or permissions with lenth not equal to 1. Not
		// expected, but theoretically possible.
		if roleDef.Properties == nil || roleDef.Properties.Permissions == nil || roleDef.Properties.RoleType == nil || roleDef.Properties.RoleName == nil {
			return "", fmt.Errorf("role definition '%s' from API response missing expected properties", *ra.Properties.RoleDefinitionID)
		}
		if len(roleDef.Properties.Permissions) != 1 {
			return "", fmt.Errorf("role definition '%s' from API response has unexpected number of permissions", *ra.Properties.RoleDefinitionID)
		}

		if *roleDef.Properties.RoleType == raSpec.Role.Type &&
			*roleDef.Properties.RoleName == raSpec.Role.Name &&
			*ra.Properties.Scope == raSpec.Scope &&
			raSpec.Role.Permission.Equal(*roleDef.Properties.Permissions[0]) {
			// Validation passes, no need to continue checking other role assignments.
			return "", nil
		}
	}

	// If no role assignments that match were found, validation fails.
	//
	// We cannot return unique failure messages for each issue that could occur because we need to
	// check all role assignments. The failure means there is no suitable role assignment, not that
	// a particular role assignment is wrong.
	return fmt.Sprintf("Principal '%s' does not have role with type '%s' and role name '%s' assigned at scope '%s' with required permissions.",
		principalID, raSpec.Role.Type, raSpec.Role.Name, raSpec.Scope), nil
}
