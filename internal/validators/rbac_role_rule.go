package validators

import (
	"bytes"
	"encoding/json"
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

// RBACRoleRuleService reconciles RBAC role rules.
type RBACRoleRuleService struct {
	raAPI roleAssignmentAPI
	rdAPI roleDefinitionAPI
}

// NewRBACRoleRuleService creates a new RBACRuleRoleService. Requires Azure client facades that
// support, role assignments, and role definitions.
func NewRBACRoleRuleService(raAPI roleAssignmentAPI, rdAPI roleDefinitionAPI) *RBACRuleService {
	return &RBACRuleService{
		raAPI: raAPI,
		rdAPI: rdAPI,
	}
}

// ReconcileRBACRule reconciles an RBAC role rule.
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
		if err := s.processRoleAssignment(raSpec, rule.PrincipalID, &latestCondition.Failures); err != nil {
			// Code this is returning to will take care of changing the validation result to a
			// failed validation, using the error returned.
			return validationResult, err
		}
	}

	if len(latestCondition.Failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Message = "Principal lacks required permissions. See failures for details."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}

func (s *RBACRoleRuleService) processRoleAssignment(raSpec v1alpha1.RoleAssignment, principalID string, failures *[]string) error {
	// Get all role assignments for principal at scope.
	raFilter := azure.RoleAssignmentRequestFilter(principalID)
	roleAssignments, err := s.raAPI.GetRoleAssignmentsForScope(principalID, &raFilter)
	if err != nil {
		return fmt.Errorf("failed to get role assignments for principal '%s' at scope '%s': %w", principalID, principalID, err)
	}

	// For each role assignment, use its role definition ID to fetch the corresponding role
	// definition. If the role definition's role type, role name, and permissions match, and the
	// role assignment's scope matches the scope defined in the rule (meaning the role isn't
	// assigned at a scope greater than required), validation passes.
	for _, ra := range roleAssignments {
		// Check role assignment API response for nils. Not expected, but theoretically possible.
		if ra.Properties == nil {
			return fmt.Errorf("role assignment '%s' does not have properties", *ra.Properties.RoleDefinitionID)
		}
		if ra.Properties.RoleDefinitionID == nil {
			return fmt.Errorf("role assignment '%s' does not have a role definition ID", ra.ID)
		}
		if ra.Properties.Scope == nil {
			return fmt.Errorf("role assignment '%s' does not have a scope", ra.ID)
		}

		roleDef, err := s.rdAPI.GetByID(*ra.Properties.RoleDefinitionID)
		if err != nil {
			return fmt.Errorf("failed to get role definition for role assignment '%s': %w", ra.ID, err)
		}

		// Check role def API response for nils. Not expected, but theoretically possible.
		if roleDef.Properties == nil {
			return fmt.Errorf("role definition '%s' does not have properties", *ra.Properties.RoleDefinitionID)
		}
		if roleDef.Properties.Permissions == nil {
			return fmt.Errorf("role definition '%s' does not have permissions", *ra.Properties.RoleDefinitionID)
		}
		if len(roleDef.Properties.Permissions) != 1 {
			return fmt.Errorf("role definition '%s' has unexpected number of permissions", *ra.Properties.RoleDefinitionID)
		}

		permsMatch, err := permissionsMatch(*roleDef.Properties.Permissions[0], raSpec.Role.Permissions)
		if err != nil {
			return fmt.Errorf("failed to compare permissions for role assignment '%s': %w", ra.ID, err)
		}
		typeMatches := *roleDef.Properties.RoleType == raSpec.Role.Type
		nameMatches := *roleDef.Properties.RoleName == raSpec.Role.Name
		scopeMatches := *ra.Properties.Scope == raSpec.Scope

		if typeMatches && nameMatches && scopeMatches && permsMatch {
			// Validation passes, no need to continue checking other role assignments.
			return nil
		}
	}

	// Otherwise, validation fails.
	*failures = append(*failures, fmt.Sprintf("Principal '%s' does not have role with type '%s' and role name '%s' assigned at scope '%s' with required permissions.",
		principalID, raSpec.Role.Type, raSpec.Role.Name, raSpec.Scope))
	return nil
}

// permissionsMatch checks if the permissions in a role definition match the permissions specified
// in the role assignment spec.
func permissionsMatch(rolePermissions armauthorization.Permission, raSpecPermissions v1alpha1.Permissions) (bool, error) {
	// A simple way to do thisSimplest way to do this is to marshal them both to JSON and compare.
	rolePermissionsJSON, err := json.Marshal(rolePermissions)
	if err != nil {
		return false, fmt.Errorf("failed to marshal role permissions to JSON: %w", err)
	}

	raSpecPermissionsJSON, err := json.Marshal(raSpecPermissions)
	if err != nil {
		return false, fmt.Errorf("failed to marshal role assignment spec permissions to JSON: %w", err)
	}

	if !bytes.Equal(rolePermissionsJSON, raSpecPermissionsJSON) {
		return false, nil
	}

	return true, nil
}
