package azure

import (
	"fmt"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	corev1 "k8s.io/api/core/v1"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/pkg/constants"
	azerr "github.com/validator-labs/validator-plugin-azure/pkg/utils/azureerrors"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapiconstants "github.com/validator-labs/validator/pkg/constants"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
)

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
}

// RBACRuleService reconciles RBAC rules.
type RBACRuleService struct {
	daAPI denyAssignmentAPI
	raAPI roleAssignmentAPI
	rdAPI roleDefinitionAPI
}

// NewRBACRuleService creates a new RBACRuleService. Requires Azure client facades that support
// getting deny assignments, role assignments, and role definitions.
func NewRBACRuleService(daAPI denyAssignmentAPI, raAPI roleAssignmentAPI, rdAPI roleDefinitionAPI) *RBACRuleService {
	return &RBACRuleService{
		daAPI: daAPI,
		raAPI: raAPI,
		rdAPI: rdAPI,
	}
}

// ReconcileRBACRule reconciles an RBAC rule.
func (s *RBACRuleService) ReconcileRBACRule(rule v1alpha1.RBACRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default ValidationResult for this role assignment rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Failures = []string{}
	latestCondition.Message = "Principal has all required permissions."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.Name())
	latestCondition.ValidationType = constants.ValidationTypeRBAC
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	for _, set := range rule.Permissions {
		if err := s.processPermissionSet(set, rule.PrincipalID, &latestCondition.Failures); err != nil {
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

// processPermissionSet processes a permission set from the rule.
func (s *RBACRuleService) processPermissionSet(set v1alpha1.PermissionSet, principalID string, failures *[]string) error {

	// Get all deny assignments and role assignments for specified scope and principal.
	// Note that in this filter, Azure checks "principalId" to make sure it's a UUID, so we don't
	// need to escape the principal ID user input from the spec.
	daFilter := util.Ptr(fmt.Sprintf("principalId eq '%s'", principalID))
	denyAssignments, err := s.daAPI.GetDenyAssignmentsForScope(set.Scope, daFilter)
	if err != nil {
		return fmt.Errorf("failed to get deny assignments: %w", azerr.AsAugmented(err))
	}
	// Note that Azure's Go SDK for their API has a bug where it doesn't escape the filter string
	// for the role assignments call we do here, so we manually escape it ourselves.
	// https://github.com/Azure/azure-sdk-for-go/issues/20847
	raFilter := util.Ptr(url.QueryEscape(fmt.Sprintf("principalId eq '%s'", principalID)))
	roleAssignments, err := s.raAPI.GetRoleAssignmentsForScope(set.Scope, raFilter)
	if err != nil {
		return fmt.Errorf("failed to get role assignments: %w", azerr.AsAugmented(err))
	}

	// For each role assignment found, get its role definition, because that's what we actually need
	// to do validation. We need to know which Actions and DataActions the role permits.
	roleDefinitions := []*armauthorization.RoleDefinition{}
	for _, ra := range roleAssignments {
		if ra.Properties == nil {
			return fmt.Errorf("role assignment properties nil")
		}
		if ra.Properties.RoleDefinitionID == nil {
			return fmt.Errorf("role assignment properties role definition ID nil")
		}
		rdID := *ra.Properties.RoleDefinitionID
		// Note that, in Azure, in the role assignments API, the value is called "role definition
		// ID", but in the role definitions API, it is called "role ID".
		roleDefinition, err := s.rdAPI.GetByID(rdID)
		if err != nil {
			return fmt.Errorf("failed to get role definition using role definition ID of role assignment: %w", azerr.AsAugmented(err))
		}
		roleDefinitions = append(roleDefinitions, roleDefinition)
	}

	// Convert from ActionStr to string.
	setActions := []string{}
	for _, a := range set.Actions {
		setActions = append(setActions, string(a))
	}
	setDataActions := []string{}
	for _, da := range set.DataActions {
		setDataActions = append(setDataActions, string(da))
	}

	// Get the results and append failure messages if needed.
	result, err := processAllCandidateActions(setActions, setDataActions, denyAssignments, roleDefinitions)
	if err != nil {
		return fmt.Errorf("failed to determine which candidate Actions and DataActions were denied and/or unpermitted: %w", err)
	}
	for denied, by := range result.actions.denied {
		*failures = append(*failures, fmt.Sprintf("Action %s denied by deny assignment %s.", denied, by))
	}
	for _, unpermitted := range result.actions.unpermitted {
		*failures = append(*failures, fmt.Sprintf("Action %s unpermitted because no role assignment permits it.", unpermitted))
	}
	for denied, by := range result.dataActions.denied {
		*failures = append(*failures, fmt.Sprintf("DataAction %s denied by deny assignment %s.", denied, by))
	}
	for _, unpermitted := range result.dataActions.unpermitted {
		*failures = append(*failures, fmt.Sprintf("DataAction %s unpermitted because no role assignment permits it.", unpermitted))
	}

	// The `failures` slice will have been changed appropriately by here. Calling code will handle
	// this appropriately.
	return nil
}
