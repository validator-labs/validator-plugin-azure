package validators

import (
	"fmt"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/constants"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapiconstants "github.com/spectrocloud-labs/validator/pkg/constants"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	corev1 "k8s.io/api/core/v1"
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

type RBACRuleService struct {
	log   logr.Logger
	daAPI denyAssignmentAPI
	raAPI roleAssignmentAPI
	rdAPI roleDefinitionAPI
}

func NewRBACRuleService(log logr.Logger, daAPI denyAssignmentAPI, raAPI roleAssignmentAPI, rdAPI roleDefinitionAPI) *RBACRuleService {
	return &RBACRuleService{
		log:   log,
		daAPI: daAPI,
		raAPI: raAPI,
		rdAPI: rdAPI,
	}
}

// ReconcileRBACRule reconciles a role assignment rule from a validation config.
func (s *RBACRuleService) ReconcileRBACRule(rule v1alpha1.RBACRule) (*vapitypes.ValidationResult, error) {

	// Build the default ValidationResult for this role assignment rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Failures = []string{}
	latestCondition.Message = "Principal has all required permissions."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.PrincipalID)
	latestCondition.ValidationType = constants.ValidationTypeRBAC
	validationResult := &vapitypes.ValidationResult{Condition: &latestCondition, State: &state}

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

	// We consider this spec invalid. Both are optional at the spec level because we need to allow
	// users to validate a set of required control Actions, a set of required DataActions, or both.
	// But, if a user provides neither, it means they don't have any validation to be done, and they
	// shouldn't create the AzureValidator.
	if set.Actions == nil && set.DataActions == nil {
		return fmt.Errorf("spec invalid; must specify at least actions or dataActions in each permission set")
	}

	// Also invalid. If they've specified one or the other, but end up being empty in Go, it again
	// means that they've only specified empty lists in the YAML, and they don't have any
	// validation to be done, and they shouldn't create the AzureValidator.
	if len(set.Actions) == 0 && len(set.DataActions) == 0 {
		return fmt.Errorf("spec invalid; must have at least one required Action or one required DataAction to validate")
	}

	// Get all deny assignments and role assignments for specified scope and principal.
	// Note that in this filter, Azure checks "principalId" to make sure it's a UUID, so we don't
	// need to escape the principal ID user input from the spec.
	daFilter := ptr.Ptr(fmt.Sprintf("principalId eq '%s'", principalID))
	denyAssignments, err := s.daAPI.GetDenyAssignmentsForScope(set.Scope, daFilter)
	if err != nil {
		return fmt.Errorf("failed to get deny assignments: %w", err)
	}
	// Note that Azure's Go SDK for their API has a bug where it doesn't escape the filter string
	// for the role assignments call we do here, so we manually escape it ourselves.
	// https://github.com/Azure/azure-sdk-for-go/issues/20847
	raFilter := ptr.Ptr(url.QueryEscape(fmt.Sprintf("principalId eq '%s'", principalID)))
	roleAssignments, err := s.raAPI.GetRoleAssignmentsForScope(set.Scope, raFilter)
	if err != nil {
		return fmt.Errorf("failed to get role assignments: %w", err)
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
			return fmt.Errorf("failed to get role definition using role definition ID of role assignment: %w", err)
		}
		roleDefinitions = append(roleDefinitions, roleDefinition)
	}

	// Get the results and append failure messages if needed.
	result, err := processAllCandidateActions(set.Actions, set.DataActions, denyAssignments, roleDefinitions)
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
