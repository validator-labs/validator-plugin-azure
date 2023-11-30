package validators

import (
	"fmt"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/constants"
	azure_utils "github.com/spectrocloud-labs/validator-plugin-azure/internal/utils/azure"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapiconstants "github.com/spectrocloud-labs/validator/pkg/constants"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	"golang.org/x/exp/maps"
	corev1 "k8s.io/api/core/v1"
)

// roleAssignmentAPI contains methods that allow getting all role assignments for a scope.
//
// Note that this is the API of our Azure client facade, not a real Azure client.
type roleAssignmentAPI interface {
	ListRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error)
}

// roleDefinitionAPI contains methods that allow getting all the information we need for an existing
// role definition.
//
// Note that this is the API of our Azure client facade, not a real Azure client.
type roleDefinitionAPI interface {
	GetPermissionDataForRoleDefinition(roleDefinitionID, scope string) (*armauthorization.Permission, error)
}

type RBACRuleService struct {
	log   logr.Logger
	raAPI roleAssignmentAPI
	rdAPI roleDefinitionAPI
}

func NewRBACRuleService(log logr.Logger, raAPI roleAssignmentAPI, rdAPI roleDefinitionAPI) *RBACRuleService {
	return &RBACRuleService{
		log:   log,
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
	latestCondition.Message = "Principal has role assignments that provide all required permissions."
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

	// Special case. Nothing to do, so skip Azure API call and don't append any failures.
	if len(set.Actions) == 0 && len(set.DataActions) == 0 {
		return nil
	}

	// Get all role assignments that apply to the specified scope where the member of the role
	// assignment is the specified principal. In this query, "principalId" must be a UUID, so this
	// shouldn't have any injection vulnerabilities.
	//
	// Note that this also returns role assignments that assign the role because the scope is a
	// surrounding scope (e.g. the subscription the scope is contained within), not just the scope
	// itself. That's okay. We want to consider a validator to be valid if it has too many
	// permissions. It should only fail if it has too few permissions.
	filter := ptr.Ptr(url.QueryEscape(fmt.Sprintf("principalId eq '%s'", principalID)))
	roleAssignments, err := s.raAPI.ListRoleAssignmentsForScope(set.Scope, filter)
	if err != nil {
		return fmt.Errorf("failed to get role assignments: %w", err)
	}

	// For each role assignment found, get the permissions data from its role definition.
	allPermissionsData := make([]*armauthorization.Permission, 0)
	for _, ra := range roleAssignments {
		// Note that Azure calls both the fully-qualified ID from the role assignment and the short
		// ID in the role definition a "role definition ID".
		if ra == nil || ra.Properties == nil || ra.Properties.RoleDefinitionID == nil {
			return fmt.Errorf("invalid data from Azure API (role definition ID property nil)")
		}
		roleDefinitionIDForQuery := azure_utils.RoleNameFromRoleDefinitionID(*ra.Properties.RoleDefinitionID)
		permissions, err := s.rdAPI.GetPermissionDataForRoleDefinition(roleDefinitionIDForQuery, set.Scope)
		if err != nil {
			return fmt.Errorf("failed to get permissions data for role definition: %w", err)
		}
		if permissions == nil {
			return fmt.Errorf("invalid data from Azure API (permissions data nil)")
		}
		allPermissionsData = append(allPermissionsData, permissions)
	}

	// Combine all permissions together.
	principalActionsMap := make(map[string]bool, 0)
	principalNotActionsMap := make(map[string]bool, 0)
	principalDataActionsMap := make(map[string]bool, 0)
	principalNotDataActionsMap := make(map[string]bool, 0)
	for _, p := range allPermissionsData {
		if p.Actions == nil {
			return fmt.Errorf("invalid data from Azure API (Actions nil)")
		}
		for _, a := range p.Actions {
			if a == nil {
				return fmt.Errorf("invalid data from Azure API (Action nil)")
			}
			principalActionsMap[*a] = true
		}
		if p.NotActions == nil {
			return fmt.Errorf("invalid data from Azure API (NotActions nil)")
		}
		for _, na := range p.NotActions {
			if na == nil {
				return fmt.Errorf("invalid data from Azure API (NotAction nil)")
			}
			principalNotActionsMap[*na] = true
		}
		if p.DataActions == nil {
			return fmt.Errorf("invalid data from Azure API (DataActions nil)")
		}
		for _, da := range p.DataActions {
			if da == nil {
				return fmt.Errorf("invalid data from Azure API (DataAction nil)")
			}
			principalDataActionsMap[*da] = true
		}
		if p.NotDataActions == nil {
			return fmt.Errorf("invalid data from Azure API (NotDataActions nil)")
		}
		for _, nda := range p.NotDataActions {
			if nda == nil {
				return fmt.Errorf("invalid data from Azure API (NotDataAction nil)")
			}
			principalNotDataActionsMap[*nda] = true
		}
	}

	// Permission data is divided into "actions" and "data actions". We need to deal with both, but
	// actions don't relate to data actions and vice versa.

	// Only process the Actions and NotActions data from the Azure API if the permission set
	// specified required Actions.
	if len(set.Actions) > 0 {
		actions := maps.Keys(principalActionsMap)
		notActions := maps.Keys(principalNotActionsMap)
		if result, err := processCandidateActions(set.Actions, actions, notActions); err != nil {
			return fmt.Errorf("failed to validate specified Actions for role: %w", err)
		} else {
			for _, missingAction := range result.missingFromActions {
				*failures = append(*failures, fmt.Sprintf("Specified Action %s missing from principal because no role assignment provides it.", missingAction))
			}
			for candidateAction, denyingAction := range result.presentInNotActions {
				// TODO: See if we can improve this in a future version. It would be helpful for the
				// user if they could see, in the failure message, which role assignment denied the
				// required Action they specified instead of only being able to see that some role
				// assignment denied it.
				*failures = append(*failures, fmt.Sprintf("Specified Action %s denied by NotAction %s in one of principal's role assignments.", candidateAction, denyingAction))
			}
		}
	}

	// Only process the DataActions and NotDataActions data from the Azure API if the permission set
	// specified required DataActions.
	if len(set.DataActions) > 0 {
		actions := maps.Keys(principalDataActionsMap)
		notActions := maps.Keys(principalNotDataActionsMap)
		if result, err := processCandidateActions(set.DataActions, actions, notActions); err != nil {
			return fmt.Errorf("failed to validate specified DataActions for role: %w", err)
		} else {
			for _, missingAction := range result.missingFromActions {
				*failures = append(*failures, fmt.Sprintf("Specified DataAction %s missing from principal because no role assignment provides it.", missingAction))
			}
			for candidateAction, denyingAction := range result.presentInNotActions {
				*failures = append(*failures, fmt.Sprintf("Specified DataAction %s denied by NotDataAction %s in one of principal's role assignments.", candidateAction, denyingAction))
			}
		}
	}

	return nil
}
