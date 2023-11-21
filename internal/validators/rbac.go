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
	corev1 "k8s.io/api/core/v1"
)

// roleAssignmentAPI2 contains methods that allow getting all role assignments for a scope.
// Note that this is the API of our Azure client facade, not a real Azure client.
//
// "2" refers to the fact that this is our second attempt at an interface like this in the package.
// If we keep this approach, this will become just the interface, not 2.
type roleAssignmentAPI2 interface {
	ListRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error)
}

type RBACRuleService struct {
	log              logr.Logger
	api              roleAssignmentAPI2
	getRoleLookupMap roleLookupMapProvider
}

func NewRBACRuleService(log logr.Logger, api roleAssignmentAPI2, roleLookupMapProvider roleLookupMapProvider) *RBACRuleService {
	return &RBACRuleService{
		log:              log,
		api:              api,
		getRoleLookupMap: roleLookupMapProvider,
	}
}

// ReconcileRBACRule reconciles a role assignment rule from a validation config.
func (s *RBACRuleService) ReconcileRBACRule(rule v1alpha1.RBACRule) (*vapitypes.ValidationResult, error) {

	// Build the default ValidationResult for this role assignment rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = "Principal has all required roles."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.PrincipalID)
	latestCondition.ValidationType = constants.ValidationTypeRBAC
	validationResult := &vapitypes.ValidationResult{Condition: &latestCondition, State: &state}

	failures := make([]string, 0)

	for i, set := range rule.Permissions {
		s.log.V(0).Info("Processing permission set of rule.", "set #", i+1)
		if err := s.processPermissionSet(set, rule.PrincipalID, &failures); err != nil {
			// Code this is returning to will take care of changing the validation result to a
			// failed validation, using the error returned.
			return validationResult, err
		}
	}

	if len(failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "Principal missing one or more required roles."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}

// processPermissionSet processes a permission set from the rule.
//   - set: The set to process.
//   - principalID: The ID of the principal to use in the filter. This comes from the rule that the
//     set is part of.
//   - failures: The list of failures being built up while processing the entire rule. Must be
//     non-nil.
func (s *RBACRuleService) processPermissionSet(set v1alpha1.PermissionSet, principalID string, failures *[]string) error {

	foundRoleNames := make(map[string]bool)

	// Get all role assignments that apply to the specified scope where the member of the role
	// assignment is the specified principal. In this query, "principalId" must be a UUID, so this
	// shouldn't have any injection vulnerabilities.
	//
	// Note that this also returns role assignments that assign the role because the scope is a
	// surrounding scope (e.g. the subscription the scope is contained within), not just the scope
	// itself.
	filter := ptr.Ptr(url.QueryEscape(fmt.Sprintf("principalId eq '%s'", principalID)))
	roleAssignments, err := s.api.ListRoleAssignmentsForScope(set.Scope, filter)
	if err != nil {
		return fmt.Errorf("failed to get role assignments: %w", err)
	}

	for _, ra := range roleAssignments {
		if ra.Properties != nil && ra.Properties.RoleDefinitionID != nil {
			foundRoleNames[azure_utils.RoleNameFromRoleDefinitionID(*ra.Properties.RoleDefinitionID)] = true
		}
	}

	roleName := set.Role

	_, ok := foundRoleNames[roleName]
	if !ok {
		*failures = append(*failures, fmt.Sprintf("Principal missing role %s", roleName))
	}

	// No error means the rule processor knows that if there were failures, they have been appended
	// to the single list of failures by now.
	return nil
}
