package validators

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/constants"
	azure_utils "github.com/spectrocloud-labs/validator-plugin-azure/internal/utils/azure"
	strings "github.com/spectrocloud-labs/validator-plugin-azure/internal/utils/strings"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapiconstants "github.com/spectrocloud-labs/validator/pkg/constants"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	corev1 "k8s.io/api/core/v1"
)

// NotGuaranteedReason is the reason permission to perform a desired action should be denied.
type NotGuaranteedReason = string

const (
	// NotGuaranteedReasonNotPresentAmongActions means that permission should be denied because the
	// action is not present among the "actions".
	NotGuaranteedReasonNotPresentAmongActions = "NotPresentAmongActions"
	// NotGuaranteedReasonNotPresentAmongActions means that permission should be denied because even
	// though the action is present among the actions, it is present among the "not actions" too.
	NotGuaranteedReasonPresentAmongNotActions = "PresentAmongNotActions"
)

// roleAssignmentAPI contains methods that allow getting all role assignments for a scope.
// Note that this is the API of our Azure client facade, not a real Azure client.
type roleAssignmentAPI interface {
	ListRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error)
}

// roleDefinitionAPI contains methods that allow getting all the information we need for an existing
// role definition.
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
//   - set: The permission being processed.
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
	roleAssignments, err := s.raAPI.ListRoleAssignmentsForScope(set.Scope, filter)
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

	if len(set.Permissions) > 0 {
		if err := s.processRolePermissions(set, failures); err != nil {
			return fmt.Errorf("failed to process permissions specified in permission set: %w", err)
		}
	}

	// No error means the rule processor knows that if there were failures, they have been appended
	// to the single list of failures by now.
	return nil
}

// processRolePermissions processes the permissions specified in a permissions set. This means it
// verifies that the permissions specified in the spec are indeed present in the role definition for
// the role specified. This is only used when permissions are specified. Otherwise, role is assumed
// to have all the needed permissions.
//   - set: The permission being processed.
//   - failures: The list of failures being built up while processing the entire rule. Must be
//     non-nil.
func (s *RBACRuleService) processRolePermissions(set v1alpha1.PermissionSet, failures *[]string) error {

	// TODO: Remove if we don't need this.
	// foundPermissions := make(map[string]bool)

	// Get all the permissions that a particular role definition has. There are two ways to get
	// the details of a role definition. You can use its fully-qualified ID or a combination of its
	// id and its scope. We do the latter because this is information that will always be available
	// in our spec.
	data, err := s.rdAPI.GetPermissionDataForRoleDefinition(set.Role, set.Scope)
	if err != nil {
		return fmt.Errorf("failed to get permission data for role definition: %w", err)
	}

	// Permission data is divided into "actions" and "data actions". We need to deal with both, but
	// actions don't relate to data actions and vice versa.

	// Actions
	if strings.AnyNil(data.Actions) || strings.AnyNil(data.NotActions) {
		return errors.New("invalid data from Azure API (nil pointers for permission actions)")
	}
	for _, action := range set.Permissions {
		if notGuaranteed, reason := notGuaranteed(action, data.Actions, data.NotActions); notGuaranteed {
			*failures = append(*failures, fmt.Sprintf("Role does not provide permission to perform action %s (reason: %s)", action, reason))
		}
	}

	// Data actions
	// TODO: Implement this after we add data actions to the spec

	// No error means the rule processor knows that if there were failures, they have been appended
	// to the single list of failures by now.
	return nil
}

// notGuaranteed determines whether, given a set of explicitly allowed actions (called "actions" in
// Azure) and a set of explicitly unallowed actions (called "not actions" in Azure), the desired
// action (which we call a "permission") is guaranteed to be allowed by Azure.
//
// We need an algorithm like this because the goal of the validator plugin is to determine whether
// the action the principal would perform is guaranteed to be allowed. The plugin must fail
// validation if there is any chance that the action is unallowed.
//
// For more info on how Azure judges whether an action is allowed, according to a role def, see:
// https://learn.microsoft.com/en-us/azure/role-based-access-control/role-definitions
func notGuaranteed(action string, actions, notActions []*string) (bool, NotGuaranteedReason) {

	// In order for the action to be allowed, it must be present among the list of allowed actions.
	if !strings.ContainsPtrToEqlTo(actions, action) {
		return true, NotGuaranteedReasonNotPresentAmongActions
	}

	// Even if the action is allowed because of the "[Data]Actions" part of role definition, it can
	// still be unallowed by the "Not[Data]Actions" part.
	if strings.ContainsPtrToEqlTo(notActions, action) {
		return true, NotGuaranteedReasonPresentAmongNotActions
	}

	return false, ""
}
