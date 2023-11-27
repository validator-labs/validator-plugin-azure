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
	string_utils "github.com/spectrocloud-labs/validator-plugin-azure/internal/utils/strings"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapiconstants "github.com/spectrocloud-labs/validator/pkg/constants"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
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
		latestCondition.Message = "Principal missing one or more required roles or one or more required roles missing required permissions."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}

// processPermissionSet processes a permission set from the rule.
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

	if err := s.processRolePermissions(set, failures); err != nil {
		return fmt.Errorf("failed to process permissions specified in permission set: %w", err)
	}

	return nil
}

// processRolePermissions processes the permissions specified in a permissions set. This means it
// verifies that the permissions specified in the spec are indeed present in the role definition for
// the role specified. This is only used when permissions are specified. Otherwise, role is assumed
// to have all the needed permissions.
func (s *RBACRuleService) processRolePermissions(set v1alpha1.PermissionSet, failures *[]string) error {

	// Special case. Nothing to do, so skip Azure API call and don't append any failures.
	if len(set.Actions) == 0 && len(set.DataActions) == 0 {
		return nil
	}

	// Get all the permissions that a particular role definition has. There are two ways to get
	// the details of a role definition. You can use its fully-qualified ID or a combination of its
	// id and its scope. We do the latter because this is information that will always be available
	// in our spec.
	perms, err := s.rdAPI.GetPermissionDataForRoleDefinition(set.Role, set.Scope)
	if err != nil {
		return fmt.Errorf("failed to get permission data for role definition: %w", err)
	}

	// Permission data is divided into "actions" and "data actions". We need to deal with both, but
	// actions don't relate to data actions and vice versa.
	if len(set.Actions) > 0 {
		if string_utils.AnyNil(perms.Actions) || string_utils.AnyNil(perms.NotActions) {
			return errors.New("invalid data from Azure API (nil pointers for permission actions or not actions)")
		}
		permsActions := string_utils.ToVals(perms.Actions)
		permsNotActions := string_utils.ToVals(perms.NotActions)
		hasNeededPermissions, err := allCandidateActionsPermitted(set.Actions, permsActions, permsNotActions)
		if err != nil {
			return fmt.Errorf("failed to validate specified actions of role: %w", err)
		}
		if !hasNeededPermissions {
			*failures = append(*failures, "role does not permit one or more specified actions")
		}
	}
	if len(set.DataActions) > 0 {
		if string_utils.AnyNil(perms.DataActions) || string_utils.AnyNil(perms.NotDataActions) {
			return errors.New("invalid data from Azure API (nil pointers for permission data actions or not data actions)")
		}
		permsDataActions := string_utils.ToVals(perms.DataActions)
		permsNotDataActions := string_utils.ToVals(perms.NotDataActions)
		hasNeededPermissions, err := allCandidateActionsPermitted(set.DataActions, permsDataActions, permsNotDataActions)
		if err != nil {
			return fmt.Errorf("failed to validate specified data actions of role: %w", err)
		}
		if !hasNeededPermissions {
			*failures = append(*failures, "role does not permit one or more specified data actions")
		}
	}

	return nil
}
