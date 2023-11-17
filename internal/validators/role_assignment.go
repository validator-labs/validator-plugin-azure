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
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapiconstants "github.com/spectrocloud-labs/validator/pkg/constants"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	corev1 "k8s.io/api/core/v1"
)

// roleAssignmentAPI contains methods that allow getting all role assignments for a subscription.
// Note that this is the API of our Azure client facade, not a real Azure client.
type roleAssignmentAPI interface {
	ListRoleAssignmentsForSubscription(subscriptionID string, filter *string) ([]*armauthorization.RoleAssignment, error)
}

// roleLookupMapProvider provides a lookup map of role names to names.
type roleLookupMapProvider func(subscriptionID string) (map[string]string, error)

type RoleAssignmentRuleService struct {
	log              logr.Logger
	api              roleAssignmentAPI
	getRoleLookupMap roleLookupMapProvider
}

func NewRoleAssignmentRuleService(log logr.Logger, api roleAssignmentAPI, roleLookupMapProvider roleLookupMapProvider) *RoleAssignmentRuleService {
	return &RoleAssignmentRuleService{
		log:              log,
		api:              api,
		getRoleLookupMap: roleLookupMapProvider,
	}
}

// ReconcileRoleAssignmentRule reconciles a role assignment rule from a validation config.
func (s *RoleAssignmentRuleService) ReconcileRoleAssignmentRule(rule v1alpha1.RoleAssignmentRule) (*vapitypes.ValidationResult, error) {

	// Build the default ValidationResult for this role assignment rule
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = "Service principal has all required roles."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.ServicePrincipalID)
	latestCondition.ValidationType = constants.ValidationTypeRoleAssignment
	validationResult := &vapitypes.ValidationResult{Condition: &latestCondition, State: &state}

	failures := make([]string, 0)
	foundRoleNames := make(map[string]bool)

	// Get all role assignments in subscription. In this query, "principalId" must be a UUID, so
	// this shouldn't have any injection vulnerabilities.
	filter := ptr.Ptr(url.QueryEscape(fmt.Sprintf("principalId eq '%s'", rule.ServicePrincipalID)))
	roleAssignments, err := s.api.ListRoleAssignmentsForSubscription(rule.SubscriptionID, filter)
	if err != nil {
		s.log.V(0).Error(err, "failed to get role assignments")
		return validationResult, err
	}

	for _, ra := range roleAssignments {
		if ra.Properties != nil && ra.Properties.RoleDefinitionID != nil {
			foundRoleNames[azure_utils.RoleNameFromRoleDefinitionID(*ra.Properties.RoleDefinitionID)] = true
		}
	}

	for _, role := range rule.Roles {
		// First, find out whether we need to look the role up by its role name if the user provided
		// its role name instead of its name.
		var roleName string
		if role.Name != nil {
			roleName = *role.Name
		} else if role.RoleName != nil {
			rolelookupMap, err := s.getRoleLookupMap(rule.SubscriptionID)
			if err != nil {
				s.log.V(0).Error(err, "failed to get role name lookup map")
				return validationResult, err
			}
			specifiedRoleName := *role.RoleName
			foundName, ok := rolelookupMap[specifiedRoleName]
			if !ok {
				err := errors.New("specified role name does not correspond to a built-in role; cannot validate")
				s.log.V(0).Error(err, "cannot validate")
				return validationResult, err
			}
			roleName = foundName
		} else {
			err := errors.New("neither role name nor name specified for role")
			s.log.V(0).Error(err, "cannot validate")
			return validationResult, err
		}

		_, ok := foundRoleNames[roleName]
		if !ok {
			failures = append(failures, fmt.Sprintf("Service principal missing role %s", roleName))
		}
	}

	if len(failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Failures = failures
		latestCondition.Message = "Service principal missing one or more required roles."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}
