package validators

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/utils/test"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	"github.com/spectrocloud-labs/validator/pkg/types"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	corev1 "k8s.io/api/core/v1"
)

type roleAssignmentAPIMock struct {
	data []*armauthorization.RoleAssignment
	err  error
}

func (m roleAssignmentAPIMock) ListRoleAssignmentsForSubscription(subscriptionID string, filter *string) ([]*armauthorization.RoleAssignment, error) {
	return m.data, m.err
}

var roleLookupMapProviderMock = func(subscriptionID string) (map[string]string, error) {
	return map[string]string{
		"Role 1": "role_1_id",
		"Role 2": "role_2_id",
	}, nil
}

type testCase struct {
	apiMock        roleAssignmentAPIMock
	expectedError  error
	expectedResult types.ValidationResult
	name           string
	rule           v1alpha1.RoleAssignmentRule
}

func TestRoleAssignmentRuleService_ReconcileRoleAssignmentRule(t *testing.T) {
	cs := []testCase{
		{
			name: "Fail (missing role assignment)",
			rule: v1alpha1.RoleAssignmentRule{
				Roles: []v1alpha1.Role{
					{
						Name: ptr.Ptr("role_1_id"),
					},
				},
				ServicePrincipalID: "sp_id",
				SubscriptionID:     "sub_id",
			},
			apiMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{},
			},
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-role-assignment",
					ValidationRule: "validation-sp_id",
					Message:        "Service principal missing one or more required roles.",
					Details:        []string{},
					Failures:       []string{"Service principal missing role role_1_id"},
					Status:         corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Pass (no roles in rule)",
			rule: v1alpha1.RoleAssignmentRule{
				Roles:              []v1alpha1.Role{},
				ServicePrincipalID: "sp_id",
				SubscriptionID:     "sub_id",
			},
			apiMock: roleAssignmentAPIMock{},
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-role-assignment",
					ValidationRule: "validation-sp_id",
					Message:        "Service principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (one role in rule, role present)",
			rule: v1alpha1.RoleAssignmentRule{
				Roles: []v1alpha1.Role{
					{
						Name: ptr.Ptr("role_1_id"),
					},
				},
				ServicePrincipalID: "sp_id",
				SubscriptionID:     "sub_id",
			},
			apiMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_1_id"),
						},
					},
				},
			},
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-role-assignment",
					ValidationRule: "validation-sp_id",
					Message:        "Service principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (one role in rule specified as role name, role present)",
			rule: v1alpha1.RoleAssignmentRule{
				Roles: []v1alpha1.Role{
					{
						RoleName: ptr.Ptr("Role 1"),
					},
				},
				ServicePrincipalID: "sp_id",
				SubscriptionID:     "sub_id",
			},
			apiMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_1_id"),
						},
					},
				},
			},
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-role-assignment",
					ValidationRule: "validation-sp_id",
					Message:        "Service principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (two roles in rule, both roles present)",
			rule: v1alpha1.RoleAssignmentRule{
				Roles: []v1alpha1.Role{
					{
						Name: ptr.Ptr("role_1_id"),
					},
					{
						Name: ptr.Ptr("role_2_id"),
					},
				},
				ServicePrincipalID: "sp_id",
				SubscriptionID:     "sub_id",
			},
			apiMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_1_id"),
						},
					},
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_2_id"),
						},
					},
				},
			},
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-role-assignment",
					ValidationRule: "validation-sp_id",
					Message:        "Service principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (one role in rule specified as role name, name not found in lookup map)",
			rule: v1alpha1.RoleAssignmentRule{
				Roles: []v1alpha1.Role{
					{
						RoleName: ptr.Ptr("RoleThatDoesNotExist"),
					},
				},
				ServicePrincipalID: "sp_id",
				SubscriptionID:     "sub_id",
			},
			apiMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{},
			},
			// Expect the default result, but also an error.
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-role-assignment",
					ValidationRule: "validation-sp_id",
					Message:        "Service principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
			expectedError: errNoSuchBuiltInRole,
		},
		{
			name: "Fail (one role in rule, but missing name and role name)",
			rule: v1alpha1.RoleAssignmentRule{
				Roles: []v1alpha1.Role{
					{},
				},
				ServicePrincipalID: "sp_id",
				SubscriptionID:     "sub_id",
			},
			apiMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{},
			},
			// Expect the default result, but also an error.
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-role-assignment",
					ValidationRule: "validation-sp_id",
					Message:        "Service principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
			expectedError: errNoRoleIdentifierSpecified,
		},
	}
	for _, c := range cs {
		svc := NewRoleAssignmentRuleService(logr.Logger{}, c.apiMock, roleLookupMapProviderMock)
		result, err := svc.ReconcileRoleAssignmentRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}
