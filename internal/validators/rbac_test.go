package validators

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/utils/test"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	corev1 "k8s.io/api/core/v1"
)

type roleAssignmentAPIMock struct {
	data []*armauthorization.RoleAssignment
	err  error
}

func (m roleAssignmentAPIMock) ListRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error) {
	return m.data, m.err
}

func TestRBACRuleService_ReconcileRBACRule(t *testing.T) {
	type testCase struct {
		name           string
		rule           v1alpha1.RBACRule
		apiMock        roleAssignmentAPIMock
		expectedError  error
		expectedResult vapitypes.ValidationResult
	}

	cs := []testCase{
		// Example scopes taken from:
		// https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
		{
			name: "Fail (missing role assignment)",
			rule: v1alpha1.RBACRule{
				PrincipalID: "p_id",
				Permissions: []v1alpha1.PermissionSet{
					{
						Role:  "role_1_id",
						Scope: "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
				},
			},
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal missing one or more required roles.",
					Details:        []string{},
					Failures:       []string{"Principal missing role role_1_id"},
					Status:         corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Pass (one permission set in rule, role from permission set present)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Role:  "role_1_id",
						Scope: "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
				},
				PrincipalID: "p_id",
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
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (two permission sets in rule, both roles from permission sets)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Role:  "role_1_id",
						Scope: "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
					{
						Role:  "role_2_id",
						Scope: "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
				},
				PrincipalID: "p_id",
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
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (one permission set in rule, role from permission set present, resource group scope)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Role:  "role_1_id",
						Scope: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg",
					},
				},
				PrincipalID: "p_id",
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
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (one permission set in rule, role from permission set present, management group scope)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Role:  "role_1_id",
						Scope: "/providers/Microsoft.Management/managementGroups/marketing-group",
					},
				},
				PrincipalID: "p_id",
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
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (one permission set in rule, role from permission set present, resource scope)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Role:  "role_1_id",
						Scope: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg/providers/Microsoft.Storage/storageAccounts/azurestorage12345/blobServices/default/containers/blob-container-01",
					},
				},
				PrincipalID: "p_id",
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
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has all required roles.",
					Details:        []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
	}
	for _, c := range cs {
		svc := NewRBACRuleService(logr.Logger{}, c.apiMock)
		result, err := svc.ReconcileRBACRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}