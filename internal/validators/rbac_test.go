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

type roleDefinitionAPIMock struct {
	// key = roleDefinitionID
	data map[string]*armauthorization.Permission
	err  error
}

func (m roleDefinitionAPIMock) GetPermissionDataForRoleDefinition(roleDefinitionID, _ string) (*armauthorization.Permission, error) {
	return m.data[roleDefinitionID], m.err
}

func TestRBACRuleService_ReconcileRBACRule(t *testing.T) {
	// Used for test cases where we need to simulate Azure having no role definitions (without
	// causing nil pointer errors).
	// noRoleDefinitions := roleDefinitionAPIMock{
	// 	data: &armauthorization.Permission{
	// 		Actions:        []*string{},
	// 		DataActions:    []*string{},
	// 		NotActions:     []*string{},
	// 		NotDataActions: []*string{},
	// 	},
	// 	err: nil,
	// }

	// Example scopes taken from:
	// https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
	subscriptionScope := "/subscriptions/00000000-0000-0000-0000-000000000000"

	type testCase struct {
		name           string
		rule           v1alpha1.RBACRule
		raAPIMock      roleAssignmentAPIMock
		rdAPIMock      roleDefinitionAPIMock
		expectedError  error
		expectedResult vapitypes.ValidationResult
	}

	// The tests for the rbac_permissions.go cover whether the Actions and NotActions are processed
	// correctly, regardless of how many roles provide them, so these test cases just need to test:
	//
	//   - That this part of the algorithm feeds multiple role assignments, if they're available,
	//     into the other part.
	//   - How we form the ValidationResult CR when validation passes or fails (error messages etc).
	//
	// Notably, we are *not* testing that specified scopes correctly match role assignments that
	// have overly broad scope (e.g. subscripton scope, permitting actions on resource groups)
	// because that's not our logic, that's Azure's logic. Our tests provide mock role assignment
	// results like how Azure provides them right now.

	cs := []testCase{
		// All required permissions provided
		{
			name: "Pass (all required actions and data actions provided by role assignments)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []string{"a/b/c/d"},
						DataActions: []string{"e/f/g/h"},
						Scope:       subscriptionScope,
					},
				},
				PrincipalID: "p_id",
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("role_id"),
						},
					},
				},
				err: nil,
			},
			rdAPIMock: roleDefinitionAPIMock{
				data: map[string]*armauthorization.Permission{
					"role_id": {
						Actions:        []*string{ptr.Ptr("a/b/c/d")},
						DataActions:    []*string{ptr.Ptr("e/f/g/h")},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has role assignments that provide all required permissions.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (all required actions and data actions provided by two role assignments)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []string{"a/b/c/d", "aa/bb/cc/dd"},
						DataActions: []string{"e/f/g/h", "ee/ff/gg/hh"},
						Scope:       subscriptionScope,
					},
				},
				PrincipalID: "p_id",
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("role_1_id"),
						},
					},
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("role_2_id"),
						},
					},
				},
				err: nil,
			},
			rdAPIMock: roleDefinitionAPIMock{
				data: map[string]*armauthorization.Permission{
					"role_1_id": {
						Actions:        []*string{ptr.Ptr("a/b/c/d")},
						DataActions:    []*string{ptr.Ptr("e/f/g/h")},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
					"role_2_id": {
						Actions:        []*string{ptr.Ptr("aa/bb/cc/dd")},
						DataActions:    []*string{ptr.Ptr("ee/ff/gg/hh")},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has role assignments that provide all required permissions.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (all required actions and data actions provided by two role assignments, with redundant role assignments)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []string{"a/b/c/d", "aa/bb/cc/dd"},
						DataActions: []string{"e/f/g/h", "ee/ff/gg/hh"},
						Scope:       subscriptionScope,
					},
				},
				PrincipalID: "p_id",
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("role_1_id"),
						},
					},
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("role_2_id"),
						},
					},
				},
				err: nil,
			},
			rdAPIMock: roleDefinitionAPIMock{
				data: map[string]*armauthorization.Permission{
					"role_1_id": {
						Actions:        []*string{ptr.Ptr("a/b/c/d")},
						DataActions:    []*string{ptr.Ptr("e/f/g/h")},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
					"role_2_id": {
						Actions:        []*string{ptr.Ptr("a/b/c/d"), ptr.Ptr("aa/bb/cc/dd")},
						DataActions:    []*string{ptr.Ptr("e/f/g/h"), ptr.Ptr("ee/ff/gg/hh")},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal has role assignments that provide all required permissions.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},

		// All required permissions not provided
		{
			name: "Fail (no required actions provided by role assignments)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []string{"a/b/c/d"},
						DataActions: []string{},
						Scope:       "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
				},
				PrincipalID: "p_id",
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_id"),
						},
					},
				},
			},
			rdAPIMock: roleDefinitionAPIMock{
				data: map[string]*armauthorization.Permission{
					"role_id": {
						Actions:        []*string{},
						DataActions:    []*string{},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal lacks required permissions. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"Specified Action a/b/c/d missing from principal because no role assignment provides it.",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (no required actions provided by role assignments, role assignments have the actions and data actions flipped around)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []string{"a/b/c/d"},
						DataActions: []string{"e/f/g/h"},
						Scope:       "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
				},
				PrincipalID: "p_id",
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_id"),
						},
					},
				},
			},
			rdAPIMock: roleDefinitionAPIMock{
				data: map[string]*armauthorization.Permission{
					"role_id": {
						Actions:        []*string{ptr.Ptr("e/f/g/h")},
						DataActions:    []*string{ptr.Ptr("a/b/c/d")},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal lacks required permissions. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"Specified Action a/b/c/d missing from principal because no role assignment provides it.",
						"Specified DataAction e/f/g/h missing from principal because no role assignment provides it.",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},

		// Some required permissions provided
		{
			name: "Fail (some required actions provided by role assignments but not all)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []string{"a/b/c/d", "aa/bb/cc/dd"},
						DataActions: []string{},
						Scope:       "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
				},
				PrincipalID: "p_id",
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_id"),
						},
					},
				},
			},
			rdAPIMock: roleDefinitionAPIMock{
				data: map[string]*armauthorization.Permission{
					"role_id": {
						Actions:        []*string{ptr.Ptr("a/b/c/d")},
						DataActions:    []*string{},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal lacks required permissions. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"Specified Action aa/bb/cc/dd missing from principal because no role assignment provides it.",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (required actions provided by role assignments but not required data actions)",
			rule: v1alpha1.RBACRule{
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []string{"a/b/c/d"},
						DataActions: []string{"e/f/g/h"},
						Scope:       "/subscriptions/00000000-0000-0000-0000-000000000000",
					},
				},
				PrincipalID: "p_id",
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.Ptr("/role_id"),
						},
					},
				},
			},
			rdAPIMock: roleDefinitionAPIMock{
				data: map[string]*armauthorization.Permission{
					"role_id": {
						Actions:        []*string{ptr.Ptr("a/b/c/d")},
						DataActions:    []*string{},
						NotActions:     []*string{},
						NotDataActions: []*string{},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-p_id",
					Message:        "Principal lacks required permissions. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"Specified DataAction e/f/g/h missing from principal because no role assignment provides it.",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
	}
	for _, c := range cs {
		svc := NewRBACRuleService(logr.Logger{}, c.raAPIMock, c.rdAPIMock)
		result, err := svc.ReconcileRBACRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}
