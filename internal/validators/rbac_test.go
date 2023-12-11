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

type denyAssignmentAPIMock struct {
	data []*armauthorization.DenyAssignment
	err  error
}

func (m denyAssignmentAPIMock) GetDenyAssignmentsForScope(_ string, _ *string) ([]*armauthorization.DenyAssignment, error) {
	// TODO: Fill in with what we need for tests
	return m.data, nil
}

type roleAssignmentAPIMock struct {
	data []*armauthorization.RoleAssignment
	err  error
}

func (m roleAssignmentAPIMock) GetRoleAssignmentsForScope(_ string, _ *string) ([]*armauthorization.RoleAssignment, error) {
	return m.data, m.err
}

type roleDefinitionAPIMock struct {
	// key = roleID
	data map[string]*armauthorization.RoleDefinition
	err  error
}

func (m roleDefinitionAPIMock) GetByID(roleID string) (*armauthorization.RoleDefinition, error) {
	return m.data[roleID], nil
}

func TestRBACRuleService_ReconcileRBACRule(t *testing.T) {

	// Example scopes taken from:
	// https://learn.microsoft.com/en-us/azure/role-based-access-control/scope-overview
	subscriptionScope := "/subscriptions/00000000-0000-0000-0000-000000000000"

	type testCase struct {
		name           string
		rule           v1alpha1.RBACRule
		daAPIMock      denyAssignmentAPIMock
		raAPIMock      roleAssignmentAPIMock
		rdAPIMock      roleDefinitionAPIMock
		expectedError  error
		expectedResult vapitypes.ValidationResult
	}

	// Note that these test cases test code that calls code in rbac_permissions.go, which is already
	// covered by tests. Therefore, we don't need to test some functionality (see
	// rbac_permissions_test.go). Here, we test that the expected failure messages are included in
	// the validation result for conditions that should cause failures. Note that the input is based
	// on how Azure responds to our API requests for a given principal and scope. Therefore, we are
	// *not* testing whether Azure is using the correct logic to determine which deny assignments
	// and role assignments match the queries. We're trusting that it does this correctly, including
	// when scope should inherit or not inherit an assignment because of the subscription->resource
	// group etc hierarchy.

	cs := []testCase{
		{
			name: "Pass (required actions and data actions provided by role assignments and not denied by deny assignments)",
			rule: v1alpha1.RBACRule{
				Name: "rule-1",
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []v1alpha1.ActionStr{"a"},
						DataActions: []v1alpha1.ActionStr{"b"},
						Scope:       subscriptionScope,
					},
				},
				PrincipalID: "p_id",
			},
			daAPIMock: denyAssignmentAPIMock{
				data: []*armauthorization.DenyAssignment{},
				err:  nil,
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
				data: map[string]*armauthorization.RoleDefinition{
					"role_id": {
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("a")},
									DataActions:    []*string{ptr.Ptr("b")},
									NotActions:     []*string{},
									NotDataActions: []*string{},
								},
							},
						},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-rule-1",
					Message:        "Principal has all required permissions.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: ptr.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (required actions and data actions provided by role assignments but denied by deny assignments)",
			rule: v1alpha1.RBACRule{
				Name: "rule-1",
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []v1alpha1.ActionStr{"a"},
						DataActions: []v1alpha1.ActionStr{"b"},
						Scope:       subscriptionScope,
					},
				},
				PrincipalID: "p_id",
			},
			daAPIMock: denyAssignmentAPIMock{
				data: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("a")},
									DataActions:    []*string{ptr.Ptr("b")},
									NotActions:     []*string{},
									NotDataActions: []*string{},
								},
							},
						},
						ID: ptr.Ptr("d"),
					},
				},
				err: nil,
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
				data: map[string]*armauthorization.RoleDefinition{
					"role_id": {
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("a")},
									DataActions:    []*string{ptr.Ptr("b")},
									NotActions:     []*string{},
									NotDataActions: []*string{},
								},
							},
						},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-rule-1",
					Message:        "Principal lacks required permissions. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"Action a denied by deny assignment d.",
						"DataAction b denied by deny assignment d.",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (required actions and data actions not provided by role assignments)",
			rule: v1alpha1.RBACRule{
				Name: "rule-1",
				Permissions: []v1alpha1.PermissionSet{
					{
						Actions:     []v1alpha1.ActionStr{"a"},
						DataActions: []v1alpha1.ActionStr{"b"},
						Scope:       subscriptionScope,
					},
				},
				PrincipalID: "p_id",
			},
			daAPIMock: denyAssignmentAPIMock{
				data: []*armauthorization.DenyAssignment{},
				err:  nil,
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
				data: map[string]*armauthorization.RoleDefinition{
					"role_id": {
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{},
									DataActions:    []*string{},
									NotActions:     []*string{},
									NotDataActions: []*string{},
								},
							},
						},
					},
				},
				err: nil,
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-rule-1",
					Message:        "Principal lacks required permissions. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"Action a unpermitted because no role assignment permits it.",
						"DataAction b unpermitted because no role assignment permits it.",
					},
					Status: corev1.ConditionFalse,
				},
				State: ptr.Ptr(vapi.ValidationFailed),
			},
		},
	}
	for _, c := range cs {
		svc := NewRBACRuleService(logr.Logger{}, c.daAPIMock, c.raAPIMock, c.rdAPIMock)
		result, err := svc.ReconcileRBACRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}
