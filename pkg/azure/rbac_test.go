package azure

import (
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	corev1 "k8s.io/api/core/v1"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
)

type denyAssignmentAPIMock struct {
	data []*armauthorization.DenyAssignment
	err  error
}

func (m denyAssignmentAPIMock) GetDenyAssignmentsForScope(_ string, _ *string) ([]*armauthorization.DenyAssignment, error) {
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
		expectedResult vapitypes.ValidationRuleResult
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

	testCases := []testCase{
		{
			name: "Pass (required actions and data actions provided by role assignments and not denied by deny assignments)",
			rule: v1alpha1.RBACRule{
				RuleName: "rule-1",
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
							RoleDefinitionID: util.Ptr("role_id"),
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
									Actions:        []*string{util.Ptr("a")},
									DataActions:    []*string{util.Ptr("b")},
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
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac",
					ValidationRule: "validation-rule-1",
					Message:        "Principal has all required permissions.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (required actions and data actions provided by role assignments but denied by deny assignments)",
			rule: v1alpha1.RBACRule{
				RuleName: "rule-1",
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
									Actions:        []*string{util.Ptr("a")},
									DataActions:    []*string{util.Ptr("b")},
									NotActions:     []*string{},
									NotDataActions: []*string{},
								},
							},
						},
						ID: util.Ptr("d"),
					},
				},
				err: nil,
			},
			raAPIMock: roleAssignmentAPIMock{
				data: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: util.Ptr("role_id"),
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
									Actions:        []*string{util.Ptr("a")},
									DataActions:    []*string{util.Ptr("b")},
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
			expectedResult: vapitypes.ValidationRuleResult{
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
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (required actions and data actions not provided by role assignments)",
			rule: v1alpha1.RBACRule{
				RuleName: "rule-1",
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
							RoleDefinitionID: util.Ptr("role_id"),
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
			expectedResult: vapitypes.ValidationRuleResult{
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
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
	}
	for _, tc := range testCases {
		svc := NewRBACRuleService(tc.daAPIMock, tc.raAPIMock, tc.rdAPIMock)
		result, err := svc.ReconcileRBACRule(tc.rule)
		util.CheckTestCase(t, result, tc.expectedResult, err, tc.expectedError)
	}
}

// fakeDAAPI is a daAPI implementation for testing.
type fakeDAAPI struct {
	d1 []*armauthorization.DenyAssignment
	d2 error
}

func (api *fakeDAAPI) GetDenyAssignmentsForScope(_ string, _ *string) ([]*armauthorization.DenyAssignment, error) {
	return api.d1, api.d2
}

// fakeRAAPI is a raAPI implementation for testing.
type fakeRAAPI struct {
	d1 []*armauthorization.RoleAssignment
	d2 error
}

func (api *fakeRAAPI) GetRoleAssignmentsForScope(_ string, _ *string) ([]*armauthorization.RoleAssignment, error) {
	return api.d1, api.d2
}

// fakeRDAPI is a rdAPI implementation for testing.
type fakeRDAPI struct {
	d1 *armauthorization.RoleDefinition
	d2 error
}

func (api *fakeRDAPI) GetByID(_ string) (*armauthorization.RoleDefinition, error) {
	return api.d1, api.d2
}

func TestRBACRuleService_processPermissionSet(t *testing.T) {

	type fields struct {
		daAPI denyAssignmentAPI
		raAPI roleAssignmentAPI
		rdAPI roleDefinitionAPI
	}
	type args struct {
		set         v1alpha1.PermissionSet
		principalID string
		failures    *[]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Returns an error when the deny assignments API returns an error.",
			fields: fields{
				daAPI: &fakeDAAPI{
					d1: []*armauthorization.DenyAssignment{},
					d2: errors.New("fail"),
				},
			},
			args:    args{},
			wantErr: true,
		},
		{
			name: "Returns an error when the deny assignments API returns data but the role assignments API returns an error.",
			fields: fields{
				daAPI: &fakeDAAPI{
					d1: []*armauthorization.DenyAssignment{},
					d2: nil,
				},
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{},
					d2: errors.New("fail"),
				},
			},
			args:    args{},
			wantErr: true,
		},
		{
			name: "Returns an error when the deny assignments API and role assignments API return data but the role assignment has no properties.",
			fields: fields{
				daAPI: &fakeDAAPI{
					d1: []*armauthorization.DenyAssignment{},
					d2: nil,
				},
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{{}},
					d2: nil,
				},
				rdAPI: &fakeRDAPI{
					d1: &armauthorization.RoleDefinition{},
					d2: nil,
				},
			},
			args:    args{},
			wantErr: true,
		},
		{
			name: "Returns an error when the deny assignments API, role assignments API, and role definitions API return data but the role assignment has no role definition ID property.",
			fields: fields{
				daAPI: &fakeDAAPI{
					d1: []*armauthorization.DenyAssignment{},
					d2: nil,
				},
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{{
						Properties: &armauthorization.RoleAssignmentProperties{},
					}},
					d2: nil,
				},
				rdAPI: &fakeRDAPI{
					d1: &armauthorization.RoleDefinition{},
					d2: nil,
				},
			},
			args:    args{},
			wantErr: true,
		},
		{
			name: "Returns an error when the deny assignments API and role assignments API return data but the role definitions API returns an error.",
			fields: fields{
				daAPI: &fakeDAAPI{
					d1: []*armauthorization.DenyAssignment{},
					d2: nil,
				},
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: util.Ptr("abc123"),
						},
					}},
					d2: nil,
				},
				rdAPI: &fakeRDAPI{
					d1: &armauthorization.RoleDefinition{},
					d2: errors.New("fail"),
				},
			},
			args:    args{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RBACRuleService{
				daAPI: tt.fields.daAPI,
				raAPI: tt.fields.raAPI,
				rdAPI: tt.fields.rdAPI,
			}
			if err := s.processPermissionSet(tt.args.set, tt.args.principalID, tt.args.failures); (err != nil) != tt.wantErr {
				t.Errorf("RBACRuleService.processPermissionSet() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
