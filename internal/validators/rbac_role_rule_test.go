package validators

import (
	"errors"
	"fmt"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
)

const (
	testScope            = "/subscriptions/00000000-0000-0000-0000-000000000000"
	testPrincipalID      = "00000000-0000-0000-0000-000000000000"
	testRoleAssignmentID = "test-role-assignment-id"
	testRoleDefinitionID = "test-role-definition-id"
	testRoleType         = "test-role-type"
	testRoleName         = "test-role-name"
	testAction           = "test-action"
)

// fakeRAAPI is a raAPI implementation for testing.
type fakeRAAPI struct {
	d1 []*armauthorization.RoleAssignment
	d2 error
}

func (api fakeRAAPI) GetRoleAssignmentsForScope(_ string, _ *string) ([]*armauthorization.RoleAssignment, error) {
	return api.d1, api.d2
}

// fakeRDAPI is a rdAPI implementation for testing.
type fakeRDAPI struct {
	// Map to store role definitions by key
	roleDefinitions map[string]*armauthorization.RoleDefinition
	// Default error to return if key not found
	defaultError error
	// Error to force, regardless of key
	forcedError error
}

func (api fakeRDAPI) GetByID(key string) (*armauthorization.RoleDefinition, error) {
	if api.forcedError != nil {
		return nil, api.forcedError
	}

	if roleDef, ok := api.roleDefinitions[key]; ok {
		return roleDef, nil
	}

	return nil, api.defaultError
}

func TestRBACRoleRuleService_ReconcileRBACRoleRule(t *testing.T) {

	type testCase struct {
		name           string
		rule           v1alpha1.RBACRoleRule
		raAPIMock      fakeRAAPI
		rdAPIMock      fakeRDAPI
		expectedError  error
		expectedResult vapitypes.ValidationRuleResult
	}

	testCases := []testCase{
		{
			name: "Pass (a role assignment provides the required permissions)",
			rule: v1alpha1.RBACRoleRule{
				Name:        "rule-1",
				PrincipalID: testPrincipalID,
				RoleAssignments: []v1alpha1.RoleAssignment{
					{
						Scope: testScope,
						Role: v1alpha1.Role{
							Type: testRoleType,
							Name: testRoleName,
							Permission: v1alpha1.Permission{
								Actions: []v1alpha1.ActionStr{testAction},
							},
						},
					},
				},
			},
			raAPIMock: fakeRAAPI{
				d1: []*armauthorization.RoleAssignment{
					{
						Properties: &armauthorization.RoleAssignmentProperties{
							RoleDefinitionID: ptr.To(testRoleDefinitionID),
							Scope:            ptr.To(testScope),
						},
						ID: ptr.To(testRoleAssignmentID),
					},
				},
			},
			rdAPIMock: fakeRDAPI{
				roleDefinitions: map[string]*armauthorization.RoleDefinition{
					testRoleDefinitionID: {
						Properties: &armauthorization.RoleDefinitionProperties{
							RoleType: ptr.To(testRoleType),
							RoleName: ptr.To(testRoleName),
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.To(testAction)},
									DataActions:    []*string{},
									NotActions:     []*string{},
									NotDataActions: []*string{},
								},
							},
						},
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac-role",
					ValidationRule: "validation-rule-1",
					Message:        "All role assignments correct. Roles contain permissions and assigned to principal at scopes.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (at least one failure occurs)",
			rule: v1alpha1.RBACRoleRule{
				Name:        "rule-1",
				PrincipalID: testPrincipalID,
				RoleAssignments: []v1alpha1.RoleAssignment{
					{
						Scope: testScope,
						Role: v1alpha1.Role{
							Type: testRoleType,
							Name: testRoleName,
							Permission: v1alpha1.Permission{
								Actions: []v1alpha1.ActionStr{testAction},
							},
						},
					},
				},
			},
			raAPIMock: fakeRAAPI{
				d1: []*armauthorization.RoleAssignment{},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-rbac-role",
					ValidationRule: "validation-rule-1",
					Message:        "Principal lacks required permissions. See failures for details.",
					Details:        []string{},
					Failures: []string{fmt.Sprintf("No role assignments found for principal '%s' at scope '%s'.",
						testPrincipalID, testScope)},
					Status: corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
	}
	for _, tc := range testCases {
		svc := NewRBACRoleRuleService(tc.raAPIMock, tc.rdAPIMock)
		result, err := svc.ReconcileRBACRoleRule(tc.rule)
		util.CheckTestCase(t, result, tc.expectedResult, err, tc.expectedError)
	}
}

func TestRBACRoleRuleService_processRoleAssignment(t *testing.T) {
	testErrMsg := "test error"

	type fields struct {
		raAPI roleAssignmentAPI
		rdAPI roleDefinitionAPI
	}
	type args struct {
		raSpec      v1alpha1.RoleAssignment
		principalID string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		want       string
		wantErr    bool
		wantErrMsg string
	}{
		{
			name: "Returns an error when the role assignments API returns an error.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d2: errors.New(testErrMsg),
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
				},
				principalID: testPrincipalID,
			},
			want:    "",
			wantErr: true,
			wantErrMsg: fmt.Sprintf("failed to get role assignments for principal '%s' at scope '%s': %s",
				testPrincipalID, testPrincipalID, testErrMsg),
		},
		{
			name: "Returns no error and a failure when role assignments API returns no role assignments.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
				},
				principalID: testPrincipalID,
			},
			want:    fmt.Sprintf("No role assignments found for principal '%s' at scope '%s'.", testPrincipalID, testScope),
			wantErr: false,
		},
		{
			name: "Returns an error when the role assignments API returns data that is missing expected properties.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{{}},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
				},
				principalID: testPrincipalID,
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: "role assignment from API response missing expected properties",
		},
		{
			name: "Returns an error when the role definitions API returns an error.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					forcedError: errors.New(testErrMsg),
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
				},
				principalID: testPrincipalID,
			},
			want:    "",
			wantErr: true,
			wantErrMsg: fmt.Sprintf("failed to get role definition '%s' (for role assignment '%s'): %s",
				testRoleDefinitionID, testRoleAssignmentID, testErrMsg),
		},
		{
			name: "Returns an error when the role definitions API returns data that is missing expected properties.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
				},
				principalID: testPrincipalID,
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: fmt.Sprintf("role definition '%s' from API response missing expected properties", testRoleDefinitionID),
		},
		{
			name: "Returns an error when the role definitions API returns data that doesn't have exactly one permission in its properties.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType:    ptr.To(testRoleType),
								RoleName:    ptr.To(testRoleName),
								Permissions: []*armauthorization.Permission{},
							},
						},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
				},
				principalID: testPrincipalID,
			},
			want:       "",
			wantErr:    true,
			wantErrMsg: fmt.Sprintf("role definition '%s' from API response has unexpected number of permissions", testRoleDefinitionID),
		},
		{
			name: "Returns no error and no failure when there is a role assignment for a role with the specified permissions.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType: ptr.To(testRoleType),
								RoleName: ptr.To(testRoleName),
								Permissions: []*armauthorization.Permission{
									{
										Actions:        []*string{ptr.To(testAction)},
										DataActions:    []*string{},
										NotActions:     []*string{},
										NotDataActions: []*string{},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
					Role: v1alpha1.Role{
						Type: testRoleType,
						Name: testRoleName,
						Permission: v1alpha1.Permission{
							Actions: []v1alpha1.ActionStr{
								v1alpha1.ActionStr(testAction),
							},
						},
					},
				},
				principalID: testPrincipalID,
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "Returns no error and no failure when the specified permissions are provided by a role assignment other than the first one encountered.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID + "2"),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID + "2"),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType: ptr.To(testRoleType),
								RoleName: ptr.To(testRoleName),
								Permissions: []*armauthorization.Permission{
									{
										Actions:        []*string{ptr.To("some-other-action")},
										DataActions:    []*string{},
										NotActions:     []*string{},
										NotDataActions: []*string{},
									},
								},
							},
						},
						testRoleDefinitionID + "2": {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType: ptr.To(testRoleType),
								RoleName: ptr.To(testRoleName),
								Permissions: []*armauthorization.Permission{
									{
										Actions:        []*string{ptr.To(testAction)},
										DataActions:    []*string{},
										NotActions:     []*string{},
										NotDataActions: []*string{},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
					Role: v1alpha1.Role{
						Type: testRoleType,
						Name: testRoleName,
						Permission: v1alpha1.Permission{
							Actions: []v1alpha1.ActionStr{
								v1alpha1.ActionStr(testAction),
							},
						},
					},
				},
				principalID: testPrincipalID,
			},
			want:    "",
			wantErr: false,
		},
		{
			name: "Returns no error and a failure when a role assignment and role definition are found with everything matching except role type.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType: ptr.To("some-other-role-type"),
								RoleName: ptr.To(testRoleName),
								Permissions: []*armauthorization.Permission{
									{
										Actions:        []*string{ptr.To(testAction)},
										DataActions:    []*string{},
										NotActions:     []*string{},
										NotDataActions: []*string{},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
					Role: v1alpha1.Role{
						Type: testRoleType,
						Name: testRoleName,
						Permission: v1alpha1.Permission{
							Actions: []v1alpha1.ActionStr{
								v1alpha1.ActionStr(testAction),
							},
						},
					},
				},
				principalID: testPrincipalID,
			},
			want: fmt.Sprintf("Principal '%s' does not have role with type '%s' and role name '%s' assigned at scope '%s' with required permissions.",
				testPrincipalID, testRoleType, testRoleName, testScope),
			wantErr: false,
		},
		{
			name: "Returns no error and a failure when a role assignment and role definition are found with everything matching except role name.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType: ptr.To(testRoleType),
								RoleName: ptr.To("some-other-role-name"),
								Permissions: []*armauthorization.Permission{
									{
										Actions:        []*string{ptr.To(testAction)},
										DataActions:    []*string{},
										NotActions:     []*string{},
										NotDataActions: []*string{},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
					Role: v1alpha1.Role{
						Type: testRoleType,
						Name: testRoleName,
						Permission: v1alpha1.Permission{
							Actions: []v1alpha1.ActionStr{
								v1alpha1.ActionStr(testAction),
							},
						},
					},
				},
				principalID: testPrincipalID,
			},
			want: fmt.Sprintf("Principal '%s' does not have role with type '%s' and role name '%s' assigned at scope '%s' with required permissions.",
				testPrincipalID, testRoleType, testRoleName, testScope),
			wantErr: false,
		},
		{
			name: "Returns no error and a failure when a role assignment and role definition are found with everything matching except role assignment scope.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To("some-other-scope"),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType: ptr.To(testRoleType),
								RoleName: ptr.To(testRoleName),
								Permissions: []*armauthorization.Permission{
									{
										Actions:        []*string{ptr.To(testAction)},
										DataActions:    []*string{},
										NotActions:     []*string{},
										NotDataActions: []*string{},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
					Role: v1alpha1.Role{
						Type: testRoleType,
						Name: testRoleName,
						Permission: v1alpha1.Permission{
							Actions: []v1alpha1.ActionStr{
								v1alpha1.ActionStr(testAction),
							},
						},
					},
				},
				principalID: testPrincipalID,
			},
			want: fmt.Sprintf("Principal '%s' does not have role with type '%s' and role name '%s' assigned at scope '%s' with required permissions.",
				testPrincipalID, testRoleType, testRoleName, testScope),
			wantErr: false,
		},
		{
			name: "Returns no error and a failure when a role assignment and role definition are found with everything matching except permissions.",
			fields: fields{
				raAPI: &fakeRAAPI{
					d1: []*armauthorization.RoleAssignment{
						{
							Properties: &armauthorization.RoleAssignmentProperties{
								RoleDefinitionID: ptr.To(testRoleDefinitionID),
								Scope:            ptr.To(testScope),
							},
							ID: ptr.To(testRoleAssignmentID),
						},
					},
				},
				rdAPI: &fakeRDAPI{
					roleDefinitions: map[string]*armauthorization.RoleDefinition{
						testRoleDefinitionID: {
							Properties: &armauthorization.RoleDefinitionProperties{
								RoleType: ptr.To(testRoleType),
								RoleName: ptr.To(testRoleName),
								Permissions: []*armauthorization.Permission{
									{
										Actions:        []*string{ptr.To("some-other-action")},
										DataActions:    []*string{},
										NotActions:     []*string{},
										NotDataActions: []*string{},
									},
								},
							},
						},
					},
				},
			},
			args: args{
				raSpec: v1alpha1.RoleAssignment{
					Scope: testScope,
					Role: v1alpha1.Role{
						Type: testRoleType,
						Name: testRoleName,
						Permission: v1alpha1.Permission{
							Actions: []v1alpha1.ActionStr{
								v1alpha1.ActionStr(testAction),
							},
						},
					},
				},
				principalID: testPrincipalID,
			},
			want: fmt.Sprintf("Principal '%s' does not have role with type '%s' and role name '%s' assigned at scope '%s' with required permissions.",
				testPrincipalID, testRoleType, testRoleName, testScope),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RBACRoleRuleService{
				raAPI: tt.fields.raAPI,
				rdAPI: tt.fields.rdAPI,
			}
			got, err := s.processRoleAssignment(tt.args.raSpec, tt.args.principalID)
			if (err != nil) != tt.wantErr {
				t.Errorf("RBACRoleRuleService.processRoleAssignment() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && err.Error() != tt.wantErrMsg {
				t.Errorf("RBACRoleRuleService.processRoleAssignment() errorMsg = '%s', wantErrMsg '%s'", err.Error(), tt.wantErrMsg)
				return
			}
			if got != tt.want {
				t.Errorf("RBACRoleRuleService.processRoleAssignment() = %v, want %v", got, tt.want)
			}
		})
	}
}
