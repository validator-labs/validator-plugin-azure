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

type roleAssignmentAPI2Mock struct {
	data []*armauthorization.RoleAssignment
	err  error
}

func (m roleAssignmentAPI2Mock) ListRoleAssignmentsForScope(scope string, filter *string) ([]*armauthorization.RoleAssignment, error) {
	return m.data, m.err
}

func TestRBACRuleService_ReconcileRBACRule(t *testing.T) {
	type testCase struct {
		apiMock        roleAssignmentAPI2Mock
		expectedError  error
		expectedResult vapitypes.ValidationResult
		name           string
		rule           v1alpha1.RBACRule
	}

	cs := []testCase{
		{
			name: "Fail (missing role assignment)",
			rule: v1alpha1.RBACRule{
				PrincipalID: "p_id",
				Permissions: []v1alpha1.PermissionSet{
					{
						Role:  "role_1_id",
						Scope: "/subscriptions/sub_id",
					},
				},
			},
			apiMock: roleAssignmentAPI2Mock{
				data: []*armauthorization.RoleAssignment{},
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
			name: "Pass (no permission sets in rule)",
			rule: v1alpha1.RBACRule{
				PrincipalID: "p_id",
			},
			apiMock: roleAssignmentAPI2Mock{
				data: []*armauthorization.RoleAssignment{},
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
		svc := NewRBACRuleService(logr.Logger{}, c.apiMock, roleLookupMapProviderMock)
		result, err := svc.ReconcileRBACRule(c.rule)
		test.CheckTestCase(t, result, c.expectedResult, err, c.expectedError)
	}
}
