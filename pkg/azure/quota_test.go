package azure

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/quota/armquota"
	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
	corev1 "k8s.io/api/core/v1"
)

type quotasAndUsagesAPIMock struct {
	quotasData map[string][]*armquota.CurrentQuotaLimitBase
	usagesData map[string][]*armquota.CurrentUsagesBase
	err        error
}

func (m quotasAndUsagesAPIMock) GetQuotasForScope(scope string) ([]*armquota.CurrentQuotaLimitBase, error) {
	return m.quotasData[scope], m.err
}

func (m quotasAndUsagesAPIMock) GetUsagesForScope(scope string) ([]*armquota.CurrentUsagesBase, error) {
	return m.usagesData[scope], m.err
}

func TestQuotaRuleService_ReconcileQuotaRule(t *testing.T) {

	type testCase struct {
		name           string
		rule           v1alpha1.QuotaRule
		apiMock        quotasAndUsagesAPIMock
		expectedError  error
		expectedResult vapitypes.ValidationRuleResult
	}

	testCases := []testCase{
		{
			name: "Pass (current usage is equal to the current quota plus the buffer - 1 resource in 1 resource set)",
			rule: v1alpha1.QuotaRule{
				RuleName: "rule-1",
				ResourceSets: []v1alpha1.ResourceSet{
					{
						Scope: "scope1",
						Resources: []v1alpha1.Resource{
							{
								Name:   "resource1",
								Buffer: 1,
							},
						},
					},
				},
			},
			apiMock: quotasAndUsagesAPIMock{
				quotasData: map[string][]*armquota.CurrentQuotaLimitBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.Properties{
								Limit: &armquota.LimitObject{
									Value: util.Ptr(int32(3)),
								},
							},
						},
					},
				},
				usagesData: map[string][]*armquota.CurrentUsagesBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.UsagesProperties{
								Usages: &armquota.UsagesObject{
									Value: util.Ptr(int32(2)),
								},
							},
						},
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-quota",
					ValidationRule: "validation-rule-1",
					Message:        "All quota limits high enough. For each resource, current usage plus buffer falls within current quota limit.",
					Details:        []string{"scope1/resource1: quota limit: 3, buffer: 1, usage: 2"},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (current usage is equal to the current quota plus the buffer - 2 resources in 1 resource set)",
			rule: v1alpha1.QuotaRule{
				RuleName: "rule-1",
				ResourceSets: []v1alpha1.ResourceSet{
					{
						Scope: "scope1",
						Resources: []v1alpha1.Resource{
							{
								Name:   "resource1",
								Buffer: 1,
							},
							{
								Name:   "resource2",
								Buffer: 1,
							},
						},
					},
				},
			},
			apiMock: quotasAndUsagesAPIMock{
				quotasData: map[string][]*armquota.CurrentQuotaLimitBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.Properties{
								Limit: &armquota.LimitObject{
									Value: util.Ptr(int32(3)),
								},
							},
						},
						{
							Name: util.Ptr("resource2"),
							Properties: &armquota.Properties{
								Limit: &armquota.LimitObject{
									Value: util.Ptr(int32(3)),
								},
							},
						},
					},
				},
				usagesData: map[string][]*armquota.CurrentUsagesBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.UsagesProperties{
								Usages: &armquota.UsagesObject{
									Value: util.Ptr(int32(2)),
								},
							},
						},
						{
							Name: util.Ptr("resource2"),
							Properties: &armquota.UsagesProperties{
								Usages: &armquota.UsagesObject{
									Value: util.Ptr(int32(2)),
								},
							},
						},
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-quota",
					ValidationRule: "validation-rule-1",
					Message:        "All quota limits high enough. For each resource, current usage plus buffer falls within current quota limit.",
					Details: []string{
						"scope1/resource1: quota limit: 3, buffer: 1, usage: 2",
						"scope1/resource2: quota limit: 3, buffer: 1, usage: 2",
					},
					Failures: []string{},
					Status:   corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (current usage is equal to the current quota plus the buffer - 1 resource each in 2 resource sets)",
			rule: v1alpha1.QuotaRule{
				RuleName: "rule-1",
				ResourceSets: []v1alpha1.ResourceSet{
					{
						Scope: "scope1",
						Resources: []v1alpha1.Resource{
							{
								Name:   "resource1",
								Buffer: 1,
							},
						},
					},
					{
						Scope: "scope2",
						Resources: []v1alpha1.Resource{
							{
								Name:   "resource2",
								Buffer: 1,
							},
						},
					},
				},
			},
			apiMock: quotasAndUsagesAPIMock{
				quotasData: map[string][]*armquota.CurrentQuotaLimitBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.Properties{
								Limit: &armquota.LimitObject{
									Value: util.Ptr(int32(3)),
								},
							},
						},
					},
					"scope2": {
						{
							Name: util.Ptr("resource2"),
							Properties: &armquota.Properties{
								Limit: &armquota.LimitObject{
									Value: util.Ptr(int32(3)),
								},
							},
						},
					},
				},
				usagesData: map[string][]*armquota.CurrentUsagesBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.UsagesProperties{
								Usages: &armquota.UsagesObject{
									Value: util.Ptr(int32(2)),
								},
							},
						},
					},
					"scope2": {
						{
							Name: util.Ptr("resource2"),
							Properties: &armquota.UsagesProperties{
								Usages: &armquota.UsagesObject{
									Value: util.Ptr(int32(2)),
								},
							},
						},
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-quota",
					ValidationRule: "validation-rule-1",
					Message:        "All quota limits high enough. For each resource, current usage plus buffer falls within current quota limit.",
					Details: []string{
						"scope1/resource1: quota limit: 3, buffer: 1, usage: 2",
						"scope2/resource2: quota limit: 3, buffer: 1, usage: 2",
					},
					Failures: []string{},
					Status:   corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (current usage is greater than the current quota plus the buffer - 1 resource set)",
			rule: v1alpha1.QuotaRule{
				RuleName: "rule-1",
				ResourceSets: []v1alpha1.ResourceSet{
					{
						Scope: "scope1",
						Resources: []v1alpha1.Resource{
							{
								Name:   "resource1",
								Buffer: 2,
							},
						},
					},
				},
			},
			apiMock: quotasAndUsagesAPIMock{
				quotasData: map[string][]*armquota.CurrentQuotaLimitBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.Properties{
								Limit: &armquota.LimitObject{
									Value: util.Ptr(int32(3)),
								},
							},
						},
					},
				},
				usagesData: map[string][]*armquota.CurrentUsagesBase{
					"scope1": {
						{
							Name: util.Ptr("resource1"),
							Properties: &armquota.UsagesProperties{
								Usages: &armquota.UsagesObject{
									Value: util.Ptr(int32(2)),
								},
							},
						},
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-quota",
					ValidationRule: "validation-rule-1",
					Message:        "Usage for one or more resources exceeded the quota plus specified buffer",
					Details:        []string{"scope1/resource1: quota limit: 3, buffer: 2, usage: 2"},
					Failures:       []string{"Remaining quota 1, less than buffer 2, for scope1/resource1"},
					Status:         corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (user specified resource that doesn't exist in the scope)",
			rule: v1alpha1.QuotaRule{
				RuleName: "rule-1",
				ResourceSets: []v1alpha1.ResourceSet{
					{
						Scope: "scope1",
						Resources: []v1alpha1.Resource{
							{
								Name:   "resource1",
								Buffer: 2,
							},
						},
					},
				},
			},
			apiMock: quotasAndUsagesAPIMock{
				quotasData: map[string][]*armquota.CurrentQuotaLimitBase{
					"scope1": {
						{
							Name: util.Ptr("resource2"),
							Properties: &armquota.Properties{
								Limit: &armquota.LimitObject{
									Value: util.Ptr(int32(3)),
								},
							},
						},
					},
				},
				usagesData: map[string][]*armquota.CurrentUsagesBase{
					"scope1": {
						{
							Name: util.Ptr("resource2"),
							Properties: &armquota.UsagesProperties{
								Usages: &armquota.UsagesObject{
									Value: util.Ptr(int32(2)),
								},
							},
						},
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-quota",
					ValidationRule: "validation-rule-1",
					Message:        "Usage for one or more resources exceeded the quota plus specified buffer",
					Details:        []string{},
					Failures:       []string{"Quota for resource 'resource1' not found. Verify that a valid scope was used for this resource."},
					Status:         corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
	}

	for _, tc := range testCases {
		svc := NewQuotaRuleService(tc.apiMock)
		result, err := svc.ReconcileQuotaRule(tc.rule)
		util.CheckTestCase(t, result, tc.expectedResult, err, tc.expectedError)
	}
}
