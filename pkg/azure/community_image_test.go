package azure

import (
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/go-logr/logr"
	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/test"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
	corev1 "k8s.io/api/core/v1"
)

type apiMock struct {
	data []*armcompute.CommunityGalleryImage
	err  error
}

func (m apiMock) GetImagesForGallery(_, _, _ string) ([]*armcompute.CommunityGalleryImage, error) {
	return m.data, m.err
}

func TestCommunityGalleryImageRuleService_ReconcileCommunityGalleryImageRule(t *testing.T) {

	type testCase struct {
		name           string
		rule           v1alpha1.CommunityGalleryImageRule
		apiMock        apiMock
		expectedError  error
		expectedResult vapitypes.ValidationRuleResult
	}

	testCases := []testCase{
		{
			name: "Pass (required images present in community gallery - 1 image)",
			rule: v1alpha1.CommunityGalleryImageRule{
				RuleName: "rule-1",
				Gallery: v1alpha1.CommunityGallery{
					Location: "location1",
					Name:     "gallery1",
				},
				Images:         []string{"image1"},
				SubscriptionID: "sub",
			},
			apiMock: apiMock{
				data: []*armcompute.CommunityGalleryImage{
					{
						Name: util.Ptr("image1"),
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-community-gallery-image",
					ValidationRule: "validation-rule-1",
					Message:        "All required images present in community gallery.",
					Details:        []string{"Found image; Name: 'image1'"},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (required images present in community gallery - 2 images)",
			rule: v1alpha1.CommunityGalleryImageRule{
				RuleName: "rule-1",
				Gallery: v1alpha1.CommunityGallery{
					Location: "location1",
					Name:     "gallery1",
				},
				Images:         []string{"image1", "image2"},
				SubscriptionID: "sub",
			},
			apiMock: apiMock{
				data: []*armcompute.CommunityGalleryImage{
					{
						Name: util.Ptr("image1"),
					},
					{
						Name: util.Ptr("image2"),
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-community-gallery-image",
					ValidationRule: "validation-rule-1",
					Message:        "All required images present in community gallery.",
					Details: []string{
						"Found image; Name: 'image1'",
						"Found image; Name: 'image2'",
					},
					Failures: []string{},
					Status:   corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (does not stop validating when image name in API response is nil)",
			rule: v1alpha1.CommunityGalleryImageRule{
				RuleName: "rule-1",
				Gallery: v1alpha1.CommunityGallery{
					Location: "location1",
					Name:     "gallery1",
				},
				Images:         []string{"image1", "image2"},
				SubscriptionID: "sub",
			},
			apiMock: apiMock{
				data: []*armcompute.CommunityGalleryImage{
					{},
					{
						Name: util.Ptr("image2"),
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-community-gallery-image",
					ValidationRule: "validation-rule-1",
					Message:        "Community gallery lacks one or more required images. See failures for details.",
					Details: []string{
						"Found image; Name: 'image2'",
					},
					Failures: []string{
						"Image 'image1' not present in community gallery.",
					},
					Status: corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (required image is not present in community gallery)",
			rule: v1alpha1.CommunityGalleryImageRule{
				RuleName: "rule-1",
				Gallery: v1alpha1.CommunityGallery{
					Location: "location1",
					Name:     "gallery1",
				},
				Images:         []string{"image2"},
				SubscriptionID: "sub",
			},
			apiMock: apiMock{
				data: []*armcompute.CommunityGalleryImage{
					{
						Name: util.Ptr("image1"),
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-community-gallery-image",
					ValidationRule: "validation-rule-1",
					Message:        "Community gallery lacks one or more required images. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"Image 'image2' not present in community gallery.",
					},
					Status: corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (gallery does not exist or is not accessible using subscription) - validation result remains passing, code returned to interprets error and changes result",
			rule: v1alpha1.CommunityGalleryImageRule{
				RuleName: "rule-1",
				Gallery: v1alpha1.CommunityGallery{
					Location: "location1",
					Name:     "gallery1",
				},
				Images:         []string{"image1"},
				SubscriptionID: "sub",
			},
			apiMock: apiMock{
				// Can be any error message, just has to have this as substring.
				err: errors.New("RESPONSE 404"),
			},
			expectedError: errors.New("community gallery gallery1 not found in location location1 using subscription sub"),
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-community-gallery-image",
					ValidationRule: "validation-rule-1",
					Message:        "All required images present in community gallery.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
	}

	for _, tc := range testCases {
		svc := NewCommunityGalleryImageRuleService(tc.apiMock, logr.Logger{})
		result, err := svc.ReconcileCommunityGalleryImageRule(tc.rule)
		test.CheckTestCase(t, result, tc.expectedResult, err, tc.expectedError)
	}
}
