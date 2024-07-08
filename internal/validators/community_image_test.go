package validators

import (
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/go-logr/logr"
	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
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
				Name: "rule-1",
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
						Properties: &armcompute.CommunityGalleryImageProperties{
							Identifier: &armcompute.CommunityGalleryImageIdentifier{
								Offer:     util.Ptr("offer1"),
								Publisher: util.Ptr("publisher1"),
								SKU:       util.Ptr("sku1"),
							},
						},
						Location: util.Ptr("location1"),
						Name:     util.Ptr("image1"),
						Type:     util.Ptr("type1"),
					},
				},
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-community-gallery-image",
					ValidationRule: "validation-rule-1",
					Message:        "All required images present in community gallery.",
					Details:        []string{"Found image; Name: 'image1'; Offer: 'offer1'; Publisher: 'publisher1'; SKU: 'sku1'; Location: 'location1'; Type: 'type1'"},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (required images present in community gallery - 2 images)",
			rule: v1alpha1.CommunityGalleryImageRule{
				Name: "rule-1",
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
						Properties: &armcompute.CommunityGalleryImageProperties{
							Identifier: &armcompute.CommunityGalleryImageIdentifier{
								Offer:     util.Ptr("offer1"),
								Publisher: util.Ptr("publisher1"),
								SKU:       util.Ptr("sku1"),
							},
						},
						Location: util.Ptr("location1"),
						Name:     util.Ptr("image1"),
						Type:     util.Ptr("type1"),
					},
					{
						Properties: &armcompute.CommunityGalleryImageProperties{
							Identifier: &armcompute.CommunityGalleryImageIdentifier{
								Offer:     util.Ptr("offer2"),
								Publisher: util.Ptr("publisher2"),
								SKU:       util.Ptr("sku2"),
							},
						},
						Location: util.Ptr("location1"),
						Name:     util.Ptr("image2"),
						Type:     util.Ptr("type1"),
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
						"Found image; Name: 'image1'; Offer: 'offer1'; Publisher: 'publisher1'; SKU: 'sku1'; Location: 'location1'; Type: 'type1'",
						"Found image; Name: 'image2'; Offer: 'offer2'; Publisher: 'publisher2'; SKU: 'sku2'; Location: 'location1'; Type: 'type1'",
					},
					Failures: []string{},
					Status:   corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (detail message fall back when API response has nil values)",
			rule: v1alpha1.CommunityGalleryImageRule{
				Name: "rule-1",
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
						Location: util.Ptr("location1"),
						Name:     util.Ptr("image1"),
						Type:     util.Ptr("type1"),
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
			name: "Pass (does not stop validating when image name in API response is nil)",
			rule: v1alpha1.CommunityGalleryImageRule{
				Name: "rule-1",
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
						"Image image1 not present in community gallery.",
					},
					Status: corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (required image is not present in community gallery)",
			rule: v1alpha1.CommunityGalleryImageRule{
				Name: "rule-1",
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
						"Image image2 not present in community gallery.",
					},
					Status: corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
		{
			name: "Fail (gallery does not exist or is not accessible using subscription) - validation result remains passing, code returned to interprets error and changes result",
			rule: v1alpha1.CommunityGalleryImageRule{
				Name: "rule-1",
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
		util.CheckTestCase(t, result, tc.expectedResult, err, tc.expectedError)
	}
}
