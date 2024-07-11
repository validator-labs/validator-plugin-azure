package validators

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
	corev1 "k8s.io/api/core/v1"
)

// doer is an interface that defines the Do method for an HTTP client.
type doer func(req *http.Request) (*http.Response, error)

// FakeHTTPClient is a fake HTTP client that implements the httpClient interface.
type fakeHTTPClient struct {
	doer doer
}

// Do is a method that satisfies the httpClient interface. Uses the doer function to return a
// response during testing.
func (f fakeHTTPClient) Do(req *http.Request) (*http.Response, error) {
	return f.doer(req)
}

// createDoer is a helper function that creates a doer function that returns either an error or a
// response with the specified status code.
func createDoer(statusCode int, err error) doer {
	if err != nil {
		return func(_ *http.Request) (*http.Response, error) {
			return nil, err
		}
	}
	return func(_ *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: statusCode,
			Body:       io.NopCloser(bytes.NewBufferString("")),
		}, nil
	}
}

func TestPublicBlobRuleService_ReconcilePublicBlobRule(t *testing.T) {

	type testCase struct {
		name           string
		rule           v1alpha1.PublicBlobRule
		httpClientMock httpClient
		expectedError  error
		expectedResult vapitypes.ValidationRuleResult
	}

	testCases := []testCase{
		{
			name: "Pass (all blobs found - 1 blob)",
			rule: v1alpha1.PublicBlobRule{
				Name:           "rule-1",
				StorageAccount: "sa1",
				Container:      "container1",
				Paths:          []string{"blob1"},
			},
			httpClientMock: fakeHTTPClient{
				doer: createDoer(http.StatusOK, nil),
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-public-blob",
					ValidationRule: "validation-rule-1",
					Message:        "All blobs present in container and publicly accessible.",
					Details: []string{
						"Blob 'blob1' in container 'container1' in storage account 'sa1' is publicly accessible.",
					},
					Failures: []string{},
					Status:   corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Pass (all blobs found - 2 blobs)",
			rule: v1alpha1.PublicBlobRule{
				Name:           "rule-1",
				StorageAccount: "sa1",
				Container:      "container1",
				Paths:          []string{"blob1", "blob2"},
			},
			httpClientMock: fakeHTTPClient{
				doer: createDoer(http.StatusOK, nil),
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-public-blob",
					ValidationRule: "validation-rule-1",
					Message:        "All blobs present in container and publicly accessible.",
					Details: []string{
						"Blob 'blob1' in container 'container1' in storage account 'sa1' is publicly accessible.",
						"Blob 'blob2' in container 'container1' in storage account 'sa1' is publicly accessible.",
					},
					Failures: []string{},
					Status:   corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (error making HTTP request)",
			rule: v1alpha1.PublicBlobRule{
				Name:           "rule-1",
				StorageAccount: "sa1",
				Container:      "container1",
				Paths:          []string{"blob1"},
			},
			httpClientMock: fakeHTTPClient{
				doer: createDoer(0, fmt.Errorf("Do error")),
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				// Code returned to overrides the state and condition.
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-public-blob",
					ValidationRule: "validation-rule-1",
					Message:        "All blobs present in container and publicly accessible.",
					Details:        []string{},
					Failures:       []string{},
					Status:         corev1.ConditionTrue,
				},
				State: util.Ptr(vapi.ValidationSucceeded),
			},
		},
		{
			name: "Fail (blob does not exist or bad config with either bad container or path)",
			rule: v1alpha1.PublicBlobRule{
				Name:           "rule-1",
				StorageAccount: "sa1",
				Container:      "container1",
				Paths:          []string{"blob1"},
			},
			httpClientMock: fakeHTTPClient{
				doer: createDoer(http.StatusNotFound, nil),
			},
			expectedError: nil,
			expectedResult: vapitypes.ValidationRuleResult{
				Condition: &vapi.ValidationCondition{
					ValidationType: "azure-public-blob",
					ValidationRule: "validation-rule-1",
					Message:        "One or more blobs not publicly accessible. See failures for details.",
					Details:        []string{},
					Failures: []string{
						"blob 'blob1' in container 'container1' in storage account 'sa1' is not publicly accessible; '404' status code in response to HEAD request",
					},
					Status: corev1.ConditionFalse,
				},
				State: util.Ptr(vapi.ValidationFailed),
			},
		},
	}

	for _, tc := range testCases {
		svc := NewPublicBlobRuleService(tc.httpClientMock)
		result, err := svc.ReconcilePublicBlobRule(tc.rule)
		util.CheckTestCase(t, result, tc.expectedResult, err, tc.expectedError)
	}
}
