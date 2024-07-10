package validators

import (
	"fmt"
	"net/http"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/internal/constants"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapiconstants "github.com/validator-labs/validator/pkg/constants"
	vapitypes "github.com/validator-labs/validator/pkg/types"
)

// httpClient defines the interface for the HTTP client used by the PublicBlobRuleService.
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// PublicBlobRuleService reconciles public blob rules.
type PublicBlobRuleService struct {
	httpClient httpClient
}

// NewPublicBlobRuleService creates a new PublicBlobRuleService.
func NewPublicBlobRuleService(client httpClient) *PublicBlobRuleService {
	return &PublicBlobRuleService{httpClient: client}
}

// ReconcilePublicBlobRule reconciles a public blob rule.
func (s *PublicBlobRuleService) ReconcilePublicBlobRule(rule v1alpha1.PublicBlobRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default ValidationResult for this rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Failures = []string{}
	latestCondition.Message = "All blobs present in container and publicly accessible."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.Name)
	latestCondition.ValidationType = constants.ValidationTypePublicBlob
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	// Use the HTTP HEAD method to check if the file exists and is accessible.
	// If the request fails, return an error.
	// If the request is successful, return the ValidationResult with a success state.
	for _, path := range rule.Paths {
		errMsg, err := s.checkBlob(rule.StorageAccount, rule.Container, path)
		if err != nil {
			return validationResult, fmt.Errorf("failed to check blob '%s' in container '%s' in storage account '%s': %w",
				path, rule.Container, rule.StorageAccount, err)
		}
		if errMsg != "" {
			latestCondition.Failures = append(latestCondition.Failures,
				fmt.Sprintf("blob '%s' in container '%s' in storage account '%s' is not publicly accessible: %s",
					path, rule.Container, rule.StorageAccount, errMsg))
			state = vapi.ValidationFailed
		} else {
			latestCondition.Details = append(latestCondition.Details,
				fmt.Sprintf("Blob '%s' in container '%s' in storage account '%s' is publicly accessible.",
					path, rule.Container, rule.StorageAccount))
		}
	}

	return validationResult, nil
}

// checkBlob checks a blob in the rule by ensuring it's accessible via HTTPS with a HEAD request.
// Returns an error message if the blob doesn't exist or is otherwise not accessible.
func (s *PublicBlobRuleService) checkBlob(storageAccount, container, path string) (string, error) {
	// Create the URL for the blob.
	url := fmt.Sprintf("https://%s.blob.core.windows.net/%s/%s", storageAccount, container, path)

	// Create a new HTTP HEAD request for the blob.
	req, err := http.NewRequest("HEAD", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// Send the request. If a 200 response comes back, we consider the file accessible.
	client := s.httpClient
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send HTTP request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Sprintf("'%s' status in HEAD request response", resp.Status), nil
	}

	// Blob accessible.
	return "", nil
}
