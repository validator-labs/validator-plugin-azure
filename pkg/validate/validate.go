// Package validate defines a Validate function that evaluates an AzureValidatorSpec and returns a ValidationResponse.
package validate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vconstants "github.com/validator-labs/validator/pkg/constants"
	"github.com/validator-labs/validator/pkg/types"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/pkg/azure"
	"github.com/validator-labs/validator-plugin-azure/pkg/constants"
	utils "github.com/validator-labs/validator-plugin-azure/pkg/utils/azure"
	"github.com/validator-labs/validator-plugin-azure/pkg/utils/strings"
)

var errInvalidTenantID = errors.New("tenant ID is invalid, must be a v4 uuid")
var errInvalidClientID = errors.New("client ID is invalid, must be a v4 uuid")
var errInvalidClientSecret = errors.New("client secret is invalid, must be a non-empty string")

// Validate validates the AzureValidatorSpec and returns a ValidationResponse.
func Validate(ctx context.Context, spec v1alpha1.AzureValidatorSpec, log logr.Logger) types.ValidationResponse {
	resp := types.ValidationResponse{
		ValidationRuleResults: make([]*types.ValidationRuleResult, 0, spec.ResultCount()),
		ValidationRuleErrors:  make([]error, 0, spec.ResultCount()),
	}

	azureAPI, err := utils.NewAzureAPI()
	if err != nil {
		vrr := buildValidationResult()
		resp.AddResult(vrr, fmt.Errorf("failed to create Azure API object: %w", err))
		return resp
	}

	ctx = context.WithoutCancel(ctx)
	if os.Getenv("IS_TEST") == "true" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(utils.TestClientTimeout))
		defer cancel()
	}

	daClient := utils.NewDenyAssignmentsClient(ctx, azureAPI.DenyAssignmentsClient)
	raClient := utils.NewRoleAssignmentsClient(ctx, azureAPI.RoleAssignmentsClient)
	rdClient := utils.NewRoleDefinitionsClient(ctx, azureAPI.RoleDefinitionsClient)
	cgiClient := utils.NewCommunityGalleryImagesClient(ctx, azureAPI.CommunityGalleryImagesClientProducer)
	qClient := utils.NewQuotasClient(ctx, azureAPI.QuotaLimitsClient, azureAPI.UsagesClient)

	// RBAC rules
	rbacSvc := azure.NewRBACRuleService(daClient, raClient, rdClient)
	for _, rule := range spec.RBACRules {
		vrr, err := rbacSvc.ReconcileRBACRule(rule)
		if err != nil {
			log.Error(err, "failed to reconcile RBAC rule")
		}
		resp.AddResult(vrr, err)
	}

	// Community gallery image rules
	cgiSvc := azure.NewCommunityGalleryImageRuleService(cgiClient, log)
	for _, rule := range spec.CommunityGalleryImageRules {
		vrr, err := cgiSvc.ReconcileCommunityGalleryImageRule(rule)
		if err != nil {
			log.Error(err, "failed to reconcile community gallery image rule")
		}
		resp.AddResult(vrr, err)
	}

	// Quota rules
	qSvc := azure.NewQuotaRuleService(qClient)
	for _, rule := range spec.QuotaRules {
		vrr, err := qSvc.ReconcileQuotaRule(rule)
		if err != nil {
			log.Error(err, "failed to reconcile quota rule")
		}
		resp.AddResult(vrr, err)
	}

	return resp
}

func buildValidationResult() *types.ValidationRuleResult {
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Message = "Initialization succeeded"
	latestCondition.ValidationRule = fmt.Sprintf(
		"%s-%s",
		vconstants.ValidationRulePrefix, constants.PluginCode,
	)
	latestCondition.ValidationType = constants.PluginCode

	return &types.ValidationRuleResult{Condition: &latestCondition, State: &state}
}

// Validates the inline auth. The data here could have not passed through kube-apiserver, so we need
// to validate here instead of relying on CRD validation.
func validateAuth(auth v1alpha1.AzureAuth) error {
	if auth.Credentials == nil {
		auth.Credentials = &v1alpha1.ServicePrincipalCredentials{}
	}

	var validationErrors []error

	if !strings.IsValidUUID(auth.Credentials.TenantID) {
		validationErrors = append(validationErrors, errInvalidTenantID)
	}
	if !strings.IsValidUUID(auth.Credentials.ClientID) {
		validationErrors = append(validationErrors, errInvalidClientID)
	}
	if auth.Credentials.ClientSecret == "" {
		validationErrors = append(validationErrors, errInvalidClientSecret)
	}

	if len(validationErrors) > 0 {
		return errors.Join(validationErrors...)
	}
	return nil
}

// Sets environment variables needed by the Azure SDK from the inline auth. The inline auth is
// assumed to have already been validated.
func configureAuth(auth v1alpha1.AzureAuth, log logr.Logger) error {
	if auth.Implicit {
		log.Info("auth.implicit set to true. Skipping setting AZURE_ env vars.")
		return nil
	}

	// Log non-secret data for help with debugging. Don't log the client secret.
	nonSecretData := map[string]string{
		"tenantId":    auth.Credentials.TenantID,
		"clientId":    auth.Credentials.ClientID,
		"environment": auth.Credentials.Environment,
	}
	log.Info("Determined Azure auth data.", "nonSecretData", nonSecretData)

	// Use collected and validated values to set env vars.
	data := map[string]string{
		"AZURE_TENANT_ID":     auth.Credentials.TenantID,
		"AZURE_CLIENT_ID":     auth.Credentials.ClientID,
		"AZURE_CLIENT_SECRET": auth.Credentials.ClientSecret,
		"AZURE_ENVIRONMENT":   auth.Credentials.Environment,
	}
	for k, v := range data {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
		log.Info("Set environment variable", "envVar", k)
	}

	return nil
}
