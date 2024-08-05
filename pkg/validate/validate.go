// Package validate defines a Validate function that evaluates an AzureValidatorSpec and returns a ValidationResponse.
package validate

import (
	"context"
	"os"
	"time"

	"github.com/go-logr/logr"
	"github.com/validator-labs/validator/pkg/types"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/pkg/azure"
	utils "github.com/validator-labs/validator-plugin-azure/pkg/utils/azure"
)

// Validate validates the AzureValidatorSpec and returns a ValidationResponse.
func Validate(spec v1alpha1.AzureValidatorSpec, log logr.Logger) types.ValidationResponse {
	resp := types.ValidationResponse{
		ValidationRuleResults: make([]*types.ValidationRuleResult, 0, spec.ResultCount()),
		ValidationRuleErrors:  make([]error, 0, spec.ResultCount()),
	}

	azureAPI, err := utils.NewAzureAPI()
	if err != nil {
		log.Error(err, "failed to create Azure API object")
		return resp
	}

	ctx := context.Background()
	if os.Getenv("IS_TEST") == "true" {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(ctx, time.Now().Add(utils.TestClientTimeout))
		defer cancel()
	}

	daClient := utils.NewDenyAssignmentsClient(ctx, azureAPI.DenyAssignmentsClient)
	raClient := utils.NewRoleAssignmentsClient(ctx, azureAPI.RoleAssignmentsClient)
	rdClient := utils.NewRoleDefinitionsClient(ctx, azureAPI.RoleDefinitionsClient)
	cgiClient := utils.NewCommunityGalleryImagesClient(ctx, azureAPI.CommunityGalleryImagesClientProducer)

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

	return resp
}
