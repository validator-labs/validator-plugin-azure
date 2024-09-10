package azure

import (
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/quota/armquota"
	corev1 "k8s.io/api/core/v1"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/pkg/constants"
	azerr "github.com/validator-labs/validator-plugin-azure/pkg/utils/azureerrors"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapiconstants "github.com/validator-labs/validator/pkg/constants"
	vapitypes "github.com/validator-labs/validator/pkg/types"
)

var (
	quotaRulePermissions = []string{
		"Microsoft.Quota/quotas/read",
		"Microsoft.Quota/usages/read",
	}
)

// quotasAPI contains methods that allow getting all the information we need for currently set
// quotas and current usage of the quotas.
type quotasAndUsagesAPI interface {
	GetQuotasForScope(scope string) ([]*armquota.CurrentQuotaLimitBase, error)
	GetUsagesForScope(scope string) ([]*armquota.CurrentUsagesBase, error)
}

// QuotaRuleService reconciles quota rules.
type QuotaRuleService struct {
	api quotasAndUsagesAPI
}

// NewQuotaRuleService creates a new QuotaRuleService. Requires an Azure client facade that supports getting all quota limits and usages for a scope.
func NewQuotaRuleService(api quotasAndUsagesAPI) *QuotaRuleService {
	return &QuotaRuleService{
		api: api,
	}
}

func (s *QuotaRuleService) ReconcileQuotaRule(rule v1alpha1.QuotaRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default ValidationResult for this rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Failures = []string{}
	latestCondition.Message = "All quotas acceptable. Current usages plus buffers fall within current quota limits."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.Name())
	latestCondition.ValidationType = constants.ValidationTypeQuota
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	for _, set := range rule.ResourceSets {
		if err := s.processResourceSet(set, &latestCondition.Failures, &latestCondition.Details); err != nil {
			// Code this is returning to will take care of changing the validation result to a
			// failed validation, using the error returned.
			return validationResult, err
		}
	}

	if len(latestCondition.Failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Message = "Usage for one or more resources exceeded the quota plus specified buffer"
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil

}

func (s *QuotaRuleService) processResourceSet(set v1alpha1.ResourceSet, failures *[]string, details *[]string) error {

	// Get all quotas for the scope. This will get quotas for a certain set of resources depending
	// on what kind of scope the user indicated. It will exclude resources for other types of
	// scopes. Arrange into a map for easy access by name later.
	quotas, err := s.api.GetQuotasForScope(set.Scope)
	if err != nil {
		return fmt.Errorf("failed to get quotas: %w", azerr.AsAugmented(err, quotaRulePermissions))
	}
	quotaMap := make(map[string]*armquota.CurrentQuotaLimitBase)
	for _, quota := range quotas {
		if quota != nil && quota.Name != nil {
			quotaMap[*quota.Name] = quota
		}
	}

	// Get all usages for the scope too, as a map.
	usages, err := s.api.GetUsagesForScope(set.Scope)
	if err != nil {
		return fmt.Errorf("failed to get usages: %w", azerr.AsAugmented(err, quotaRulePermissions))
	}
	usageMap := make(map[string]*armquota.CurrentUsagesBase)
	for _, usage := range usages {
		if usage != nil && usage.Name != nil {
			usageMap[*usage.Name] = usage
		}
	}

	// For each resource in the resource set, check its quota, check its usage, and determine
	// whether it has adequate buffer according to the rule. If it doesn't, add a failure.
	// Resources specified without matching quota or usage data from Azure mean the user
	// misconfigured the rule, so this causes a failure too.
	for _, resource := range set.Resources {
		name := resource.Name
		buffer := resource.Buffer

		quota, ok := quotaMap[name]
		if !ok {
			*failures = append(*failures, fmt.Sprintf("Quota for resource '%s' not found. Verify that a valid scope was used for this resource.", name))
			continue
		}
		if quota.Properties == nil || quota.Properties.Limit == nil {
			return fmt.Errorf("properties in quotas API response were nil")
		}
		// Azure uses an interface for this part of the response data, and its code comments say
		// you're supposed to use a type switch to see what concrete type it actually. But, I wasn't
		// able to see any other concrete type that I could parse a value from. This seems to be the
		// only supported concrete type right now. If that changes in the future because Azure adds
		// another concrete type that a limit value could be parsed from, this should be updated.
		limitObject, ok := quota.Properties.Limit.(*armquota.LimitObject)
		if !ok {
			return fmt.Errorf("limit property from Azure API was unexpected concrete type")
		}
		if limitObject == nil || limitObject.Value == nil {
			return fmt.Errorf("limit value from Azure API was nil")
		}
		currentQuotaLimit := *limitObject.Value

		usage, ok := usageMap[name]
		if !ok {
			// If a user specifies a quota that isn't found, that's a user error (they likely used
			// the wrong scope), but if a usage isn't found for that quota, that's likely an issue
			// on Azure's side, because the Azure usages API is supposed to return a usage for every
			// quota.
			return fmt.Errorf("usage for resource %s not found", name)
		}
		if usage.Properties == nil || usage.Properties.Usages == nil || usage.Properties.Usages.Value == nil {
			return fmt.Errorf("properties in usages API response were nil")
		}
		currentUsage := *usage.Properties.Usages.Value

		// Always append details, regardless of whether over limit.
		detailMsg := fmt.Sprintf(
			"%s/%s: quota limit: %d, buffer: %d, usage: %d",
			set.Scope, name, currentQuotaLimit, buffer, currentUsage,
		)
		*details = append(*details, detailMsg)

		// If over, append a failure too.
		remainder := currentQuotaLimit - currentUsage
		if remainder < buffer {
			failureMsg := fmt.Sprintf(
				"Remaining quota %d, less than buffer %d, for %s/%s",
				remainder, buffer, set.Scope, name,
			)
			*failures = append(*failures, failureMsg)
		}
	}

	return nil
}
