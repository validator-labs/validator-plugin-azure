// Package azure contains services that reconcile the validation rules supported by the plugin.
package azure

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/pkg/constants"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapiconstants "github.com/validator-labs/validator/pkg/constants"
	vapitypes "github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
)

// communityGalleryImageAPI contains methods that allow getting all the information we need for
// community galleries and images within them.
type communityGalleryImageAPI interface {
	GetImagesForGallery(location, name, subscriptionID string) ([]*armcompute.CommunityGalleryImage, error)
}

// CommunityGalleryImageRuleService reconciles community gallery image rules.
type CommunityGalleryImageRuleService struct {
	api communityGalleryImageAPI
	log logr.Logger
}

// NewCommunityGalleryImageRuleService creates a new CommunityGalleryImageRuleService. Requires an
// Azure client facade that supports getting all images for a gallery.
func NewCommunityGalleryImageRuleService(api communityGalleryImageAPI, log logr.Logger) *CommunityGalleryImageRuleService {
	return &CommunityGalleryImageRuleService{
		api: api,
		log: log,
	}
}

// ReconcileCommunityGalleryImageRule reconciles a community gallery image rule.
func (s *CommunityGalleryImageRuleService) ReconcileCommunityGalleryImageRule(rule v1alpha1.CommunityGalleryImageRule) (*vapitypes.ValidationRuleResult, error) {

	log := s.log.WithValues("rule", rule.Name(), "images", rule.Images, "gallery", rule.Gallery.Name, "location", rule.Gallery.Location, "subscription", rule.SubscriptionID)

	// Build the default ValidationResult for this rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Failures = []string{}
	latestCondition.Message = "All required images present in community gallery."
	latestCondition.ValidationRule = fmt.Sprintf(
		"%s-%s",
		vapiconstants.ValidationRulePrefix, util.Sanitize(rule.Name()),
	)
	latestCondition.ValidationType = constants.ValidationTypeCommunityGalleryImages
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	imagesInGallery, err := s.api.GetImagesForGallery(rule.Gallery.Location, rule.Gallery.Name, rule.SubscriptionID)
	if err != nil {
		if strings.Contains(err.Error(), "RESPONSE 404") {
			return validationResult, fmt.Errorf("community gallery %s not found in location %s using subscription %s", rule.Gallery.Name, rule.Gallery.Location, rule.SubscriptionID)
		}
		return validationResult, fmt.Errorf("failed to get all images in community gallery: %w", err)
	}
	images := map[string]bool{}
	for _, image := range imagesInGallery {
		if image.Name == nil {
			log.Error(nil, "Image name in API response was nil.")
			continue
		}
		images[*image.Name] = true
	}

	// Find out which of the images in the rule are not present in the gallery.
	for _, ruleImageName := range rule.Images {
		if _, ok := images[ruleImageName]; !ok {
			latestCondition.Failures = append(latestCondition.Failures, fmt.Sprintf("Image '%s' not present in community gallery.", ruleImageName))
		} else {
			latestCondition.Details = append(latestCondition.Details, fmt.Sprintf("Found image; Name: '%s'", ruleImageName))
		}
	}

	if len(latestCondition.Failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Message = "Community gallery lacks one or more required images. See failures for details."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}
