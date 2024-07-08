package validators

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/internal/constants"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vapiconstants "github.com/validator-labs/validator/pkg/constants"
	vapitypes "github.com/validator-labs/validator/pkg/types"
)

// communityGalleryImageAPI contains methods that allow getting all the information we need for
// community galleries and images within them.
type communityGalleryImageAPI interface {
	GetImagesForGallery(location, name, subscriptionID string) ([]*armcompute.CommunityGalleryImage, error)
}

type CommunityGalleryImageRuleService struct {
	api communityGalleryImageAPI
	log logr.Logger
}

func NewCommunityGalleryImageRuleService(api communityGalleryImageAPI, log logr.Logger) *CommunityGalleryImageRuleService {
	return &CommunityGalleryImageRuleService{
		api: api,
		log: log,
	}
}

func (s *CommunityGalleryImageRuleService) ReconcileCommunityGalleryImageRule(rule v1alpha1.CommunityGalleryImageRule) (*vapitypes.ValidationRuleResult, error) {

	// Build the default ValidationResult for this rule.
	state := vapi.ValidationSucceeded
	latestCondition := vapi.DefaultValidationCondition()
	latestCondition.Failures = []string{}
	latestCondition.Message = "All required images present in community gallery."
	latestCondition.ValidationRule = fmt.Sprintf("%s-%s", vapiconstants.ValidationRulePrefix, rule.Name)
	latestCondition.ValidationType = constants.ValidationTypeCommunityGalleryImages
	validationResult := &vapitypes.ValidationRuleResult{Condition: &latestCondition, State: &state}

	imagesInGallery, err := s.api.GetImagesForGallery(rule.Gallery.Location, rule.Gallery.Name, rule.SubscriptionID)
	if err != nil {
		if strings.Contains(err.Error(), "RESPONSE 404") {
			return validationResult, fmt.Errorf("community gallery %s not found in location %s using subscription %s", rule.Gallery.Name, rule.Gallery.Location, rule.SubscriptionID)
		}
		return validationResult, fmt.Errorf("failed to get all images in gallery: %w", err)
	}
	images := map[string]bool{}
	for _, image := range imagesInGallery {
		if image.Name == nil {
			s.log.Error(nil, "Image name in API response was nil.", "rule", rule.Name)
			continue
		}
		images[*image.Name] = true
	}

	// Find out which of the images in the rule are not present in the gallery.
	for _, image := range rule.Images {
		if _, ok := images[image]; !ok {
			latestCondition.Failures = append(latestCondition.Failures, fmt.Sprintf("Image %s not present in community gallery.", image))
		}
	}

	if len(latestCondition.Failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Message = "Community gallery lacks one or more required images. See failures for details."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}
