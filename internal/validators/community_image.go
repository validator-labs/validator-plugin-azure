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

	log := s.log.WithValues("rule", rule.Name, "image", rule.Images, "gallery", rule.Gallery.Name, "location", rule.Gallery.Location, "subscription", rule.SubscriptionID)

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
		return validationResult, fmt.Errorf("failed to get all images in community gallery: %w", err)
	}
	images := map[string]*armcompute.CommunityGalleryImage{}
	for _, image := range imagesInGallery {
		if image.Name == nil {
			log.Error(nil, "Image name in API response was nil.")
			continue
		}
		images[*image.Name] = image
	}

	// Find out which of the images in the rule are not present in the gallery.
	for _, ruleImageName := range rule.Images {
		if image, ok := images[ruleImageName]; !ok {
			latestCondition.Failures = append(latestCondition.Failures, fmt.Sprintf("Image %s not present in community gallery.", ruleImageName))
		} else {
			var detailsMsg string
			if image.Properties == nil || image.Properties.Identifier == nil ||
				image.Properties.Identifier.Offer == nil || image.Properties.Identifier.Publisher == nil ||
				image.Properties.Identifier.SKU == nil || image.Location == nil || image.Type == nil {
				log.Error(nil, "One or more detailed properties in API response were nil.")
				detailsMsg = fmt.Sprintf("Found image; Name: '%s'", *image.Name)
			} else {
				detailsMsg = fmt.Sprintf("Found image; Name: '%s'; Offer: '%s'; Publisher: '%s'; SKU: '%s'; Location: '%s'; Type: '%s'",
					*image.Name,
					*image.Properties.Identifier.Offer,
					*image.Properties.Identifier.Publisher,
					*image.Properties.Identifier.SKU,
					*image.Location,
					*image.Type)
			}
			latestCondition.Details = append(latestCondition.Details, detailsMsg)
		}
	}

	if len(latestCondition.Failures) > 0 {
		state = vapi.ValidationFailed
		latestCondition.Message = "Community gallery lacks one or more required images. See failures for details."
		latestCondition.Status = corev1.ConditionFalse
	}

	return validationResult, nil
}
