/*
Copyright 2023.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AzureValidatorSpec defines the desired state of AzureValidator
type AzureValidatorSpec struct {
	// Rules for validating that the correct role assignments have been created in Azure RBAC to
	// provide needed permissions.
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="RBACRules must have unique names",rule="self.all(e, size(self.filter(x, x.name == e.name)) == 1)"
	RBACRules []RBACRule `json:"rbacRules,omitempty" yaml:"rbacRules,omitempty"`
	// Rules for validating that images exist in an Azure Compute Gallery published as a community
	// gallery.
	CommunityGalleryImageRules []CommunityGalleryImageRule `json:"communityGalleryImageRules,omitempty" yaml:"communityGalleryImageRules,omitempty"`
	Auth                       AzureAuth                   `json:"auth" yaml:"auth"`
}

func (s AzureValidatorSpec) ResultCount() int {
	return len(s.RBACRules) + len(s.CommunityGalleryImageRules)
}

// Conveys that a specified security principal (aka principal) should have the specified
// permissions, via roles. It doesn't matter which roles provide the permissions as long as enough
// role assignments exist that the principal has all of the permissions and no deny assignments
// exist that deny the permissions.
type RBACRule struct {
	// Unique identifier for the rule in the validator. Used to ensure conditions do not overwrite
	// each other.
	Name string `json:"name" yaml:"name"`
	// The permissions that the principal must have. If the principal has permissions less than
	// this, validation will fail. If the principal has permissions equal to or more than this
	// (e.g., inherited permissions from higher level scope, more roles than needed) validation
	// will pass.
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=20
	//+kubebuilder:validation:XValidation:message="Each permission set must have Actions, DataActions, or both defined",rule="self.all(item, size(item.actions) > 0 || size(item.dataActions) > 0)"
	Permissions []PermissionSet `json:"permissionSets" yaml:"permissionSets"`
	// The principal being validated. This can be any type of principal - Device, ForeignGroup,
	// Group, ServicePrincipal, or User.
	PrincipalID string `json:"principalId" yaml:"principalId"`
}

// Conveys that one or more images in a community gallery exist.
type CommunityGalleryImageRule struct {
	// Unique identifier for the rule in the validator. Used to ensure conditions do not overwrite
	// each other.
	Name string `json:"name" yaml:"name"`
	// Gallery is the community gallery.
	Gallery CommunityGallery `json:"gallery" yaml:"gallery"`
	// Images are the names of the images to check for in the gallery.
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=20
	Images []string `json:"images" yaml:"images"`
	// The subscription ID to verify that the community galleries are available to. Used in API
	// calls to URL
	// `subscriptions/<subscription>/providers/Microsoft.Compute/locations/<location>/communityGalleries/<gallery>/images`.
	SubscriptionID string `json:"subscriptionID" yaml:"subscriptionID"`
}

// CommunityGallery is a community gallery in a particular location.
type CommunityGallery struct {
	// Location is the location of the community gallery.
	Location string `json:"location" yaml:"location"`
	// Name is the name of the community gallery.
	Name string `json:"name" yaml:"name"`
}

type AzureAuth struct {
	// If true, the AzureValidator will use the Azure SDK's default credential chain to authenticate.
	// Set to true if using WorkloadIdentityCredentials.
	Implicit bool `json:"implicit" yaml:"implicit"`
	// Name of a Secret in the same namespace as the AzureValidator that contains Azure credentials.
	// The secret data's keys and values are expected to align with valid Azure environment variable credentials,
	// per the options defined in https://pkg.go.dev/github.com/Azure/azure-sdk-for-go/sdk/azidentity#readme-environment-variables.
	SecretName string `json:"secretName,omitempty" yaml:"secretName,omitempty"`
}

// ActionStr is a type used for Action strings and DataAction strings. Alias exists to enable
// kubebuilder max string length validation for arrays of these.
// +kubebuilder:validation:MaxLength=200
type ActionStr string

// Conveys that the security principal should be the member of a role assignment that provides the
// specified role for the specified scope. Scope can be either subscription, resource group, or
// resource.
type PermissionSet struct {
	// If provided, the actions that the role must be able to perform. Must not contain any
	// wildcards. If not specified, the role is assumed to already be able to perform all required
	// actions.
	//+kubebuilder:validation:MaxItems=1000
	//+kubebuilder:validation:XValidation:message="Actions cannot have wildcards.",rule="self.all(item, !item.contains('*'))"
	Actions []ActionStr `json:"actions,omitempty" yaml:"actions,omitempty"`
	// If provided, the data actions that the role must be able to perform. Must not contain any
	// wildcards. If not provided, the role is assumed to already be able to perform all required
	// data actions.
	//+kubebuilder:validation:MaxItems=1000
	//+kubebuilder:validation:XValidation:message="DataActions cannot have wildcards.",rule="self.all(item, !item.contains('*'))"
	DataActions []ActionStr `json:"dataActions,omitempty" yaml:"dataActions,omitempty"`
	// The minimum scope of the role. Role assignments found at higher level scopes will satisfy
	// this. For example, a role assignment found with subscription scope will satisfy a permission
	// set where the role scope specified is a resource group within that subscription.
	Scope string `json:"scope" yaml:"scope"`
}

// AzureValidatorStatus defines the observed state of AzureValidator
type AzureValidatorStatus struct{}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// AzureValidator is the Schema for the azurevalidators API
type AzureValidator struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AzureValidatorSpec   `json:"spec,omitempty"`
	Status AzureValidatorStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// AzureValidatorList contains a list of AzureValidator
type AzureValidatorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureValidator `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AzureValidator{}, &AzureValidatorList{})
}
