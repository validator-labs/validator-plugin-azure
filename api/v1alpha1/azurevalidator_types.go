/*
Copyright 2024.

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
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/validator-labs/validator/pkg/plugins"
	"github.com/validator-labs/validator/pkg/validationrule"

	"github.com/validator-labs/validator-plugin-azure/pkg/constants"
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

var _ plugins.PluginSpec = (*AzureValidatorSpec)(nil)

// PluginCode returns the Azure validator's plugin code.
func (s AzureValidatorSpec) PluginCode() string {
	return constants.PluginCode
}

// ResultCount returns the number of validation results expected for an AzureValidatorSpec.
func (s AzureValidatorSpec) ResultCount() int {
	return len(s.RBACRules) + len(s.CommunityGalleryImageRules)
}

// RBACRule verifies that a security principal has permissions via role assignments and that no deny
// assignments deny the permissions.
type RBACRule struct {
	validationrule.ManuallyNamed `json:"-"`

	// Unique identifier for the rule in the validator. Used to ensure conditions do not overwrite
	// each other.
	RuleName string `json:"name" yaml:"name"`
	// The permissions that the principal must have. If the principal has permissions less than
	// this, validation will fail. If the principal has permissions equal to or more than this
	// (e.g., inherited permissions from higher level scope, more roles than needed) validation
	// will pass.
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=20
	//+kubebuilder:validation:XValidation:message="Each permission set must have Actions, DataActions, or both defined",rule="self.all(item, size(item.actions) > 0 || size(item.dataActions) > 0)"
	Permissions []PermissionSet `json:"permissionSets" yaml:"permissionSets"`
	// The principal being validated. This can be any type of principal - Device, ForeignGroup,
	// Group, ServicePrincipal, or User. If using a service principal, this is the "application
	// object ID". In the Azure portal, this can be found by navigating to Entra ID, selecting the
	// application registration of the service principal, navigating from that page to the managed
	// application page, and copying the "object ID". This ID is different from the tenant ID,
	// client ID, and object ID of the application registration.
	PrincipalID string `json:"principalId" yaml:"principalId"`
}

var _ validationrule.Interface = (*RBACRule)(nil)

// Name returns the name of the RBAC rule.
func (r RBACRule) Name() string {
	return r.RuleName
}

// SetName sets the name of the RBAC rule.
func (r *RBACRule) SetName(name string) {
	r.RuleName = name
}

// CommunityGalleryImageRule verifies that one or more images in a community gallery exist and are
// accessible by a particular subscription.
type CommunityGalleryImageRule struct {
	validationrule.ManuallyNamed `json:"-"`

	// RuleName is a unique identifier for the rule in the validator. Used to ensure conditions do
	// not overwrite each other.
	// +kubebuilder:validation:MaxLength=200
	RuleName string `json:"name" yaml:"name"`
	// Gallery is the community gallery.
	Gallery CommunityGallery `json:"gallery" yaml:"gallery"`
	// Images is a list of image names.
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=1000
	Images []string `json:"images" yaml:"images"`
	// SubscriptionID is the ID of the subscription.
	SubscriptionID string `json:"subscriptionID" yaml:"subscriptionID"`
}

var _ validationrule.Interface = (*CommunityGalleryImageRule)(nil)

// Name returns the name of the community gallery image rule.
func (r CommunityGalleryImageRule) Name() string {
	return r.RuleName
}

// SetName sets the name of the community gallery image rule.
func (r *CommunityGalleryImageRule) SetName(name string) {
	r.RuleName = name
}

// CommunityGallery is a community gallery in a particular location.
type CommunityGallery struct {
	// Location is the location of the community gallery (e.g. "westus").
	Location string `json:"location" yaml:"location"`
	// Name is the name of the community gallery.
	Name string `json:"name" yaml:"name"`
}

// AzureAuth defines authentication configuration for an AzureValidator.
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

// PermissionSet is part of an RBAC rule and verifies that a security principal has the specified
// permissions (via role assignments) at the specified scope. Scope can be either subscription,
// resource group, or resource.
type PermissionSet struct {
	// Actions is a list of actions that the role must be able to perform. Must not contain any
	// wildcards. If not specified, the role is assumed to already be able to perform all required
	// actions.
	//+kubebuilder:validation:MaxItems=1000
	//+kubebuilder:validation:XValidation:message="Actions cannot have wildcards.",rule="self.all(item, !item.contains('*'))"
	Actions []ActionStr `json:"actions,omitempty" yaml:"actions,omitempty"`
	// DataActions is a list of data actions that the role must be able to perform. Must not
	// contain any wildcards. If not provided, the role is assumed to already be able to perform
	// all required data actions.
	//+kubebuilder:validation:MaxItems=1000
	//+kubebuilder:validation:XValidation:message="DataActions cannot have wildcards.",rule="self.all(item, !item.contains('*'))"
	DataActions []ActionStr `json:"dataActions,omitempty" yaml:"dataActions,omitempty"`
	// Scope is the minimum scope of the role. Role assignments found at higher level scopes will
	// satisfy this. For example, a role assignment found with subscription scope will satisfy a
	// permission set where the role scope specified is a resource group within that subscription.
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

// GetKind returns the Azure validator's kind.
func (v AzureValidator) GetKind() string {
	return reflect.TypeOf(v).Name()
}

// PluginCode returns the Azure validator's plugin code.
func (v AzureValidator) PluginCode() string {
	return v.Spec.PluginCode()
}

// ResultCount returns the number of validation results expected for an AzureValidator.
func (v AzureValidator) ResultCount() int {
	return v.Spec.ResultCount()
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
