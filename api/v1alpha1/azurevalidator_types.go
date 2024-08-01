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
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// AzureValidatorSpec defines the desired state of AzureValidator
type AzureValidatorSpec struct {
	// Rules for validating that images exist in an Azure Compute Gallery published as a community
	// gallery.
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="CommunityGalleryImageRules must have unique names",rule="self.all(e, size(self.filter(x, x.name == e.name)) == 1)"
	CommunityGalleryImageRules []CommunityGalleryImageRule `json:"communityGalleryImageRules,omitempty" yaml:"communityGalleryImageRules,omitempty"`
	// RBACRoleRules validate that a security principal has permissions at a specified scope via
	// role assignments and role definitions.
	// +kubebuilder:validation:MaxItems=5
	// +kubebuilder:validation:XValidation:message="RBACRoleRules must have unique names",rule="self.all(e, size(self.filter(x, x.name == e.name)) == 1)"
	RBACRoleRules []RBACRoleRule `json:"rbacRoleRules,omitempty" yaml:"rbacRoleRules,omitempty"`
	Auth          AzureAuth      `json:"auth" yaml:"auth"`
}

// ResultCount returns the number of validation results expected for an AzureValidatorSpec.
func (s AzureValidatorSpec) ResultCount() int {
	return len(s.CommunityGalleryImageRules) + len(s.RBACRoleRules)
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

// CommunityGalleryImageRule verifies that one or more images in a community gallery exist and are
// accessible by a particular subscription.
type CommunityGalleryImageRule struct {
	// Name is a unique identifier for the rule in the validator. Used to ensure conditions do not
	// overwrite each other.
	// +kubebuilder:validation:MaxLength=200
	Name string `json:"name" yaml:"name"`
	// Gallery is the community gallery.
	Gallery CommunityGallery `json:"gallery" yaml:"gallery"`
	// Images is a list of image names.
	//+kubebuilder:validation:MinItems=1
	//+kubebuilder:validation:MaxItems=1000
	Images []string `json:"images" yaml:"images"`
	// SubscriptionID is the ID of the subscription.
	SubscriptionID string `json:"subscriptionID" yaml:"subscriptionID"`
}

// CommunityGallery is a community gallery in a particular location.
type CommunityGallery struct {
	// Location is the location of the community gallery (e.g. "westus").
	// +kubebuilder:validation:MaxLength=50
	Location string `json:"location" yaml:"location"`
	// Name is the name of the community gallery.
	// +kubebuilder:validation:MaxLength=200
	Name string `json:"name" yaml:"name"`
}

// RBACRoleRule verifies that a role definition with a role type, role name, and set of permissions
// exists, and that it is assigned at a scope to a security principal.
type RBACRoleRule struct {
	// Name is a unique identifier for the rule in the validator. Used to ensure conditions do not
	// overwrite each other.
	// +kubebuilder:validation:MaxLength=200
	Name string `json:"name" yaml:"name"`
	// PrincipalID is the security principal being validated. This can be any type of principal -
	// Device, ForeignGroup, Group, ServicePrincipal, or User.
	// +kubebuilder:validation:MaxLength=200
	PrincipalID string `json:"principalId" yaml:"principalId"`
	// RoleAssignments are combinations of scope and role data.
	// +kubebuilder:validation:MinItems=1
	RoleAssignments []RoleAssignment `json:"roleAssignments" yaml:"roleAssignments"`
}

// RoleAssignment is a combination of scope and role data.
type RoleAssignment struct {
	// Scope is the exact scope the role is assigned to the security principal at.
	// +kubebuilder:validation:MaxLength=200
	Scope string `json:"scope" yaml:"scope"`
	// Role is the role data.
	Role Role `json:"role" yaml:"role"`
}

// Role is role data in a role assignment. Is it a subset of a role definition.
type Role struct {
	// Name is the role name property of the role definition.
	// +kubebuilder:validation:MaxLength=200
	Name string `json:"name" yaml:"name"`
	// Type is the role type property of the role definition. Must be "BuiltInRole" or "Custom".
	// Required to disambiguate built in roles and custom roles with the same name.
	// +kubebuilder:validation:Enum=BuiltInRole;CustomRole
	Type string `json:"type" yaml:"type"`
	// Permission is the permissions data of the role definition.
	Permission Permission `json:"permissions" yaml:"permissions"`
}

// Permission is the permission data in a role definition.
type Permission struct {
	// Actions is the "actions" of the role definition.
	Actions []ActionStr `json:"actions,omitempty" yaml:"actions,omitempty"`
	// DataActions is the "dataActions" of the role definition.
	DataActions []ActionStr `json:"dataActions,omitempty" yaml:"dataActions,omitempty"`
	// NotActions is the "notActions" of the role definition.
	NotActions []ActionStr `json:"notActions,omitempty" yaml:"notActions,omitempty"`
	// NotDataActions is the "notDataActions" of the role definition.
	NotDataActions []ActionStr `json:"notDataActions,omitempty" yaml:"notDataActions,omitempty"`
}

// Equal compares a Permission (from the spec) to an armauthorization.Permission (from the Azure API
// response).
func (p Permission) Equal(other armauthorization.Permission) bool {
	compareSlices := func(a []ActionStr, b []*string) bool {
		if len(a) != len(b) {
			return false
		}
		for i, val := range a {
			aVal := string(val)
			if b[i] == nil {
				return false
			}
			bVal := *b[i]
			if aVal != bVal {
				return false
			}
		}
		return true
	}

	return compareSlices(p.Actions, other.Actions) &&
		compareSlices(p.DataActions, other.DataActions) &&
		compareSlices(p.NotActions, other.NotActions) &&
		compareSlices(p.NotDataActions, other.NotDataActions)
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
