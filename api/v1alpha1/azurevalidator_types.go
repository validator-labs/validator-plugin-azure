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

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AzureValidatorSpec defines the desired state of AzureValidator
type AzureValidatorSpec struct {
	// Rules for validating role assignments in Azure RBAC.
	RoleAssignmentRules []RoleAssignmentRule `json:"roleAssignmentRules"`
}

func (s AzureValidatorSpec) ResultCount() int {
	return len(s.RoleAssignmentRules)
}

// RoleAssignmentRule is a rule that validates that one or more desired role assignments exist
// within a subscription. For each role assignment, the role is specified as its role name (e.g.
// "Contributor") or its name (e.g. "b24988ac-6180-42a0-ab88-20f7382dd24c" for Contributor). If the
// role name is specified, the validator takes care of looking up the name automatically.
type RoleAssignmentRule struct {
	Roles              []Role `json:"roles"`
	ServicePrincipalID string `json:"servicePrincipalId"`
	SubscriptionID     string `json:"subscriptionId"`
}

// Role allow users to specify either a role's role name (e.g. "Contributor") or a role's name (e.g.
// "b24988ac-6180-42a0-ab88-20f7382dd24c"), which is the name of the role with the role name
// "Contributor". This allows role assignments with custom roles to be validated too, not just
// built-in roles.
//
// If role is specified, it is used. If role is not specified but role name is specified, role name
// is used. If neither are specified, it is a misconfiguration and validation will fail.
type Role struct {
	Name     *string `json:"name,omitempty"`
	RoleName *string `json:"roleName,omitempty"`
}

// Conveys that a specified security principal (aka principal) should have the specified
// permissions, via roles.
type RBACRule struct {
	// The permissions that the principal must have. If the principal has permissions less than
	// this, validation will fail. If the principal has permissions equal to or more than this
	// (e.g., inherited permissions from higher level scope, more roles than needed) validation
	// will pass.
	Permissions []PermissionSet `json:"permissionSets"`
	// The principal being validated. This can be any type of principal - Device, ForeignGroup,
	// Group, ServicePrincipal, or User.
	PrincipalID string `json:"principalId"`
}

// Conveys that the security principal should be the member of a role assignment that provides the
// specified role for the specified scope. Scope can be either subscription, resource group, or
// resource.
//
// If permissions are specified, then it also conveys that the specified role should provide the
// specified permissions. This is useful for validating a custom role when one is used instead of a
// built-in role.
type PermissionSet struct {
	Permissions []string `json:"permissions,omitempty"`
	Role        string   `json:"role"`
	Scope       string   `json:"scope"`
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
