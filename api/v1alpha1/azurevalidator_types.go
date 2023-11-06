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
	validatorv1alpha1 "github.com/spectrocloud-labs/validator/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// EDIT THIS FILE!  THIS IS SCAFFOLDING FOR YOU TO OWN!
// NOTE: json tags are required.  Any new fields you add must have json tags for the fields to be serialized.

// AzureValidatorSpec defines the desired state of AzureValidator
type AzureValidatorSpec struct {
	// Describes the service principal to test when performing validations that
	// involve checking what service principals can do.
	Auth AzureAuth `json:"auth"`

	DefaultRegion string `json:"defaultRegion"`

	// TODO: Add Azure specific stuff to be validated (probably just the role
	// at first).
	// SubscriptionID string `json:"subscriptionId"`
}

type AzureAuth struct {
	// Instead of having the details specified as part of the spec, allow the
	// details to be specified in a secret, and allow the spec to control the
	// name of the secret that the plugin looks in.
	SecretName string `json:"secretName,omitempty"`
}

// AzureValidatorStatus defines the observed state of AzureValidator
type AzureValidatorStatus struct {
	// +optional
	// +patchMergeKey=type
	// +patchStrategy=merge
	Conditions []validatorv1alpha1.ValidationCondition `json:"conditions,omitempty" patchStrategy:"merge" patchMergeKey:"type"`
}

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
	metav1.TypeMeta `json:",inline"  `
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AzureValidator `json:"items"`
}

func init() {
	SchemeBuilder.Register(&AzureValidator{}, &AzureValidatorList{})
}
