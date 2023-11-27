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

package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/constants"
	azure_utils "github.com/spectrocloud-labs/validator-plugin-azure/internal/utils/azure"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/validators"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
	vres "github.com/spectrocloud-labs/validator/pkg/validationresult"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AzureValidatorReconciler reconciles an AzureValidator object
type AzureValidatorReconciler struct {
	client.Client
	Log    logr.Logger
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=azurevalidators,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=azurevalidators/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=validation.spectrocloud.labs,resources=azurevalidators/finalizers,verbs=update

// Reconcile reconciles each rule found in each AzureValidator in the cluster and creates ValidationResults accordingly
func (r *AzureValidatorReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	r.Log.V(0).Info("Reconciling AzureValidator", "name", req.Name, "namespace", req.Namespace)

	validator := &v1alpha1.AzureValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		if !apierrs.IsNotFound(err) {
			r.Log.Error(err, "failed to fetch AzureValidator", "key", req)
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Get the active validator's validation result
	vr := &vapi.ValidationResult{}
	nn := ktypes.NamespacedName{
		Name:      validationResultName(validator),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		vres.HandleExistingValidationResult(nn, vr, r.Log)
	} else {
		if !apierrs.IsNotFound(err) {
			r.Log.V(0).Error(err, "unexpected error getting ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
		}
		if err := vres.HandleNewValidationResult(r.Client, buildValidationResult(validator), r.Log); err != nil {
			return ctrl.Result{}, err
		}
	}

	azureAPI, err := azure_utils.NewAzureAPI()
	if err != nil {
		r.Log.V(0).Error(err, "failed to create Azure API object: %w", err)
	} else {
		raClient := azure_utils.NewAzureRoleAssignmentsClient(azureAPI.RoleAssignments)
		rdClient := azure_utils.NewAzureRoleDefinitionsClient(azureAPI.RoleDefinitions)

		// RBAC rules
		svc := validators.NewRBACRuleService(r.Log, raClient, rdClient)
		for _, rule := range validator.Spec.RBACRules {
			validationResult, err := svc.ReconcileRBACRule(rule)
			if err != nil {
				r.Log.V(0).Error(err, "failed to reconcile RBAC rule")
			}
			vres.SafeUpdateValidationResult(r.Client, nn, validationResult, err, r.Log)
		}
	}

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AzureValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AzureValidator{}).
		Complete(r)
}

func buildValidationResult(validator *v1alpha1.AzureValidator) *vapi.ValidationResult {
	return &vapi.ValidationResult{
		ObjectMeta: metav1.ObjectMeta{
			Name:      validationResultName(validator),
			Namespace: validator.Namespace,
			OwnerReferences: []metav1.OwnerReference{
				{
					APIVersion: validator.APIVersion,
					Kind:       validator.Kind,
					Name:       validator.Name,
					UID:        validator.UID,
					Controller: ptr.Ptr(true),
				},
			},
		},
		Spec: vapi.ValidationResultSpec{
			Plugin:          constants.PluginCode,
			ExpectedResults: validator.Spec.ResultCount(),
		},
	}
}

func validationResultName(validator *v1alpha1.AzureValidator) string {
	return fmt.Sprintf("validator-plugin-azure-%s", validator.Name)
}
