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
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/internal/constants"
	azure_utils "github.com/validator-labs/validator-plugin-azure/internal/utils/azure"
	"github.com/validator-labs/validator-plugin-azure/internal/validators"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	"github.com/validator-labs/validator/pkg/types"
	"github.com/validator-labs/validator/pkg/util"
	vres "github.com/validator-labs/validator/pkg/validationresult"
)

var ErrSecretNameRequired = errors.New("auth.secretName is required")

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
	l := r.Log.V(0).WithValues("name", req.Name, "namespace", req.Namespace)
	l.Info("Reconciling AzureValidator")

	validator := &v1alpha1.AzureValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "failed to fetch AzureValidator")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Configure Azure environment variable credentials from a secret, if applicable
	if !validator.Spec.Auth.Implicit {
		if validator.Spec.Auth.SecretName == "" {
			l.Error(ErrSecretNameRequired, "failed to reconcile AzureValidator with empty auth.secretName")
			return ctrl.Result{}, ErrSecretNameRequired
		}
		if err := r.envFromSecret(validator.Spec.Auth.SecretName, req.Namespace); err != nil {
			l.Error(err, "failed to configure environment from secret")
			return ctrl.Result{}, err
		}
	}

	// Get the active validator's validation result
	vr := &vapi.ValidationResult{}
	p, err := patch.NewHelper(vr, r.Client)
	if err != nil {
		l.Error(err, "failed to create patch helper")
		return ctrl.Result{}, err
	}
	nn := ktypes.NamespacedName{
		Name:      validationResultName(validator),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		vres.HandleExistingValidationResult(vr, r.Log)
	} else {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "unexpected error getting ValidationResult")
		}
		if err := vres.HandleNewValidationResult(ctx, r.Client, p, buildValidationResult(validator), r.Log); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	// Always update the expected result count in case the validator's rules have changed
	vr.Spec.ExpectedResults = validator.Spec.ResultCount()

	resp := types.ValidationResponse{
		ValidationRuleResults: make([]*types.ValidationRuleResult, 0, vr.Spec.ExpectedResults),
		ValidationRuleErrors:  make([]error, 0, vr.Spec.ExpectedResults),
	}

	azureAPI, err := azure_utils.NewAzureAPI()
	if err != nil {
		l.Error(err, "failed to create Azure API object")
	} else {
		azureCtx := context.WithoutCancel(ctx)
		if os.Getenv("IS_TEST") == "true" {
			var cancel context.CancelFunc
			azureCtx, cancel = context.WithDeadline(ctx, time.Now().Add(azure_utils.TestClientTimeout))
			defer cancel()
		}

		daClient := azure_utils.NewAzureDenyAssignmentsClient(azureCtx, azureAPI.DenyAssignments)
		raClient := azure_utils.NewAzureRoleAssignmentsClient(azureCtx, azureAPI.RoleAssignments)
		rdClient := azure_utils.NewAzureRoleDefinitionsClient(azureCtx, azureAPI.RoleDefinitions)

		// RBAC rules
		svc := validators.NewRBACRuleService(daClient, raClient, rdClient)
		for _, rule := range validator.Spec.RBACRules {
			vrr, err := svc.ReconcileRBACRule(rule)
			if err != nil {
				l.Error(err, "failed to reconcile RBAC rule")
			}
			resp.AddResult(vrr, err)
		}
	}

	// Patch the ValidationResult with the latest ValidationRuleResults
	if err := vres.SafeUpdateValidationResult(ctx, p, vr, resp, r.Log); err != nil {
		return ctrl.Result{}, err
	}

	l.Info("Requeuing for re-validation in two minutes.")
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// envFromSecret sets environment variables from a secret to configure Azure credentials
func (r *AzureValidatorReconciler) envFromSecret(name, namespace string) error {
	r.Log.Info("Configuring environment from secret", "name", name, "namespace", namespace)

	nn := ktypes.NamespacedName{Name: name, Namespace: namespace}
	secret := &corev1.Secret{}
	if err := r.Get(context.Background(), nn, secret); err != nil {
		return err
	}

	for k, v := range secret.Data {
		if err := os.Setenv(k, string(v)); err != nil {
			return err
		}
		r.Log.Info("Set environment variable", "key", k)
	}
	return nil
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
					Controller: util.Ptr(true),
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
