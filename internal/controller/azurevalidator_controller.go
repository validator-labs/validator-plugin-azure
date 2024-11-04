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

// Package controller defines a controller for reconciling AzureValidator objects.
package controller

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrs "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	ktypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/cluster-api/util/patch"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/validator-labs/validator-plugin-azure/pkg/utils/strings"
	"github.com/validator-labs/validator-plugin-azure/pkg/validate"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vres "github.com/validator-labs/validator/pkg/validationresult"
)

var errSecretNameRequired = errors.New("auth.secretName is required")
var errInvalidTenantID = errors.New("auth.credentials.tenantId is invalid, must be a v4 uuid")
var errInvalidClientID = errors.New("auth.credentials.clientId is invalid, must be a v4 uuid")
var errInvalidClientSecret = errors.New("auth.credentials.clientSecret is invalid, must be a non-empty string")

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

	// If using implicit auth, assume the Azure auth env vars are already set. Otherwise, check
	// each auth source in order, and set env vars manually using values from them.
	// 1 - Inline creds
	// 2 - Kubernetes secret name
	if !validator.Spec.Auth.Implicit {
		if validator.Spec.Auth.Credentials != nil {
			creds := *validator.Spec.Auth.Credentials
			if !strings.IsValidUUID(creds.TenantID) {
				l.Error(errInvalidTenantID, "failed to reconcile AzureValidator with invalid auth.credentials.tenantId")
				return ctrl.Result{}, errInvalidTenantID
			}
			if !strings.IsValidUUID(creds.ClientID) {
				l.Error(errInvalidClientID, "failed to reconcile AzureValidator with invalid auth.credentials.clientId")
				return ctrl.Result{}, errInvalidClientID
			}
			if creds.ClientSecret == "" {
				l.Error(errInvalidClientSecret, "failed to reconcile AzureValidator with invalid auth.credentials.clientSecret")
				return ctrl.Result{}, errInvalidClientSecret
			}

			if err := r.envFromInline(creds); err != nil {
				l.Error(err, "failed to configure environment from inline credentials")
				return ctrl.Result{}, err
			}
		} else {
			if validator.Spec.Auth.SecretName == "" {
				l.Error(errSecretNameRequired, "failed to reconcile AzureValidator with empty auth.secretName")
				return ctrl.Result{}, errSecretNameRequired
			}

			if err := r.envFromSecret(validator.Spec.Auth.SecretName, req.Namespace); err != nil {
				l.Error(err, "failed to configure environment from secret")
				return ctrl.Result{}, err
			}
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
		Name:      vres.Name(validator),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		vres.HandleExisting(vr, r.Log)
	} else {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "unexpected error getting ValidationResult")
		}
		if err := vres.HandleNew(ctx, r.Client, p, vres.Build(validator), r.Log); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{RequeueAfter: time.Millisecond}, nil
	}

	// Always update the expected result count in case the validator's rules have changed
	vr.Spec.ExpectedResults = validator.Spec.ResultCount()

	// Validate the rules
	resp := validate.Validate(ctx, validator.Spec, r.Log)

	// Patch the ValidationResult with the latest ValidationRuleResults
	if err := vres.SafeUpdate(ctx, p, vr, resp, r.Log); err != nil {
		return ctrl.Result{}, err
	}

	l.Info("Requeuing for re-validation in two minutes.")
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// envFromInline sets environment variables from inline credentials to configure Azure credentials
func (r *AzureValidatorReconciler) envFromInline(creds v1alpha1.ServicePrincipalCredentials) error {
	r.Log.Info("Configuring environment from inline credentials")

	data := map[string]string{
		"AZURE_TENANT_ID":     creds.TenantID,
		"AZURE_CLIENT_ID":     creds.ClientID,
		"AZURE_CLIENT_SECRET": creds.ClientSecret,
	}

	for k, v := range data {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
		r.Log.Info("Set environment variable", "key", k)
	}
	return nil
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
