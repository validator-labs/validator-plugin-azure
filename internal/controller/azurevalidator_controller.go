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
	"fmt"
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
	"github.com/validator-labs/validator-plugin-azure/pkg/validate"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vres "github.com/validator-labs/validator/pkg/validationresult"
)

const (
	secretKeyTenantID     = "AZURE_TENANT_ID"
	secretKeyClientID     = "AZURE_CLIENT_ID"
	secretKeyClientSecret = "AZURE_CLIENT_SECRET"
	secretKeyEnvironment  = "AZURE_ENVIRONMENT"
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
	var err error
	l := r.Log.V(0).WithValues("name", req.Name, "namespace", req.Namespace)
	l.Info("Reconciling AzureValidator")

	validator := &v1alpha1.AzureValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		if !apierrs.IsNotFound(err) {
			l.Error(err, "failed to fetch AzureValidator")
		}
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// Override auth data in spec with auth data from Secret if applicable.
	if validator.Spec.Auth, err = r.authFromSecret(validator.Spec.Auth, req.Namespace, l); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to get auth data from Secret: %w", err)
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

// Checks whether the spec indicates that auth data should come from a k8s Secret instead of inline
// auth. If so, all data must come from the Secret. If any is missing, returns an error. If all data
// is present, overrides the data in the auth object.
func (r *AzureValidatorReconciler) authFromSecret(auth v1alpha1.AzureAuth, reqNamespace string, l logr.Logger) (v1alpha1.AzureAuth, error) {
	// If using implicit auth, there is no need to check for k8s Secrets.
	if auth.Implicit {
		l.Info("auth.implicit set to true. Skipping setting AZURE_ env vars.")
		return auth, nil
	}

	// Same if no secret name provided.
	if auth.SecretName == "" {
		l.Info("No Secret name provided. Skipping looking for Secret to override auth data.")
		return auth, nil
	}

	if auth.Credentials == nil {
		auth.Credentials = &v1alpha1.ServicePrincipalCredentials{}
	}

	l.Info("auth.secretName provided. Using Secret as source for any AZURE_ env vars defined in its data.", "secretName", auth.SecretName, "secretNamespace", reqNamespace)
	nn := ktypes.NamespacedName{Name: auth.SecretName, Namespace: reqNamespace}
	secret := &corev1.Secret{}
	if err := r.Get(context.Background(), nn, secret); err != nil {
		return auth, fmt.Errorf("failed to get Secret: %w", err)
	}

	tenantID, ok := secret.Data[secretKeyTenantID]
	if !ok {
		return v1alpha1.AzureAuth{}, fmt.Errorf("Key %s missing from Secret", secretKeyTenantID)
	}
	auth.Credentials.TenantID = string(tenantID)

	clientID, ok := secret.Data[secretKeyClientID]
	if !ok {
		return v1alpha1.AzureAuth{}, fmt.Errorf("Key %s missing from Secret", secretKeyClientID)
	}
	auth.Credentials.ClientID = string(clientID)

	clientSecret, ok := secret.Data[secretKeyClientSecret]
	if !ok {
		return v1alpha1.AzureAuth{}, fmt.Errorf("Key %s missing from Secret", secretKeyClientSecret)
	}
	auth.Credentials.ClientSecret = string(clientSecret)

	if environment, ok := secret.Data[secretKeyEnvironment]; !ok {
		l.Info("Azure environment not specified in secret. Using default environment.")
	} else {
		auth.Credentials.Environment = string(environment)
	}

	return auth, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AzureValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AzureValidator{}).
		Complete(r)
}
