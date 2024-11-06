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
	"fmt"
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

var errInvalidTenantID = errors.New("tenant ID is invalid, must be a v4 uuid")
var errInvalidClientID = errors.New("client ID is invalid, must be a v4 uuid")
var errInvalidClientSecret = errors.New("client secret is invalid, must be a non-empty string")

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

	// Ensure all four Azure env vars are set.
	if err := r.configureAzureAuth(validator.Spec.Auth, req.Namespace, l); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to set Azure auth env vars: %w", err)
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

// configureAzureAuth sets environment variables used to control which Azure cloud environment is
// used and which credentials to use for authenticating with Azure. Order or precedence for source:
// 1 - Kubernetes Secret
// 2 - Specified inline in spec
// Validates each value, regardless of its source, and returns an error if env vars couldn't be
// set for any reason.
func (r *AzureValidatorReconciler) configureAzureAuth(auth v1alpha1.AzureAuth, reqNamespace string, l logr.Logger) error {
	if auth.Implicit {
		l.Info("auth.implicit set to true. Skipping setting AZURE_ env vars.")
		return nil
	}

	if auth.Credentials == nil {
		auth.Credentials = &v1alpha1.ServicePrincipalCredentials{}
	}

	// If Secret name provided, override any AZURE_ values with values from its data.
	if auth.SecretName != "" {
		l.Info("auth.secretName provided. Using Secret as source for any AZURE_ env vars defined in its data.", "secretName", auth.SecretName, "secretNamespace", reqNamespace)
		nn := ktypes.NamespacedName{Name: auth.SecretName, Namespace: reqNamespace}
		secret := &corev1.Secret{}
		if err := r.Get(context.Background(), nn, secret); err != nil {
			return fmt.Errorf("failed to get Secret: %w", err)
		}
		if tenantID, ok := secret.Data["AZURE_TENANT_ID"]; ok {
			l.Info("Using tenant ID from Secret.")
			auth.Credentials.TenantID = string(tenantID)
		}
		if clientID, ok := secret.Data["AZURE_CLIENT_ID"]; ok {
			l.Info("Using client ID from Secret.")
			auth.Credentials.ClientID = string(clientID)
		}
		if clientSecret, ok := secret.Data["AZURE_CLIENT_SECRET"]; ok {
			l.Info("Using client secret from Secret.")
			auth.Credentials.ClientSecret = string(clientSecret)
		}
		if environment, ok := secret.Data["AZURE_ENVIRONMENT"]; ok {
			l.Info("Using Azure environment from Secret.")
			auth.Credentials.Environment = string(environment)
		}
	}

	// Validate values collected from inline config and/or Secret. We can't rely on CRD validation
	// for this because some of the values may have come from a Secret, and there is no way for the
	// Kube API to validate content in its data.
	//
	// Note that there is no step to validate environment because an empty string is valid. The
	// Azure SDKs will handle that by defaulting to the public Azure cloud.
	if !strings.IsValidUUID(auth.Credentials.TenantID) {
		return errInvalidTenantID
	}
	if !strings.IsValidUUID(auth.Credentials.ClientID) {
		return errInvalidClientID
	}
	if auth.Credentials.ClientSecret == "" {
		return errInvalidClientSecret
	}

	// Log non-secret data for help with debugging. Don't log the client secret.
	nonSecretData := map[string]string{
		"tenantId":         auth.Credentials.TenantID,
		"clientId":         auth.Credentials.ClientID,
		"azureEnvironment": auth.Credentials.Environment,
	}
	l.Info("Determined Azure auth data.", "nonSecretData", nonSecretData)

	// Use collected and validated values to set env vars.
	data := map[string]string{
		"AZURE_TENANT_ID":     auth.Credentials.TenantID,
		"AZURE_CLIENT_ID":     auth.Credentials.ClientID,
		"AZURE_CLIENT_SECRET": auth.Credentials.ClientSecret,
		"AZURE_ENVIRONMENT":   auth.Credentials.Environment,
	}
	for k, v := range data {
		if err := os.Setenv(k, v); err != nil {
			return err
		}
		r.Log.Info("Set environment variable", "envVar", k)
	}

	return nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AzureValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AzureValidator{}).
		Complete(r)
}
