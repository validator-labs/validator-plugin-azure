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

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armsubscriptions"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	"github.com/spectrocloud-labs/validator-plugin-azure/internal/constants"
	v8or "github.com/spectrocloud-labs/validator/api/v1alpha1"
	"github.com/spectrocloud-labs/validator/pkg/types"
	v8ores "github.com/spectrocloud-labs/validator/pkg/validationresult"

	ktypes "k8s.io/apimachinery/pkg/types"

	v8orconstants "github.com/spectrocloud-labs/validator/pkg/constants"

	apierrs "k8s.io/apimachinery/pkg/api/errors"
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

	// Preparing the Azure client. For now, this code is here. Assume that the
	// wiring up of the secret with the Azure creds, mounted as env vars,
	// enables the Azure SDK's chained authentication.
	var cred *azidentity.DefaultAzureCredential
	var err error
	if cred, err = azidentity.NewDefaultAzureCredential(nil); err != nil {
		// Stealing this approach from the AWS version for now. If an Azure
		// client can't be prepared, this can't be fixed by an immediate
		// requeue.
		r.Log.Error(err, "failed to prepare default Azure credential")
		return ctrl.Result{}, nil
	}
	fmt.Printf("Created default Azure cred: %v\n", cred)

	// First we get the active validator out of k8s.
	validator := &v1alpha1.AzureValidator{}
	if err := r.Get(ctx, req.NamespacedName, validator); err != nil {
		// Ignore not-found errors, since they can't be fixed by an immediate requeue
		if apierrs.IsNotFound(err) {
			return ctrl.Result{}, nil
		}
		r.Log.Error(err, "failed to fetch AzureValidator")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	// With the active validator, we can then look for its validation
	// result. So we try to get the validation result out of k8s. It might
	// not exist yet.
	//
	// If we find that it *does* exist, we handle it as an existing validation
	// result, which means to just do some logging with the data in it. It
	// doesn't involve doing more reading from k8s, writing to k8s, etc.
	//
	// If we find that it *does not* exist, we handle it as a new validation
	// result, which means to create a new validation result object, update
	// its status, save it in k8s. Its status is a "state" and "conditions". We
	// use "InProgress" as the state because this is a brand new validation
	// result object and we haven't done anything meaningful yet. We use an
	// an empty set of conditions for the same reason.
	vr := &v8or.ValidationResult{}
	nn := ktypes.NamespacedName{
		Name:      fmt.Sprintf("validator-plugin-azure-%s", validator.Name),
		Namespace: req.Namespace,
	}
	if err := r.Get(ctx, nn, vr); err == nil {
		res, err := v8ores.HandleExistingValidationResult(nn, vr, r.Log)
		if res != nil {
			return *res, err
		}
	} else {
		if !apierrs.IsNotFound(err) {
			r.Log.V(0).Error(err, "unexpected error getting ValidationResult", "name", nn.Name, "namespace", nn.Namespace)
		}
		res, err := v8ores.HandleNewValidationResult(r.Client, constants.PluginCode, nn, vr, r.Log)
		if res != nil {
			return *res, err
		}
	}

	// The above was just for checking the state of the validation result in
	// k8s. It wasn't actually doing the validation. Now, we need to do the
	// validation, which means to use Go code to interact with Azure via its Go
	// SDK and then save the result in the validation result. It will be either
	// a fail or a pass and the validators framework can read it and do stuff
	// with it later.
	//
	// For now, this is just no op validation. It's a success result.

	// Helper to make the new validation result object. Modeled after helpers
	// that I saw in the AWS version. Later, this should be moved to somewhere
	// else in this codebase. This function's role is to make a default
	// validation result. If validation fails, the result will be modified to
	// convey this. If validation does not fail, the result will remain the
	// same.
	buildValidationResult := func() *types.ValidationResult {
		// Pick a validation state
		state := v8or.ValidationSucceeded

		// Make a validation condition
		latestCondition := v8or.DefaultValidationCondition()
		latestCondition.Message = "Validation passed because the Azure subscription details request was successful."
		latestCondition.ValidationRule = fmt.Sprintf("%s-%s", v8orconstants.ValidationRulePrefix, "validator-subscription-details-rule")
		latestCondition.ValidationType = constants.ValidationTypeTest

		// Once both are built, put them into a validation result
		return &types.ValidationResult{
			Condition: &latestCondition,
			State:     &state,
		}
	}

	// Breaking the pattern from the AWS version temporarily. Instead of
	// modifying the default validation result to indicate failure, here we
	// create an entire failed validation result from scratch. This is okay for
	// now because we don't have a concept of validation failing because one
	// "subvalidation" fails. It's all or nothing for this subscription details
	// iteration.
	buildFailedValidationResult := func() *types.ValidationResult {
		// Pick a validation state
		state := v8or.ValidationFailed

		// Make a validation condition
		latestCondition := v8or.DefaultValidationCondition()
		latestCondition.Message = "Validation failed because the Azure subscription details request was unsuccessful."
		latestCondition.ValidationRule = fmt.Sprintf("%s-%s", v8orconstants.ValidationRulePrefix, "validator-subscription-details-rule")
		latestCondition.ValidationType = constants.ValidationTypeTest

		// Once both are built, put them into a validation result
		return &types.ValidationResult{
			Condition: &latestCondition,
			State:     &state,
		}
	}

	// Actual validation logic here!

	// TODO: Set up getting subscription ID (and later, config for the real
	//       world use cases) from the config (maybe Helm chart config).
	subscriptionID := "9b16dd0b-1bea-4c9a-a291-65e6f44c4745"

	// Try to get details about the subscription used with the Azure account
	r.Log.V(0).Info("Getting details of Azure subscription.", "subscription ID", subscriptionID)
	var failed *types.MonotonicBool
	var result *types.ValidationResult
	client, err := armsubscriptions.NewClient(cred, nil)
	if err != nil {
		// Stealing this approach from the AWS version for now. If an Azure
		// client can't be prepared, this can't be fixed by an immediate
		// requeue.
		r.Log.Error(err, "failed to prepare Azure subscriptions client")
		return ctrl.Result{}, nil
	}
	// Creating an error variable just for being able to call safeUpdate func.
	var validationError error
	res, err := client.Get(context.TODO(), subscriptionID, nil)
	if err != nil {
		validationError = err
		// TODO: Decide whether this Info should actually be an Error.
		r.Log.V(0).Info("Failed to get subscription details.", "subscription ID", subscriptionID)
		failed = &types.MonotonicBool{Ok: true}
		result = buildFailedValidationResult()
	} else {
		r.Log.V(0).Info("Subscription display name retrieved.", "subscription ID", subscriptionID, "display name", *res.DisplayName)
		failed = &types.MonotonicBool{Ok: false}
		result = buildValidationResult()
	}

	// End of actual validation logic here!

	// Save the updated validation result. The difference between this code and
	// the code above is that the code above just saves a placeholder in k8s
	// whereas this is more involved. It will eventually be the result of doing
	// all the Azure validation stuff. Once the Azure validation stuff is
	// implemented, it would have "conditions" added to it by now, which will be
	// saved.
	v8ores.SafeUpdateValidationResult(r.Client, nn, result, failed, validationError, r.Log)

	r.Log.V(0).Info("Requeuing for re-validation in two minutes.", "name", req.Name, "namespace", req.Namespace)
	return ctrl.Result{RequeueAfter: time.Second * 120}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *AzureValidatorReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&v1alpha1.AzureValidator{}).
		Complete(r)
}
