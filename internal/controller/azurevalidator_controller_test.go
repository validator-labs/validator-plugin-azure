package controller

import (
	"context"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	//+kubebuilder:scaffold:imports
)

const azureValidatorName = "azure-validator"

var _ = Describe("AzureValidator controller", Ordered, func() {

	BeforeEach(func() {
		// toggle true/false to enable/disable the AzureValidator controller specs
		if false {
			Skip("skipping")
		}
	})

	It("Should not create a ValidationResult when neither Actions nor DataActions are defined in any permission set", func() {
		By("Attempting to create a new AzureValidator with one invalid permission set")

		ctx := context.Background()

		val := &v1alpha1.AzureValidator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      azureValidatorName,
				Namespace: validatorNamespace,
			},
			Spec: v1alpha1.AzureValidatorSpec{
				RBACRules: []v1alpha1.RBACRule{
					{
						Permissions: []v1alpha1.PermissionSet{
							{
								Scope:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg",
								Actions: []v1alpha1.ActionStr{"action_1"},
							},
						},
						PrincipalID: "p_id",
					},
					{
						Permissions: []v1alpha1.PermissionSet{
							{
								Scope: "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg2",
							},
						},
						PrincipalID: "p_id",
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, val)).Should(MatchError(ContainSubstring("Each permission set must have Actions, DataActions, or both defined")))
	})

	It("Should not create a ValidationResult when any Action has a wildcard", func() {
		By("Attempting to create a new AzureValidator with one invalid permission set")

		ctx := context.Background()

		val := &v1alpha1.AzureValidator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      azureValidatorName,
				Namespace: validatorNamespace,
			},
			Spec: v1alpha1.AzureValidatorSpec{
				RBACRules: []v1alpha1.RBACRule{
					{
						Permissions: []v1alpha1.PermissionSet{
							{
								Scope:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg",
								Actions: []v1alpha1.ActionStr{"things/*"},
							},
						},
						PrincipalID: "p_id",
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, val)).Should(MatchError(ContainSubstring("Actions cannot have wildcards")))
	})

	It("Should not create a ValidationResult when any DataAction has a wildcard", func() {
		By("Attempting to create a new AzureValidator with one invalid permission set")

		ctx := context.Background()

		val := &v1alpha1.AzureValidator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      azureValidatorName,
				Namespace: validatorNamespace,
			},
			Spec: v1alpha1.AzureValidatorSpec{
				RBACRules: []v1alpha1.RBACRule{
					{
						Permissions: []v1alpha1.PermissionSet{
							{
								Scope:       "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg",
								DataActions: []v1alpha1.ActionStr{"things/*"},
							},
						},
						PrincipalID: "p_id",
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, val)).Should(MatchError(ContainSubstring("DataActions cannot have wildcards")))
	})

	It("Should create a ValidationResult and update its Status with a failed condition", func() {
		By("By creating a new AzureValidator")

		ctx := context.Background()

		authSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "azure-creds",
				Namespace: validatorNamespace,
			},
			Data: map[string][]byte{
				"AZURE_CLIENT_ID":     []byte("client_id"),
				"AZURE_TENANT_ID":     []byte("tenant_id"),
				"AZURE_CLIENT_SECRET": []byte("client_secret"),
			},
		}

		val := &v1alpha1.AzureValidator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      azureValidatorName,
				Namespace: validatorNamespace,
			},
			Spec: v1alpha1.AzureValidatorSpec{
				Auth: v1alpha1.AzureAuth{
					Implicit:   false,
					SecretName: "azure-creds",
				},
				RBACRules: []v1alpha1.RBACRule{
					{
						Permissions: []v1alpha1.PermissionSet{
							{
								Scope:   "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/Example-Storage-rg",
								Actions: []v1alpha1.ActionStr{"action_1"},
							},
						},
						PrincipalID: "p_id",
					},
				},
			},
		}

		vr := &vapi.ValidationResult{}
		vrKey := types.NamespacedName{Name: validationResultName(val), Namespace: validatorNamespace}

		valEmptySecretName := val.DeepCopy()
		valEmptySecretName.Name = fmt.Sprintf("%s-empty-secret-name", azureValidatorName)
		valEmptySecretName.Spec.Auth.SecretName = ""
		Expect(k8sClient.Create(ctx, valEmptySecretName)).Should(Succeed())

		valInvalidSecretName := val.DeepCopy()
		valInvalidSecretName.Name = fmt.Sprintf("%s-invalid-secret-name", azureValidatorName)
		valInvalidSecretName.Spec.Auth.SecretName = "invalid-secret-name"
		Expect(k8sClient.Create(ctx, valInvalidSecretName)).Should(Succeed())

		Expect(k8sClient.Create(ctx, authSecret)).Should(Succeed())
		Expect(k8sClient.Create(ctx, val)).Should(Succeed())

		// Wait for the ValidationResult's Status to be updated
		Eventually(func() bool {
			if err := k8sClient.Get(ctx, vrKey, vr); err != nil {
				return false
			}
			stateOk := vr.Status.State == vapi.ValidationFailed
			return stateOk
		}, timeout, interval).Should(BeTrue(), "failed to create a ValidationResult")
	})
})
