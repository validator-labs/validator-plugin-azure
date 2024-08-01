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

	It("Should not create a ValidationResult when an invalid RBACRoleRule is applied (missing principal ID)", func() {
		By("Attempting to create a new AzureValidator")

		ctx := context.Background()

		val := &v1alpha1.AzureValidator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      azureValidatorName,
				Namespace: validatorNamespace,
			},
			Spec: v1alpha1.AzureValidatorSpec{
				RBACRoleRules: []v1alpha1.RBACRoleRule{
					{
						Name: "rule-1",
						RoleAssignments: []v1alpha1.RoleAssignment{
							{
								Scope: "test-scope",
								Role: v1alpha1.Role{
									Name: "test-role-name",
									Type: "test-role-type",
								},
							},
						},
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, val)).Should(MatchError(ContainSubstring(
			"spec.rbacRoleRules[0].principalId: Required value")))
	})

	It("Should not create a ValidationResult when an invalid RBACRoleRule is applied (missing role assignments)", func() {
		By("Attempting to create a new AzureValidator")

		ctx := context.Background()

		val := &v1alpha1.AzureValidator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      azureValidatorName,
				Namespace: validatorNamespace,
			},
			Spec: v1alpha1.AzureValidatorSpec{
				RBACRoleRules: []v1alpha1.RBACRoleRule{
					{
						Name:        "rule-1",
						PrincipalID: "test-principal-id",
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, val)).Should(MatchError(ContainSubstring(
			"spec.rbacRoleRules[0].roleAssignments: Required value")))
	})

	It("Should not create a ValidationResult when an invalid RBACRoleRule is applied (empty role assignments)", func() {
		By("Attempting to create a new AzureValidator with one invalid permission set")

		ctx := context.Background()

		val := &v1alpha1.AzureValidator{
			ObjectMeta: metav1.ObjectMeta{
				Name:      azureValidatorName,
				Namespace: validatorNamespace,
			},
			Spec: v1alpha1.AzureValidatorSpec{
				RBACRoleRules: []v1alpha1.RBACRoleRule{
					{
						Name:            "rule-1",
						PrincipalID:     "test-principal-id",
						RoleAssignments: []v1alpha1.RoleAssignment{},
					},
				},
			},
		}

		Expect(k8sClient.Create(ctx, val)).Should(MatchError(ContainSubstring(
			"spec.rbacRoleRules[0].roleAssignments: Invalid value: 0: spec.rbacRoleRules[0].roleAssignments in body should have at least 1 items")))
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
				RBACRoleRules: []v1alpha1.RBACRoleRule{
					{
						Name:        "rule-1",
						PrincipalID: "test-principal-id",
						RoleAssignments: []v1alpha1.RoleAssignment{
							{
								Scope: "test-scope",
								Role: v1alpha1.Role{
									Name: "test-role-name",
									Type: "test-role-type",
								},
							},
						},
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
