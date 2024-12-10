package controller

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/assert"

	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/validator-labs/validator/api/v1alpha1"
	vres "github.com/validator-labs/validator/pkg/validationresult"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	// +kubebuilder:scaffold:imports
)

const (
	azureValidatorName = "azure-validator"
	testUUID           = "07207036-b574-4b0c-aa6b-587106eab479"
)

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
				"AZURE_CLIENT_ID":     []byte(testUUID),
				"AZURE_TENANT_ID":     []byte(testUUID),
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
		vrKey := types.NamespacedName{Name: vres.Name(val), Namespace: validatorNamespace}

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

func Test_AzureValidatorReconciler_authFromSecret(t *testing.T) {
	logger := logr.Logger{}
	scheme := runtime.NewScheme()
	_ = corev1.AddToScheme(scheme) // Add corev1 scheme for fake client

	tests := []struct {
		name           string
		auth           v1alpha1.AzureAuth
		secret         *corev1.Secret
		expectedAuth   v1alpha1.AzureAuth
		expectedError  error
		expectOverride bool
	}{
		{
			name: "Skips looking for Secret and overriding inline config when implicit auth is enabled",
			auth: v1alpha1.AzureAuth{Implicit: true},
			expectedAuth: v1alpha1.AzureAuth{
				Implicit: true,
			},
		},
		{
			name:         "Skips looking for Secret and overriding inline config when no secret name is specified",
			auth:         v1alpha1.AzureAuth{},
			expectedAuth: v1alpha1.AzureAuth{},
		},
		{
			name: "Returns an error when Secret is not found",
			auth: v1alpha1.AzureAuth{
				SecretName: "nonexistent-secret",
			},
			expectedAuth: v1alpha1.AzureAuth{
				SecretName: "nonexistent-secret",
			},
			expectedError: fmt.Errorf("failed to get Secret: secrets \"nonexistent-secret\" not found"),
		},
		{
			name: "Returns an error when Secret is missing key for tenant ID",
			auth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{},
			},
			expectedAuth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
			},
			expectedError: fmt.Errorf("Key AZURE_TENANT_ID missing from Secret"),
		},
		{
			name: "Returns an error when Secret is missing key for client ID",
			auth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"AZURE_TENANT_ID": []byte("tenant-id"),
				},
			},
			expectedAuth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
				Credentials: &v1alpha1.ServicePrincipalCredentials{
					TenantID: "tenant-id",
				},
			},
			expectedError: fmt.Errorf("Key AZURE_CLIENT_ID missing from Secret"),
		},
		{
			name: "Returns an error when Secret is missing key for client secret",
			auth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"AZURE_TENANT_ID": []byte("tenant-id"),
					"AZURE_CLIENT_ID": []byte("client-id"),
				},
			},
			expectedAuth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
				Credentials: &v1alpha1.ServicePrincipalCredentials{
					TenantID: "tenant-id",
					ClientID: "client-id",
				},
			},
			expectedError: fmt.Errorf("Key AZURE_CLIENT_SECRET missing from Secret"),
		},
		{
			name: "Does not return an error when key for Azure environment is missing",
			auth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
			},
			secret: &corev1.Secret{
				Data: map[string][]byte{},
			},
			expectedAuth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
				Credentials: &v1alpha1.ServicePrincipalCredentials{
					TenantID:     "tenant-id",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			expectedError: fmt.Errorf("Key AZURE_TENANT_ID missing from Secret"),
		},
		{
			name: "Overrides inline config when implicit auth is not enabled, a secret name is specified, the Secret is found, and the Secret contains all required auth data",
			auth: v1alpha1.AzureAuth{SecretName: "azure-secret"},
			secret: &corev1.Secret{
				Data: map[string][]byte{
					"AZURE_TENANT_ID":     []byte("tenant-id"),
					"AZURE_CLIENT_ID":     []byte("client-id"),
					"AZURE_CLIENT_SECRET": []byte("client-secret"),
					"AZURE_ENVIRONMENT":   []byte("azure-environment"),
				},
			},
			expectedAuth: v1alpha1.AzureAuth{
				SecretName: "azure-secret",
				Credentials: &v1alpha1.ServicePrincipalCredentials{
					TenantID:     "tenant-id",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					Environment:  "azure-environment",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up fake client and reconciler
			objects := []runtime.Object{}
			if tt.secret != nil {
				tt.secret.ObjectMeta.Name = tt.auth.SecretName
				tt.secret.ObjectMeta.Namespace = "default"
				objects = append(objects, tt.secret)
			}
			client := fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objects...).Build()
			reconciler := AzureValidatorReconciler{
				Client: client,
			}

			// Assert auth data augmented by secret or not.
			result, err := reconciler.authFromSecret(tt.auth, "default", logger)
			if tt.expectedError != nil {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError.Error())
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedAuth, result)
			}
		})
	}
}
