package controller

import (
	"context"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	vapi "github.com/spectrocloud-labs/validator/api/v1alpha1"
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

	val := &v1alpha1.AzureValidator{
		ObjectMeta: metav1.ObjectMeta{
			Name:      azureValidatorName,
			Namespace: validatorNamespace,
		},
		Spec: v1alpha1.AzureValidatorSpec{
			RoleAssignmentRules: []v1alpha1.RoleAssignmentRule{
				{
					// TODO: Fill this in with real values I can use to run a test.
					Roles: []v1alpha1.Role{
						{
							Name:     new(string),
							RoleName: new(string),
						},
					},
					ServicePrincipalID: "",
					SubscriptionID:     "",
				},
			},
		},
	}

	vr := &vapi.ValidationResult{}
	vrKey := types.NamespacedName{Name: validationResultName(val), Namespace: validatorNamespace}

	It("Should do something", func() {
		By("By creating a new AzureValidator")

		ctx := context.Background()

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
