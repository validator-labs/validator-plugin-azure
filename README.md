[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/validator-labs/validator-plugin-azure/issues)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Test](https://github.com/validator-labs/validator-plugin-azure/actions/workflows/test.yaml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/validator-labs/validator-plugin-azure)](https://goreportcard.com/report/github.com/validator-labs/validator-plugin-azure)
[![codecov](https://codecov.io/gh/validator-labs/validator-plugin-azure/graph/badge.svg?token=QHR08U8SEQ)](https://codecov.io/gh/validator-labs/validator-plugin-azure)
[![Go Reference](https://pkg.go.dev/badge/github.com/validator-labs/validator-plugin-azure.svg)](https://pkg.go.dev/github.com/validator-labs/validator-plugin-azure)

# validator-plugin-azure

The Azure [validator](https://github.com/validator-labs/validator) plugin ensures that your Azure environment matches a user-configurable expected state.

## Description

The Azure validator plugin reconciles `AzureValidator` custom resources to perform the following validations against your Azure environment:

1. Compare the Azure RBAC permissions associated with a [security principal](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview#security-principal) against an expected permission set.
1. Verify that images in [community image galleries](https://learn.microsoft.com/en-us/azure/virtual-machines/share-gallery-community) exist.

Each `AzureValidator` CR is (re)-processed every two minutes to continuously ensure that your Azure environment matches the expected state.

See the [samples](https://github.com/validator-labs/validator-plugin-azure/tree/main/config/samples) directory for example `AzureValidator` configurations. Some samples require you to add data to the rules configured in them such as the Azure subscription to use.

### Rules

#### RBAC rule

This rule compares the Azure RBAC permissions associated with a [security principal](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview#security-principal) against an expected permission set.

It checks if an Azure security principal (e.g., users, service principals) has the required Azure RBAC permissions. In Azure RBAC, permissions are applied to principals by a role assignment being created that links a role (which can be a BuiltInRole or a CustomRole) to the principal at a particular scope. API operations at that scope or lower (e.g. operations against a subscription or against a resource group within the subscription) are permitted but operations outside of that scope are not.

Validation is successful if the principal has the necessary permissions, either from one role assignment or a combination of role assignments.

The list of permissions defined in the spec cannot have an action or data action with a wildcard. However, the roles that provide the permissions (via role assignments) may have wildcards in their actions and data actions.

Note that you must use the correct ID when configuring the `principalId` in the spec for the principal. For a service principal, this is the "application object ID" found in the Azure portal under Entra ID > application registration > managed application page > "object ID". Note that this is different from the tenant ID, client ID, and object ID of the application registration.

Service principal example:

![3](https://github.com/user-attachments/assets/59b54214-10f6-4c7c-9ec5-eeeadfada35e)

![4](https://github.com/user-attachments/assets/560acda5-2515-4c87-a1e3-1f400492f4ad)

See [azurevalidator-rbac-one-permission-set-all-actions-permitted-by-one-role.yaml](config/samples/azurevalidator-rbac-one-permission-set-all-actions-permitted-by-one-role.yaml`) for an example rule spec.

#### Community image gallery rule

This rule verifies that images in [community image galleries](https://learn.microsoft.com/en-us/azure/virtual-machines/share-gallery-community) exist.

See [azurevalidator-communitygalleryimages-one-image.yaml](config/samples/azurevalidator-communitygalleryimages-one-image.yaml) for an example rule spec.

#### Quota rule

This rule verifies that quota limits are set to a high enough level that current usage plus a buffer you configure isn't higher than the quota. This helps you ensure quotas stay high enough for your expected usage.

See [azurevalidator-quota-one-resource-set-one-resource.yaml](config/samples/azurevalidator-quota-one-resource-set-one-resource.yaml) for an example rule spec.

This is powered by Azure's [Quota Service API](https://learn.microsoft.com/en-us/rest/api/quota). The API uses scope and resource name to specify the quota limit or and usage. Scopes include the resource provider of the quota limit or usage. Each resource provider supports certain resource names. Putting this all together, this means an example of a correct scope for the `availabilitySets` resource is: `subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/{azure location}`. Azure's website has more detailed [examples](https://learn.microsoft.com/en-us/rest/api/quota/#quota-api-put-call-and-scope) of which resource providers are available and which scopes are valid for them.

At time of writing, the website does not contain a complete list of which resources are available for each resource provider. To determine this, you must make your own [Quota - List](https://learn.microsoft.com/en-us/rest/api/quota/quota/list?view=rest-quota-2023-02-01&tabs=HTTP) API call to each resource provider to get a list of which quota limits exist in your account. Each quota limit will contain a resource name you can use when defining quota rules. See [Quotas_listQuotaLimitsForCompute](https://learn.microsoft.com/en-us/rest/api/quota/quota/list?view=rest-quota-2023-02-01&tabs=HTTP#quotas_listquotalimitsforcompute) for an example request and response on Azure's website for this endpoint.

Example quota limit from this API call:

```json
{
  "id": "/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/westus/providers/Microsoft.Quota/quotas/availabilitySets",
  "name": "availabilitySets",
  "properties": {
    "isQuotaApplicable": false,
    "limit": {
      "limitObjectType": "LimitValue",
      "limitType": "Independent",
      "value": 2500
    },
    "name": {
      "localizedValue": "Availability Sets",
      "value": "availabilitySets"
    },
    "properties": {},
    "unit": "Count"
  },
  "type": "Microsoft.Quota/Quotas"
},
```

The resource name is `availabilitySets` and the scope is `/subscriptions/{subscriptionId}/providers/Microsoft.Compute/locations/westus`. You would use these values when defining a quota rule.

## Authn & Authz

Authentication details for the Azure validator controller are provided within each `AzureValidator` custom resource. Azure authentication can be configured either implicitly or explicitly:

* Implicit (`AzureValidator.auth.implicit == true`)
  * [Workload identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
    * In this scenario, a valid ServiceAccount must be specified during plugin installation. See [values.yaml](chart/validator-plugin-azure/values.yaml) for details.
* Explicit (`AzureValidator.auth.implicit == false && AzureValidator.auth.secretName != ""`)
  * [Environment variables](https://learn.microsoft.com/en-us/azure/developer/go/azure-sdk-authentication#-option-1-define-environment-variables)

> [!NOTE]
> See [values.yaml](chart/validator-plugin-azure/values.yaml) for additional configuration details for each authentication option.

### Minimal Azure RBAC permissions by validation type

For validation to succeed, certain Azure RBAC permissions must be assigned to the principal used via role assignments. The minimal required [operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations) that must be listed under `Actions` in the role assignments, by rule, are as follows.

We recommend creating custom roles with the permissions noted here and assigning them instead of assigning built-in roles, but built-in roles that can be used too are listed here under each rule type.

#### RBAC rule

Create a custom role with the following permissions:

* Microsoft.Authorization/denyAssignments/read
* Microsoft.Authorization/roleAssignments/read
* Microsoft.Authorization/roleDefinitions/read

Alternative built-in role: [Managed Identity Operator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#managed-identity-operator)

#### Community gallery image rule

Create a custom role with the permission `Microsoft.Compute/locations/communityGalleries/images/read`.

Alternative built-in role: [Virtual Machine Contributor](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/compute#virtual-machine-contributor)

#### Quota rule

Create a custom role with the following permissions:

* Microsoft.Quota/quotas/read
* Microsoft.Quota/usages/read

Alternative built-in role: [Quota Request Operator](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/management-and-governance#quota-request-operator)

## Connecting to Azure Government or Azure in China

By default, the plugin connects the Azure SDK to the public Azure cloud. Override `azureEnvironment` to change which cloud is connected to, using the following values.

|`azureEnvironment` value|Cloud|
|------------------------|-----|
|AzureCloud|public Azure cloud|
|AzureUSGovernment|[Azure Government](https://learn.microsoft.com/en-us/azure/azure-government/documentation-government-welcome)|
|AzureChinaCloud|[Azure in China](https://learn.microsoft.com/en-us/azure/china/overview-operations)|

## Installation

The Azure validator plugin is meant to be [installed by validator](https://github.com/validator-labs/validator/tree/gh_pages#installation) (via a ValidatorConfig), but it can also be installed directly as follows:

```bash
helm repo add validator-plugin-azure https://validator-labs.github.io/validator-plugin-azure
helm repo update
helm install validator-plugin-azure validator-plugin-azure/validator-plugin-azure -n validator-plugin-azure --create-namespace
```

## Development

You’ll need a Kubernetes cluster to run against. You can use [kind](https://sigs.k8s.io/kind) to get a local cluster for testing, or run against a remote cluster.

**Note:** Your controller will automatically use the current context in your kubeconfig file (i.e. whatever cluster `kubectl cluster-info` shows).

### Running on the cluster

1. Install Instances of Custom Resources:

```sh
kubectl apply -f config/samples/
```

2. Build and push your image to the location specified by `IMG`:

```sh
make docker-build docker-push IMG=<some-registry>/validator-plugin-azure:tag
```

3. Deploy the controller to the cluster with the image specified by `IMG`:

```sh
make deploy IMG=<some-registry>/validator-plugin-azure:tag
```

### Uninstall CRDs

To delete the CRDs from the cluster:

```sh
make uninstall
```

### Undeploy controller

UnDeploy the controller from the cluster:

```sh
make undeploy
```

### How it works

This project aims to follow the Kubernetes [Operator pattern](https://kubernetes.io/docs/concepts/extend-kubernetes/operator/).

It uses [Controllers](https://kubernetes.io/docs/concepts/architecture/controller/), which provide a reconcile function responsible for synchronizing resources until the desired state is reached on the cluster.

### Test It Out

1. Install the CRDs into the cluster:

```sh
make install
```

2. Run your controller (this will run in the foreground, so switch to a new terminal if you want to leave it running):

```sh
make run
```

**NOTE:** You can also run this in one step by running: `make install run`

### Modifying the API definitions

If you are editing the API definitions, generate the manifests such as CRs or CRDs using:

```sh
make manifests
```

## Contributing

All contributions are welcome! Feel free to reach out on the [Spectro Cloud community Slack](https://spectrocloudcommunity.slack.com/join/shared_invite/zt-g8gfzrhf-cKavsGD_myOh30K24pImLA#/shared-invite/email).

Make sure `pre-commit` is [installed](https://pre-commit.com#install).

Install the `pre-commit` scripts:

```console
pre-commit install --hook-type commit-msg
pre-commit install --hook-type pre-commit
```

**NOTE:** Run `make --help` for more information on all potential `make` targets

More information can be found via the [Kubebuilder Documentation](https://book.kubebuilder.io/introduction.html)

## License

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
