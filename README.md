[![Contributions Welcome](https://img.shields.io/badge/contributions-welcome-brightgreen.svg?style=flat)](https://github.com/spectrocloud-labs/validator-plugin-azure/issues)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
![Build](https://github.com/spectrocloud-labs/validator-plugin-azure/actions/workflows/build_container.yaml/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/spectrocloud-labs/validator-plugin-azure)](https://goreportcard.com/report/github.com/spectrocloud-labs/validator-plugin-azure)
[![Go Reference](https://pkg.go.dev/badge/github.com/spectrocloud-labs/validator-plugin-azure.svg)](https://pkg.go.dev/github.com/spectrocloud-labs/validator-plugin-azure)

# validator-plugin-azure

The Azure [validator](https://github.com/spectrocloud-labs/validator) plugin ensures that your Azure environment matches a user-configurable expected state.

## Description

The Azure validator plugin reconciles `AzureValidator` custom resources to perform the following validations against your Azure environment:

1. Compare the Azure RBAC permissions associated with a [security principal](https://learn.microsoft.com/en-us/azure/role-based-access-control/overview#security-principal) against an expected permission set.

Each `AzureValidator` CR is (re)-processed every two minutes to continuously ensure that your Azure environment matches the expected state.

See the [samples](https://github.com/spectrocloud-labs/validator-plugin-azure/tree/main/config/samples) directory for example `AzureValidator` configurations.

## Authn & Authz

Authentication details for the Azure validator controller are provided within each `AzureValidator` custom resource. Azure authentication can be configured either implicitly or explicitly:

* Implicit
  * Plugin is authenticated by [workload identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-overview)
  * To use this method:
    1. Set Helm value `AzureValidator.auth.implicit` to `true`.
    1. Ensure workload identity is set up for your AKS cluster, including the [managed identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster#create-a-managed-identity) and [federated identity credential](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster#establish-federated-identity-credential).
    1. Create a Kubernetes ServiceAccount for use with the plugin that is [configured appropriately for workload identity](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster#create-kubernetes-service-account) and set Helm value `AzureValidator.auth.serviceAccountName` to the name of this ServiceAccount.
* Explicit
  * Plugin is authenticated by values provided by a Kubernetes Secret.
  * To use this method:
    1. Set Helm value `AzureValidator.auth.implicit` to `false`.
    1. Ensure that a Secret exists with `TENANT_ID`, `CLIENT_ID`, and `CLIENT_SECRET`.
    1. If using a Secret name other than "azure-creds", set Helm value `Auth.secret.secretName`.

> [!NOTE]
> See [values.yaml](https://github.com/spectrocloud-labs/validator-plugin-azure/tree/main/chart/validator-plugin-azure/values.yaml) for additional configuration details for each authentication option.

### Minimal Azure RBAC permissions by validation type

For validation to succeed, certain Azure RBAC permissions must be assigned to the principal used via role assignments. The minimal required [operations](https://learn.microsoft.com/en-us/azure/role-based-access-control/resource-provider-operations) that must be listed under `Actions` in the role assignments are as follows:

* `Microsoft.Authorization/denyAssignments/read`
* `Microsoft.Authorization/roleAssignments/read`
* `Microsoft.Authorization/roleDefinitions/read`

If you want to use a built-in role instead of a custom role to provide these permissions, you can use [`Managed Identity Operator`](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#managed-identity-operator).

## Installation

The Azure validator plugin is meant to be [installed by validator](https://github.com/spectrocloud-labs/validator/tree/gh_pages#installation) (via a ValidatorConfig), but it can also be installed directly as follows:

```bash
helm repo add validator-plugin-azure https://spectrocloud-labs.github.io/validator-plugin-azure
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
