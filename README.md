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

#### RBAC rule

Create a custom role with the following permissions:

    Microsoft.Authorization/denyAssignments/read
    Microsoft.Authorization/roleAssignments/read
    Microsoft.Authorization/roleDefinitions/read

Alternatively, you can use the built-in [Managed Identity Operator role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles#managed-identity-operator), which includes these permissions.

#### Community gallery image rule

Create a custom role with the permission `Microsoft.Compute/locations/communityGalleries/images/read`.

If you prefer to use a built-in role, the [Virtual Machine Contributor role](https://learn.microsoft.com/en-us/azure/role-based-access-control/built-in-roles/compute#virtual-machine-contributor) includes the necessary permissions to read community gallery images. However, be aware that this role also grants permissions to modify and delete virtual machines and other compute resources. If you only need read-only access, consider creating a custom role as described above.

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
