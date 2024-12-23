
Validator-plugin-azure
===========

Perform various Azure validations (Principal RBAC, AAD Application API permissions, and Service Quotas)


## Configuration

The following table lists the configurable parameters of the Validator-plugin-azure chart and their default values.

| Parameter                | Description             | Default        |
| ------------------------ | ----------------------- | -------------- |
| `controllerManager.manager.args` |  | `["--health-probe-bind-address=:8081", "--metrics-bind-address=:8443", "--leader-elect"]` |
| `controllerManager.manager.containerSecurityContext.allowPrivilegeEscalation` |  | `false` |
| `controllerManager.manager.containerSecurityContext.capabilities.drop` |  | `["ALL"]` |
| `controllerManager.manager.image.repository` |  | `"quay.io/validator-labs/validator-plugin-azure"` |
| `controllerManager.manager.image.tag` | x-release-please-version | `"v0.0.26"` |
| `controllerManager.manager.resources.limits.cpu` |  | `"500m"` |
| `controllerManager.manager.resources.limits.memory` |  | `"128Mi"` |
| `controllerManager.manager.resources.requests.cpu` |  | `"10m"` |
| `controllerManager.manager.resources.requests.memory` |  | `"64Mi"` |
| `controllerManager.manager.volumeMounts` |  | `[]` |
| `controllerManager.replicas` |  | `1` |
| `controllerManager.serviceAccount.annotations` |  | `{}` |
| `controllerManager.volumes` |  | `[]` |
| `controllerManager.podLabels` |  | `{}` |
| `kubernetesClusterDomain` |  | `"cluster.local"` |
| `metricsService.ports` |  | `[{"name": "https", "port": 8443, "protocol": "TCP", "targetPort": 8443}]` |
| `metricsService.type` |  | `"ClusterIP"` |
| `auth.serviceAccountName` |  | `""` |
| `azureEnvironment` |  | `"AzureCloud"` |



---
_Documentation generated by [Frigate](https://frigate.readthedocs.io)._

