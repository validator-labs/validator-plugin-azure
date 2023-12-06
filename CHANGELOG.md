# Changelog

## [0.0.3](https://github.com/spectrocloud-labs/validator-plugin-azure/compare/v0.0.2...v0.0.3) (2023-12-06)


### Features

* add implicit auth support to Helm chart ([#31](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/31)) ([7f0a707](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/7f0a707d7e851813d379450076bedee44fbb5247))
* RBAC rules ([#21](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/21)) ([d532c56](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/d532c560ebe00a0597da00e9fe76449b94064900))


### Bug Fixes

* **deps:** update module github.com/azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2 to v2.2.0 ([#24](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/24)) ([1b737ca](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/1b737ca14d82fb35165bc5b2a2b284aa0715030c))
* **deps:** update module github.com/onsi/ginkgo/v2 to v2.13.2 ([#26](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/26)) ([abb4784](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/abb478431b7937076bdd1cfc51d2274e831c0e25))
* **deps:** update module github.com/spectrocloud-labs/validator to v0.0.26 ([#25](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/25)) ([fd6fc77](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/fd6fc7701a8b6535c55a9d5e9de4b131df89daf9))
* **deps:** update module github.com/spectrocloud-labs/validator to v0.0.27 ([#28](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/28)) ([03575e7](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/03575e7638aab27d15919ccb510dfa114698cf0c))
* **deps:** update module github.com/spectrocloud-labs/validator to v0.0.28 ([#32](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/32)) ([bca0a38](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/bca0a388b022ee860fdc47546299ffa0105e0b47))


### Other

* **deps:** update actions/setup-go action to v5 ([#34](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/34)) ([293a890](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/293a890c93e47fd23a33c8f2f34b9ace2bba2a3d))
* **deps:** update actions/setup-python action to v5 ([#33](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/33)) ([169bdb5](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/169bdb5997d57f6452667fae7f76672068aedcbd))
* **deps:** update anchore/sbom-action action to v0.15.1 ([#30](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/30)) ([47b0704](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/47b0704f763ee3d6cc62cf78eb654bc3f9ece3ff))
* **deps:** update google-github-actions/release-please-action action to v4 ([#29](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/29)) ([35f91aa](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/35f91aa46e8bde9cd63509fdc7cd9958fde7d2b5))
* release 0.0.3 ([272d22b](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/272d22b4a444cfd5449e83324de449ac0dc80d1f))

## [0.0.2](https://github.com/spectrocloud-labs/validator-plugin-azure/compare/v0.0.1...v0.0.2) (2023-11-22)


### Features

* add Helm chart & configure Azure auth ([#22](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/22)) ([22db01a](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/22db01a230f09388dbc5a5fe081e2484a98951ca))
* configurable GOARCH for image builds ([#23](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/23)) ([414c6dc](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/414c6dc3df71357bbfac08bfe1a0e4363801498d))
* role assignment validation ([#8](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/8)) ([486a98d](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/486a98dc2fd0191954526f55790711777b5fe5c2))
* unit tests and beginning int. tests ([#15](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/15)) ([cb303cc](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/cb303cca46adfa00984ea87cc4c3fb0150d333c0))


### Bug Fixes

* **deps:** update kubernetes packages to v0.28.4 ([#16](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/16)) ([568a475](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/568a475dacb71b57291af35f2a57cb46b9d28458))
* **deps:** update module github.com/azure/azure-sdk-for-go/sdk/azcore to v1.9.0 ([#13](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/13)) ([4631be0](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/4631be014e137fd62abd469adde51a10cede23ed))
* **deps:** update module github.com/spectrocloud-labs/validator to v0.0.25 ([#19](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/19)) ([0890fda](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/0890fda90e71a16dc770dd2a1cc1de54ea1a4a9d))
* set owner references on VR to ensure cleanup ([#18](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/18)) ([7254a99](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/7254a9907c27663e245eb3719f80b8f8ba544974))


### Other

* **deps:** update anchore/sbom-action action to v0.15.0 ([#20](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/20)) ([41b36cd](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/41b36cd0c80244f68fa6a4c16175dd0ff9a38ae5))
* **deps:** update docker/build-push-action digest to 4a13e50 ([#17](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/17)) ([9e8b862](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/9e8b86214d25c7191bc0e27be131bb8d359caf92))
* GHA workflows ([#14](https://github.com/spectrocloud-labs/validator-plugin-azure/issues/14)) ([a99e0b2](https://github.com/spectrocloud-labs/validator-plugin-azure/commit/a99e0b2e05cb991f36124e5b1bdbbafc727af605))
