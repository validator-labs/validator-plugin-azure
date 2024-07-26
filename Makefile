include build/makelib/common.mk
include build/makelib/plugin.mk

# Image URL to use all building/pushing image targets
IMG ?= quay.io/validator-labs/validator-plugin-azure:latest

# Helm vars
CHART_NAME=validator-plugin-azure

.PHONY: dev
dev:
	devspace dev -n validator-plugin-azure-system

# Static Analysis / CI

chartCrds = chart/validator-plugin-azure/crds/validation.spectrocloud.labs_azurevalidators.yaml

reviewable-ext:
	rm $(chartCrds)
	cp config/crd/bases/validation.spectrocloud.labs_azurevalidators.yaml $(chartCrds)
