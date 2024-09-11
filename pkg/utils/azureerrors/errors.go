// Package azureerrors contains helpers for detecting various known error types from Azure API
// responses and wrapping them.
package azureerrors

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
)

const (
	authHelpMsg = "ensure Azure plugin is authenticated correctly; see plugin README for authentication details"
)

// defaultAzureCredential returns whether the issue that caused error err to be returned by the
// Azure SDK when it was used for an API request was that the SDK failed to use the
// defaultAzureCredential strategy to authenticate the request.
//   - err: An error returned by the Azure SDK during an API request.
func defaultAzureCredential(err error) bool {
	return strings.Contains(err.Error(), "DefaultAzureCredential: ")
}

// badClientSecret returns whether the issue that caused error err to be returned by the Azure SDK
// when it was used for an API request was that was that the SDK failed to authenticate the request
// because the client secret used was not a correct client secret for the client ID used.
//   - err: An error returned by the Azure SDK during an API request.
func badClientSecret(err error) bool {
	return strings.Contains(err.Error(), "AADSTS7000215")
}

// authFailed returns whether the issue that caused error err to be returned by the Azure SDK when
// it was used for an API request was that the security principal authenticated was unauthorized
// (e.g. missing required role assignment).
//   - err: An error returned by the Azure SDK during an API request.
func authFailed(err error) bool {
	var rerr *azcore.ResponseError
	return errors.As(err, &rerr) && rerr.ErrorCode == "AuthorizationFailed"
}

// AsAugmented checks whether an error returned by the Azure SDK matched some known Azure errors. If
// the error matches, it produces a new, augmented error by adding information we think will help
// the user use the plugin correctly. If it didn't match, it returns the error as is.
//   - err: An error returned by the Azure SDK.
//   - permissionsNeeded: The permissions the Azure client needed to have in order for the operation
//     it just performed to be successful. Used to form a good error message for the user, whichever
//     operation was being attempted.
func AsAugmented(err error, permissionsNeeded []string) error {
	// This is the order Azure returns various errors in. We check them in that order.
	if defaultAzureCredential(err) {
		return fmt.Errorf("DefaultAzureCredential error; %s: %w", authHelpMsg, err)
	}
	if badClientSecret(err) {
		return fmt.Errorf("invalid client secret provided for client ID; %s: %w", authHelpMsg, err)
	}
	if authFailed(err) {
		return fmt.Errorf("plugin authenticated as service principal successfully but principal was unauthorized; ensure principal has permissions %s via role assignments and that no deny assignments forbid them: %w", permissionsNeeded, err)
	}

	return err
}
