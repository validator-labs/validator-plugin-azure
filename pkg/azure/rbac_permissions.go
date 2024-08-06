package azure

import (
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"golang.org/x/exp/maps"

	map_utils "github.com/validator-labs/validator-plugin-azure/pkg/utils/maps"
)

const (
	wildcard = "*"
)

// deniedAndUnpermitted is data about which candidate actions were denied because a deny assignment
// denied them and which were unpermitted because no role assignment permitted them.
type deniedAndUnpermitted struct {
	// denied are the candidate Actions that were denied by a deny assignment and the name of the
	// deny assignment that denied them.
	denied map[string]string
	// unpermitted are the candidate Actions that weren't permitted because no role assignment
	// permitted them.
	unpermitted []string
}

// result is the data about which Actions and DataActions were denied and unpermitted.
type result struct {
	actions     deniedAndUnpermitted
	dataActions deniedAndUnpermitted
}

// denyAssignmentInfo is a container for permission data from the Azure API response that we've
// validated as non-nil. Used for both control Actions and DataActions. Important to use instead of
// slices of strings because it lets us tie NotActions to the Actions they subtract from on a per
// role basis. Unlike roleInfo below, this lets us retain deny assignment ID (the fully-qualified ID
// where it's a path with the scope on the left and the name of the deny assignment on the right)
// too so that we can report the names of deny assignments that deny candidate Actions or
// DataActions to the user.
type denyAssignmentInfo struct {
	actions    []string
	notActions []string
	id         string
}

// roleInfo is a container for permission data from the Azure API response that we've validated as
// non-nil. Used for both control Actions and DataActions. Important to use instead of slices of
// strings because it lets us tie NotActions to the Actions they subtract from on a per role basis.
type roleInfo struct {
	actions    []string
	notActions []string
}

// processAllCandidateActions determines, based on a set of deny assignments and roles (associated
// with role assignments), which required actions and data actions are denied by presence of deny
// assignment and/or unpermitted by lack of role assignment.
//
// It is assumed that all required actions and data actions have no wildcards because of CRD
// validation.
// nolint:gocyclo
func processAllCandidateActions(candidateActions, candidateDataActions []string, denyAssignments []*armauthorization.DenyAssignment, roles []*armauthorization.RoleDefinition) (result, error) {
	errNil := func(subject string) error {
		return fmt.Errorf("%s nil", subject)
	}
	appendStr := func(vals *[]string, val string) {
		*vals = append(*vals, val)
	}
	appendDenyInfo := func(vals *[]denyAssignmentInfo, val denyAssignmentInfo) {
		*vals = append(*vals, val)
	}
	appendRoleInfo := func(vals *[]roleInfo, val roleInfo) {
		*vals = append(*vals, val)
	}

	// Dereference all the data from Azure, while validating it for our algorithm's constraints.
	// Deny assignments and role assignments that exist in the user's Azure account must have at
	// most one wildcard each.
	denyAssignmentInfoControl := []denyAssignmentInfo{}
	denyAssignmentInfoData := []denyAssignmentInfo{}
	roleInfoControl := []roleInfo{}
	roleInfoData := []roleInfo{}
	for _, denyAssignment := range denyAssignments {
		if denyAssignment == nil {
			return result{}, errNil("deny assignment")
		}
		if denyAssignment.ID == nil {
			return result{}, errNil("deny assignment ID")
		}
		denyAssignmentID := *denyAssignment.ID
		if denyAssignment.Properties == nil {
			return result{}, errNil("deny assignment properties")
		}
		if denyAssignment.Properties.Permissions == nil {
			return result{}, errNil("deny assignment properties permissions")
		}
		permissions := denyAssignment.Properties.Permissions
		// We can expect there to only be one permissions item in the list of permissions. That's
		// just how Azure works.
		if len(permissions) != 1 {
			return result{}, errNil("deny assignment permissions length not equal to 1")
		}
		permission := permissions[0]
		if permission.Actions == nil {
			return result{}, errNil("deny assignment Actions")
		}
		actions := []string{}
		for _, ptr := range permission.Actions {
			if ptr == nil {
				return result{}, errNil("deny assignment Action")
			}
			action := *ptr
			if numWildcards(action) > 1 {
				return result{}, fmt.Errorf("deny assignment Action %s has multiple wildcards", action)
			}
			appendStr(&actions, action)
		}
		if permission.NotActions == nil {
			return result{}, errNil("deny assignment NotActions")
		}
		notActions := []string{}
		for _, ptr := range permission.NotActions {
			if ptr == nil {
				return result{}, errNil("deny assignment NotAction")
			}
			notAction := *ptr
			if numWildcards(notAction) > 1 {
				return result{}, fmt.Errorf("deny assignment NotAction %s has multiple wildcards", notAction)
			}
			appendStr(&notActions, notAction)
		}
		appendDenyInfo(&denyAssignmentInfoControl, denyAssignmentInfo{
			actions:    actions,
			notActions: notActions,
			id:         denyAssignmentID,
		})
		if permission.DataActions == nil {
			return result{}, errNil("deny assignment DataActions")
		}
		dataActions := []string{}
		for _, ptr := range permission.DataActions {
			if ptr == nil {
				return result{}, errNil("deny assignment DataAction")
			}
			dataAction := *ptr
			if numWildcards(dataAction) > 1 {
				return result{}, fmt.Errorf("deny assignment DataAction %s has multiple wildcards", dataAction)
			}
			appendStr(&dataActions, dataAction)
		}
		if permission.NotDataActions == nil {
			return result{}, errNil("deny assignment NotDataActions")
		}
		notDataActions := []string{}
		for _, ptr := range permission.NotDataActions {
			if ptr == nil {
				return result{}, errNil("deny assignment NotDataAction")
			}
			notDataAction := *ptr
			if numWildcards(notDataAction) > 1 {
				return result{}, fmt.Errorf("deny assignment NotDataAction %s has multiple wildcards", notDataAction)
			}
			appendStr(&notDataActions, notDataAction)
		}
		appendDenyInfo(&denyAssignmentInfoData, denyAssignmentInfo{
			actions:    dataActions,
			notActions: notDataActions,
			id:         denyAssignmentID,
		})
	}
	for _, role := range roles {
		if role == nil {
			return result{}, errNil("role")
		}
		if role.Properties == nil {
			return result{}, errNil("role properties")
		}
		if role.Properties.Permissions == nil {
			return result{}, errNil("role properties permissions")
		}
		permissions := role.Properties.Permissions
		// We can expect there to only be one permissions item in the list of permissions. That's
		// just how Azure works.
		if len(permissions) != 1 {
			return result{}, errNil("role permissions length not equal to 1")
		}
		permission := permissions[0]
		if permission.Actions == nil {
			return result{}, errNil("role Actions")
		}
		actions := []string{}
		for _, ptr := range permission.Actions {
			if ptr == nil {
				return result{}, errNil("role Action")
			}
			action := *ptr
			if numWildcards(action) > 1 {
				return result{}, fmt.Errorf("role Action %s has multiple wildcards", action)
			}
			appendStr(&actions, action)
		}
		if permission.NotActions == nil {
			return result{}, errNil("role NotActions")
		}
		notActions := []string{}
		for _, ptr := range permission.NotActions {
			if ptr == nil {
				return result{}, errNil("role NotAction")
			}
			notAction := *ptr
			if numWildcards(notAction) > 1 {
				return result{}, fmt.Errorf("role NotAction %s has multiple wildcards", notAction)
			}
			appendStr(&notActions, notAction)
		}
		appendRoleInfo(&roleInfoControl, roleInfo{
			actions:    actions,
			notActions: notActions,
		})
		if permission.DataActions == nil {
			return result{}, errNil("role DataActions")
		}
		dataActions := []string{}
		for _, ptr := range permission.DataActions {
			if ptr == nil {
				return result{}, errNil("role DataAction")
			}
			dataAction := *ptr
			if numWildcards(dataAction) > 1 {
				return result{}, fmt.Errorf("role DataAction %s has multiple wildcards", dataAction)
			}
			appendStr(&dataActions, dataAction)
		}
		if permission.NotDataActions == nil {
			return result{}, errNil("role NotDataActions")
		}
		notDataActions := []string{}
		for _, ptr := range permission.NotDataActions {
			if ptr == nil {
				return result{}, errNil("role NotDataAction")
			}
			notDataAction := *ptr
			if numWildcards(notDataAction) > 1 {
				return result{}, fmt.Errorf("role NotDataAction %s has multiple wildcards", notDataAction)
			}
			appendStr(&notDataActions, notDataAction)
		}
		appendRoleInfo(&roleInfoData, roleInfo{
			actions:    dataActions,
			notActions: notDataActions,
		})
	}

	// Use dereferenced data to find denied and unpermitted for control Actions, and then for
	// DataActions.
	return result{
		actions:     findDeniedAndUnpermitted(candidateActions, denyAssignmentInfoControl, roleInfoControl),
		dataActions: findDeniedAndUnpermitted(candidateDataActions, denyAssignmentInfoData, roleInfoData),
	}, nil
}

// findDeniedAndUnpermitted determines, based on a set of NotActions and Actions, from deny
// assignments and from role assignments, which candidate actions should be denied due to the deny
// assignments and which should be unpermitted due to the role assignments.
//
// This logic can be used for both control Actions and DataActions. They just need to come from the
// right source (deny assignment vs. role).
func findDeniedAndUnpermitted(candidateActions []string, denyAssignments []denyAssignmentInfo, roles []roleInfo) deniedAndUnpermitted {
	// Begin with all candidate Actions marked as "unpermitted". It's better to start with all
	// candidates considered unpermitted and marking them as permitted later instead of starting
	// with an empty list of unpermitted actions and adding candidates to it later because of how
	// the algorithm below works.
	unpermitted := map_utils.FromKeys(candidateActions, true)
	// Begin with no candidate Actions marked as denied.
	//   keys = candidate Actions
	//   values = names of denying deny assignments
	denied := make(map[string]string, 0)

candidateActions:
	for _, candidateAction := range candidateActions {
		for _, denyAssignment := range denyAssignments {
			// Does any NotAction in the deny assignment match the candidate Action?
			if matches, _ := candidateActionMatches(candidateAction, denyAssignment.notActions); matches {
				// Move on to next deny assignment because this NotAction matching means the deny
				// assignment does not deny the candidate Action.
				continue
			}
			// Does any Action in the deny assignment match the candidate Action?
			if matches, _ := candidateActionMatches(candidateAction, denyAssignment.actions); matches {
				// Mark candidate action as "denied by deny assignment {denyAssignmentId}".
				denied[candidateAction] = denyAssignment.id
			}
		}
		for _, role := range roles {
			// Does any NotAction in the role match the candidate Action?
			if matches, _ := candidateActionMatches(candidateAction, role.notActions); matches {
				// Move on to next role because this NotAction matching means the role does not
				// permit the candidate Action.
				continue
			}
			// Does any Action in the role match the candidate Action?
			if matches, _ := candidateActionMatches(candidateAction, role.actions); matches {
				// Mark candidate action as permitted.
				delete(unpermitted, candidateAction)
				// Move on to next candidate Action because this Action matching means the role
				// permits the candidate Action.
				continue candidateActions
			}
		}
	}

	// We've now considered all deny assignments and roles for all candidate actions. We've
	// determined which candidate Actions were denied and which were simply not permitted in the
	// first place. It's possible for a candidate Action to be both denied and not permitted. We
	// report two failures for such candidate Actions so that the user gets as much info as possible
	// each time they observe the validation result.
	return deniedAndUnpermitted{
		denied:      denied,
		unpermitted: maps.Keys(unpermitted),
	}
}

// candidateActionMatches determines whether a candidate Action matches any compared Actions, where
// the compared Actions are Actions or NotActions, from roles or deny assignments. Returns the
// matching compared Action when a match is found.
//
// The candidate Action must have no wildcards. The compared Actions must have no more than one
// wildcard each.
func candidateActionMatches(candidateAction string, comparedActions []string) (bool, string) {
	for _, comparedAction := range comparedActions {
		if !hasWildcard(comparedAction) {
			// If allowed action has no wildcard, candidate action must be equal to it exactly in
			// order for the candidate action to be permitted.
			if candidateAction == comparedAction {
				return true, comparedAction
			}
			// Whether the action permitted the candidate action because it was equal to it or it
			// didn't, we can move on to the next action, because if it has no wildcard, it is
			// impossible for it to permit the candidate action via wildcard.
			continue
		}

		// Special case for when string is just a single char - the wildcard.
		if comparedAction == wildcard {
			return true, comparedAction
		}

		// If allowed action string has a wildcard, candidate action must match when we take the
		// wildcard into account.

		if comparedAction[0:1] == wildcard {
			// Wildcard is at beginning of allowed action. No prefix in action string to take into
			// account.
			// Find the suffix of the action string. If that suffix is also a suffix of the
			// candidate action, permit the candidate action.
			actionSuffix := strings.TrimPrefix(comparedAction, wildcard)
			if strings.HasSuffix(candidateAction, actionSuffix) {
				return true, comparedAction
			}
		}

		if comparedAction[len(comparedAction)-1:] == wildcard {
			// Wildcard is at end of allowed action. No suffix in action string to take into
			// account.
			// Find the prefix of the action string. If that prefix is also a prefix of the
			// candidate action, permit the candidate action.
			actionPrefix := strings.TrimSuffix(comparedAction, wildcard)
			if strings.HasPrefix(candidateAction, actionPrefix) {
				return true, comparedAction
			}
		}

		// Wildcard is somewhere in the middle. Must take into account prefix and suffix.
		// Split the action string by the wildcard. The first segment is a prefix. The second is a
		// suffix. If the candidate action has this prefix as a prefix and has this suffix as a
		// suffix, permit the candidate action.
		splitAction := strings.Split(comparedAction, wildcard)
		actionPrefix := splitAction[0]
		actionSuffix := splitAction[1]
		if strings.HasPrefix(candidateAction, actionPrefix) && strings.HasSuffix(candidateAction, actionSuffix) {
			return true, comparedAction
		}
	}

	// Compared action not relevant when there was no match.
	return false, ""
}

// numWildcards returns how many wildcards an action string has.
func numWildcards(action string) int {
	return strings.Count(action, wildcard)
}

// hasWildcard returns true IFF an action has one wildcard. Helper is useful for clarity in
// algorithm.
func hasWildcard(action string) bool {
	return numWildcards(action) == 1
}
