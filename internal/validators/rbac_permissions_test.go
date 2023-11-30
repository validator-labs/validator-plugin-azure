package validators

import (
	"reflect"
	"testing"
)

func Test_processCandidateActions(t *testing.T) {
	allPermitted := result{
		missingFromActions:  make([]string, 0),
		presentInNotActions: make(map[string]string, 0),
	}

	type args struct {
		candidateActions []string
		actions          []string
		notActions       []string
	}
	tests := []struct {
		name    string
		args    args
		want    result
		wantErr bool
	}{
		// Actions and not actions in the test cases are both candidate actions.
		// Example candidate actions use the form "<Microsoft.Provider>/<resource>/<subResource>/<action>".
		// Note that action here refers to the action part of a candidate action, not how action
		// could be used as an action or as a not action.

		// Test cases with invalid data, where we expect errors.
		{
			name: "one candidate action (empty string)",
			args: args{
				candidateActions: []string{""},
			},
			wantErr: true,
		},
		{
			name: "one candidate action, one action (empty string)",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{""},
			},
			wantErr: true,
		},
		{
			name: "one candidate action, one action, one not action (empty string)",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{""},
			},
			wantErr: true,
		},
		{
			name: "one candidate action (one wildcard)",
			args: args{
				candidateActions: []string{"*"},
			},
			wantErr: true,
		},
		{
			name: "one candidate action, one action (two wildcards)",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/*/sr/*"},
			},
			wantErr: true,
		},
		{
			name: "one candidate action, one action, one not action (two wildcards)",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/*/sr/*"},
			},
			wantErr: true,
		},

		// Test cases with no candidate actions. No wildcards.
		{
			name: "no candidate actions, no actions, no not actions",
			args: args{
				candidateActions: []string{},
				actions:          []string{},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "no candidate actions, no not actions",
			args: args{
				candidateActions: []string{},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "no candidate actions, no actions",
			args: args{
				candidateActions: []string{},
				actions:          []string{},
				notActions:       []string{"P/r/sr/a"},
			},
			want: allPermitted,
		},
		{
			name: "no candidate actions, some actions and some not actions",
			args: args{
				candidateActions: []string{},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/r/sr/a"},
			},
			want: allPermitted,
		},

		// Test cases with one candidate action. No wildcards.
		{
			name: "one candidate action, no actions, no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{},
				notActions:       []string{},
			},
			want: result{
				missingFromActions:  []string{"P/r/sr/a"},
				presentInNotActions: map[string]string{},
			},
		},
		{
			name: "one candidate action, present in actions, no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, no actions, present in not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{},
				notActions:       []string{"P/r/sr/a"},
			},
			want: result{
				missingFromActions:  []string{"P/r/sr/a"},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/r/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/a"},
			},
		},

		// Test cases with one candidate action and multiple actions to permit it. Cases test whether candidate Actions
		// that should be permitted are, even if the first Action is not enough to permit it.
		{
			name: "one candidate action, present in two actions (as first action), no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a", "P/r/sr/b"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in two actions (as second action), no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/b", "P/r/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},

		// Test cases with one candidate Action and multiple NotActions to deny them. Cases test whether candidate
		// Actions that should be denied are, even if the first NotAction is not enough to deny it.
		{
			name: "one candidate action, present in actions, present in not actions (as first not action)",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/r/sr/a", "P/r/sr/b"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions (as first not action)",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/r/sr/b", "P/r/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/a"},
			},
		},

		// Test cases with one candidate action, an action with a wildcard that permits it, and
		// no not actions. Cases test how the wild card permits it.
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like */r/sr/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"*/r/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like P/*/sr/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/*/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like P/r/*/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/*/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like P/r/sr/*",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/*"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like */sr/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"*/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like P/*/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/*/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like P/r/*",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/*"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like */a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"*/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like P/*",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/*"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, present in actions with wildcard, no not actions, wildcard used like *",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"*"},
				notActions:       []string{},
			},
			want: allPermitted,
		},

		// Test cases with one candidate action, an action that permits it, and a not action with
		// a wildcard that denies it. Cases test how the wild card denies it.
		//
		// Note that there's no need to have another group of tests after this one where we have
		// both actions and not actions, because if an action is already denied because there's no
		// action to permit it, any not actions present are not relevant.
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like */r/sr/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"*/r/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "*/r/sr/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like P/*/sr/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/*/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/*/sr/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like P/r/*/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/r/*/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/*/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like P/r/sr/*",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/r/sr/*"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/*"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like */sr/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"*/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "*/sr/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like P/*/a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/*/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/*/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like P/r/*",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/r/*"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/*"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like */a",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"*/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "*/a"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like P/*",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"P/*"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/*"},
			},
		},
		{
			name: "one candidate action, present in actions, present in not actions with wildcard, wildcard used like *",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a"},
				notActions:       []string{"*"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "*"},
			},
		},

		// Test cases where there are multiple candidate actions.
		{
			name: "two candidate actions, both present in actions (in the same order), no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a", "P/r/sr/b"},
				actions:          []string{"P/r/sr/a", "P/r/sr/b"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "two candidate actions, both present in actions (in opposite order), no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a", "P/r/sr/b"},
				actions:          []string{"P/r/sr/b", "P/r/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "two candidate actions, one action (wildcard), no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a", "P/r/sr/b"},
				actions:          []string{"P/r/sr/*"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "two candidate actions, one action (wildcard), one not action that denies one of the candidate actions",
			args: args{
				candidateActions: []string{"P/r/sr/a", "P/r/sr/b"},
				actions:          []string{"P/r/sr/*"},
				notActions:       []string{"P/r/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/a"},
			},
		},
		{
			name: "two candidate actions, one action (wildcard), one not action that denies one of the candidate actions via wildcard",
			args: args{
				candidateActions: []string{"P/r/sr/a", "P/r/sr/b"},
				actions:          []string{"P/r/sr/*"},
				notActions:       []string{"P/r/sr/*"},
			},
			want: result{
				missingFromActions: []string{},
				presentInNotActions: map[string]string{
					"P/r/sr/a": "P/r/sr/*",
					"P/r/sr/b": "P/r/sr/*",
				},
			},
		},
		{
			name: "two candidate actions, one action (wildcard at high level), one not action that denies one of the candidate actions via wildcard",
			args: args{
				candidateActions: []string{"P/r/sr/a", "P/r/sr/b"},
				actions:          []string{"P/r/*"},
				notActions:       []string{"P/r/sr/*"},
			},
			want: result{
				missingFromActions: []string{},
				presentInNotActions: map[string]string{
					"P/r/sr/a": "P/r/sr/*",
					"P/r/sr/b": "P/r/sr/*",
				},
			},
		},

		// Test cases where there is redundant data, which should not lead to failed validations and
		// should not include redundant failure data. Failures should be deduplicated.
		{
			name: "one candidate action, two identical actions, no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a", "P/r/sr/a"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, one action that permits it, one action that permits it at a higher level via wildcard, no not actions",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a", "*"},
				notActions:       []string{},
			},
			want: allPermitted,
		},
		{
			name: "one candidate action, two identical actions, two identical not actions that deny them",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a", "P/r/sr/a"},
				notActions:       []string{"P/r/sr/a", "P/r/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/a"},
			},
		},
		{
			name: "one candidate action, one action that permits it, one action that permits it at a higher level via wildcard, two identical not actions that deny them",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a", "*"},
				notActions:       []string{"P/r/sr/a", "*"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "P/r/sr/a"},
			},
		},
		{
			name: "one candidate action, one action that permits it, one action that permits it at a higher level via wildcard, one not actions that denies it, one not action that denies it at a higher level via wildcard, wildcard not action specified first",
			args: args{
				candidateActions: []string{"P/r/sr/a"},
				actions:          []string{"P/r/sr/a", "*"},
				notActions:       []string{"*", "P/r/sr/a"},
			},
			want: result{
				missingFromActions:  []string{},
				presentInNotActions: map[string]string{"P/r/sr/a": "*"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := processCandidateActions(tt.args.candidateActions, tt.args.actions, tt.args.notActions)
			if (err != nil) != tt.wantErr {
				t.Errorf("processCandidateActions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("processCandidateActions() = %v, want %v", got, tt.want)
			}
		})
	}
}
