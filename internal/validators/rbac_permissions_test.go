package validators

import (
	"reflect"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/spectrocloud-labs/validator/pkg/util/ptr"
)

func Test_processAllCandidateActions(t *testing.T) {
	type args struct {
		candidateActions     []string
		candidateDataActions []string
		denyAssignments      []*armauthorization.DenyAssignment
		roles                []*armauthorization.RoleDefinition
	}
	tests := []struct {
		name    string
		args    args
		want    result
		wantErr bool
	}{
		// Note that these tests test code that calls code that is already covered by tests below.
		// Therefore, we don't need to test some functionality (see below). Here, we test how input
		// checked for invalid values (nils and wildcard uses we're not allowing), whether control
		// Actions are handled separately from DataActions, for both deny assignments and role
		// assignments, and whether parsing the raw Azure data (with pointers) into the data for the
		// helper functions works correctly.

		// Cases that test invalid input.
		{
			name: "candidate Action with wildcard",
			args: args{
				candidateActions:     []string{"*"},
				candidateDataActions: []string{},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles:                []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "candidate Action with multiple wildcards",
			args: args{
				candidateActions:     []string{"*/*"},
				candidateDataActions: []string{},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles:                []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "candidate DataAction with wildcard",
			args: args{
				candidateActions:     []string{"a"},
				candidateDataActions: []string{"*"},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles:                []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "candidate DataAction with multiple wildcards",
			args: args{
				candidateActions:     []string{"a"},
				candidateDataActions: []string{"*/*"},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles:                []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments:      []*armauthorization.DenyAssignment{nil},
				roles:                []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment ID",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						ID: nil,
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment properties",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: nil,
						ID:         ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment properties permissions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: nil,
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "deny assignment properties permissions length 0",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "deny assignment properties permissions length greater than 1",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{},
								{},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment Actions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions: nil,
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment Action",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions: []*string{nil},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "deny assignment Action with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment NotActions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:    []*string{ptr.Ptr("*")},
									NotActions: nil,
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment NotAction",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:    []*string{ptr.Ptr("*")},
									NotActions: []*string{nil},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "deny assignment NotAction with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:    []*string{ptr.Ptr("*")},
									NotActions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment DataActions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:     []*string{ptr.Ptr("*")},
									NotActions:  []*string{ptr.Ptr("*")},
									DataActions: nil,
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment DataAction",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:     []*string{ptr.Ptr("*")},
									NotActions:  []*string{ptr.Ptr("*")},
									DataActions: []*string{nil},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "deny assignment DataAction with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:     []*string{ptr.Ptr("*")},
									NotActions:  []*string{ptr.Ptr("*")},
									DataActions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment NotDataActions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: nil,
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil deny assignment NotDataAction",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{nil},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "deny assignment NotDataAction with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{nil},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role properties",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: nil,
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role properties permissions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: nil,
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "role properties permissions length 0",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "role properties permissions length greater than 1",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{},
								{},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role Actions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions: nil,
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role Action",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions: []*string{nil},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "role NotAction with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role NotActions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:    []*string{ptr.Ptr("*")},
									NotActions: nil,
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role NotAction",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:    []*string{ptr.Ptr("*")},
									NotActions: []*string{nil},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "role NotAction with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:    []*string{ptr.Ptr("*")},
									NotActions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role DataActions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:     []*string{ptr.Ptr("*")},
									NotActions:  []*string{ptr.Ptr("*")},
									DataActions: nil,
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role DataAction",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:     []*string{ptr.Ptr("*")},
									NotActions:  []*string{ptr.Ptr("*")},
									DataActions: []*string{nil},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "role DataAction with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:     []*string{ptr.Ptr("*")},
									NotActions:  []*string{ptr.Ptr("*")},
									DataActions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role NotDataActions",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: nil,
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "nil role NotDataAction",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{nil},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},
		{
			name: "role NotDataAction with multiple wildcards",
			args: args{
				candidateActions:     []string{},
				candidateDataActions: []string{},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*")},
								},
							},
						},
						ID: ptr.Ptr("da"),
					},
				},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("*")},
									NotActions:     []*string{ptr.Ptr("*")},
									DataActions:    []*string{ptr.Ptr("*")},
									NotDataActions: []*string{ptr.Ptr("*/*")},
								},
							},
						},
					},
				},
			},
			want:    result{},
			wantErr: true,
		},

		// Cases that test handling Actions and DataActions separately with them fed into the
		// algorithm helpers correctly.
		{
			name: "1 candidate Action that should be permitted, 1 candidate DataAction that should be permitted",
			args: args{
				candidateActions:     []string{"a"},
				candidateDataActions: []string{"b"},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("a")},
									NotActions:     []*string{},
									DataActions:    []*string{ptr.Ptr("b")},
									NotDataActions: []*string{},
								},
							},
						},
					},
				},
			},
			want: result{
				actions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{},
				},
				dataActions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{},
				},
			},
			wantErr: false,
		},
		{
			name: "1 candidate Action that should not be permitted, 1 candidate DataAction that should not be permitted",
			args: args{
				candidateActions:     []string{"a"},
				candidateDataActions: []string{"b"},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{},
									NotActions:     []*string{},
									DataActions:    []*string{},
									NotDataActions: []*string{},
								},
							},
						},
					},
				},
			},
			want: result{
				actions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{"a"},
				},
				dataActions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{"b"},
				},
			},
			wantErr: false,
		},
		{
			name: "1 candidate Action that should not be permitted, 1 candidate DataAction that should be permitted",
			args: args{
				candidateActions:     []string{"a"},
				candidateDataActions: []string{"b"},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("a")},
									NotActions:     []*string{ptr.Ptr("a")},
									DataActions:    []*string{ptr.Ptr("b")},
									NotDataActions: []*string{},
								},
							},
						},
					},
				},
			},
			want: result{
				actions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{"a"},
				},
				dataActions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{},
				},
			},
			wantErr: false,
		},
		{
			name: "1 candidate Action that should be permitted, 1 candidate DataAction that should not permitted",
			args: args{
				candidateActions:     []string{"a"},
				candidateDataActions: []string{"b"},
				denyAssignments:      []*armauthorization.DenyAssignment{},
				roles: []*armauthorization.RoleDefinition{
					{
						Properties: &armauthorization.RoleDefinitionProperties{
							Permissions: []*armauthorization.Permission{
								{
									Actions:        []*string{ptr.Ptr("a")},
									NotActions:     []*string{},
									DataActions:    []*string{ptr.Ptr("b")},
									NotDataActions: []*string{ptr.Ptr("b")},
								},
							},
						},
					},
				},
			},
			want: result{
				actions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{},
				},
				dataActions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{"b"},
				},
			},
			wantErr: false,
		},

		// Cases that test parsing into deny assignments (because cases above happen to already
		// test parsing into roles) with them fed into the algorithm helpers correctly.
		{
			name: "Parsing a deny assignment.",
			args: args{
				candidateActions:     []string{"a"},
				candidateDataActions: []string{"b"},
				denyAssignments: []*armauthorization.DenyAssignment{
					{
						ID: ptr.Ptr("da1"),
						Properties: &armauthorization.DenyAssignmentProperties{
							Permissions: []*armauthorization.DenyAssignmentPermission{
								{
									Actions:        []*string{ptr.Ptr("a")},
									NotActions:     []*string{ptr.Ptr("a")},
									DataActions:    []*string{ptr.Ptr("b")},
									NotDataActions: []*string{ptr.Ptr("b")},
								},
							},
						},
					},
				},
				roles: []*armauthorization.RoleDefinition{},
			},
			want: result{
				actions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{"a"},
				},
				dataActions: deniedAndUnpermitted{
					denied:      map[string]string{},
					unpermitted: []string{"b"},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := processAllCandidateActions(tt.args.candidateActions, tt.args.candidateDataActions, tt.args.denyAssignments, tt.args.roles)
			if (err != nil) != tt.wantErr {
				t.Errorf("processAllCandidateActions() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("processAllCandidateActions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_findDeniedAndUnpermitted(t *testing.T) {
	type args struct {
		candidateActions []string
		denyAssignments  []denyAssignmentInfo
		roles            []roleInfo
	}
	tests := []struct {
		name string
		args args
		want deniedAndUnpermitted
	}{
		// Note that in these tests, "candidate action" means either a candidate Action or a candidate DataAction. This
		// is the part of the algorithm generic with respect to type of Action.

		// Also note that these tests test code that calls code that is already covered by tests below. Therefore, we
		// don't need to test some functionality (see below). Here, we test how different combinations of candidate
		// Actions, deny assignments, and roles result in denied and/or unpermitted candidate Actions.

		// Cases that test, for 1 candidate Action, every combination of deny assignment and role, where there is 0 or 1
		// matching Actions or NotActions.
		{
			name: "0 deny assign, 0 role",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments:  []denyAssignmentInfo{},
				roles:            []roleInfo{},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 0 matching NA), 0 role",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 0 matching NA), 0 role",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{},
			},
			want: deniedAndUnpermitted{
				denied: map[string]string{
					"a": "da1",
				},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 1 matching NA), 0 role",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 1 matching NA), 0 role",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "0 deny assign, 1 role (0 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "0 deny assign, 1 role (1 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
		{
			name: "0 deny assign, 1 role (0 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "0 deny assign, 1 role (1 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 0 matching NA), 1 role (0 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 0 matching NA), 1 role (0 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 0 matching NA), 1 role (1 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
		{
			name: "1 deny assign (0 matching A, 0 matching NA), 1 role (1 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 0 matching NA), 1 role (0 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied: map[string]string{
					"a": "da1",
				},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 0 matching NA), 1 role (0 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied: map[string]string{
					"a": "da1",
				},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 0 matching NA), 1 role (1 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied: map[string]string{
					"a": "da1",
				},
				unpermitted: []string{},
			},
		},
		{
			name: "1 deny assign (1 matching A, 0 matching NA), 1 role (1 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied: map[string]string{
					"a": "da1",
				},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 1 matching NA), 1 role (0 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 1 matching NA), 1 role (0 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (0 matching A, 1 matching NA), 1 role (1 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
		{
			name: "1 deny assign (0 matching A, 1 matching NA), 1 role (1 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 1 matching NA), 1 role (0 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 1 matching NA), 1 role (0 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 deny assign (1 matching A, 1 matching NA), 1 role (1 matching A, 0 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
		{
			name: "1 deny assign (1 matching A, 1 matching NA), 1 role (1 matching A, 1 matching NA)",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
						id:         "da1",
					},
				},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{"a"},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"a"},
			},
		},

		// Cases for other situations. Not exhaustive like above. Best effort.
		{
			name: "1 deny assignment that denies but is not the first deny assignment",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments: []denyAssignmentInfo{
					{
						actions:    []string{"b"},
						notActions: []string{},
						id:         "da1",
					},
					{
						actions:    []string{"a"},
						notActions: []string{},
						id:         "da2",
					},
				},
				roles: []roleInfo{},
			},
			want: deniedAndUnpermitted{
				denied: map[string]string{
					"a": "da2",
				},
				unpermitted: []string{"a"},
			},
		},
		{
			name: "1 role that permits but is not the first role",
			args: args{
				candidateActions: []string{"a"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{"b"},
						notActions: []string{},
					},
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
		{
			name: "2 candidate actions, both permitted",
			args: args{
				candidateActions: []string{"a", "b"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
					{
						actions:    []string{"b"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
		{
			name: "2 candidate actions, 1 unpermitted and 1 permitted",
			args: args{
				candidateActions: []string{"a", "b"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{"a"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{"b"},
			},
		},
		{
			name: "2 candidate actions, both permitted by the same action (wildcard only)",
			args: args{
				candidateActions: []string{"a", "b"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{"*"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
		{
			name: "2 candidate actions, both permitted by the same action (not wildcard only)",
			args: args{
				candidateActions: []string{"a/b", "a/c"},
				denyAssignments:  []denyAssignmentInfo{},
				roles: []roleInfo{
					{
						actions:    []string{"a/*"},
						notActions: []string{},
					},
				},
			},
			want: deniedAndUnpermitted{
				denied:      map[string]string{},
				unpermitted: []string{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := findDeniedAndUnpermitted(tt.args.candidateActions, tt.args.denyAssignments, tt.args.roles); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("findDeniedAndUnpermitted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_candidateActionMatches(t *testing.T) {
	type args struct {
		candidateAction string
		comparedActions []string
	}
	tests := []struct {
		name  string
		args  args
		want  bool
		want1 string
	}{
		// Note that in these tests, "candidate Action" means either a candidate Action or a candidate DataAction. This
		// part of the algorithm is generic with respect to type of Action.

		// Cases that test when a candidate Action matches because the compared Action is the wildcard only or the
		// candidate Action exactly, regardless of compared Action order.
		{
			name: "No compared Actions",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{},
			},
			want:  false,
			want1: "",
		},
		{
			name: "1 compared Action, which is candidate Action exactly",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"a/b/c/d"},
			},
			want:  true,
			want1: "a/b/c/d",
		},
		{
			name: "1 compared Action, which is wildcard only",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"*"},
			},
			want:  true,
			want1: "*",
		},
		{
			name: "2 compared Actions, first is candidate Action exactly, second is some other Action",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"a/b/c/d", "e/f/g/h"},
			},
			want:  true,
			want1: "a/b/c/d",
		},
		{
			name: "2 compared Actions, first is some other candidate Action, second is candidate Action exactly",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"e/f/g/h", "a/b/c/d"},
			},
			want:  true,
			want1: "a/b/c/d",
		},
		{
			name: "2 compared Actions, first is wildcard only, second is candidate Action exactly",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"*", "a/b/c/d"},
			},
			want:  true,
			want1: "*",
		},
		{
			name: "2 compared Actions, first is candidate Action exactly, second is wildcard only",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"a/b/c/d", "*"},
			},
			want:  true,
			want1: "a/b/c/d",
		},

		// Cases that test, when a compared action isn't the wildcard only, how a wildcard in a compared Action is able
		// to result in a match. We must confirm that wildcards are able to to used in Actions with up to 4 components,
		// in any place among the components, and taking the place of up to 3 components.
		{
			name: "Wildcard is like */b/c/d",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"*/b/c/d"},
			},
			want:  true,
			want1: "*/b/c/d",
		},
		{
			name: "Wildcard is like a/*/c/d",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"a/*/c/d"},
			},
			want:  true,
			want1: "a/*/c/d",
		},
		{
			name: "Wildcard is like a/b/*/d",
			args: args{
				candidateAction: "a/b/*/d",
				comparedActions: []string{"a/b/*/d"},
			},
			want:  true,
			want1: "a/b/*/d",
		},
		{
			name: "Wildcard is like a/b/c/*",
			args: args{
				candidateAction: "a/b/c/*",
				comparedActions: []string{"a/b/c/*"},
			},
			want:  true,
			want1: "a/b/c/*",
		},
		{
			name: "Wildcard is like */c/d",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"*/c/d"},
			},
			want:  true,
			want1: "*/c/d",
		},
		{
			name: "Wildcard is like a/*/d",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"a/*/d"},
			},
			want:  true,
			want1: "a/*/d",
		},
		{
			name: "Wildcard is like a/b/*",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"a/b/*"},
			},
			want:  true,
			want1: "a/b/*",
		},
		{
			name: "Wildcard is like */d",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"*/d"},
			},
			want:  true,
			want1: "*/d",
		},
		{
			name: "Wildcard is like a/*",
			args: args{
				candidateAction: "a/b/c/d",
				comparedActions: []string{"a/*"},
			},
			want:  true,
			want1: "a/*",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1 := candidateActionMatches(tt.args.candidateAction, tt.args.comparedActions)
			if got != tt.want {
				t.Errorf("candidateActionMatches() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("candidateActionMatches() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
