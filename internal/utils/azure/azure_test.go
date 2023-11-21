package azure

import (
	"testing"
)

func Test_RoleNameFromRoleDefinitionID(t *testing.T) {
	type args struct {
		roleDefinitionID string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Extracts a role ID successfully from a role definition ID.",
			args: args{
				roleDefinitionID: "/subscriptions/45e41ba5-078e-4f83-893c-f7fd7f5aed19/providers/Microsoft.Authorization/roleDefinitions/a8fd7d79-1dee-4829-8ef8-8b7b97711fe9",
			},
			want: "a8fd7d79-1dee-4829-8ef8-8b7b97711fe9",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RoleNameFromRoleDefinitionID(tt.args.roleDefinitionID); got != tt.want {
				t.Errorf("RoleNameFromRoleDefinitionID() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRoleAssignmentScopeSubscription(t *testing.T) {
	type args struct {
		scope string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Success - resource group scope",
			args: args{
				scope: "/subscriptions/ee724176-6b76-4478-845c-577c730c2165/resourceGroups/resource-group-a/providers/Microsoft.Authorization/roleAssignments/bbd7cf6d-5638-42d7-8a02-adcd442a81c0",
			},
			want:    "ee724176-6b76-4478-845c-577c730c2165",
			wantErr: false,
		},
		{
			name: "Success - subscription scope",
			args: args{
				scope: "/subscriptions/d3decd23-c892-4995-be46-e5d1e25740fb/providers/Microsoft.Authorization/roleAssignments/6f6a7a0b-91f4-4d42-b968-7c6c19872c2c",
			},
			want:    "d3decd23-c892-4995-be46-e5d1e25740fb",
			wantErr: false,
		},
		{
			name: "Fail - unknown hierarchy in string",
			args: args{
				scope: "/planets/7baa89a1-6021-4526-aadc-6d6f998f5aea/plants/Microsoft.trees/evergreen/e0206297-48df-4967-b579-691f1ad4ad31",
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "Fail - not UUID in normal hierarchy",
			args: args{
				scope: "/subscriptions/sub1/resourceGroups/resource-group-a/providers/Microsoft.Authorization/roleAssignments/8230d1a2-4839-4667-8200-be1d950098d3",
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RoleAssignmentScopeSubscription(tt.args.scope)
			if (err != nil) != tt.wantErr {
				t.Errorf("RoleAssignmentScopeSubscription() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("RoleAssignmentScopeSubscription() = %v, want %v", got, tt.want)
			}
		})
	}
}
