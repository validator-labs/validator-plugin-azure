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
