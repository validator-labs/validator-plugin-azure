package validators

import (
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	"github.com/spectrocloud-labs/validator-plugin-azure/api/v1alpha1"
	vapitypes "github.com/spectrocloud-labs/validator/pkg/types"
)

// TODO: Make this implement the needed interface and fill in any state it
// needs to do that.
type roleAssignmentsAPIMock struct {
}

// func (m roleAssignmentsAPIMock) NewListForSubscriptionPager(options *armauthorization.RoleAssignmentsClientListForSubscriptionOptions) *runtime.Pager[armauthorization.RoleAssignmentsClientListForSubscriptionResponse] {

// }

// var roleAssignmentService = NewRoleAssignmentRuleService(logr.Logger{}, roleAssignmentsAPIMock{})

func TestRoleAssignmentRuleService_ReconcileRoleAssignmentRule(t *testing.T) {
	type fields struct {
		log logr.Logger
		api roleAssignmentAPI
	}
	type args struct {
		rule v1alpha1.RoleAssignmentRule
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *vapitypes.ValidationResult
		wantErr bool
	}{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &RoleAssignmentRuleService{
				log: tt.fields.log,
				api: tt.fields.api,
			}
			got, err := s.ReconcileRoleAssignmentRule(tt.args.rule)
			if (err != nil) != tt.wantErr {
				t.Errorf("RoleAssignmentRuleService.ReconcileRoleAssignmentRule() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RoleAssignmentRuleService.ReconcileRoleAssignmentRule() = %v, want %v", got, tt.want)
			}
		})
	}
}
