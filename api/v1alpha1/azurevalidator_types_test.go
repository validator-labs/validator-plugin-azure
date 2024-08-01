/*
Copyright 2024.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"k8s.io/utils/ptr"
)

func TestPermission_Equal(t *testing.T) {
	type fields struct {
		Actions        []ActionStr
		DataActions    []ActionStr
		NotActions     []ActionStr
		NotDataActions []ActionStr
	}
	type args struct {
		other armauthorization.Permission
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   bool
	}{
		{
			name:   "Returns true when both empty.",
			fields: fields{},
			args: args{
				other: armauthorization.Permission{},
			},
			want: true,
		},
		{
			name: "Returns true when equal.",
			fields: fields{
				Actions:        []ActionStr{"a", "b"},
				DataActions:    []ActionStr{"c", "d"},
				NotActions:     []ActionStr{"d", "e"},
				NotDataActions: []ActionStr{"f", "g"},
			},
			args: args{
				other: armauthorization.Permission{
					Actions:        []*string{ptr.To("a"), ptr.To("b")},
					DataActions:    []*string{ptr.To("c"), ptr.To("d")},
					NotActions:     []*string{ptr.To("d"), ptr.To("e")},
					NotDataActions: []*string{ptr.To("f"), ptr.To("g")},
				},
			},
			want: true,
		},
		{
			name: "Returns true when equal (some slices omitted).",
			fields: fields{
				Actions: []ActionStr{"a", "b"},
			},
			args: args{
				other: armauthorization.Permission{
					Actions: []*string{ptr.To("a"), ptr.To("b")},
				},
			},
			want: true,
		},
		{
			name: "Returns false when inequal (1).",
			fields: fields{
				Actions: []ActionStr{"a", "b"},
			},
			args: args{
				other: armauthorization.Permission{
					Actions: []*string{ptr.To("c"), ptr.To("d")},
				},
			},
			want: false,
		},
		{
			name: "Returns false when inequal (2).",
			fields: fields{
				Actions: []ActionStr{"a", "b"},
			},
			args: args{
				other: armauthorization.Permission{
					Actions: []*string{ptr.To("c")},
				},
			},
			want: false,
		},
		{
			name: "Returns false when inequal (3).",
			fields: fields{
				Actions: []ActionStr{"a", "b"},
			},
			args: args{
				other: armauthorization.Permission{},
			},
			want: false,
		},
		{
			name: "Returns false when inequal (4).",
			fields: fields{
				Actions: []ActionStr{"a", "b"},
			},
			args: args{
				other: armauthorization.Permission{
					Actions: []*string{nil, nil},
				},
			},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Permission{
				Actions:        tt.fields.Actions,
				DataActions:    tt.fields.DataActions,
				NotActions:     tt.fields.NotActions,
				NotDataActions: tt.fields.NotDataActions,
			}
			if got := p.Equal(tt.args.other); got != tt.want {
				t.Errorf("Permission.Equal() = %v, want %v", got, tt.want)
			}
		})
	}
}
