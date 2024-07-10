package maps

import (
	"reflect"
	"testing"
)

func TestFromKeys(t *testing.T) {
	type args struct {
		keys  []string
		value string
	}
	tests := []struct {
		name string
		args args
		want map[string]string
	}{
		{
			name: "Creates the expected map",
			args: args{
				keys:  []string{"a", "b"},
				value: "x",
			},
			want: map[string]string{
				"a": "x",
				"b": "x",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromKeys(tt.args.keys, tt.args.value); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FromKeys() = %v, want %v", got, tt.want)
			}
		})
	}
}
