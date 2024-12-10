package validate

import (
	"os"
	"reflect"
	"testing"

	"github.com/go-logr/logr"
	"github.com/google/uuid"
	"github.com/validator-labs/validator-plugin-azure/api/v1alpha1"
	// +kubebuilder:scaffold:imports
)

func Test_validateAuth(t *testing.T) {
	tenID := uuid.New().String()
	cliID := uuid.New().String()

	type args struct {
		auth v1alpha1.AzureAuth
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "No error for valid inline auth data",
			args: args{
				auth: v1alpha1.AzureAuth{
					Credentials: &v1alpha1.ServicePrincipalCredentials{
						TenantID:     tenID,
						ClientID:     cliID,
						ClientSecret: "c",
						Environment:  "d",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "No panic for nil auth.Credentials",
			args: args{
				auth: v1alpha1.AzureAuth{},
			},
			wantErr: true,
		},
		{
			name: "Error for invalid tenant ID",
			args: args{
				auth: v1alpha1.AzureAuth{
					Credentials: &v1alpha1.ServicePrincipalCredentials{
						TenantID:     "",
						ClientID:     cliID,
						ClientSecret: "c",
						Environment:  "d",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error for invalid client ID",
			args: args{
				auth: v1alpha1.AzureAuth{
					Credentials: &v1alpha1.ServicePrincipalCredentials{
						TenantID:     tenID,
						ClientID:     "",
						ClientSecret: "c",
						Environment:  "d",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Error for invalid client secret",
			args: args{
				auth: v1alpha1.AzureAuth{
					Credentials: &v1alpha1.ServicePrincipalCredentials{
						TenantID:     tenID,
						ClientID:     cliID,
						ClientSecret: "",
						Environment:  "d",
					},
				},
			},
			wantErr: true,
		},
		{
			name: "No error for valid auth data but missing environment",
			args: args{
				auth: v1alpha1.AzureAuth{
					Credentials: &v1alpha1.ServicePrincipalCredentials{
						TenantID:     tenID,
						ClientID:     cliID,
						ClientSecret: "c",
					},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateAuth(tt.args.auth); (err != nil) != tt.wantErr {
				t.Errorf("validateAuth() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_configureAuth(t *testing.T) {
	tenID := uuid.New().String()
	cliID := uuid.New().String()

	type args struct {
		auth v1alpha1.AzureAuth
		log  logr.Logger
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantEnvVars map[string]string
	}{
		{
			name: "Sets all env vars given inline auth config",
			args: args{
				auth: v1alpha1.AzureAuth{
					Credentials: &v1alpha1.ServicePrincipalCredentials{
						TenantID:     tenID,
						ClientID:     cliID,
						ClientSecret: "c",
						Environment:  "d",
					},
				},
			},
			wantErr: false,
			wantEnvVars: map[string]string{
				"AZURE_TENANT_ID":     tenID,
				"AZURE_CLIENT_ID":     cliID,
				"AZURE_CLIENT_SECRET": "c",
				"AZURE_ENVIRONMENT":   "d",
			},
		},
		{
			name: "No env vars set when implicit auth enabled",
			args: args{
				auth: v1alpha1.AzureAuth{
					Implicit: true,
				},
			},
			wantErr:     false,
			wantEnvVars: map[string]string{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Save the current environment variables to restore them later
			originalEnv := make(map[string]string)
			for k := range tt.wantEnvVars {
				originalEnv[k] = os.Getenv(k)
			}

			// Clean up and reset environment variables after the test
			defer func() {
				for k, v := range originalEnv {
					if v == "" {
						os.Unsetenv(k)
					} else {
						os.Setenv(k, v)
					}
				}
			}()

			// Check err result
			if err := configureAuth(tt.args.auth, tt.args.log); (err != nil) != tt.wantErr {
				t.Errorf("configureAuth() error = %v, wantErr %v", err, tt.wantErr)
			}

			// Check env var result
			actualEnvVars := make(map[string]string)
			for k := range tt.wantEnvVars {
				actualEnvVars[k] = os.Getenv(k)
			}
			if !reflect.DeepEqual(actualEnvVars, tt.wantEnvVars) {
				t.Errorf("Env vars = %v; want %v", actualEnvVars, tt.wantEnvVars)
			}
		})
	}
}
