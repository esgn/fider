package actions

import (
	"context"
	"strings"
	"strconv"

	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"

	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/pkg/rand"
	"github.com/getfider/fider/app/pkg/validate"
)

// check if string is an integer
func IsInteger(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
 }

// CreateEditLdapConfig is used to create/edit Ldap config
type CreateEditLdapConfig struct {
	Model *models.CreateEditLdapConfig
}

// Initialize the model
func (input *CreateEditLdapConfig) Initialize() interface{} {
	input.Model = new(models.CreateEditLdapConfig)
	return input.Model
}

// IsAuthorized returns true if current user is authorized to perform this action
func (input *CreateEditLdapConfig) IsAuthorized(ctx context.Context, user *models.User) bool {
	return user != nil && user.IsAdministrator()
}

// Validate if current model is valid
func (input *CreateEditLdapConfig) Validate(ctx context.Context, user *models.User) *validate.Result {
	result := validate.Success()

	if input.Model.Provider != "" {
		getConfig := &query.GetCustomLdapConfigByProvider{Provider: input.Model.Provider}
		err := bus.Dispatch(ctx, getConfig)
		if err != nil {
			return validate.Error(err)
		}
		input.Model.ID = getConfig.Result.ID
		if input.Model.BindPassword == "" {
			input.Model.BindPassword = getConfig.Result.BindPassword
		}

	} else {
		input.Model.Provider = "_" + strings.ToLower(rand.String(10))
	}

	if input.Model.Status != enum.LdapConfigEnabled &&
		input.Model.Status != enum.LdapConfigDisabled {
		result.AddFieldFailure("status", "Invalid status.")
	}

	if input.Model.DisplayName == "" {
		result.AddFieldFailure("displayName", "Display Name is required.")
	} else if len(input.Model.DisplayName) > 50 {
		result.AddFieldFailure("displayName", "Display Name must have less than 50 characters.")
	}

	if input.Model.LdapDomain == "" {
		result.AddFieldFailure("ldapDomain", "Ldap Domain is required.")
	} else if len(input.Model.LdapDomain) > 100 {
		result.AddFieldFailure("ldapDomain", "LDAP Domain must have less than 100 characters.")
	}

	if input.Model.LdapPort == "" {
		result.AddFieldFailure("ldapPort", "LDAP port is required.")
	} else if len(input.Model.LdapPort) > 10 {
		result.AddFieldFailure("ldapPort", "LDAP port must have less than 500 characters.")
	} else if !IsInteger(input.Model.LdapPort) {
		result.AddFieldFailure("ldapPort", "LDAP must be an integer")
	}

	if input.Model.BindUsername == "" {
		result.AddFieldFailure("bindUsername", "Bind username is required.")
	} else if len(input.Model.BindUsername) > 100 {
		result.AddFieldFailure("bindUsername", "Bind username must have less than 100 characters.")
	}

	if input.Model.BindPassword == "" {
		result.AddFieldFailure("bindPassword", "Bind password is required.")
	} else if len(input.Model.BindPassword) > 100 {
		result.AddFieldFailure("bindPassword", "Bind password must have less than 100 characters.")
	}

	if input.Model.RootDN == "" {
		result.AddFieldFailure("rootDN", "Root DN is required.")
	} else if len(input.Model.RootDN) > 100 {
		result.AddFieldFailure("rootDN", "Root DN must have less than 100 characters.")
	}

	if input.Model.Scope == "" {
		result.AddFieldFailure("scope", "Scope is required.")
	} else if len(input.Model.Scope) > 100 {
		result.AddFieldFailure("scope", "Scope must have less than 100 characters.")
	}

	if input.Model.UserSearchFilter == "" {
		result.AddFieldFailure("scope", "User Search Filter is required.")
	} else if len(input.Model.UserSearchFilter) > 100 {
		result.AddFieldFailure("scope", "User Search Filter must have less than 100 characters.")
	}

	if input.Model.UsernameLdapAttribute == "" {
		result.AddFieldFailure("usernameLdapAttribute", "Username LDAP attribute is required.")
	} else if len(input.Model.UsernameLdapAttribute) > 100 {
		result.AddFieldFailure("scope", "Username LDAP attribute must have less than 100 characters.")
	}

	return result
}
