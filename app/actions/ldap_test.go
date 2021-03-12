package actions_test

import (
	"context"
	"github.com/getfider/fider/app/actions"
	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/enum"
	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/rand"
	"testing"
)

func TestCreateEditLdapConfig_Validate_InvalidInput(t *testing.T) {
	RegisterT(t)

	testCases := []struct {
		expected []string
		input    *models.CreateEditLdapConfig
	}{
		{
			expected: []string{"status", "protocol", "scope", "displayName", "ldapHostname", "ldapPort", "bindUsername", "bindPassword", "rootDN", "userSearchFilter", "usernameLdapAttribute", "nameLdapAttribute", "mailLdapAttribute"},
			input:    &models.CreateEditLdapConfig{},
		},
		{
			expected: []string{"status", "protocol", "scope", "displayName", "ldapHostname", "ldapPort", "bindUsername", "bindPassword", "rootDN", "userSearchFilter", "usernameLdapAttribute", "nameLdapAttribute", "mailLdapAttribute"},
			input: &models.CreateEditLdapConfig{
				ID:                    0,
				Provider:              "",
				DisplayName:           rand.String(51),
				Status:                0,
				Protocol:              0,
				LdapHostname:          rand.String(301),
				LdapPort:              "12345678910",
				BindUsername:          rand.String(101),
				BindPassword:          rand.String(101),
				RootDN:                rand.String(251),
				Scope:                 0,
				UserSearchFilter:      rand.String(501),
				UsernameLdapAttribute: rand.String(101),
				NameLdapAttribute:     rand.String(101),
				MailLdapAttribute:     rand.String(101),
			},
		},
		{
			expected: []string{"ldapPort"},
			input: &models.CreateEditLdapConfig{
				ID:                    0,
				Provider:              "",
				DisplayName:           "Test",
				Status:                enum.LdapConfigEnabled,
				Protocol:              enum.LDAP,
				LdapHostname:          "Hostname",
				LdapPort:              "Invalid",
				BindUsername:          "Bind Username",
				BindPassword:          "Bind Password",
				RootDN:                "Root DN",
				Scope:                 enum.ScopeBaseObject,
				UserSearchFilter:      "User Search Filter",
				UsernameLdapAttribute: "Username LDAP Attribute",
				NameLdapAttribute:     "Name LDAP Attribute",
				MailLdapAttribute:     "Mail LDAP Attribute",
			},
		},
	}

	for _, testCase := range testCases {
		action := &actions.CreateEditLdapConfig{
			Model: testCase.input,
		}
		result := action.Validate(context.Background(), nil)
		ExpectFailed(result, testCase.expected...)
	}
}

func TestCreateEditLdapConfig_Validate_ValidInput(t *testing.T) {
	RegisterT(t)

	input := &models.CreateEditLdapConfig{
		ID:                    0,
		Provider:              "",
		DisplayName:           "Test",
		Status:                enum.LdapConfigEnabled,
		Protocol:              enum.LDAP,
		LdapHostname:          "Hostname",
		LdapPort:              "1234",
		BindUsername:          "Bind Username",
		BindPassword:          "Bind Password",
		RootDN:                "Root DN",
		Scope:                 enum.ScopeBaseObject,
		UserSearchFilter:      "User Search Filter",
		UsernameLdapAttribute: "Username LDAP Attribute",
		NameLdapAttribute:     "Name LDAP Attribute",
		MailLdapAttribute:     "Mail LDAP Attribute",
	}

	action := &actions.CreateEditLdapConfig{Model: input}
	result := action.Validate(context.Background(), nil)
	ExpectSuccess(result)
}

func TestCreateEditLdapConfig_Initialize(t *testing.T) {
	RegisterT(t)

	action := &actions.CreateEditLdapConfig{}
	action.Initialize()
	Expect(action.Model.ID).Equals(0)
}

func TestCreateEditLdapConfig_IsAuthorized(t *testing.T) {
	RegisterT(t)

	action := &actions.CreateEditLdapConfig{}
	Expect(action.IsAuthorized(context.Background(), nil)).IsFalse()
	Expect(action.IsAuthorized(context.Background(), &models.User{})).IsFalse()
	Expect(action.IsAuthorized(context.Background(), &models.User{Role: enum.RoleAdministrator})).IsTrue()
}
