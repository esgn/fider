package postgres_test

import (
	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/query"
	"testing"

	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
)

func TestGetCustomLdapConfigByProvider(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	ldapConfig := &query.GetCustomLdapConfigByProvider{Provider: "ldap_test"}
	err := bus.Dispatch(avengersTenantCtx, ldapConfig)
	Expect(err).IsNil()
	Expect(ldapConfig.Result).IsNotNil()

	Expect(ldapConfig.Result.ID).Equals(1)
	Expect(ldapConfig.Result.Provider).Equals("ldap_test")
	Expect(ldapConfig.Result.DisplayName).Equals("Testing Ldap Server")
	Expect(ldapConfig.Result.Status).Equals(2)
	Expect(ldapConfig.Result.LdapHostname).Equals("localhost")
	Expect(ldapConfig.Result.LdapPort).Equals("389")
	Expect(ldapConfig.Result.BindUsername).Equals("cn=readonly,dc=example,dc=org")
	Expect(ldapConfig.Result.BindPassword).Equals("readonly")
	Expect(ldapConfig.Result.RootDN).Equals("dc=example,dc=org")
	Expect(ldapConfig.Result.Scope).Equals(3)
	Expect(ldapConfig.Result.UserSearchFilter).Equals("(objectClass=inetOrgPerson)")
	Expect(ldapConfig.Result.UsernameLdapAttribute).Equals("uid")
	Expect(ldapConfig.Result.NameLdapAttribute).Equals("displayName")
	Expect(ldapConfig.Result.MailLdapAttribute).Equals("mail")
	Expect(ldapConfig.Result.Protocol).Equals(1)
	Expect(ldapConfig.Result.CertCheck).Equals(false)
}

func TestListCustomLdapConfig(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	ldapConfigs := &query.ListCustomLdapConfig{}
	err := bus.Dispatch(avengersTenantCtx, ldapConfigs)
	Expect(err).IsNil()
	Expect(ldapConfigs.Result).HasLen(2)

	Expect(ldapConfigs.Result[0].ID).Equals(1)
	Expect(ldapConfigs.Result[0].Provider).Equals("ldap_test")

	Expect(ldapConfigs.Result[1].ID).Equals(2)
	Expect(ldapConfigs.Result[1].Provider).Equals("other_ldap")
}

func TestSaveCustomLdapConfig_EditExisting(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	newLdapConfig := &cmd.SaveCustomLdapConfig{
		Config: &models.CreateEditLdapConfig{
			ID:                    2,
			DisplayName:           "Edited Ldap Server",
			Status:                0,
			Protocol:              0,
			CertCheck:             false,
			LdapHostname:          "",
			LdapPort:              "0",
			BindUsername:          "",
			BindPassword:          "",
			RootDN:                "",
			Scope:                 0,
			UserSearchFilter:      "",
			UsernameLdapAttribute: "",
			NameLdapAttribute:     "",
			MailLdapAttribute:     "",
		},
	}
	err := bus.Dispatch(avengersTenantCtx, newLdapConfig)
	Expect(err).IsNil()

	editedLdapConfig := &query.GetCustomLdapConfigByProvider{Provider: "other_ldap"}
	err = bus.Dispatch(avengersTenantCtx, editedLdapConfig)
	Expect(err).IsNil()
	Expect(editedLdapConfig.Result).IsNotNil()

	Expect(editedLdapConfig.Result.ID).Equals(2)
	Expect(editedLdapConfig.Result.DisplayName).Equals("Edited Ldap Server")
}

func TestSaveCustomLdapConfig_CreateNew(t *testing.T) {
	SetupDatabaseTest(t)
	defer TeardownDatabaseTest()

	newLdapConfig := &cmd.SaveCustomLdapConfig{
		Config: &models.CreateEditLdapConfig{
			Provider:              "new_ldap",
			DisplayName:           "New Ldap Server",
			Status:                0,
			Protocol:              0,
			CertCheck:             false,
			LdapHostname:          "",
			LdapPort:              "0",
			BindUsername:          "",
			BindPassword:          "",
			RootDN:                "",
			Scope:                 0,
			UserSearchFilter:      "",
			UsernameLdapAttribute: "",
			NameLdapAttribute:     "",
			MailLdapAttribute:     "",
		},
	}
	err := bus.Dispatch(avengersTenantCtx, newLdapConfig)
	Expect(err).IsNil()

	editedLdapConfig := &query.GetCustomLdapConfigByProvider{Provider: "new_ldap"}
	err = bus.Dispatch(avengersTenantCtx, editedLdapConfig)
	Expect(err).IsNil()
	Expect(editedLdapConfig.Result).IsNotNil()

	Expect(editedLdapConfig.Result.ID).Equals(newLdapConfig.Config.ID)
	Expect(editedLdapConfig.Result.DisplayName).Equals("New Ldap Server")
}
