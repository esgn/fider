package ldap_test

import (
	"context"
	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/services/ldap"
	"testing"

	"github.com/getfider/fider/app/models/query"

	. "github.com/getfider/fider/app/pkg/assert"
	"github.com/getfider/fider/app/pkg/bus"
)

func TestGetLdapProfile_Correct(t *testing.T) {
	setupBus(t)
	bus.Init(&ldap.Service{})

	getProfile := &query.GetLdapProfile{
		Provider: "ldap_test",
		Username: "developer",
	}

	err := bus.Dispatch(context.Background(), getProfile)
	Expect(err).IsNil()
	Expect(getProfile.Result.Email).Equals("developer@example.org")
}

func TestGetLdapProfile_IncorrectProvider(t *testing.T) {
	setupBus(t)
	bus.Init(&ldap.Service{})

	getProfile := &query.GetLdapProfile{
		Provider: "incorrect",
		Username: "developer",
	}

	err := bus.Dispatch(context.Background(), getProfile)
	Expect(err).IsNotNil()
	Expect(getProfile.Result).IsNil()
}

func TestGetLdapProfile_IncorrectUser(t *testing.T) {
	setupBus(t)
	bus.Init(&ldap.Service{})

	getProfile := &query.GetLdapProfile{
		Provider: "ldap_test",
		Username: "incorrect",
	}

	err := bus.Dispatch(context.Background(), getProfile)
	Expect(err).IsNotNil()
	Expect(getProfile.Result).IsNil()
}

func TestListActiveLdapProviders(t *testing.T) {
	setupBus(t)
	bus.Init(&ldap.Service{})

	listActiveProviders := &query.ListActiveLdapProviders{}

	err := bus.Dispatch(context.Background(), listActiveProviders)
	Expect(err).IsNil()
	Expect(listActiveProviders.Result).HasLen(1)

	Expect(listActiveProviders.Result[0].IsEnabled).IsTrue()
	Expect(listActiveProviders.Result[0].Provider).Equals("ldap_test")
}

func TestListAllLdapProviders(t *testing.T) {
	setupBus(t)
	bus.Init(&ldap.Service{})

	listAllProviders := &query.ListAllLdapProviders{}

	err := bus.Dispatch(context.Background(), listAllProviders)
	Expect(err).IsNil()
	Expect(listAllProviders.Result).HasLen(2)

	Expect(listAllProviders.Result[0].IsEnabled).IsTrue()
	Expect(listAllProviders.Result[0].Provider).Equals("ldap_test")
	Expect(listAllProviders.Result[0].DisplayName).Equals("Testing Ldap Server")

	Expect(listAllProviders.Result[1].IsEnabled).IsFalse()
	Expect(listAllProviders.Result[1].Provider).Equals("other_ldap")
	Expect(listAllProviders.Result[1].DisplayName).Equals("Second Ldap Server")
}

func setupBus(t *testing.T) {
	RegisterT(t)
	bus.Init(&ldap.Service{})

	ldapProvider1 := &models.LdapConfig{
		ID:                    1,
		Provider:              "ldap_test",
		DisplayName:           "Testing Ldap Server",
		Status:                2,
		Protocol:              1,
		CertCheck:             false,
		LdapHostname:          "localhost",
		LdapPort:              "389",
		BindUsername:          "cn=readonly,dc=example,dc=org",
		BindPassword:          "readonly",
		RootDN:                "dc=example,dc=org",
		Scope:                 3,
		UserSearchFilter:      "(objectClass=inetOrgPerson)",
		UsernameLdapAttribute: "uid",
		NameLdapAttribute:     "displayName",
		MailLdapAttribute:     "mail",
	}

	ldapProvider2 := &models.LdapConfig{
		ID:                    2,
		Provider:              "other_ldap",
		DisplayName:           "Second Ldap Server",
		Status:                1,
		Protocol:              3,
		CertCheck:             true,
		LdapHostname:          "",
		LdapPort:              "636",
		BindUsername:          "",
		BindPassword:          "",
		RootDN:                "",
		Scope:                 1,
		UserSearchFilter:      "",
		UsernameLdapAttribute: "",
		NameLdapAttribute:     "",
		MailLdapAttribute:     "",
	}

	bus.AddHandler(func(ctx context.Context, q *query.GetCustomLdapConfigByProvider) error {
		switch q.Provider {
		case "ldap_test":
			q.Result = ldapProvider1
		case "other_ldap":
			q.Result = ldapProvider2
		default:
			return app.ErrNotFound
		}
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.ListCustomLdapConfig) error {
		q.Result = make([]*models.LdapConfig, 2)
		q.Result[0] = ldapProvider1
		q.Result[1] = ldapProvider2
		return nil
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByProvider) error {
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *query.GetUserByEmail) error {
		return app.ErrNotFound
	})

	bus.AddHandler(func(ctx context.Context, q *cmd.RegisterUser) error {
		return nil
	})
}
