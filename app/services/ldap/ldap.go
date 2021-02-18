package ldap

import (
	"context"
	"crypto/tls"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap"

	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/log"
)

func init() {
	bus.Register(Service{})
}

type Service struct{}

func (s Service) Name() string {
	return "HTTP"
}

func (s Service) Category() string {
	return "Ldap"
}

func (s Service) Enabled() bool {
	return true
}

func (s Service) Init() {
	bus.AddHandler(getLdapProfile)
	bus.AddHandler(listActiveLdapProviders)
	bus.AddHandler(listAllLdapProviders)
	bus.AddHandler(testLdapServer)
}

func getProviderStatus(key string) int {
	if key == "" {
		return enum.LdapConfigDisabled
	}
	return enum.LdapConfigEnabled
}

/* testLdapServer test if LDAP server can be accessed by the read only user */

func testLdapServer(ctx context.Context, c *cmd.TestLdapServer) error {

	// Get LDAP provider configuration from database
	ldapConfig := &query.GetCustomLdapConfigByProvider{Provider: c.Provider}
	err := bus.Dispatch(ctx, ldapConfig)
	if err != nil {
		log.Errorf(ctx, " Could not get LDAP information for @{Provider}", dto.Props{"Provider": c.Provider})
		return err
	}

	// Get protocol from LDAP provider configuration
	protocol := "ldap://"
	if ldapConfig.Result.Protocol == enum.LDAPS {
		protocol = "ldaps://"
	}

	ldapURL := protocol + ldapConfig.Result.LdapHostname + ":" + ldapConfig.Result.LdapPort

	// Connect to LDAP
	// TODO : Handle timeout properly
	// Should be done via
	l, err := ldap.DialURL(ldapURL)
	l.SetTimeout(3 * time.Second)
	if err != nil {
		log.Errorf(ctx, "Could not dial LDAP url : @{LdapURL}", dto.Props{"LdapURL": ldapURL})
		return err
	}
	defer l.Close()

	// Reconnect with TLS if necessary
	if ldapConfig.Result.Protocol == enum.LDAPTLS {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Errorf(ctx, "Could not activate TLS for @{LdapURL}", dto.Props{"LdapURL": ldapURL})
			return err
		}
	}

	// Bind with read only user
	err = l.Bind(ldapConfig.Result.BindUsername, ldapConfig.Result.BindPassword)
	if err != nil {
		log.Errorf(ctx, "Could not bind with @{Username} for @{LdapURL}", dto.Props{"Username": ldapConfig.Result.BindUsername, "LdapURL": ldapURL})
		return err
	}

	return nil
}

/* getLdapProfile is the main method implementing LDAD authentication */

func getLdapProfile(ctx context.Context, q *query.GetLdapProfile) error {

	// Get LDAP provider configuration from database
	ldapConfig := &query.GetCustomLdapConfigByProvider{Provider: q.Provider}
	err := bus.Dispatch(ctx, ldapConfig)
	if err != nil {
		log.Errorf(ctx, " Could not get LDAP provider information for @{Provider}", dto.Props{"Provider": q.Provider})
		return err
	}

	// Get protocol from LDAP provider configuration
	protocol := "ldap://"
	if ldapConfig.Result.Protocol == enum.LDAPS {
		protocol = "ldaps://"
	}
	ldapURL := protocol + ldapConfig.Result.LdapHostname + ":" + ldapConfig.Result.LdapPort

	// Connect to LDAP
	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		log.Errorf(ctx, "Could not dial LDAP url : @{LdapURL}", dto.Props{"LdapURL": ldapURL})
		return errors.New("Could not connect to LDAP")
	}
	defer l.Close()

	// Reconnect with TLS
	if ldapConfig.Result.Protocol == enum.LDAPTLS {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			log.Errorf(ctx, "Could not activate TLS for @{LdapURL}", dto.Props{"LdapURL": ldapURL})
			return err
		}
	}

	// First Bind with read only user
	err = l.Bind(ldapConfig.Result.BindUsername, ldapConfig.Result.BindPassword)
	if err != nil {
		log.Errorf(ctx, "Could not bind with @{Username} for @{LdapURL}", dto.Props{"Username": ldapConfig.Result.BindUsername, "LdapURL": ldapURL})
		return err
	}

	// Search for given username
	var filter = "(&" + ldapConfig.Result.UserSearchFilter + "(" + ldapConfig.Result.UsernameLdapAttribute + "=" + q.Username + "))"
	searchRequest := ldap.NewSearchRequest(
		ldapConfig.Result.RootDN,
		(ldapConfig.Result.Scope - 1), ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		log.Errorf(ctx, "Could not search ldap with @{Filter}", dto.Props{"Filter": filter})
		return err
	}

	// Verify search results
	if len(sr.Entries) != 1 {
		log.Errorf(ctx, "@{Length} user found with @{Filter}", dto.Props{"Length": sr.Entries, "Filter": filter})
		return errors.New("User not found")
	}

	// Get DN of the user to be tested
	userDN := sr.Entries[0].DN

	// Bind as user to verify their password
	err = l.Bind(userDN, q.Password)
	if err != nil {
		log.Errorf(ctx, "Could not bind with @{User}", dto.Props{"User": userDN})
		return err
	}

	// Rebind with read only user
	err = l.Bind(ldapConfig.Result.BindUsername, ldapConfig.Result.BindPassword)
	if err != nil {
		log.Errorf(ctx, "Could not bind with @{Username} for @{LdapURL}", dto.Props{"Username": ldapConfig.Result.BindUsername, "LdapURL": ldapURL})
		return err
	}

	// Search for user id, name and email
	searchRequest2 := ldap.NewSearchRequest(
		ldapConfig.Result.RootDN,
		(ldapConfig.Result.Scope - 1), ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{ldapConfig.Result.MailLdapAttribute, ldapConfig.Result.NameLdapAttribute, ldapConfig.Result.UsernameLdapAttribute},
		nil,
	)

	sr2, err2 := l.Search(searchRequest2)
	if err2 != nil {
		log.Errorf(ctx, "Could not search ldap with @{Filter}", dto.Props{"Filter": filter})
		return err
	}

	// Verify search results
	if len(sr2.Entries) != 1 {
		log.Errorf(ctx, "@{Length} user found with @{Filter}", dto.Props{"Length": sr.Entries, "Filter": filter})
		return errors.New("User not found")
	}

	// Create user profile
	profile := &dto.LdapUserProfile{
		ID:    strings.TrimSpace(sr2.Entries[0].GetAttributeValue(ldapConfig.Result.UsernameLdapAttribute)),
		Name:  strings.TrimSpace(sr2.Entries[0].GetAttributeValue(ldapConfig.Result.NameLdapAttribute)),
		Email: strings.ToLower(sr2.Entries[0].GetAttributeValue(ldapConfig.Result.MailLdapAttribute)),
	}

	q.Result = profile

	return nil
}

/* listActiveLdapProviders returns a list of enabled LDAP providers */

func listActiveLdapProviders(ctx context.Context, q *query.ListActiveLdapProviders) error {
	allLdapProviders := &query.ListAllLdapProviders{}
	err := bus.Dispatch(ctx, allLdapProviders)
	if err != nil {
		return err
	}

	list := make([]*dto.LdapProviderOption, 0)
	for _, p := range allLdapProviders.Result {
		if p.IsEnabled {
			list = append(list, p)
		}
	}
	q.Result = list
	return nil
}

/* listAllLdapProviders returns a list of all LDAP providers */

func listAllLdapProviders(ctx context.Context, q *query.ListAllLdapProviders) error {
	ldapProviders := &query.ListCustomLdapConfig{}
	err := bus.Dispatch(ctx, ldapProviders)
	if err != nil {
		return errors.Wrap(err, "failed to get list of custom Ldap providers")
	}

	list := make([]*dto.LdapProviderOption, 0)

	for _, p := range ldapProviders.Result {
		list = append(list, &dto.LdapProviderOption{
			Provider:    p.Provider,
			DisplayName: p.DisplayName,
			IsEnabled:   p.Status == enum.LdapConfigEnabled,
		})
	}

	q.Result = list
	return nil
}

/* getConfig returns the properties of a given LDAP provider */

func getConfig(ctx context.Context, provider string) (*models.LdapConfig, error) {

	getCustomLdap := &query.GetCustomLdapConfigByProvider{Provider: provider}
	err := bus.Dispatch(ctx, getCustomLdap)
	if err != nil {
		return nil, err
	}

	return getCustomLdap.Result, nil
}
