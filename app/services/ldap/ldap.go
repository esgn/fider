package ldap

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"strings"

	ldap "github.com/go-ldap/ldap"

	//"strings"

	//"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/dto"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	//"github.com/getfider/fider/app/pkg/jsonq"
	//"github.com/getfider/fider/app/pkg/validate"
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
	//bus.AddHandler(parseLdapRawProfile)
	//bus.AddHandler(getOAuthAuthorizationURL)
	//bus.AddHandler(getOAuthProfile)
	//bus.AddHandler(getOAuthRawProfile)
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

func testLdapServer(ctx context.Context, c *cmd.TestLdapServer) error {

	ldapConfig := &query.GetCustomLdapConfigByProvider{Provider: c.Provider}
	err := bus.Dispatch(ctx, ldapConfig)
	if err != nil {

		return err
	}

	ldapURL := "ldap://" + ldapConfig.Result.LdapDomain + ":" + ldapConfig.Result.LdapPort

	// Connect to LDAP
	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		return err
	}
	defer l.Close()

	// Reconnect with TLS
	if ldapConfig.Result.Tls == enum.LdapConfigEnabled {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
	}

	// Bind with read only user
	err = l.Bind(ldapConfig.Result.BindUsername, ldapConfig.Result.BindPassword)
	if err != nil {
		return err
	}

	return nil
}

// getLdapProfile is the main method implementing LDAD authentication

func getLdapProfile(ctx context.Context, q *query.GetLdapProfile) error {

	// authentify user against ldap and get user profile

	ldapConfig := &query.GetCustomLdapConfigByProvider{Provider: q.Provider}
	err := bus.Dispatch(ctx, ldapConfig)
	if err != nil {

		return err
	}

	ldapURL := "ldap://" + ldapConfig.Result.LdapDomain + ":" + ldapConfig.Result.LdapPort

	// Connect to LDAP
	l, err := ldap.DialURL(ldapURL)
	if err != nil {
		return err
	}
	defer l.Close()

	// Reconnect with TLS
	if ldapConfig.Result.Tls == enum.LdapConfigEnabled {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return err
		}
	}

	// First Bind with read only user
	err = l.Bind(ldapConfig.Result.BindUsername, ldapConfig.Result.BindPassword)
	if err != nil {
		return err
	}

	// Search for given username
	var filter = "(&" + ldapConfig.Result.UserSearchFilter + "(" + ldapConfig.Result.UsernameLdapAttribute + "=" + q.Username + "))"
	searchRequest := ldap.NewSearchRequest(
		ldapConfig.Result.RootDN,
		ldapConfig.Result.Scope, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"dn"},
		nil,
	)

	sr, err := l.Search(searchRequest)
	if err != nil {
		return err
	}

	// Verify search results
	if len(sr.Entries) != 1 {
		fmt.Println("User does not exist or too many entries returned")
		fmt.Println(filter)
		fmt.Println(sr)
		return errors.New("User not found")
	}

	// Get dn of the user to be tested
	userDN := sr.Entries[0].DN

	// Bind as user to verify their password
	err = l.Bind(userDN, q.Password)
	if err != nil {
		fmt.Println("Cannot bind with client username and password")
		return err
	}

	// Rebind with read only user
	err = l.Bind(ldapConfig.Result.BindUsername, ldapConfig.Result.BindPassword)
	if err != nil {
		return err
	}

	searchRequest2 := ldap.NewSearchRequest(
		ldapConfig.Result.RootDN,
		ldapConfig.Result.Scope, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{ldapConfig.Result.MailLdapAttribute, ldapConfig.Result.NameLdapAttribute, ldapConfig.Result.UsernameLdapAttribute},
		nil,
	)

	sr2, err2 := l.Search(searchRequest2)
	if err2 != nil {
		return err
	}

	if len(sr2.Entries) != 1 {
		log.Fatal("Missing attributes")
		return errors.New("User not found")
	}

	profile := &dto.LdapUserProfile{
		ID:    strings.TrimSpace(sr2.Entries[0].GetAttributeValue(ldapConfig.Result.UsernameLdapAttribute)),
		Name:  strings.TrimSpace(sr2.Entries[0].GetAttributeValue(ldapConfig.Result.NameLdapAttribute)),
		Email: strings.ToLower(sr2.Entries[0].GetAttributeValue(ldapConfig.Result.MailLdapAttribute)),
	}

	q.Result = profile

	return nil
}

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

func listAllLdapProviders(ctx context.Context, q *query.ListAllLdapProviders) error {
	ldapProviders := &query.ListCustomLdapConfig{}
	err := bus.Dispatch(ctx, ldapProviders)
	if err != nil {
		return errors.Wrap(err, "failed to get list of custom Ldap providers")
	}

	list := make([]*dto.LdapProviderOption, 0)

	//ldapBaseURL := web.OAuthBaseURL(ctx)

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

func getConfig(ctx context.Context, provider string) (*models.LdapConfig, error) {

	getCustomLdap := &query.GetCustomLdapConfigByProvider{Provider: provider}
	err := bus.Dispatch(ctx, getCustomLdap)
	if err != nil {
		return nil, err
	}

	return getCustomLdap.Result, nil
}

/*func parseLdapRawProfile(ctx context.Context, c *cmd.ParseLdapRawProfile) error {
	config, err := getConfig(ctx, c.Provider)
	if err != nil {
		return err
	}

	query := jsonq.New(c.Body)
	profile := &dto.LdapUserProfile{
		ID:    strings.TrimSpace(query.String(config.JSONUserIDPath)),
		Name:  strings.TrimSpace(query.String(config.JSONUserNamePath)),
		Email: strings.ToLower(strings.TrimSpace(query.String(config.JSONUserEmailPath))),
	}

	if profile.ID == "" {
		return app.ErrUserIDRequired
	}

	if profile.Name == "" && profile.Email != "" {
		parts := strings.Split(profile.Email, "@")
		profile.Name = parts[0]
	}

	if profile.Name == "" {
		profile.Name = "Anonymous"
	}

	if len(validate.Email(profile.Email)) != 0 {
		profile.Email = ""
	}

	c.Result = profile
	return nil
}*/

/*func getOAuthAuthorizationURL(ctx context.Context, q *query.GetOAuthAuthorizationURL) error {
	config, err := getConfig(ctx, q.Provider)
	if err != nil {
		return err
	}

	oauthBaseURL := web.OAuthBaseURL(ctx)
	authURL, _ := url.Parse(config.AuthorizeURL)
	parameters := url.Values{}
	parameters.Add("client_id", config.ClientID)
	parameters.Add("scope", config.Scope)
	parameters.Add("redirect_uri", fmt.Sprintf("%s/oauth/%s/callback", oauthBaseURL, q.Provider))
	parameters.Add("response_type", "code")
	parameters.Add("state", q.Redirect+"|"+q.Identifier)
	authURL.RawQuery = parameters.Encode()
	q.Result = authURL.String()
	return nil
}

func getOAuthProfile(ctx context.Context, q *query.GetOAuthProfile) error {
	config, err := getConfig(ctx, q.Provider)
	if err != nil {
		return err
	}

	if config.Status == enum.OAuthConfigDisabled {
		return errors.New("Provider %s is disabled", q.Provider)
	}

	rawProfile := &query.GetOAuthRawProfile{Provider: q.Provider, Code: q.Code}
	err = bus.Dispatch(ctx, rawProfile)
	if err != nil {
		return err
	}

	parseRawProfile := &cmd.ParseOAuthRawProfile{Provider: q.Provider, Body: rawProfile.Result}
	err = bus.Dispatch(ctx, parseRawProfile)
	if err != nil {
		return err
	}

	q.Result = parseRawProfile.Result
	return nil
}

func getOAuthRawProfile(ctx context.Context, q *query.GetOAuthRawProfile) error {
	config, err := getConfig(ctx, q.Provider)
	if err != nil {
		return err
	}

	oauthBaseURL := web.OAuthBaseURL(ctx)
	exchange := (&oauth2.Config{
		ClientID:     config.ClientID,
		ClientSecret: config.ClientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:  config.AuthorizeURL,
			TokenURL: config.TokenURL,
		},
		RedirectURL: fmt.Sprintf("%s/oauth/%s/callback", oauthBaseURL, q.Provider),
	}).Exchange

	oauthToken, err := exchange(ctx, q.Code)
	if err != nil {
		return err
	}

	if config.ProfileURL == "" {
		parts := strings.Split(oauthToken.AccessToken, ".")
		if len(parts) != 3 {
			return errors.New("AccessToken is not JWT")
		}

		body, _ := jwt.DecodeSegment(parts[1])
		q.Result = string(body)
		return nil
	}

	req := &cmd.HTTPRequest{
		URL:    config.ProfileURL,
		Method: "GET",
		Headers: map[string]string{
			"Authorization": "Bearer " + oauthToken.AccessToken,
		},
	}

	if err := bus.Dispatch(ctx, req); err != nil {
		return err
	}

	if req.ResponseStatusCode != 200 {
		return errors.New("Failed to request profile. Status Code: %d. Body: %s", req.ResponseStatusCode, string(req.ResponseBody))
	}

	q.Result = string(req.ResponseBody)
	return nil
}
*/
