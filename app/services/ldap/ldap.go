package ldap

import (
	"context"
	//"strings"

	//"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models"
	//"github.com/getfider/fider/app/models/cmd"
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
	//bus.AddHandler(listActiveOAuthProviders)
	bus.AddHandler(listAllLdapProviders)
}

func getProviderStatus(key string) int {
	if key == "" {
		return enum.LdapConfigDisabled
	}
	return enum.LdapConfigEnabled
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

func listActiveOAuthProviders(ctx context.Context, q *query.ListActiveOAuthProviders) error {
	allOAuthProviders := &query.ListAllOAuthProviders{}
	err := bus.Dispatch(ctx, allOAuthProviders)
	if err != nil {
		return err
	}

	list := make([]*dto.OAuthProviderOption, 0)
	for _, p := range allOAuthProviders.Result {
		if p.IsEnabled {
			list = append(list, p)
		}
	}
	q.Result = list
	return nil
}
*/

func listAllLdapProviders(ctx context.Context, q *query.ListAllLdapProviders) error {
	ldapProviders := &query.ListCustomLdapConfig{}
	err := bus.Dispatch(ctx, ldapProviders)
	if err != nil {
		return errors.Wrap(err, "failed to get list of custom Ldap providers")
	}

	list := make([]*dto.LdapProviderOption, 0)

	//ldapBaseURL := web.OAuthBaseURL(ctx)

	for _, p := range ldapProviders.Result {
		list = append(list, &dto.LdapProviderOption {
			Provider:                   p.Provider,
			DisplayName:                p.DisplayName,
			LdapDomain:		            p.LdapDomain,
			LdapPort:                   p.LdapPort,
			BindUsername:               p.BindUsername,
			BindPassword:               p.BindPassword,
			RootDN:                     p.RootDN,
			Scope:                      p.Scope,
			UserSearchFilter:           p.UserSearchFilter,
			UsernameLdapAttribute:      p.UsernameLdapAttribute,
			IsEnabled:                  p.Status == enum.LdapConfigEnabled,
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
