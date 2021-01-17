package query

import (
	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/dto"
)

type GetCustomLdapConfigByProvider struct {
	Provider string

	Result *models.LdapConfig
}

type ListCustomLdapConfig struct {
	Result []*models.LdapConfig
}

type GetLdapAuthorizationURL struct {
	Provider   string
	Redirect   string
	Identifier string

	Result string
}

type GetLdapProfile struct {
	Provider string
	Username string
	Password string

	Result *dto.LdapUserProfile
}

type GetLdapRawProfile struct {
	Provider string
	Code     string

	Result string
}

type ListActiveLdapProviders struct {
	Result []*dto.LdapProviderOption
}

type ListAllLdapProviders struct {
	Result []*dto.LdapProviderOption
}
