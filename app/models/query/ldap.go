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

type GetLdapProfile struct {
	Provider string
	Username string

	Result *dto.LdapUserProfile
}

type ListActiveLdapProviders struct {
	Result []*dto.LdapProviderOption
}

type ListAllLdapProviders struct {
	Result []*dto.LdapProviderOption
}
