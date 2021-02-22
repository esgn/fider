package cmd

import (
	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/dto"
)

type TestLdapServer struct {
	Provider string
}

type VerifyLdapUser struct {
	Provider string
	Username string
	Password string
}

type SaveCustomLdapConfig struct {
	Config *models.CreateEditLdapConfig
}

type ParseLdapRawProfile struct {
	Provider string
	Body     string

	Result *dto.LdapUserProfile
}
