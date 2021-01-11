package postgres

import (
	"context"
	"strconv"
	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/models/cmd"

	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/dbx"
	"github.com/getfider/fider/app/pkg/errors"
)

type dbLdapConfig struct {
	ID                     int    `db:"id"`
	Provider               string `db:"provider"`
	DisplayName            string `db:"display_name"`
	Status                 int    `db:"status"`
	LdapDomain             string `db:"ldap_domain"`
	Port                   int    `db:"ldap_port"`
	BindUsername           string `db:"bind_username"`
	BindPassword           string `db:"bind_password"`
	RootDN                 string `db:"root_dn"`
	Scope                  string `db:"scope"`
	UserSearchFilter       string `db:"user_search_filter"`
	UsernameLdapAttribute  string `db:"username_ldap_attribute"`
}

func (m *dbLdapConfig) toModel() *models.LdapConfig {
	return &models.LdapConfig {
		ID:                    m.ID,
		Provider:              m.Provider,
		DisplayName:           m.DisplayName,
		Status:                m.Status,
		LdapDomain:            m.LdapDomain,
		LdapPort:              strconv.Itoa(m.Port),
		BindUsername:          m.BindUsername,
		BindPassword:          m.BindPassword,
		RootDN:                m.RootDN,
		Scope:                 m.Scope,
		UserSearchFilter:      m.UserSearchFilter,
		UsernameLdapAttribute: m.UsernameLdapAttribute,
	}
}

func getCustomLdapConfigByProvider(ctx context.Context, q *query.GetCustomLdapConfigByProvider) error {
	return using(ctx, func(trx *dbx.Trx, tenant *models.Tenant, user *models.User) error {
		if tenant == nil {
			return app.ErrNotFound
		}

		config := &dbLdapConfig{}
		err := trx.Get(config, `
		SELECT id, provider, display_name, status,
					ldap_domain, ldap_port, 
					bind_username, bind_password, root_dn,
					scope, user_search_filter, username_ldap_attribute
		FROM ldap_providers
		WHERE tenant_id = $1 AND provider = $2
		`, tenant.ID, q.Provider)
		if err != nil {
			return err
		}

		q.Result = config.toModel()
		return nil
	})
}

func listCustomLdapConfig(ctx context.Context, q *query.ListCustomLdapConfig) error {
	return using(ctx, func(trx *dbx.Trx, tenant *models.Tenant, user *models.User) error {
		configs := []*dbLdapConfig{}

		if tenant != nil {
			err := trx.Select(&configs, `
			SELECT id, provider, display_name, status,
						ldap_domain, ldap_port, 
						 bind_username, bind_password, root_dn,
						 scope, user_search_filter, username_ldap_attribute
			FROM ldap_providers
			WHERE tenant_id = $1
			ORDER BY id`, tenant.ID)
			if err != nil {
				return err
			}
		}

		q.Result = make([]*models.LdapConfig, len(configs))
		for i, config := range configs {
			q.Result[i] = config.toModel()
		}
		return nil
	})
}

func saveCustomLdapConfig(ctx context.Context, c *cmd.SaveCustomLdapConfig) error {
	return using(ctx, func(trx *dbx.Trx, tenant *models.Tenant, user *models.User) error {
		var err error

		if c.Config.ID == 0 {
			query := `INSERT INTO ldap_providers (
				tenant_id, provider, display_name, status,
				ldap_domain, ldap_port, bind_username,
				bind_password, root_dn, scope, user_search_filter,
				username_ldap_attribute
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			RETURNING id`

			err = trx.Get(&c.Config.ID, query, tenant.ID, c.Config.Provider,
				c.Config.DisplayName, c.Config.Status, c.Config.LdapDomain, c.Config.LdapPort,
				c.Config.BindUsername, c.Config.BindPassword, c.Config.RootDN,
				c.Config.Scope, c.Config.UserSearchFilter, c.Config.UsernameLdapAttribute)

		} else {
			query := `
				UPDATE ldap_providers 
				SET display_name = $3, status = $4, ldap_domain = $5, ldap_port = $6, 
				bind_username = $7, bind_password = $8, root_dn = $9, scope = $10, 
				user_search_filter = $11, username_ldap_attribute = $12
			WHERE tenant_id = $1 AND id = $2`

			_, err = trx.Execute(query, tenant.ID, c.Config.ID,
				c.Config.DisplayName, c.Config.Status, c.Config.LdapDomain, c.Config.LdapPort,
				c.Config.BindUsername, c.Config.BindPassword, c.Config.RootDN,
				c.Config.Scope, c.Config.UserSearchFilter, c.Config.UsernameLdapAttribute)
		}

		if err != nil {
			return errors.Wrap(err, "failed to save Ldap Provider")
		}

		return nil
	})
}