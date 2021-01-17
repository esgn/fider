package handlers

import (
	"github.com/getfider/fider/app"
	"github.com/getfider/fider/app/actions"
	"github.com/getfider/fider/app/models"
	"github.com/getfider/fider/app/models/cmd"
	"github.com/getfider/fider/app/models/enum"
	"github.com/getfider/fider/app/models/query"
	"github.com/getfider/fider/app/pkg/bus"
	"github.com/getfider/fider/app/pkg/errors"
	"github.com/getfider/fider/app/pkg/web"
	webutil "github.com/getfider/fider/app/pkg/web/util"
)

// SignInByLdap comment
func SignInByLdap() web.HandlerFunc {
	return func(c *web.Context) error {

		provider := c.Param("provider")

		// Input validation : Username and password present ?
		input := new(actions.SignInWithLdap)
		if result := c.BindTo(input); !result.Ok {
			return c.HandleValidation(result)
		}

		// Get user profile from Ldap
		ldapUser := &query.GetLdapProfile{Provider: provider, Username: input.Model.Username, Password: input.Model.Password}
		if err := bus.Dispatch(c, ldapUser); err != nil {
			return c.Failure(err)
		}

		// Is the already registered with the current provider ?
		var user *models.User
		userByProvider := &query.GetUserByProvider{Provider: provider, UID: ldapUser.Result.ID}
		err := bus.Dispatch(c, userByProvider)
		user = userByProvider.Result

		// If it doesn't we look for an existing user with the email adress obtained from LDAP
		if errors.Cause(err) == app.ErrNotFound && ldapUser.Result.Email != "" {
			userByEmail := &query.GetUserByEmail{Email: ldapUser.Result.Email}
			err = bus.Dispatch(c, userByEmail)
			user = userByEmail.Result
		}

		// If the userbyProvider search has failed
		if err != nil {

			// And than no user was found
			if errors.Cause(err) == app.ErrNotFound {

				// In case the fider instance is private we skip the process
				if c.Tenant().IsPrivate {
					return c.Redirect("/not-invited")
				}

				// We create a new user with the provided provider
				user = &models.User{
					Name:   ldapUser.Result.Name,
					Tenant: c.Tenant(),
					Email:  ldapUser.Result.Email,
					Role:   enum.RoleVisitor,
					Providers: []*models.UserProvider{
						&models.UserProvider{
							UID:  ldapUser.Result.ID,
							Name: provider,
						},
					},
				}

				// And insert it into the database
				if err = bus.Dispatch(c, &cmd.RegisterUser{User: user}); err != nil {
					return c.Failure(err)
				}

			}
			// If no error was returned but the user is missing a provider
		} else if !user.HasProvider(provider) {

			if err = bus.Dispatch(c, &cmd.RegisterUserProvider{
				UserID:       user.ID,
				ProviderName: provider,
				ProviderUID:  ldapUser.Result.ID,
			}); err != nil {
				return c.Failure(err)
			}

		}

		webutil.AddAuthUserCookie(c, user)

		return c.Ok(web.Map{})
	}
}
