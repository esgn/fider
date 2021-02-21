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
	"github.com/getfider/fider/app/pkg/validate"
	"github.com/getfider/fider/app/pkg/web"
	webutil "github.com/getfider/fider/app/pkg/web/util"
)

/* SignInByLdap allows user to sign in using a LDAP provider */

func SignInByLdap() web.HandlerFunc {
	return func(c *web.Context) error {

		provider := c.Param("provider")

		// Input validation : Are username and password present in the query ?
		input := new(actions.SignInWithLdap)
		if result := c.BindTo(input); !result.Ok {
			return c.HandleValidation(result)
		}

		// Get user profile from LDAP server
		// TODO : This should be an action if we stick to fider logic
		// The actions should validate that the user exists in LDAP
		// Then a second query should be emitted to get the LDAP profile
		// It two queries instead of one though
		ldapUser := &query.GetLdapProfile{Provider: provider, Username: input.Model.Username, Password: input.Model.Password}
		if err := bus.Dispatch(c, ldapUser); err != nil {
			// Final user password must no appear anywhere in the logs
			c.Request.Body = "{\"username\":" + "\"" + input.Model.Username + "\"}"
			// TODO : Do something cleaner here
			e := validate.Error(err)
			e.AddFieldFailure("ldapPassword", "USER UNKNOWN")
			return c.BadRequest(web.Map{
				"errors": e.Errors,
			})
		}

		// Is the user already registered with the current LDAP provider ?
		var user *models.User
		userByProvider := &query.GetUserByProvider{Provider: provider, UID: ldapUser.Result.ID}
		err := bus.Dispatch(c, userByProvider)
		user = userByProvider.Result

		// If the user is not already registered
		// we look for an existing user with the email adress obtained from LDAP
		if errors.Cause(err) == app.ErrNotFound && ldapUser.Result.Email != "" {
			userByEmail := &query.GetUserByEmail{Email: ldapUser.Result.Email}
			err = bus.Dispatch(c, userByEmail)
			user = userByEmail.Result
		}

		// If the GetUserByEmail search has failed
		if err != nil {

			// And than no user was found
			if errors.Cause(err) == app.ErrNotFound {

				// Yet in case the fider instance is private we exit the process
				if c.Tenant().IsPrivate {
					return c.Redirect("/not-invited")
				}

				// Then we create a new user with the provided provider
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
					// Password must no appear anywhere in the logs
					c.Request.Body = "{\"username\":" + "\"" + input.Model.Username + "\"}"
					return c.Failure(err)
				}

			}
			// If no error was returned but the user is still missing a provider
		} else if !user.HasProvider(provider) {

			if err = bus.Dispatch(c, &cmd.RegisterUserProvider{
				UserID:       user.ID,
				ProviderName: provider,
				ProviderUID:  ldapUser.Result.ID,
			}); err != nil {
				// Password must no appear anywhere in the logs
				c.Request.Body = "{\"username\":" + "\"" + input.Model.Username + "\"}"
				return c.Failure(err)
			}

		}

		// Add auth cookie
		webutil.AddAuthUserCookie(c, user)

		return c.Ok(web.Map{})
	}
}
