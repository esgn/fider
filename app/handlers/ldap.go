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

//SignInByLdap allows user to sign in using a LDAP provider
func SignInByLdap() web.HandlerFunc {
	return func(c *web.Context) error {

		// Input validation
		// * Checks that username and password are provided
		// * Checks that user exists in LDAP and its username/password are valid
		input := new(actions.SignInWithLdap)
		if result := c.BindTo(input); !result.Ok {
			return c.HandleValidation(result)
		}

		// Get user information from LDAP server
		ldapUser := &query.GetLdapProfile{Provider: input.Model.Provider, Username: input.Model.Username}
		if err := bus.Dispatch(c, ldapUser); err != nil {
			return c.Failure(err)
		}

		// Is the user already registered with the current LDAP provider ?
		var user *models.User
		userByProvider := &query.GetUserByProvider{Provider: input.Model.Provider, UID: ldapUser.Result.ID}
		err := bus.Dispatch(c, userByProvider)
		user = userByProvider.Result

		// If the user is not already registered
		// we look for an existing user with the email adress obtained from LDAP
		if errors.Cause(err) == app.ErrNotFound && ldapUser.Result.Email != "" {
			userByEmail := &query.GetUserByEmail{Email: ldapUser.Result.Email}
			err = bus.Dispatch(c, userByEmail)
			user = userByEmail.Result
		}

		// If the GetUserByEmail() search has failed
		if err != nil {

			// Because no user was found
			if errors.Cause(err) == app.ErrNotFound {

				// By the way if the fider instance is private we exit the process
				if c.Tenant().IsPrivate {
					return c.Redirect("/not-invited")
				}

				// Then we create a new user with the provider reference sent by the login form
				user = &models.User{
					Name:   ldapUser.Result.Name,
					Tenant: c.Tenant(),
					Email:  ldapUser.Result.Email,
					Role:   enum.RoleVisitor,
					Providers: []*models.UserProvider{
						{
							UID:  ldapUser.Result.ID,
							Name: input.Model.Provider,
						},
					},
				}

				// And insert it into the database
				if err = bus.Dispatch(c, &cmd.RegisterUser{User: user}); err != nil {
					// Password must no appear anywhere in the logs
					// c.Request.Body = "{\"username\":" + "\"" + input.Model.Username + "\"}"
					return c.Failure(err)
				}

			}
			// If no error was returned but the user is still missing a provider
		} else if !user.HasProvider(input.Model.Provider) {

			// We add the new user to the current provider
			if err = bus.Dispatch(c, &cmd.RegisterUserProvider{
				UserID:       user.ID,
				ProviderName: input.Model.Provider,
				ProviderUID:  ldapUser.Result.ID,
			}); err != nil {
				// Password must no appear anywhere in the logs
				//c.Request.Body = "{\"username\":" + "\"" + input.Model.Username + "\"}"
				return c.Failure(err)
			}
		}

		// Add auth cookie if everything went fine
		webutil.AddAuthUserCookie(c, user)

		// Redirect POST request to GET home page using HTTP 303
		return c.Ok(web.Map{})
	}
}
