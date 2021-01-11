package handlers

import (
	"github.com/getfider/fider/app/pkg/web"
)

// LdapEcho exchanges Ldap Code for a user profile and return directly to the UI, without storing it
func LdapEcho() web.HandlerFunc {
	return nil
}

// LdapToken exchanges Ldap Code for a user profile
// The user profile is then used to either get an existing user on Fider or creating a new one
// Once Fider user is retrieved/created, an authentication cookie is store in user's browser
func LdapToken() web.HandlerFunc {
	return nil
}

// LdapCallback handles the redirect back from the Ldap provider
// This callback can run on either Tenant or Login address
// If the request is for a sign in, we redirect the user to the tenant address
// If the request is for a sign up, we exchange the Ldap code and get the user profile
func LdapCallback() web.HandlerFunc {
	return nil
}

// SignInByLdap is responsible for redirecting the user to the Ldap authorization URL for given provider
// A cookie is stored in user's browser with a random identifier that is later used to verify the authenticity of the request
func SignInByLdap() web.HandlerFunc {
	return nil
}
