package dto

//LdapUserProfile represents an Ldap user profile
type LdapUserProfile struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

//LdapProviderOption represents an Ldap provider that can be used to authenticate
type LdapProviderOption struct {
	Provider    string `json:"provider"`
	DisplayName string `json:"displayName"`
	IsEnabled   bool   `json:"isEnabled"`
}
