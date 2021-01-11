package dto

//LdapUserProfile represents an Ldap user profile
type LdapUserProfile struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

//LDapProviderOption represents an OAuth provider that can be used to authenticate
type LdapProviderOption struct {
	Provider              string       `json:"provider"`
	DisplayName           string       `json:"displayName"`
	Status                int          `json:"status"`
	LdapDomain            string       `json:"ldapDomain"`
	LdapPort              string	   `json:"ldapPort"`
	BindUsername          string	   `json:"bindUsername"`
	BindPassword          string	   `json:"bindPassword"`
	RootDN                string	   `json:"rootDN"`
	Scope                 string	   `json:"scope"`
	UserSearchFilter      string	   `json:"userSearchFilter"`
	UsernameLdapAttribute string	   `json:"usernameLdapAttribute"`
	IsEnabled             bool         `json:"isEnabled"`
}
