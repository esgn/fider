package models

import (
	"encoding/json"
	"time"
)

// SystemSettings is the system-wide settings
type SystemSettings struct {
	Mode            string
	BuildTime       string
	Version         string
	Environment     string
	GoogleAnalytics string
	Compiler        string
	Domain          string
	HasLegal        bool
}

// Notification is the system generated notification entity
type Notification struct {
	ID        int       `json:"id" db:"id"`
	Title     string    `json:"title" db:"title"`
	Link      string    `json:"link" db:"link"`
	Read      bool      `json:"read" db:"read"`
	CreatedAt time.Time `json:"createdAt" db:"created_at"`
}

// CreateEditOAuthConfig is used to create/edit an OAuth Configuration
type CreateEditOAuthConfig struct {
	ID                int
	Logo              *ImageUpload `json:"logo"`
	Provider          string       `json:"provider"`
	Status            int          `json:"status"`
	DisplayName       string       `json:"displayName"`
	ClientID          string       `json:"clientID"`
	ClientSecret      string       `json:"clientSecret"`
	AuthorizeURL      string       `json:"authorizeURL" format:"lower"`
	TokenURL          string       `json:"tokenURL" format:"lower"`
	Scope             string       `json:"scope"`
	ProfileURL        string       `json:"profileURL" format:"lower"`
	JSONUserIDPath    string       `json:"jsonUserIDPath"`
	JSONUserNamePath  string       `json:"jsonUserNamePath"`
	JSONUserEmailPath string       `json:"jsonUserEmailPath"`
}

// OAuthConfig is the configuration of a custom OAuth provider
type OAuthConfig struct {
	ID                int
	Provider          string
	DisplayName       string
	LogoBlobKey       string
	Status            int
	ClientID          string
	ClientSecret      string
	AuthorizeURL      string
	TokenURL          string
	ProfileURL        string
	Scope             string
	JSONUserIDPath    string
	JSONUserNamePath  string
	JSONUserEmailPath string
}

// MarshalJSON returns the JSON encoding of OAuthConfig
func (o OAuthConfig) MarshalJSON() ([]byte, error) {
	secret := "..."
	if len(o.ClientSecret) >= 10 {
		secret = o.ClientSecret[0:3] + "..." + o.ClientSecret[len(o.ClientSecret)-3:]
	}
	return json.Marshal(map[string]interface{}{
		"id":                o.ID,
		"provider":          o.Provider,
		"displayName":       o.DisplayName,
		"logoBlobKey":       o.LogoBlobKey,
		"status":            o.Status,
		"clientID":          o.ClientID,
		"clientSecret":      secret,
		"authorizeURL":      o.AuthorizeURL,
		"tokenURL":          o.TokenURL,
		"profileURL":        o.ProfileURL,
		"scope":             o.Scope,
		"jsonUserIDPath":    o.JSONUserIDPath,
		"jsonUserNamePath":  o.JSONUserNamePath,
		"jsonUserEmailPath": o.JSONUserEmailPath,
	})
}

// CreateEditLdapConfig is used to create/edit an LDAP Configuration
type CreateEditLdapConfig struct {
	ID                    int
	Provider              string `json:"provider"`
	DisplayName           string `json:"displayName"`
	Status                int    `json:"status"`
	Protocol              int    `json:"protocol"`
	LdapDomain            string `json:"ldapDomain"`
	LdapPort              string `json:"ldapPort"`
	BindUsername          string `json:"bindUsername"`
	BindPassword          string `json:"bindPassword"`
	RootDN                string `json:"rootDN"`
	Scope                 int    `json:"scope"`
	UserSearchFilter      string `json:"userSearchFilter"`
	UsernameLdapAttribute string `json:"usernameLdapAttribute"`
	NameLdapAttribute     string `json:"nameLdapAttribute"`
	MailLdapAttribute     string `json:"mailLdapAttribute"`
}

// LdapConfig is the configuration of a custom LDAP provider
type LdapConfig struct {
	ID                    int
	Provider              string
	DisplayName           string
	Status                int
	Protocol              int
	LdapDomain            string
	LdapPort              string
	BindUsername          string
	BindPassword          string
	RootDN                string
	Scope                 int
	UserSearchFilter      string
	UsernameLdapAttribute string
	NameLdapAttribute     string
	MailLdapAttribute     string
}

// MarshalJSON returns the JSON encoding of LdapConfig
func (o LdapConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(map[string]interface{}{
		"id":                    o.ID,
		"provider":              o.Provider,
		"displayName":           o.DisplayName,
		"status":                o.Status,
		"protocol":              o.Protocol,
		"ldapDomain":            o.LdapDomain,
		"ldapPort":              o.LdapPort,
		"bindUsername":          o.BindUsername,
		"bindPassword":          "password will remain secret",
		"rootDN":                o.RootDN,
		"scope":                 o.Scope,
		"userSearchFilter":      o.UserSearchFilter,
		"usernameLdapAttribute": o.UsernameLdapAttribute,
		"nameLdapAttribute":     o.NameLdapAttribute,
		"mailLdapAttribute":     o.MailLdapAttribute,
	})
}

// APIAuthorize is used during API Authorize process
type APIAuthorize struct {
	APIKey string `json:"apiKey"`
}

// Event is used for tracking client audit events and actions
type Event struct {
	ID        int       `json:"id"`
	ClientIP  string    `json:"clientIP"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"createdAt"`
}
