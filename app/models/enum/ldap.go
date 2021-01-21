package enum

var (
	//LdapConfigDisabled is used to disable an LdapConfig for signin
	LdapConfigDisabled = 1
	//LdapConfigEnabled is used to enable an LdapConfig for public use
	LdapConfigEnabled = 2
	//ScopeBaseObject is used to define the LDAP search scope
	//In go-ldap the corresponding value is 0
	ScopeBaseObject = 1
	//ScopeSingleLevel is used to define the LDAP search scope
	//In go-ldap the corresponding value is 1
	ScopeSingleLevel = 2
	//ScopeWholeSubtree is used to define the LDAP search scope
	//In go-ldap the corresponding value is 2
	ScopeWholeSubtree = 3
	//LDAP protocol identifier
	LDAP = 1
	//LdapTLS protocol identifier
	LDAPTLS = 2
	//LDAPS protocole identifier
	LDAPS = 3
)
