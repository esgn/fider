export interface OAuthProviderOption {
  provider: string;
  displayName: string;
  clientID: string;
  url: string;
  callbackURL: string;
  logoBlobKey: string;
  isCustomProvider: boolean;
  isEnabled: boolean;
}

export interface LdapProviderOption {
  provider: string;
  displayName: string;
  isEnabled: boolean;
}

export interface SystemSettings {
  mode: string;
  buildTime: string;
  version: string;
  environment: string;
  compiler: string;
  domain: string;
  hasLegal: boolean;
  baseURL: string;
  stripePublicKey?: string;
  tenantAssetsURL: string;
  globalAssetsURL: string;
  oauth: OAuthProviderOption[];
  ldap: LdapProviderOption[];
}

export interface UserSettings {
  [key: string]: string;
}

export const OAuthConfigStatus = {
  Disabled: 1,
  Enabled: 2
}

export interface OAuthConfig {
  provider: string;
  displayName: string;
  status: number;
  clientID: string;
  clientSecret: string;
  authorizeURL: string;
  tokenURL: string;
  profileURL: string;
  logoBlobKey: string;
  scope: string;
  jsonUserIDPath: string;
  jsonUserNamePath: string;
  jsonUserEmailPath: string;
}

export const LdapConfigStatus = {
  Disabled: 1,
  Enabled: 2
}

// These values derived from go-ldap v3
export const LdapScopeStatus = {
  ScopeBaseObject : 1,
  ScopeSingleLevel: 2,
  ScopeWholeSubtree: 3
}

export interface LdapConfig {
  provider: string;
  displayName: string;
  status: number;
  tls: number;
  ldapDomain: string;
  ldapPort: string;
  bindUsername: string;
  bindPassword: string;
  rootDN: string;
  scope: number;
  userSearchFilter: string;
  usernameLdapAttribute: string;
  nameLdapAttribute: string;
  mailLdapAttribute: string;
}

export interface ImageUpload {
  bkey?: string;
  upload?: {
    fileName?: string;
    content?: string;
    contentType?: string;
  };
  remove: boolean;
}
