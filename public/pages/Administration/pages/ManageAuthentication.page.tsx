import React from "react";

import { Segment, List, ListItem, Button, Heading, OAuthProviderLogo, Field } from "@fider/components";
import { OAuthConfig, OAuthProviderOption, LdapConfig, LdapProviderOption } from "@fider/models";
import { OAuthForm } from "../components/OAuthForm";
import { LdapForm } from "../components/LdapForm";
import { actions, notify, Fider } from "@fider/services";
import { FaEdit, FaPlay, FaSignInAlt } from "react-icons/fa";
import { AdminBasePage } from "../components/AdminBasePage";

import "./ManageAuthentication.page.scss";

interface ManageAuthenticationPageProps {
  oauthProviders: OAuthProviderOption[];
  ldapProviders: LdapProviderOption[];
}

interface ManageAuthenticationPageState {
  isAddingOauth: boolean;
  editingOauth?: OAuthConfig;
  isAddingLdap: boolean;
  editingLdap?: LdapConfig;
}

export default class ManageAuthenticationPage extends AdminBasePage<
  ManageAuthenticationPageProps,
  ManageAuthenticationPageState
> {
  public id = "p-admin-authentication";
  public name = "authentication";
  public icon = FaSignInAlt;
  public title = "Authentication";
  public subtitle = "Manage your site authentication";

  constructor(props: ManageAuthenticationPageProps) {
    super(props);
    this.state = {
      isAddingOauth: false,
      isAddingLdap: false
    };
  }

  /* OAUTH PART */

  private addNewOauth = async () => {
    this.setState({ isAddingOauth: true, editingOauth: undefined });
  };

  private editOauth = async (provider: string) => {
    const result = await actions.getOAuthConfig(provider);
    if (result.ok) {
      this.setState({ editingOauth: result.data, isAddingOauth: false });
    } else {
      notify.error("Failed to retrieve OAuth configuration. Try again later");
    }
  };

  private startOauthTest = async (provider: string) => {
    const redirect = `${Fider.settings.baseURL}/oauth/${provider}/echo`;
    window.open(`/oauth/${provider}?redirect=${redirect}`, "oauth-test", "width=1100,height=600,status=no,menubar=no");
  };

  private cancelOauth = async () => {
    this.setState({ isAddingOauth: false, editingOauth: undefined });
  };

  /* LDAP PART */

  private addNewLdap = async () => {
    this.setState({ isAddingLdap: true, editingLdap: undefined });
  };

  private editLdap = async (provider: string) => {
    const result = await actions.getLdapConfig(provider);
    if (result.ok) {
      this.setState({ editingLdap: result.data, isAddingLdap: false });
    } else {
      notify.error("Failed to retrieve OAuth configuration. Try again later");
    }
  };

  private startLdapTest = async (provider: string) => {
    const result = await actions.testLdapServer(provider);
    if (result.ok)
    {
      notify.success("Success ! LDAP is available !")
    } else {
      notify.error("LDAP is not avaible. Please review configuration")
    }
  };

  private cancelLdap = async () => {
    this.setState({ isAddingLdap: false, editingLdap: undefined });
  };

  /* CONTENT PART */

  public content() {

    // OAUTH
    if (this.state.isAddingOauth) {
      return <OAuthForm onCancel={this.cancelOauth} />;
    }

    if (this.state.editingOauth) {
      return <OAuthForm config={this.state.editingOauth} onCancel={this.cancelOauth} />;
    }

    if (this.state.isAddingLdap) {
      return <LdapForm onCancel={this.cancelLdap} />;
    }

    if (this.state.editingLdap) {
      return <LdapForm config={this.state.editingLdap} onCancel={this.cancelLdap} />;
    }

    const enabled = <p className="m-enabled">Enabled</p>;
    const disabled = <p className="m-disabled">Disabled</p>;

    return (
      <>

        <Segment>
        <Heading
          title="TODO : Mail authentication"
          subtitle="You can use this section to deactivate or activate mail authentication"          size="small"
        />      
        <p className="info">
          Bear in mind that an other administrator from another user provider (LDAP or OAuth) must have been defined before doing so
        </p>
        <Field label="Status">
        </Field>
        </Segment>


        <Segment>

        <Heading
          title="LDAP"
          subtitle="You can use these section to add a LDAP connection for authenticating users"
          size="small"
        />

          <List divided={true}>
            {this.props.ldapProviders.map(o => (
                <ListItem key={o.provider}>
                  {(
                    <>
                      {Fider.session.user.isAdministrator && (
                        <Button onClick={this.editLdap.bind(this, o.provider)} size="mini" className="right">
                          <FaEdit />
                          Edit
                        </Button>
                         )}
                        <Button onClick={this.startLdapTest.bind(this, o.provider)} size="mini" className="right">
                            <FaPlay />
                              Test
                        </Button>
                    </>
                  )}
                  <div className="l-provider">
                    <strong>{o.displayName}</strong>
                    {o.isEnabled ? enabled : disabled}
                </div>
                </ListItem>
            ))
           }
          </List>

        {Fider.session.user.isAdministrator && (
          <Button color="positive" onClick={this.addNewLdap}>
            Add new LDAP server
          </Button>
        )}
        </Segment>
        <Segment>

        <Heading
          title="OAuth Providers"
          subtitle="You can use these section to add any authentication provider thats supports the OAuth2 protocol."
          size="small"
        />
        <p className="info">
          Additional information is available in our{" "}
          <a target="_blank" href="https://getfider.com/docs/configuring-oauth/">
            OAuth Documentation
          </a>
          .
        </p>
          <List divided={true}>
            {this.props.oauthProviders.map(o => (
              <ListItem key={o.provider}>
                {o.isCustomProvider && (
                  <>
                    {Fider.session.user.isAdministrator && (
                      <Button onClick={this.editOauth.bind(this, o.provider)} size="mini" className="right">
                        <FaEdit />
                        Edit
                      </Button>
                    )}
                    <Button onClick={this.startOauthTest.bind(this, o.provider)} size="mini" className="right">
                      <FaPlay />
                      Test
                    </Button>
                  </>
                )}
                <div className="l-provider">
                  <OAuthProviderLogo option={o} />
                  <strong>{o.displayName}</strong>
                  {o.isEnabled ? enabled : disabled}
                </div>
                {o.isCustomProvider && (
                  <span className="info">
                    <strong>Client ID:</strong> {o.clientID} <br />
                    <strong>Callback URL:</strong> {o.callbackURL}
                  </span>
                )}
              </ListItem>
            ))}
          </List>
        {Fider.session.user.isAdministrator && (
          <Button color="positive" onClick={this.addNewOauth}>
            Add new OAUTH server
          </Button>
        )}
        </Segment>

      </>
    );
  }
}
