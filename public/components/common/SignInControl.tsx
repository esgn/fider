import "./SignInControl.scss";

import React, { useState } from "react";
import { SocialSignInButton, Form, Button, Input, Message,Field,DropDown,DropDownItem } from "@fider/components";
import { device, actions, Failure, isCookieEnabled } from "@fider/services";
import { useFider } from "@fider/hooks";

interface SignInControlProps {
  useEmail: boolean;
  redirectTo?: string;
  onEmailSent?: (email: string) => void;
}

export const SignInControl: React.FunctionComponent<SignInControlProps> = props => {
  const fider = useFider();
  const oauthProvidersLen = fider.settings.oauth.length;
  const ldapProvidersLen = fider.settings.ldap.length;
  const [email, setEmail] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<Failure | undefined>(undefined);
  const [ldapError, setLdapError] = useState<Failure | undefined>(undefined);
  const [ldapProvider, setLdapProvider] = useState((ldapProvidersLen>0 && fider.settings.ldap[0].provider) || "");

  const signIn = async () => {
    const result = await actions.signIn(email);
    if (result.ok) {
      setEmail("");
      setError(undefined);
      if (props.onEmailSent) {
        props.onEmailSent(email);
      }
    } else if (result.error) {
      setError(result.error);
    }
  };

  const ldapSignIn = async () => {
    const result = await actions.ldapSignIn(username,password,ldapProvider);
    if (result.ok) {
      setUsername("");
      setPassword("");
      setLdapError(undefined);
      location.href = "/";
    } else if (result.error) {
      setLdapError(result.error);
    }
  };

  const updateLdapProvider = (item: DropDownItem) => {
    if (item) {
      setLdapProvider(item.value)
    }
  };
  
  if (!isCookieEnabled()) {
    return (
      <Message type="error">
        <h3>Cookies Required</h3>
        <p>Cookies are not enabled on your browser. Please enable cookies in your browser preferences to continue.</p>
      </Message>
    );
  }

  return (

    <div className="c-signin-control">

      {ldapProvidersLen > 0 && (
          <div className="l-signin-ldap">
            <Form error={ldapError}>
              <Input field="ldapUsername"
                            value={username}
                            label="Log in with your LDAP account"
                            placeholder="LDAP username"
                            onChange={setUsername}
                            ></Input>

              <Input field="ldapPassword"
                            value={password}
                            placeholder="LDAP password"
                            onChange={setPassword}
                            password={true}
                            ></Input>

              <Field label="LDAP Server">
                <DropDown
                    items={[
                    ...fider.settings.ldap.map(x => ({ value: x.provider, label: x.displayName }))
                    ]}
                    defaultValue={ldapProvider}
                    placeholder="Select a LDAP provider"
                    onChange={updateLdapProvider}
                    inline={true}
                />
              </Field>
              <Button type="submit" color="positive" disabled={((username === "")||(password === ""))} onClick={ldapSignIn}>
                  Sign in
              </Button>
            </Form>
          </div>
        )}

      {ldapProvidersLen > 0 && (props.useEmail || oauthProvidersLen > 0) && <div className="c-divider">OR</div>}

      {oauthProvidersLen > 0 && (
        <div className="l-signin-social">
                      Login with OAuth2
          <div className="row">
            {fider.settings.oauth.map((o, i) => (
              <React.Fragment key={o.provider}>
                {i % 4 === 0 && <div className="col-lf" />}
                <div
                  className={`col-sm l-provider-${o.provider} l-social-col ${
                    oauthProvidersLen === 1 ? "l-social-col-100" : ""
                  }`}
                >
                  <SocialSignInButton option={o} redirectTo={props.redirectTo} />
                </div>
              </React.Fragment>
            ))}
          </div>
          <p className="info">We will never post to these accounts on your behalf.</p>
        </div>
      )}

      {oauthProvidersLen > 0 && props.useEmail && <div className="c-divider">OR</div>}

      {props.useEmail && (
        <div className="l-signin-email">
          <p>Enter your email address to sign in</p>
          <Form error={error}>
            <Input
              field="email"
              value={email}
              autoFocus={!device.isTouch()}
              onChange={setEmail}
              placeholder="yourname@example.com"
              suffix={
                <Button type="submit" color="positive" disabled={email === ""} onClick={signIn}>
                  Sign in
                </Button>
              }
            />
          </Form>
        </div>
      )}

    </div>
  );
};
