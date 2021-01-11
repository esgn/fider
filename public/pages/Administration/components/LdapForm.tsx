import React, { useState } from "react";
import { LdapConfig, LdapConfigStatus} from "@fider/models";
import { Failure, actions } from "@fider/services";
import { Form, Button, Input, Heading, Field, Toggle, Select, SelectOption } from "@fider/components";
import { useFider } from "@fider/hooks";

interface LdapFormProps {
  config?: LdapConfig;
  onCancel: () => void;
}

export const LdapForm: React.FC<LdapFormProps> = props => {


  const fider = useFider();
  const [provider] = useState((props.config && props.config.provider) || "");
  const [displayName, setDisplayName] = useState((props.config && props.config.displayName) || "");
  const [enabled, setEnabled] = useState((props.config && props.config.status === LdapConfigStatus.Enabled) || false);
  const [ldapDomain, setLdapDomain] = useState((props.config && props.config.ldapDomain) || "");
  const [ldapPort, setLdapPort] = useState((props.config && props.config.ldapPort) || "389");
  const [bindUsername, setBindUsername] = useState((props.config && props.config.bindUsername) || "");
  const [bindPassword, setBindPassword] = useState((props.config && props.config.bindPassword) || "");
  const [bindPasswordEnabled, setBindPasswordEnabled] = useState(!props.config);
  const [rootDN, setRootDN] = useState((props.config && props.config.rootDN) || "");
  let scope = ((props.config && props.config.scope) || "2");
  const [userSearchFilter, setUserSearchFilter] = useState((props.config && props.config.userSearchFilter) || "");
  const [usernameLdapAttribute, setUsernameLdapAttribute] = useState((props.config && props.config.usernameLdapAttribute) || "");
  const [error, setError] = useState<Failure | undefined>();

  const notifyStatusChange = (opt?: SelectOption) => {
    if(opt) {
      scope = opt.value;
    } 
  };

  const handleSave = async () => {
    const result = await actions.saveLdapConfig({
      provider,
      status: enabled ? LdapConfigStatus.Enabled : LdapConfigStatus.Disabled,
      displayName,
      ldapDomain,
      ldapPort,
      bindUsername,
      bindPassword: bindPasswordEnabled ? bindPassword : "",
      rootDN,
      scope,
      userSearchFilter,
      usernameLdapAttribute,
    });
    if (result.ok) {
      location.reload();
    } else {
      setError(result.error);
    }
  };

  const handleCancel = async () => {
    props.onCancel();
  };

  const enableBindPassword = () => {
    setBindPassword("");
    setBindPasswordEnabled(true);
  };

  const title = props.config ? `LDAP Provider: ${props.config.displayName}` : "New LDAP Provider";
  return (
    <>
      <Heading title={title} size="small" />
      <Form error={error}>
        <div className="row">

          <div className="col-sm-9">
            <Input
              field="displayName"
              label="Display Name"
              maxLength={50}
              value={displayName}
              disabled={!fider.session.user.isAdministrator}
              onChange={setDisplayName}
              placeholder="My LDAP server"
            />
          </div>

        </div>

        <Input
          field="ldapDomain"
          label="LDAP Domain"
          maxLength={300}
          value={ldapDomain}
          disabled={!fider.session.user.isAdministrator}
          onChange={setLdapDomain}
          placeholder="ldap://mydomain.com"
        />

        <Input
          field="ldapPort"
          label="LDAP Port"
          maxLength={10}
          value={ldapPort}
          disabled={!fider.session.user.isAdministrator}
          onChange={setLdapPort}
        />

        <Input
          field="bindUsername"
          label="Bind Username"
          maxLength={100}
          value={bindUsername}
          disabled={!fider.session.user.isAdministrator}
          onChange={setBindUsername}
          placeholder="read_only_username"
        />  

        <Input
          field="bindPassword"
          label="Bind Password"
          maxLength={100}
          value={bindPassword}
          disabled={!bindPasswordEnabled}
          onChange={setBindPassword}
          afterLabel={
            !bindPasswordEnabled ? (
              <>
                <span className="info">omitted for security reasons.</span>
                <span className="info clickable" onClick={enableBindPassword}>
                  change
                </span>
              </>
            ) : (
              undefined
            )
          }
          placeholder="read_only_username_password"
        />

        <Input
          field="rootDN"
          label="Root DN"
          maxLength={300}
          value={rootDN}
          disabled={!fider.session.user.isAdministrator}
          onChange={setRootDN}
          placeholder="DC=domain,DC=com"
        />

        <Select
          field="scope"
          label="Scope"
          defaultValue={scope}
          onChange={notifyStatusChange}
          options={[{ value: "0", label: "ScopeBaseObject" },{ value: "1", label: "ScopeSingleLevel" },{value:"2", label:"ScopeWholeSubtree"}]}
        />
        
        <Input
          field="userSearchFilter"
          label="User Search Filter"
          maxLength={500}
          value={userSearchFilter}
          disabled={!fider.session.user.isAdministrator}
          onChange={setUserSearchFilter}
        />

        <Input
          field="usernameLdapAttribute"
          label="Username Ldap Attribute"
          maxLength={100}
          value={usernameLdapAttribute}
          disabled={!fider.session.user.isAdministrator}
          onChange={setUsernameLdapAttribute}
          placeholder="uid"
        />

        <div className="row">
          <div className="col-sm-4">
            <Field label="Status">
              <Toggle active={enabled} onToggle={setEnabled} />
              <span>{enabled ? "Enabled" : "Disabled"}</span>
              {enabled && (
                <p className="info">
                  This provider will be available for everyone to use during the sign in process. It is recommended that
                  you keep it disable and test it before enabling it. The Test button is available after saving this
                  configuration.
                </p>
              )}
              {!enabled && <p className="info">Users won't be able to sign in with this Provider.</p>}
            </Field>
          </div>
        </div>

        <div className="c-form-field">
          <Button color="positive" onClick={handleSave}>
            Save
          </Button>
          <Button color="cancel" onClick={handleCancel}>
            Cancel
          </Button>
        </div>

      </Form>
    </>
  );
};
