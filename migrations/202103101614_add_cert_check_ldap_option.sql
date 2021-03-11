alter table ldap_providers add cert_check bool null;

update ldap_providers set cert_check = true;

alter table ldap_providers alter column cert_check set not null;
