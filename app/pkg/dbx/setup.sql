TRUNCATE TABLE blobs RESTART IDENTITY CASCADE;
TRUNCATE TABLE logs RESTART IDENTITY CASCADE;
TRUNCATE TABLE tenants RESTART IDENTITY CASCADE;

INSERT INTO tenants (name, subdomain, created_at, cname, invitation, welcome_message, status, is_private, custom_css, logo_bkey) 
VALUES ('Demonstration', 'demo', now(), '', '', '', 1, false, '', '');

INSERT INTO users (name, email, tenant_id, created_at, role, status, avatar_type, avatar_bkey) 
VALUES ('Jon Snow', 'jon.snow@got.com', 1, now(), 3, 1, 2, '');
INSERT INTO user_providers (user_id, tenant_id, provider, provider_uid, created_at) 
VALUES (1, 1, 'facebook', 'FB1234', now());

INSERT INTO users (name, email, tenant_id, created_at, role, status, avatar_type, avatar_bkey) 
VALUES ('Arya Stark', 'arya.stark@got.com', 1, now(), 1, 1, 2, '');
INSERT INTO user_providers (user_id, tenant_id, provider, provider_uid, created_at) 
VALUES (2, 1, 'google', 'GO5678', now());

INSERT INTO users (name, email, tenant_id, created_at, role, status, avatar_type, avatar_bkey) 
VALUES ('Sansa Stark', 'sansa.stark@got.com', 1, now(), 1, 1, 2, '');

INSERT INTO tenants (name, subdomain, created_at, cname, invitation, welcome_message, status, is_private, custom_css, logo_bkey) 
VALUES ('Avengers', 'avengers', now(), 'feedback.avengers.com', '', '', 1, false, '', '');

INSERT INTO users (name, email, tenant_id, created_at, role, status, avatar_type, avatar_bkey) 
VALUES ('Tony Stark', 'tony.stark@avengers.com', 2, now(), 3, 1, 2, '');
INSERT INTO user_providers (user_id, tenant_id, provider, provider_uid, created_at) 
VALUES (4, 2, 'facebook', 'FB2222', now());

INSERT INTO users (name, email, tenant_id, created_at, role, status, avatar_type, avatar_bkey) 
VALUES ('The Hulk', 'the.hulk@avengers.com', 2, now(), 1, 1, 2, '');
INSERT INTO user_providers (user_id, tenant_id, provider, provider_uid, created_at) 
VALUES (5, 2, 'google', 'GO1111', now());

INSERT INTO ldap_providers (tenant_id, provider, display_name, status, ldap_hostname, ldap_port, bind_username, bind_password, root_dn, scope, user_search_filter, username_ldap_attribute, name_ldap_attribute, mail_ldap_attribute, protocol, cert_check)
VALUES (2, 'ldap_test', 'Testing Ldap Server', 2, 'localhost', 389, 'cn=readonly,dc=example,dc=org', 'readonly', 'dc=example,dc=org', 3, '(objectClass=inetOrgPerson)', 'uid', 'displayName', 'mail', 1, false),
       (2, 'other_ldap', 'Second Ldap Server', 1, '', 636, '', '', '', 1, '', '', '', '', 3, true);
