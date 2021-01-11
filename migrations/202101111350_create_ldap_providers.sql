create table if not exists ldap_providers (
  id                   serial not null, 
  tenant_id            int not null,
  -- the strange identifier that will be indexed by user_providers
  provider             varchar(30) not null,
  display_name         varchar(50) not null,
  status               int not null,
  ldap_domain          varchar(300) not null,
  ldap_port            int not null,
  bind_username         varchar(100) not null,
  bind_password         varchar(100) not null,
  root_dn              varchar(100) not null,
  scope                int not null,
  user_search_filter   varchar(500) not null,
  username_ldap_attribute varchar(100) not null,
  created_on           timestamptz not null default now(),
  primary key (id),
  foreign key (tenant_id) references tenants(id)
);

CREATE UNIQUE INDEX tenant_id_ldap_provider_key ON ldap_providers (tenant_id, provider);

-- Add identity provider type 
-- 0 is oauth
-- 1 is ldap
ALTER TABLE user_providers ADD COLUMN provider_type int not null;
UPDATE user_providers SET provider_type = 0;
