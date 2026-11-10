-- The database, its roles, the shared table and its row-level security.
-- Run once, as the bootstrap superuser, on an empty server (postgres/install.sh).
--
-- A credential minted by OpenBao is a login role that is a member of exactly two
-- of the roles below:
--   * one tenant role (scope_<tenant>), which the row-level security policies
--     name, and which holds no privilege on the table;
--   * one operation role (op_<tool>), which holds the column privileges of one
--     tool, and which no policy names.
-- The rows come from the first membership and the columns from the second.
\set ON_ERROR_STOP on

CREATE DATABASE tvm;
REVOKE ALL ON DATABASE tvm FROM PUBLIC;
-- A per-request credential has no reason to open any other database either.
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
REVOKE CONNECT ON DATABASE template1 FROM PUBLIC;
\connect tvm

-- ---------------------------------------------------------------------------
-- Roles. None of them can log in except bao_admin, the role OpenBao uses to
-- create and drop the per-request credentials.
-- ---------------------------------------------------------------------------
CREATE ROLE docs_owner          NOLOGIN NOBYPASSRLS NOSUPERUSER;

CREATE ROLE scope_tenant1       NOLOGIN NOBYPASSRLS NOSUPERUSER;
CREATE ROLE scope_tenant2       NOLOGIN NOBYPASSRLS NOSUPERUSER;

CREATE ROLE op_read             NOLOGIN NOBYPASSRLS NOSUPERUSER;
CREATE ROLE op_search           NOLOGIN NOBYPASSRLS NOSUPERUSER;
CREATE ROLE op_append           NOLOGIN NOBYPASSRLS NOSUPERUSER;

-- CREATEROLE and the right to grant the tenant and operation roles, nothing
-- else. INHERIT FALSE and SET FALSE keep bao_admin from using their privileges
-- itself.
CREATE ROLE bao_admin LOGIN PASSWORD :'bao_admin_password' CREATEROLE NOBYPASSRLS NOSUPERUSER;
GRANT scope_tenant1, scope_tenant2, op_read, op_search, op_append
   TO bao_admin WITH ADMIN OPTION, INHERIT FALSE, SET FALSE;

GRANT CONNECT ON DATABASE tvm TO bao_admin, scope_tenant1, scope_tenant2,
                                op_read, op_search, op_append;

REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE SCHEMA app AUTHORIZATION docs_owner;
GRANT USAGE ON SCHEMA app TO scope_tenant1, scope_tenant2, op_read, op_search, op_append;

-- ---------------------------------------------------------------------------
-- The table, created by its owner so that docs_owner owns it and its policies.
-- ---------------------------------------------------------------------------
SET ROLE docs_owner;

-- The primary key starts with scope, so a duplicate-key error can only ever be
-- about a row of the same tenant.
CREATE TABLE app.documents (
    scope      text        NOT NULL,
    doc_id     text        NOT NULL,
    title      text        NOT NULL,
    body       text        NOT NULL,
    replies    text        NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (scope, doc_id)
);

-- Column privileges, one operation role per tool. No role but the owner holds
-- anything on `scope`: a credential cannot read the tenant column, and an
-- UPDATE that sets it is refused before any policy is evaluated.
REVOKE ALL ON app.documents FROM PUBLIC;
GRANT SELECT (doc_id, title, body, replies, updated_at) ON app.documents TO op_read;
GRANT SELECT (doc_id, title, body)                      ON app.documents TO op_search;
GRANT SELECT (doc_id, replies)                          ON app.documents TO op_append;
GRANT UPDATE (replies, updated_at)                      ON app.documents TO op_append;

-- Two policies per tenant, both naming that tenant's role and nobody else, both
-- with the same condition. The PERMISSIVE one gives the role its rows; the
-- RESTRICTIVE one is combined with AND, so a permissive policy added later
-- cannot widen the tenant. No policy says USING (true): a tenant role that was
-- given no policy sees no rows at all, so a forgotten policy fails closed.
CREATE POLICY documents_allow_tenant1 ON app.documents
    AS PERMISSIVE FOR ALL
    TO scope_tenant1
    USING (scope = 'tenant1') WITH CHECK (scope = 'tenant1');

CREATE POLICY documents_restrict_tenant1 ON app.documents
    AS RESTRICTIVE FOR ALL
    TO scope_tenant1
    USING (scope = 'tenant1') WITH CHECK (scope = 'tenant1');

CREATE POLICY documents_allow_tenant2 ON app.documents
    AS PERMISSIVE FOR ALL
    TO scope_tenant2
    USING (scope = 'tenant2') WITH CHECK (scope = 'tenant2');

CREATE POLICY documents_restrict_tenant2 ON app.documents
    AS RESTRICTIVE FOR ALL
    TO scope_tenant2
    USING (scope = 'tenant2') WITH CHECK (scope = 'tenant2');

ALTER TABLE app.documents ENABLE ROW LEVEL SECURITY;

-- Sample data, inserted before FORCE: until then the owner is exempt from the
-- policies, afterwards it matches none of them and can no longer write a row.
INSERT INTO app.documents (scope, doc_id, title, body) VALUES
  ('tenant1', 't1-001', 'Settlement retry policy', 'Retries are capped at three attempts.'),
  ('tenant1', 't1-002', 'Chargeback runbook',      'Escalate to the duty engineer.'),
  ('tenant2', 't2-001', 'Invoice dunning ladder',  'Three reminders, then suspension.'),
  ('tenant2', 't2-002', 'Proration rules',         'Mid-cycle changes prorate by day.');

-- Without FORCE the owner would see every row without passing the policies.
ALTER TABLE app.documents FORCE ROW LEVEL SECURITY;

RESET ROLE;
