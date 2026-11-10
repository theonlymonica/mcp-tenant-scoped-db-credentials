-- Checks the system catalogs for the configurations that bypass row-level
-- security. Run it after every schema change, for example after adding a tenant
-- or a view:
--
--     bash postgres/check_rls.sh
--
-- The first block reads the catalogs; the second one logs in as a probe role of
-- each tenant and counts the rows it sees, then rolls everything back. Either
-- raises an error on the first violation; "row-level security checks passed"
-- is printed when there is none.
\set ON_ERROR_STOP on
\connect tvm

DO $check$
DECLARE
  bad text;
BEGIN
  -- 1. Every table in schema app has row-level security enabled AND forced.
  SELECT string_agg(c.relname, ', ') INTO bad
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname = 'app' AND c.relkind IN ('r', 'p')
     AND NOT (c.relrowsecurity AND c.relforcerowsecurity);
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'table(s) without ENABLE + FORCE ROW LEVEL SECURITY: %', bad;
  END IF;

  -- 2. No role but the bootstrap superuser bypasses row-level security.
  SELECT string_agg(rolname, ', ') INTO bad FROM pg_roles
   WHERE (rolbypassrls OR rolsuper) AND rolname <> 'postgres';
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'role(s) with BYPASSRLS or SUPERUSER: %', bad;
  END IF;

  -- 3. No SECURITY DEFINER function: it would run with its owner's rows.
  SELECT string_agg(n.nspname || '.' || p.proname, ', ') INTO bad
    FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
   WHERE p.prosecdef AND n.nspname NOT IN ('pg_catalog', 'information_schema');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'SECURITY DEFINER function(s): %', bad;
  END IF;

  -- 4. Every view runs with the caller's privileges (security_invoker), and no
  --    materialized view exists, because it would hold its owner's rows.
  SELECT string_agg(n.nspname || '.' || c.relname, ', ') INTO bad
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
   WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
     AND (c.relkind = 'm'
          OR (c.relkind = 'v' AND NOT coalesce(c.reloptions @> ARRAY['security_invoker=true'], false)));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'view(s) without security_invoker, or materialized view(s): %', bad;
  END IF;

  -- 5. Every unique index of a table in app includes the scope column, so a
  --    duplicate-key error cannot reveal a row of another tenant.
  SELECT string_agg(i.indexrelid::regclass::text, ', ') INTO bad
    FROM pg_index i
    JOIN pg_class t ON t.oid = i.indrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
   WHERE n.nspname = 'app' AND i.indisunique
     AND NOT EXISTS (SELECT 1 FROM pg_attribute a
                      WHERE a.attrelid = t.oid AND a.attname = 'scope'
                        AND a.attnum = ANY (i.indkey));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'unique index(es) that do not include scope: %', bad;
  END IF;

  -- 6. No foreign key points at a table in app: the check runs without the
  --    policies, so a violation would reveal that a row exists.
  SELECT string_agg(conname, ', ') INTO bad FROM pg_constraint
   WHERE contype = 'f'
     AND confrelid IN (SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                        WHERE n.nspname = 'app');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'foreign key(s) referencing a table in app: %', bad;
  END IF;

  -- 7. On every table in app, every tenant role has exactly one PERMISSIVE and
  --    one RESTRICTIVE policy, named for it alone, FOR ALL, whose USING and
  --    WITH CHECK are both `scope = '<tenant>'`. A restrictive policy that says
  --    USING (true) would pass a count but filter nothing.
  SELECT string_agg(t.relname || '/' || r.rolname || '/' || k.kind, ', ') INTO bad
    FROM pg_class t
    JOIN pg_namespace n ON n.oid = t.relnamespace
    CROSS JOIN pg_roles r
    CROSS JOIN (VALUES ('PERMISSIVE'), ('RESTRICTIVE')) AS k(kind)
   WHERE n.nspname = 'app' AND t.relkind IN ('r', 'p') AND starts_with(r.rolname, 'scope_')
     AND (SELECT count(*) FROM pg_policies p
           WHERE p.schemaname = 'app' AND p.tablename = t.relname
             AND p.permissive = k.kind AND p.cmd = 'ALL'
             AND p.roles = ARRAY[r.rolname]::name[]
             AND p.qual       = format('(scope = %L::text)', substr(r.rolname, 7))
             AND p.with_check = format('(scope = %L::text)', substr(r.rolname, 7))) <> 1;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'table/tenant role without exactly one policy of this kind and condition: %', bad;
  END IF;

  --    ...and there is no other policy: none for PUBLIC, for several roles, or
  --    for a role that is not a tenant role. Such a policy is how a row becomes
  --    visible outside its tenant.
  SELECT string_agg(p.tablename || '.' || p.policyname, ', ') INTO bad FROM pg_policies p
   WHERE p.schemaname = 'app'
     AND NOT (cardinality(p.roles) = 1 AND starts_with(p.roles[1]::text, 'scope_')
              AND p.cmd = 'ALL'
              AND p.qual       = format('(scope = %L::text)', substr(p.roles[1]::text, 7))
              AND p.with_check = format('(scope = %L::text)', substr(p.roles[1]::text, 7)));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'unexpected policy on a table in app: %', bad;
  END IF;

  -- 8. No tenant role or operation role can log in or holds a table-wide
  --    privilege, and nobody but the owner holds a privilege on scope.
  SELECT string_agg(rolname, ', ') INTO bad FROM pg_roles
   WHERE (starts_with(rolname, 'scope_') OR starts_with(rolname, 'op_')) AND rolcanlogin;
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'tenant or operation role(s) with LOGIN: %', bad;
  END IF;
  SELECT string_agg(DISTINCT grantee, ', ') INTO bad FROM information_schema.table_privileges
   WHERE table_schema = 'app' AND grantee <> 'docs_owner';
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'table-wide privilege(s) on app tables granted to: %', bad;
  END IF;
  SELECT string_agg(DISTINCT grantee, ', ') INTO bad FROM information_schema.column_privileges
   WHERE table_schema = 'app' AND column_name = 'scope' AND grantee <> 'docs_owner';
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'privilege(s) on the scope column granted to: %', bad;
  END IF;

  -- 9. The owner of a table can drop its policies or switch row-level security
  --    off, so no owner of a table in app can log in or has a member.
  SELECT string_agg(DISTINCT o.rolname, ', ') INTO bad
    FROM pg_class t
    JOIN pg_namespace n ON n.oid = t.relnamespace
    JOIN pg_roles o ON o.oid = t.relowner
   WHERE n.nspname = 'app' AND t.relkind IN ('r', 'p')
     AND (o.rolcanlogin OR EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.roleid = o.oid));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'table owner(s) that can log in or have members: %', bad;
  END IF;

  -- 10. bao_admin is the only role that can create roles. It holds roles only
  --     to grant them (ADMIN), never to use them (no INHERIT, no SET): the
  --     tenant and operation roles, and each credential it created, on which
  --     PostgreSQL gives the creator ADMIN. It must not hold, even that way, a
  --     role with an attribute, a predefined role, or the owner of anything in
  --     app: it could grant that role to a credential.
  SELECT string_agg(rolname, ', ') INTO bad FROM pg_roles
   WHERE rolcreaterole AND rolname NOT IN ('postgres', 'bao_admin');
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'role(s) with CREATEROLE: %', bad;
  END IF;
  SELECT string_agg(g.rolname, ', ') INTO bad
    FROM pg_auth_members m
    JOIN pg_roles g ON g.oid = m.roleid
    JOIN pg_roles u ON u.oid = m.member
   WHERE u.rolname = 'bao_admin'
     AND (NOT m.admin_option OR m.inherit_option OR m.set_option
          OR (NOT (starts_with(g.rolname, 'scope_') OR starts_with(g.rolname, 'op_'))
              AND (g.rolsuper OR g.rolcreaterole OR g.rolcreatedb OR g.rolreplication OR g.rolbypassrls
                   OR starts_with(g.rolname, 'pg_')
                   OR EXISTS (SELECT 1 FROM pg_namespace n WHERE n.nspname = 'app' AND n.nspowner = g.oid)
                   OR EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
                               WHERE n.nspname = 'app' AND c.relowner = g.oid))));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'bao_admin holds role(s) it could use or hand out: %', bad;
  END IF;

  --     Every other member of a tenant or operation role is a per-request
  --     credential: no attribute of its own, no ADMIN on anything, at most one
  --     tenant and one operation, and no other role. ("At most", because a
  --     credential being revoked loses its two roles one after the other.)
  SELECT string_agg(u.rolname, ', ') INTO bad
    FROM pg_roles u
   WHERE u.rolname <> 'bao_admin'
     AND EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                  WHERE m.member = u.oid
                    AND (starts_with(g.rolname, 'scope_') OR starts_with(g.rolname, 'op_')))
     AND (u.rolsuper OR u.rolcreaterole OR u.rolcreatedb OR u.rolreplication OR u.rolbypassrls
          OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
               WHERE m.member = u.oid AND starts_with(g.rolname, 'scope_')) > 1
          OR (SELECT count(*) FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
               WHERE m.member = u.oid AND starts_with(g.rolname, 'op_')) > 1
          OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                      WHERE m.member = u.oid
                        AND NOT (starts_with(g.rolname, 'scope_') OR starts_with(g.rolname, 'op_')))
          OR EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member = u.oid AND m.admin_option));
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'credential role(s) with an attribute, another role, or more than one tenant or operation: %', bad;
  END IF;

  -- 11. PUBLIC can connect to no database, so a credential reaches only tvm.
  SELECT string_agg(d.datname, ', ') INTO bad
    FROM pg_database d, aclexplode(coalesce(d.datacl, acldefault('d', d.datdba))) a
   WHERE d.datallowconn AND a.grantee = 0 AND a.privilege_type = 'CONNECT';
  IF bad IS NOT NULL THEN
    RAISE EXCEPTION 'database(s) PUBLIC can connect to: %', bad;
  END IF;
END
$check$;

-- 12. What a credential actually sees. For each tenant a probe role is created
--     the way OpenBao creates one (the tenant role and op_read), and the rows
--     it counts are compared with the rows of that tenant. A role with an
--     operation and no tenant must count none. Nothing survives the ROLLBACK.
BEGIN;
DO $probe$
DECLARE
  r record;
  probe text;
  seen bigint;
  expected bigint;
BEGIN
  FOR r IN SELECT rolname, substr(rolname, 7) AS tenant FROM pg_roles
            WHERE starts_with(rolname, 'scope_') ORDER BY rolname LOOP
    probe := 'rls_probe_' || r.tenant;
    EXECUTE format('CREATE ROLE %I NOLOGIN', probe);
    EXECUTE format('GRANT %I, op_read TO %I', r.rolname, probe);
    SELECT count(*) INTO expected FROM app.documents WHERE scope = r.tenant;
    EXECUTE format('SET LOCAL ROLE %I', probe);
    SELECT count(*) INTO seen FROM app.documents;
    RESET ROLE;
    IF seen <> expected THEN
      RAISE EXCEPTION 'a credential of % sees % row(s), the tenant has %', r.tenant, seen, expected;
    END IF;
  END LOOP;

  CREATE ROLE rls_probe_no_tenant NOLOGIN;
  GRANT op_read TO rls_probe_no_tenant;
  SET LOCAL ROLE rls_probe_no_tenant;
  SELECT count(*) INTO seen FROM app.documents;
  RESET ROLE;
  IF seen <> 0 THEN
    RAISE EXCEPTION 'a role with no tenant sees % row(s)', seen;
  END IF;

  RAISE NOTICE 'row-level security checks passed';
END
$probe$;
ROLLBACK;
