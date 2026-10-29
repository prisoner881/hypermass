-- ============================================================================
-- Hypermass: assetdb reporting functions
-- ============================================================================
--
-- Creates the helper and reporting functions used to query a Hypermass
-- (OWASP Amass) asset database:
--
--   fqdn_by_domains(domains_csv)
--       Every fqdn row at or under the listed domains. The building block the
--       other functions use.
--
--   ips_by_domains(domains_csv, since, include_neighbors, max_cname_depth)
--       IP addresses tied to the listed domains (forward DNS through CNAME
--       chains, PTR, certificates, owned netblocks, optional neighbors), with
--       the reasons and evidence for each.
--
--   tplinks_by_domain(domains_csv)
--       Third-party links: out-of-scope domains the listed domains point at
--       (NS/CNAME/MX/SRV records or page links), with evidence and last-seen.
--
--   other_domains_by_inscope_domains(domains_csv)
--       The out-of-scope linked domains that are not yet tracked for any
--       company in public.domains.
--
--   techstack_by_domains(domains_csv)
--       The technology stack of the listed domains: per host, service and
--       product, with release, CPE, ports, identifying plugins and last-seen.
--
-- Every function takes the in-scope domains as one comma-separated string,
-- e.g. 'example.com,example.co.uk'. Nothing is hardcoded.
--
-- ---------------------------------------------------------------------------
-- Prerequisites
-- ---------------------------------------------------------------------------
-- 1. The asset-db schema must already exist in the database: run the Hypermass
--    engine against it once (it applies the asset-db migrations on start-up),
--    or apply the asset-db migrations directly. That provides the fqdn,
--    entity, edge, *_type_lu and other asset tables, and the citext extension.
--    This file checks for them and stops with an error if they are missing.
--
-- 2. Three functions also read tables that are NOT part of asset-db. They are
--    created regardless, but return an error when called until these exist:
--      public.public_suffix_list  tplinks_by_domain,
--                                 other_domains_by_inscope_domains
--      public.domains             other_domains_by_inscope_domains
--      (public.companies is referenced by public.domains' foreign key)
--
-- ---------------------------------------------------------------------------
-- Applying
-- ---------------------------------------------------------------------------
--   psql -h <host> -U postgres -d assetdb -v ON_ERROR_STOP=1 -f hypermass_functions.sql
--
-- The whole file runs in one transaction: if anything fails, nothing is
-- created. It is safe to re-run; every function uses CREATE OR REPLACE.
-- Note that CREATE OR REPLACE cannot change a function's result columns. If a
-- later version of this file changes them, DROP FUNCTION the old one first.
-- ============================================================================

BEGIN;

-- Stop early, with a clear message, if the asset-db schema is not present.
DO $$
BEGIN
    IF to_regtype('citext') IS NULL
       OR to_regclass('public.fqdn') IS NULL
       OR to_regclass('public.entity') IS NULL
       OR to_regclass('public.edge') IS NULL
       OR to_regclass('public.entity_type_lu') IS NULL THEN
        RAISE EXCEPTION 'asset-db schema not found in database "%"', current_database()
            USING HINT = 'Run the Hypermass engine against this database once (or apply the asset-db migrations), then apply this file again.';
    END IF;
END
$$;

-- ============================================================================
-- fqdn_by_domains -- required by all of the functions below
-- ============================================================================

CREATE OR REPLACE FUNCTION public.fqdn_by_domains(
	domains_csv text)
    RETURNS SETOF fqdn 
    LANGUAGE 'plpgsql'
    COST 100
    STABLE  PARALLEL UNSAFE
    ROWS 1000
    SET work_mem = '512MB'
AS $BODY$
DECLARE
    doms   text[];
    dom    text;
    sql    text;
    first  boolean := true;
BEGIN
    -- split incoming CSV list into an array
    doms := string_to_array(lower(domains_csv), ',');
    sql := 'SELECT f.* FROM public.fqdn AS f WHERE ';
    FOREACH dom IN ARRAY doms LOOP
        dom := trim(dom);
        IF dom IS NULL OR dom = '' THEN
            CONTINUE;
        END IF;
        IF NOT first THEN
            sql := sql || ' OR ';
        ELSE
            first := false;
        END IF;
        sql := sql || format(
            '(f.reverse_fqdn = REVERSE(%L) OR f.reverse_fqdn LIKE REVERSE(%L) || ''.%%'')',
            dom, dom
        );
    END LOOP;
    -- nothing to search for
    IF first THEN
        RETURN;
    END IF;
    RETURN QUERY EXECUTE sql;
END;
$BODY$;

ALTER FUNCTION public.fqdn_by_domains(text)
    OWNER TO postgres;

-- ============================================================================
-- ips_by_domains
-- ============================================================================

CREATE OR REPLACE FUNCTION public.ips_by_domains(
    domains_csv       text,
    since             timestamp without time zone DEFAULT NULL,
    include_neighbors boolean DEFAULT false,
    max_cname_depth   integer DEFAULT 10
)
RETURNS TABLE (ip_address inet, reasons text[], evidence text[])
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SET jit = off
SET work_mem = '256MB'
AS $fn$
DECLARE
    v_doms     text[];
    t_fqdn     smallint;
    t_ip       smallint;
    t_ident    smallint;
    t_contact  smallint;
    t_ipnet    smallint;
    t_netblock smallint;
    t_cert     smallint;
    t_service  smallint;
    r_basic    smallint;
    r_simple   smallint;
    r_port     smallint;
BEGIN
    -- Normalize the input: lowercase, trim, drop a trailing dot, de-duplicate.
    SELECT array_agg(DISTINCT d) INTO v_doms
    FROM (
        SELECT rtrim(lower(btrim(x)), '.') AS d
        FROM unnest(string_to_array(domains_csv, ',')) AS x
    ) s
    WHERE d <> '';

    IF v_doms IS NULL THEN
        RETURN;
    END IF;

    SELECT id INTO t_fqdn     FROM public.entity_type_lu WHERE name = 'fqdn';
    SELECT id INTO t_ip       FROM public.entity_type_lu WHERE name = 'ipaddress';
    SELECT id INTO t_ident    FROM public.entity_type_lu WHERE name = 'identifier';
    SELECT id INTO t_contact  FROM public.entity_type_lu WHERE name = 'contactrecord';
    SELECT id INTO t_ipnet    FROM public.entity_type_lu WHERE name = 'ipnetrecord';
    SELECT id INTO t_netblock FROM public.entity_type_lu WHERE name = 'netblock';
    SELECT id INTO t_cert     FROM public.entity_type_lu WHERE name = 'tlscertificate';
    SELECT id INTO t_service  FROM public.entity_type_lu WHERE name = 'service';
    SELECT id INTO r_basic    FROM public.edge_type_lu   WHERE name = 'basicdnsrelation';
    SELECT id INTO r_simple   FROM public.edge_type_lu   WHERE name = 'simplerelation';
    SELECT id INTO r_port     FROM public.edge_type_lu   WHERE name = 'portrelation';

    RETURN QUERY
    WITH RECURSIVE
    -- In-domain FQDNs and their entity ids.
    seed AS MATERIALIZED (
        SELECT DISTINCT en.entity_id, f.fqdn::text AS name
        FROM unnest(v_doms) AS d(dom)
        CROSS JOIN LATERAL (
            SELECT f1.id, f1.fqdn
            FROM public.fqdn f1
            WHERE f1.reverse_fqdn = reverse(d.dom)
            UNION ALL
            SELECT f2.id, f2.fqdn
            FROM public.fqdn f2
            WHERE f2.reverse_fqdn ~>=~ (reverse(d.dom) || '.')
              AND f2.reverse_fqdn ~<~  (reverse(d.dom) || '/')
        ) f
        CROSS JOIN LATERAL (
            SELECT e.entity_id
            FROM public.entity e
            WHERE e.etype_id = t_fqdn AND e.row_id = f.id
            OFFSET 0
        ) en
    ),

    -- Forward resolution: the seeds plus every name reached through CNAMEs.
    chain (entity_id, seed_name, depth) AS (
        SELECT s.entity_id, s.name, 0
        FROM seed s
        UNION
        SELECT x.to_id, c.seed_name, c.depth + 1
        FROM chain c
        CROSS JOIN LATERAL (
            SELECT ed.to_entity_id AS to_id
            FROM public.edge ed
            WHERE ed.from_entity_id = c.entity_id
              AND ed.etype_id = r_basic
              AND ed.label = 'dns_record'
              AND ed.content -> 'header' ->> 'rr_type' = '5'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) x
        WHERE c.depth < max_cname_depth
    ),

    -- Each name's A/AAAA records are read once, then joined back to every seed
    -- that reaches the name; a CNAME target shared by thousands of seeds would
    -- otherwise be probed once per seed.
    chain_names AS MATERIALIZED (
        SELECT DISTINCT entity_id FROM chain
    ),

    addr AS MATERIALIZED (
        SELECT n.entity_id, x.to_id AS ip_entity
        FROM chain_names n
        CROSS JOIN LATERAL (
            SELECT ed.to_entity_id AS to_id
            FROM public.edge ed
            WHERE ed.from_entity_id = n.entity_id
              AND ed.etype_id = r_basic
              AND ed.label = 'dns_record'
              AND ed.content -> 'header' ->> 'rr_type' IN ('1', '28')
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) x
    ),

    fwd AS MATERIALIZED (
        SELECT DISTINCT a.ip_entity, c.seed_name
        FROM addr a
        JOIN (SELECT DISTINCT entity_id, seed_name FROM chain) c ON c.entity_id = a.entity_id
    ),

    -- Reverse DNS: IP -ptr_record-> <ip>.in-addr.arpa -dns_record(PTR)-> seed.
    ptr AS (
        SELECT p.ip_entity, s.name AS seed_name
        FROM seed s
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS arpa
            FROM public.edge ed
            WHERE ed.to_entity_id = s.entity_id
              AND ed.etype_id = r_basic
              AND ed.label = 'dns_record'
              AND ed.content -> 'header' ->> 'rr_type' = '12'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) a
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS ip_entity
            FROM public.edge ed
            WHERE ed.to_entity_id = a.arpa
              AND ed.etype_id = r_simple
              AND ed.label = 'ptr_record'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) p
    ),

    -- Certificates naming a seed, de-duplicated before expanding to services.
    certs AS MATERIALIZED (
        SELECT c.cert_entity, min(s.name) AS seed_name
        FROM seed s
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS cert_entity
            FROM public.edge ed
            WHERE ed.to_entity_id = s.entity_id
              AND ed.etype_id = r_simple
              AND ed.label IN ('san_dns_name', 'common_name')
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) c
        GROUP BY c.cert_entity
    ),

    cert AS (
        SELECT p.from_id AS ip_entity, c.seed_name
        FROM certs c
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS svc_entity
            FROM public.edge ed
            WHERE ed.to_entity_id = c.cert_entity
              AND ed.etype_id = r_simple
              AND ed.label = 'certificate'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) sv
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS from_id
            FROM public.edge ed
            WHERE ed.to_entity_id = sv.svc_entity
              -- "+ 0" keeps etype_id out of the index condition, so this hop is
              -- always driven by to_entity_id; where port edges are rare the
              -- planner could otherwise pick idx_edge_etype and read every
              -- port edge for each service.
              AND ed.etype_id + 0 = r_port
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) p
    ),

    -- Owned netblocks: email at a listed domain -> contact -> IPNetRecord -> netblock.
    owned_nb AS MATERIALIZED (
        SELECT n.nb_entity, min(i.id_value) AS email
        FROM unnest(v_doms) AS d(dom)
        CROSS JOIN LATERAL (
            SELECT ident.id, ident.id_value
            FROM public.identifier ident
            WHERE lower(split_part(ident.id_value, '@', 2)) = d.dom
              AND ident.id_type = 'email'
            OFFSET 0
        ) i
        CROSS JOIN LATERAL (
            SELECT e.entity_id
            FROM public.entity e
            WHERE e.etype_id = t_ident AND e.row_id = i.id
            OFFSET 0
        ) ie
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS contact_entity
            FROM public.edge ed
            WHERE ed.to_entity_id = ie.entity_id
              AND ed.etype_id = r_simple
              AND ed.label = 'id'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) c
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS rec_entity
            FROM public.edge ed
            WHERE ed.to_entity_id = c.contact_entity
              AND ed.etype_id = r_simple
              AND ed.label IN ('registrant', 'admin_contact', 'abuse_contact', 'technical_contact')
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) r
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS nb_entity
            FROM public.edge ed
            WHERE ed.to_entity_id = r.rec_entity
              AND ed.etype_id = r_simple
              AND ed.label = 'registration'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) n
        -- The same labels also link DomainRecords, AutnumRecords and Organizations;
        -- keep only ContactRecord -> IPNetRecord -> Netblock.
        WHERE EXISTS (SELECT 1 FROM public.entity e WHERE e.entity_id = c.contact_entity AND e.etype_id = t_contact)
          AND EXISTS (SELECT 1 FROM public.entity e WHERE e.entity_id = r.rec_entity AND e.etype_id = t_ipnet)
          AND EXISTS (SELECT 1 FROM public.entity e WHERE e.entity_id = n.nb_entity AND e.etype_id = t_netblock)
        GROUP BY n.nb_entity
    ),

    owned AS (
        SELECT x.ip_entity, (nbr.netblock_cidr::text || ' via ' || o.email) AS ev
        FROM owned_nb o
        CROSS JOIN LATERAL (
            SELECT nbt.netblock_cidr
            FROM public.entity e
            JOIN public.netblock nbt ON nbt.id = e.row_id
            WHERE e.entity_id = o.nb_entity
            OFFSET 0
        ) nbr
        CROSS JOIN LATERAL (
            SELECT ed.to_entity_id AS ip_entity
            FROM public.edge ed
            WHERE ed.from_entity_id = o.nb_entity
              AND ed.etype_id = r_simple
              AND ed.label = 'contains'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) x
    ),

    -- Optional weak path: small netblocks that contain a forward_dns address.
    nbr_nb AS MATERIALIZED (
        SELECT DISTINCT n.nb_entity, n.cidr
        FROM (SELECT DISTINCT ip_entity FROM fwd) f
        CROSS JOIN LATERAL (
            SELECT ed.from_entity_id AS nb_entity, nbt.netblock_cidr AS cidr
            FROM public.edge ed
            JOIN public.entity e ON e.entity_id = ed.from_entity_id AND e.etype_id = t_netblock
            JOIN public.netblock nbt ON nbt.id = e.row_id
            WHERE ed.to_entity_id = f.ip_entity
              AND ed.etype_id = r_simple
              AND ed.label = 'contains'
              AND (since IS NULL OR ed.updated_at >= since)
              AND ((family(nbt.netblock_cidr) = 4 AND masklen(nbt.netblock_cidr) >= 20)
                OR (family(nbt.netblock_cidr) = 6 AND masklen(nbt.netblock_cidr) >= 116))
            OFFSET 0
        ) n
        WHERE include_neighbors
    ),

    neighbor AS (
        SELECT x.ip_entity, n.cidr::text AS ev
        FROM nbr_nb n
        CROSS JOIN LATERAL (
            SELECT ed.to_entity_id AS ip_entity
            FROM public.edge ed
            WHERE ed.from_entity_id = n.nb_entity
              AND ed.etype_id = r_simple
              AND ed.label = 'contains'
              AND (since IS NULL OR ed.updated_at >= since)
            OFFSET 0
        ) x
    ),

    hits AS (
        SELECT ip_entity, 'forward_dns'::text AS reason, seed_name AS ev FROM fwd
        UNION ALL SELECT ip_entity, 'ptr', seed_name FROM ptr
        UNION ALL SELECT ip_entity, 'cert', seed_name FROM cert
        UNION ALL SELECT ip_entity, 'owned_netblock', ev FROM owned
        UNION ALL SELECT ip_entity, 'neighbor', ev FROM neighbor
    ),

    per_ip AS (
        SELECT h.ip_entity,
               array_agg(DISTINCT h.reason ORDER BY h.reason) AS reasons,
               array_agg(DISTINCT h.ev ORDER BY h.ev) AS evidence
        FROM hits h
        GROUP BY h.ip_entity
    )

    SELECT a.ip_address, p.reasons, p.evidence
    FROM per_ip p
    CROSS JOIN LATERAL (
        SELECT ipt.ip_address
        FROM public.entity e
        JOIN public.ipaddress ipt ON ipt.id = e.row_id
        WHERE e.entity_id = p.ip_entity
          AND e.etype_id = t_ip
        OFFSET 0
    ) a
    ORDER BY a.ip_address;
END
$fn$;

ALTER FUNCTION public.ips_by_domains(text, timestamp without time zone, boolean, integer)
    OWNER TO postgres;

-- ============================================================================
-- tplinks_by_domain
-- ============================================================================

-- tplinks_by_domain(domains_csv text)
--
-- Goal: list the third-party links from a set of in-scope domains: every
-- out-of-scope domain that the in-scope hosts point at through NS, CNAME, MX or
-- SRV records, or link to from their web pages, with the evidence for each
-- link and when it was last seen.
--
-- domains_csv is a comma-separated list of in-scope root domains, the same
-- format fqdn_by_domains takes, e.g. 'eset.com,eset.de,eset.co.uk'.
--
-- Returns one row per (other_domain, evidence):
--   other_domain  the out-of-scope registered domain (e.g. cloudflare.net)
--   evidence      '<in-scope host> -> <NS|CNAME|MX|SRV|LINK> -> <out-of-scope host>'
--   updated_at    when that link was last seen
--
-- The inner query is the tuned TP Links query, unchanged except that the
-- in-scope list comes from the domains_csv argument instead of the my.domains
-- session setting. The outer SELECT only casts the columns to the declared
-- result types, so the function works whether public_suffix_list.suffix is text
-- or citext. jit is turned off for the call, as the tuned query expects.
--
-- STRICT: a NULL argument returns no rows instead of erroring.
--
-- Usage:
--   SELECT *
--   FROM tplinks_by_domain('eset.co,eset.co.jp,eset.com,eset.co.uk,eset.de')
--   ORDER BY other_domain, evidence;

CREATE OR REPLACE FUNCTION public.tplinks_by_domain(domains_csv text)
    RETURNS TABLE (other_domain text, evidence text, updated_at timestamp)
    LANGUAGE plpgsql
    STABLE
    STRICT
    PARALLEL UNSAFE
    ROWS 1000
    SET jit = off
AS $BODY$
#variable_conflict use_column
BEGIN
    RETURN QUERY
    SELECT q.other_domain::text,
           q.evidence::text,
           q.updated_at::timestamp
    FROM (
        WITH target_fqdns AS (
            SELECT *
            FROM fqdn_by_domains(domains_csv)
        ),
        target_entities AS (
            SELECT e.entity_id, f.id AS fqdn_id, f.fqdn, f.reverse_fqdn
            FROM target_fqdns f
            JOIN entity e
              ON e.etype_id = 7
             AND e.row_id   = f.id
        ),
        dns_links AS (
            SELECT DISTINCT
                   te.fqdn              AS source_fqdn,
                   f_other.fqdn         AS other_fqdn,
                   f_other.reverse_fqdn AS other_reverse_fqdn,
                   (ed.content->'header'->>'rr_type')::int AS rr_type,
                   ed.updated_at        AS edge_updated_at
            FROM target_entities te
            JOIN edge ed
              ON ed.from_entity_id = te.entity_id
             AND (ed.content->'header'->>'rr_type')::int IN (2, 5, 15, 33)
            JOIN entity e_other
              ON e_other.entity_id = ed.to_entity_id
             AND e_other.etype_id = 7
            JOIN fqdn f_other
              ON f_other.id = e_other.row_id
            WHERE f_other.reverse_fqdn NOT LIKE 'apra.%'
        ),
        page_links AS (
            SELECT DISTINCT
                   te.fqdn              AS source_fqdn,
                   f_other.fqdn         AS other_fqdn,
                   f_other.reverse_fqdn AS other_reverse_fqdn,
                   -1                   AS rr_type,
                   ed_contains.updated_at AS edge_updated_at
            FROM target_entities te
            JOIN edge ed_origin
              ON ed_origin.to_entity_id = te.entity_id
             AND ed_origin.label = 'domain'
            JOIN entity e_origin_url
              ON e_origin_url.entity_id = ed_origin.from_entity_id
             AND e_origin_url.table_name = 'public.url'::citext
            JOIN edge ed_file
              ON ed_file.from_entity_id = e_origin_url.entity_id
             AND ed_file.label = 'file'
            JOIN edge ed_contains
              ON ed_contains.from_entity_id = ed_file.to_entity_id
             AND ed_contains.label = 'contains'
            JOIN edge ed_link_dom
              ON ed_link_dom.from_entity_id = ed_contains.to_entity_id
             AND ed_link_dom.label = 'domain'
            JOIN entity e_other
              ON e_other.entity_id = ed_link_dom.to_entity_id
             AND e_other.etype_id = 7
            JOIN fqdn f_other
              ON f_other.id = e_other.row_id
            WHERE f_other.reverse_fqdn NOT LIKE 'apra.%'
        ),
        fqdn_links AS (
            SELECT * FROM dns_links
            UNION
            SELECT * FROM page_links
        ),
        oos AS (
            SELECT fl.*
            FROM fqdn_links fl
            LEFT JOIN target_fqdns d
              ON d.reverse_fqdn = fl.other_reverse_fqdn
            WHERE d.id IS NULL
        ),
        psl_exact AS (
            SELECT suffix, suffix AS suffix_nostar
            FROM public.public_suffix_list
            WHERE is_icann
              AND suffix NOT LIKE '*.%'
        ),
        psl_wild AS (
            SELECT suffix, replace(suffix, '*.', '') AS suffix_nostar
            FROM public.public_suffix_list
            WHERE is_icann
              AND suffix LIKE '*.%'
        ),
        cands AS (
            SELECT
                o.*,
                array_to_string(labs[i:], '.') AS cand
            FROM oos o
            CROSS JOIN LATERAL (SELECT string_to_array(o.other_fqdn, '.') AS labs) s
            CROSS JOIN LATERAL generate_series(1, coalesce(array_length(s.labs, 1), 0)) AS i
        ),
        matched AS (
            SELECT c.source_fqdn, c.other_fqdn, c.other_reverse_fqdn,
                   c.rr_type, c.edge_updated_at, p.suffix, p.suffix_nostar
            FROM cands c
            JOIN psl_exact p ON p.suffix = c.cand
            UNION ALL
            SELECT c.source_fqdn, c.other_fqdn, c.other_reverse_fqdn,
                   c.rr_type, c.edge_updated_at, p.suffix, p.suffix_nostar
            FROM cands c
            JOIN psl_wild p ON p.suffix_nostar = c.cand
        ),
        best AS (
            SELECT DISTINCT ON (source_fqdn, other_fqdn, other_reverse_fqdn, rr_type, edge_updated_at)
                   source_fqdn, other_fqdn, other_reverse_fqdn, rr_type, edge_updated_at,
                   suffix, suffix_nostar
            FROM matched
            ORDER BY source_fqdn, other_fqdn, other_reverse_fqdn, rr_type, edge_updated_at,
                     length(suffix) DESC
        )
        SELECT
               CASE
                 WHEN array_length(string_to_array(b.other_fqdn, '.'), 1)
                    > array_length(string_to_array(b.suffix_nostar, '.'), 1)
                 THEN split_part(
                        b.other_fqdn, '.',
                        array_length(string_to_array(b.other_fqdn, '.'), 1)
                          - array_length(string_to_array(b.suffix_nostar, '.'), 1)
                      ) || '.' || b.suffix_nostar
                 ELSE b.suffix_nostar
               END AS other_domain,
               b.source_fqdn
                 || ' -> '
                 || CASE b.rr_type
                      WHEN 2  THEN 'NS'
                      WHEN 5  THEN 'CNAME'
                      WHEN 15 THEN 'MX'
                      WHEN 33 THEN 'SRV'
                      WHEN -1 THEN 'LINK'
                      ELSE 'OTHER'
                    END
                 || ' -> '
                 || b.other_fqdn AS evidence,
               max(b.edge_updated_at) AS updated_at
        FROM best b
        GROUP BY 1, 2
        ORDER BY 1, 2
    ) q
    ORDER BY 1, 2;
END;
$BODY$;

COMMENT ON FUNCTION public.tplinks_by_domain(text) IS
    'Third-party links from the given in-scope domains (comma-separated): out-of-scope domain, evidence (host -> NS/CNAME/MX/SRV/LINK -> host) and last-seen time.';

ALTER FUNCTION public.tplinks_by_domain(text)
    OWNER TO postgres;

-- ============================================================================
-- other_domains_by_inscope_domains
-- ============================================================================

-- other_domains_by_inscope_domains(domains_csv text)
--
-- Goal: list the out-of-scope domains that a set of in-scope domains links to
-- (via NS, CNAME, MX, SRV records or page links) that are not yet tracked
-- anywhere in the database, i.e. that appear in no company's
-- public.domains.domain.
--
-- domains_csv is a comma-separated list of in-scope root domains, the same
-- format fqdn_by_domains takes, e.g. 'wpengine.com,wpengine.io,studiopress.com'.
--
-- The inner query is the tuned out-of-scope links query, unchanged except that
-- the in-scope list comes from the domains_csv argument instead of the
-- my.domains session setting. The outer query (1) deduplicates its
-- other_domain column, (2) removes every domain already present in
-- public.domains for ANY company, and (3) returns just the remaining domains.
-- All matching is case-insensitive: values are lowercased and compared as
-- citext. jit is turned off for the call, as the tuned query expects.
--
-- STRICT: a NULL argument returns no rows instead of erroring.
--
-- Usage:
--   SELECT domain
--   FROM other_domains_by_inscope_domains(
--       'studiopress.com,weproxy.com,wpengine.com,wpengine.io,wpengine.net,'
--       'wpengine.org,wpenginepowered.com,wpeproxy.com,wpesvc.net')
--   ORDER BY domain;

CREATE OR REPLACE FUNCTION public.other_domains_by_inscope_domains(domains_csv text)
    RETURNS TABLE (domain citext)
    LANGUAGE plpgsql
    STABLE
    STRICT
    PARALLEL UNSAFE
    ROWS 1000
    SET jit = off
AS $BODY$
#variable_conflict use_column
BEGIN
    RETURN QUERY
    SELECT DISTINCT lower(q.other_domain)::citext AS domain
    FROM (
        WITH target_fqdns AS (
            SELECT *
            FROM fqdn_by_domains(domains_csv)
        ),
        target_entities AS (
            SELECT e.entity_id, f.id AS fqdn_id, f.fqdn, f.reverse_fqdn
            FROM target_fqdns f
            JOIN entity e
              ON e.etype_id = 7
             AND e.row_id   = f.id
        ),
        dns_links AS (
            SELECT DISTINCT
                   te.fqdn              AS source_fqdn,
                   f_other.fqdn         AS other_fqdn,
                   f_other.reverse_fqdn AS other_reverse_fqdn,
                   (ed.content->'header'->>'rr_type')::int AS rr_type,
                   ed.updated_at        AS edge_updated_at
            FROM target_entities te
            JOIN edge ed
              ON ed.from_entity_id = te.entity_id
             AND (ed.content->'header'->>'rr_type')::int IN (2, 5, 15, 33)
            JOIN entity e_other
              ON e_other.entity_id = ed.to_entity_id
             AND e_other.etype_id = 7
            JOIN fqdn f_other
              ON f_other.id = e_other.row_id
            WHERE f_other.reverse_fqdn NOT LIKE 'apra.%'
        ),
        page_links AS (
            SELECT DISTINCT
                   te.fqdn              AS source_fqdn,
                   f_other.fqdn         AS other_fqdn,
                   f_other.reverse_fqdn AS other_reverse_fqdn,
                   -1                   AS rr_type,
                   ed_contains.updated_at AS edge_updated_at
            FROM target_entities te
            JOIN edge ed_origin
              ON ed_origin.to_entity_id = te.entity_id
             AND ed_origin.label = 'domain'
            JOIN entity e_origin_url
              ON e_origin_url.entity_id = ed_origin.from_entity_id
             AND e_origin_url.table_name = 'public.url'::citext
            JOIN edge ed_file
              ON ed_file.from_entity_id = e_origin_url.entity_id
             AND ed_file.label = 'file'
            JOIN edge ed_contains
              ON ed_contains.from_entity_id = ed_file.to_entity_id
             AND ed_contains.label = 'contains'
            JOIN edge ed_link_dom
              ON ed_link_dom.from_entity_id = ed_contains.to_entity_id
             AND ed_link_dom.label = 'domain'
            JOIN entity e_other
              ON e_other.entity_id = ed_link_dom.to_entity_id
             AND e_other.etype_id = 7
            JOIN fqdn f_other
              ON f_other.id = e_other.row_id
            WHERE f_other.reverse_fqdn NOT LIKE 'apra.%'
        ),
        fqdn_links AS (
            SELECT * FROM dns_links
            UNION
            SELECT * FROM page_links
        ),
        oos AS (
            SELECT fl.*
            FROM fqdn_links fl
            LEFT JOIN target_fqdns d
              ON d.reverse_fqdn = fl.other_reverse_fqdn
            WHERE d.id IS NULL
        ),
        psl_exact AS (
            SELECT suffix, suffix AS suffix_nostar
            FROM public.public_suffix_list
            WHERE is_icann
              AND suffix NOT LIKE '*.%'
        ),
        psl_wild AS (
            SELECT suffix, replace(suffix, '*.', '') AS suffix_nostar
            FROM public.public_suffix_list
            WHERE is_icann
              AND suffix LIKE '*.%'
        ),
        cands AS (
            SELECT
                o.*,
                array_to_string(labs[i:], '.') AS cand
            FROM oos o
            CROSS JOIN LATERAL (SELECT string_to_array(o.other_fqdn, '.') AS labs) s
            CROSS JOIN LATERAL generate_series(1, coalesce(array_length(s.labs, 1), 0)) AS i
        ),
        matched AS (
            SELECT c.source_fqdn, c.other_fqdn, c.other_reverse_fqdn,
                   c.rr_type, c.edge_updated_at, p.suffix, p.suffix_nostar
            FROM cands c
            JOIN psl_exact p ON p.suffix = c.cand
            UNION ALL
            SELECT c.source_fqdn, c.other_fqdn, c.other_reverse_fqdn,
                   c.rr_type, c.edge_updated_at, p.suffix, p.suffix_nostar
            FROM cands c
            JOIN psl_wild p ON p.suffix_nostar = c.cand
        ),
        best AS (
            SELECT DISTINCT ON (source_fqdn, other_fqdn, other_reverse_fqdn, rr_type, edge_updated_at)
                   source_fqdn, other_fqdn, other_reverse_fqdn, rr_type, edge_updated_at,
                   suffix, suffix_nostar
            FROM matched
            ORDER BY source_fqdn, other_fqdn, other_reverse_fqdn, rr_type, edge_updated_at,
                     length(suffix) DESC
        )
        SELECT
               CASE
                 WHEN array_length(string_to_array(b.other_fqdn, '.'), 1)
                    > array_length(string_to_array(b.suffix_nostar, '.'), 1)
                 THEN split_part(
                        b.other_fqdn, '.',
                        array_length(string_to_array(b.other_fqdn, '.'), 1)
                          - array_length(string_to_array(b.suffix_nostar, '.'), 1)
                      ) || '.' || b.suffix_nostar
                 ELSE b.suffix_nostar
               END AS other_domain,
               b.source_fqdn
                 || ' -> '
                 || CASE b.rr_type
                      WHEN 2  THEN 'NS'
                      WHEN 5  THEN 'CNAME'
                      WHEN 15 THEN 'MX'
                      WHEN 33 THEN 'SRV'
                      WHEN -1 THEN 'LINK'
                      ELSE 'OTHER'
                    END
                 || ' -> '
                 || b.other_fqdn AS evidence,
               max(b.edge_updated_at) AS updated_at
        FROM best b
        GROUP BY 1, 2
        ORDER BY 1, 2
    ) q
    WHERE q.other_domain IS NOT NULL
      -- Drop any domain already tracked for any company (citext = citext, so
      -- the comparison is case-insensitive).
      AND NOT EXISTS (
          SELECT 1
          FROM public.domains d
          WHERE d.domain = lower(q.other_domain)::citext
      )
    ORDER BY 1;
END;
$BODY$;

COMMENT ON FUNCTION public.other_domains_by_inscope_domains(text) IS
    'Out-of-scope domains linked from the given in-scope domains (comma-separated) that are not tracked in public.domains for any company. Case-insensitive.';

ALTER FUNCTION public.other_domains_by_inscope_domains(text)
    OWNER TO postgres;

-- ============================================================================
-- techstack_by_domains
-- ============================================================================

-- techstack_by_domains(domains_csv text)
--
-- Goal: list the technology stack of a set of in-scope domains: for every host
-- under those domains, each service found on it (on the host itself or on one
-- of its A/AAAA addresses) and the products identified on that service, with
-- the product's type, release, icon, website and CPE, the ports it was seen on,
-- the plugins that identified it, and when it was last seen on that host.
--
-- domains_csv is a comma-separated list of in-scope root domains, the same
-- format fqdn_by_domains takes, e.g. 'buffalo.edu,campaignforub.org'.
--
-- Returns one row per (fqdn, service_type, product_name, product_type):
--   fqdn, updated_at, service_type, port, product_name, product_type,
--   product_release, icon, website, cpe, identified_by
--
-- The body is the tuned Tech-Stack script, unchanged except that:
--   * the in-scope list comes from the domains_csv argument instead of the
--     my.domains session setting;
--   * the lookup-table check that was a DO block runs at the start of the body;
--   * the final SELECT is returned by RETURN QUERY, with its columns cast to the
--     declared result types (so the function works whether the source columns
--     are text or citext);
--   * the temp tables are dropped once the result has been produced.
-- Each intermediate set is still a temp table with ANALYZE, so the joins are
-- planned from real row counts, exactly as in the script.
--
-- Because it creates temp tables, the function is VOLATILE and cannot run in a
-- read-only transaction or on a hot standby. It uses the same temp-table names
-- as the script (tmp_hosts, tmp_ip_map, ...) and drops them, so do not call it
-- while you are still using tables of those names from the script in the same
-- session. jit is turned off for the call, as the tuned script expects, and the
-- "table does not exist, skipping" notices from DROP TABLE IF EXISTS are hidden.
--
-- STRICT: a NULL argument returns no rows instead of erroring.
--
-- Usage:
--   SELECT *
--   FROM techstack_by_domains('boldlybuffalo.com,buffalobold.net,buffalo.edu,campaignforub.org')
--   ORDER BY fqdn, port;

CREATE OR REPLACE FUNCTION public.techstack_by_domains(domains_csv text)
    RETURNS TABLE (
        fqdn            text,
        updated_at      timestamp,
        service_type    text,
        port            text,
        product_name    text,
        product_type    text,
        product_release text,
        icon            text,
        website         text,
        cpe             text,
        identified_by   text
    )
    LANGUAGE plpgsql
    VOLATILE
    STRICT
    PARALLEL UNSAFE
    ROWS 1000
    SET jit = off
    SET client_min_messages = warning
AS $BODY$
#variable_conflict use_column
BEGIN
        IF (SELECT array_agg(id ORDER BY id) FROM entity_type_lu
            WHERE name IN ('fqdn','ipaddress','product','productrelease','service'))
           IS DISTINCT FROM ARRAY[7,10,17,18,19]::smallint[]
        OR (SELECT array_agg(id ORDER BY id) FROM edge_type_lu
            WHERE name IN ('basicdnsrelation','portrelation','simplerelation'))
           IS DISTINCT FROM ARRAY[1,2,4]::smallint[]
        OR (SELECT array_agg(id ORDER BY id) FROM tag_type_lu
            WHERE name IN ('simpleproperty','sourceproperty'))
           IS DISTINCT FROM ARRAY[2,3]::smallint[] THEN
            RAISE EXCEPTION 'unexpected type ids in the lookup tables; update the constants in this function';
        END IF;

    DROP TABLE IF EXISTS tmp_hosts;
    CREATE TEMP TABLE tmp_hosts AS
    SELECT f.fqdn::text AS host, e.entity_id
    FROM fqdn_by_domains(domains_csv) f
    CROSS JOIN LATERAL (
        SELECT e.entity_id FROM entity e
        WHERE e.etype_id = 7 AND e.row_id = f.id          -- entity_etype_id_row_id_key
        OFFSET 0
    ) e;
    ANALYZE tmp_hosts;

    -- Each host's addresses (A = 1, AAAA = 28).
    DROP TABLE IF EXISTS tmp_ip_map;
    CREATE TEMP TABLE tmp_ip_map AS
    SELECT DISTINCT h.host, d.ip_entity_id
    FROM tmp_hosts h
    CROSS JOIN LATERAL (
        SELECT ed.to_entity_id AS ip_entity_id
        FROM edge ed
        WHERE ed.from_entity_id = h.entity_id
          AND ed.etype_id = 1                             -- basicdnsrelation
          AND ed.label = 'dns_record'
          AND ed.content -> 'header' ->> 'rr_type' IN ('1', '28')
        OFFSET 0
    ) d;
    ANALYZE tmp_ip_map;

    -- Services on each host: keyed by the FQDN itself, or by one of its addresses.
    DROP TABLE IF EXISTS tmp_svc;
    CREATE TEMP TABLE tmp_svc AS
    SELECT DISTINCT x.host, x.svc_entity_id, x.port
    FROM (
        SELECT h.host, p.svc_entity_id, p.port
        FROM tmp_hosts h
        CROSS JOIN LATERAL (
            SELECT ed.to_entity_id AS svc_entity_id, (ed.content ->> 'port_number')::int AS port
            FROM edge ed
            WHERE ed.from_entity_id = h.entity_id
              AND ed.etype_id = 2                         -- portrelation
            OFFSET 0
        ) p
        UNION ALL
        SELECT m.host, p.svc_entity_id, p.port
        FROM tmp_ip_map m
        CROSS JOIN LATERAL (
            SELECT ed.to_entity_id AS svc_entity_id, (ed.content ->> 'port_number')::int AS port
            FROM edge ed
            WHERE ed.from_entity_id = m.ip_entity_id
              AND ed.etype_id = 2
            OFFSET 0
        ) p
    ) x;
    ANALYZE tmp_svc;

    -- Each intermediate set is a temp table with ANALYZE, so the joins below are
    -- planned from real row counts. (CTE results have no statistics: the planner
    -- guesses a few dozen rows and picks nested loops that compare every row of one
    -- set against every row of another.)

    -- Service type, once per service.
    DROP TABLE IF EXISTS tmp_svc_type;
    CREATE TEMP TABLE tmp_svc_type AS
    SELECT s.svc_entity_id, r.service_type
    FROM (SELECT DISTINCT svc_entity_id FROM tmp_svc) s
    CROSS JOIN LATERAL (
        SELECT srv.service_type
        FROM entity e
        JOIN service srv ON srv.id = e.row_id
        WHERE e.entity_id = s.svc_entity_id AND e.etype_id = 19
        OFFSET 0
    ) r;
    ANALYZE tmp_svc_type;

    -- Every product_used edge of every service, read once, with its target's type
    -- and when it was last updated (the product last observed on that service).
    DROP TABLE IF EXISTS tmp_used;
    CREATE TEMP TABLE tmp_used AS
    SELECT s.svc_entity_id, u.edge_id, u.to_id, u.updated_at, t.etype_id, t.row_id, t.natural_key
    FROM tmp_svc_type s
    CROSS JOIN LATERAL (
        SELECT ed.edge_id, ed.to_entity_id AS to_id, ed.updated_at
        FROM edge ed
        WHERE ed.from_entity_id = s.svc_entity_id
          AND ed.etype_id = 4                             -- simplerelation
          AND ed.label = 'product_used'
        OFFSET 0
    ) u
    CROSS JOIN LATERAL (
        SELECT e.etype_id, e.row_id, e.natural_key::text AS natural_key
        FROM entity e
        WHERE e.entity_id = u.to_id
        OFFSET 0
    ) t;
    ANALYZE tmp_used;

    -- Product rows and properties, once per product.
    DROP TABLE IF EXISTS tmp_prod;
    CREATE TEMP TABLE tmp_prod AS
    SELECT pe.prod_entity, p.product_name, p.product_type, tg.icon, tg.website, tg.cpe
    FROM (SELECT DISTINCT to_id AS prod_entity, row_id FROM tmp_used WHERE etype_id = 17) pe
    CROSS JOIN LATERAL (
        SELECT product_name, product_type FROM product WHERE id = pe.row_id OFFSET 0
    ) p
    CROSS JOIN LATERAL (
        SELECT (array_agg(t.property_value ORDER BY t.updated_at DESC) FILTER (WHERE t.property_name = 'icon'))[1]    AS icon,
               (array_agg(t.property_value ORDER BY t.updated_at DESC) FILTER (WHERE t.property_name = 'website'))[1] AS website,
               (array_agg(t.property_value ORDER BY t.updated_at DESC) FILTER (WHERE t.property_name = 'cpe'))[1]     AS cpe
        FROM entity_tag t
        WHERE t.entity_id = pe.prod_entity                -- unique key (entity_id, ttype_id, property_name, ...)
          AND t.ttype_id = 2                              -- simpleproperty
          AND t.property_name IN ('icon', 'website', 'cpe')
    ) tg;
    ANALYZE tmp_prod;

    -- For each (service, product): the release the service uses that the product
    -- links to (exact match on the edge unique key (etype_id, from, to, label)).
    DROP TABLE IF EXISTS tmp_rel;
    CREATE TEMP TABLE tmp_rel AS
    SELECT DISTINCT ON (up.svc_entity_id, up.to_id)
           up.svc_entity_id, up.to_id AS prod_entity, ur.natural_key AS product_release
    FROM tmp_used up
    JOIN tmp_used ur ON ur.svc_entity_id = up.svc_entity_id AND ur.etype_id = 18
    WHERE up.etype_id = 17
      AND EXISTS (
          SELECT 1 FROM edge x
          WHERE x.etype_id = 4 AND x.from_entity_id = up.to_id
            AND x.to_entity_id = ur.to_id AND x.label = 'release'
      )
    ORDER BY up.svc_entity_id, up.to_id, length(ur.natural_key) DESC, ur.natural_key DESC;
    ANALYZE tmp_rel;

    -- Which plugins identified each product on each service (source tags on the
    -- product_used edge).
    DROP TABLE IF EXISTS tmp_src;
    CREATE TEMP TABLE tmp_src AS
    SELECT u.edge_id, et.property_name AS source
    FROM tmp_used u
    CROSS JOIN LATERAL (
        SELECT et.property_name
        FROM edge_tag et
        WHERE et.edge_id = u.edge_id                      -- unique key (edge_id, ttype_id, property_name, ...)
          AND et.ttype_id = 3                             -- sourceproperty
          AND et.property_name IN ('Protocol-Probes', 'Tech-Stack')
        OFFSET 0
    ) et
    WHERE u.etype_id = 17;
    ANALYZE tmp_src;

    RETURN QUERY
    SELECT q.fqdn::text,
           q.updated_at::timestamp,
           q.service_type::text,
           q.port::text,
           q.product_name::text,
           q.product_type::text,
           q.product_release::text,
           q.icon::text,
           q.website::text,
           q.cpe::text,
           q.identified_by::text
    FROM (
        SELECT
            s.host AS fqdn,
            MAX(u.updated_at)::timestamp(0) AS updated_at,  -- latest sighting of the product on this host
            sv.service_type,
            string_agg(DISTINCT s.port::text, ',') AS port,
            p.product_name,
            p.product_type,
            MAX(r.product_release) AS product_release,
            MAX(p.icon) AS icon,
            MAX(p.website) AS website,
            MAX(p.cpe) AS cpe,
            string_agg(DISTINCT sr.source, ',' ORDER BY sr.source) AS identified_by
        FROM tmp_svc s
        JOIN tmp_svc_type sv ON sv.svc_entity_id = s.svc_entity_id
        JOIN tmp_used u ON u.svc_entity_id = s.svc_entity_id AND u.etype_id = 17
        JOIN tmp_prod p ON p.prod_entity = u.to_id
        LEFT JOIN tmp_rel r ON r.svc_entity_id = s.svc_entity_id AND r.prod_entity = u.to_id
        LEFT JOIN tmp_src sr ON sr.edge_id = u.edge_id
        GROUP BY s.host, sv.service_type, p.product_name, p.product_type
        ORDER BY 1, 4
    ) q
    ORDER BY 1, 4;

    -- The result is already collected; the scratch tables are no longer needed.
    DROP TABLE IF EXISTS tmp_hosts;
    DROP TABLE IF EXISTS tmp_ip_map;
    DROP TABLE IF EXISTS tmp_svc;
    DROP TABLE IF EXISTS tmp_svc_type;
    DROP TABLE IF EXISTS tmp_used;
    DROP TABLE IF EXISTS tmp_prod;
    DROP TABLE IF EXISTS tmp_rel;
    DROP TABLE IF EXISTS tmp_src;
END;
$BODY$;

COMMENT ON FUNCTION public.techstack_by_domains(text) IS
    'Tech stack of the given in-scope domains (comma-separated): per host, service and product, with type, release, icon, website, CPE, ports, identifying plugins and last-seen time.';

ALTER FUNCTION public.techstack_by_domains(text)
    OWNER TO postgres;

COMMIT;
