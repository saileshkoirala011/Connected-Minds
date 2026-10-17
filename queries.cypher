-- GraphSentinel: Reference Cypher Queries
-- All queries parameterised with $param notation (FalkorDB / openCypher).
-- Source of truth is queries.py; this file is for submission reference.

-- ============================================================
-- 1. SCHEMA INDEXES (run once at startup)
-- ============================================================
CREATE INDEX FOR (n:File)      ON (n.repo, n.path);
CREATE INDEX FOR (n:Function)  ON (n.repo, n.qualname);
CREATE INDEX FOR (n:Package)   ON (n.repo, n.name);
CREATE INDEX FOR (n:Vuln)      ON (n.id);
CREATE INDEX FOR (n:IngestJob) ON (n.id);
CREATE INDEX FOR (n:Repo)      ON (n.repo);

-- ============================================================
-- 2. HEALTH
-- ============================================================
RETURN 1 AS ok;

-- ============================================================
-- 3. REPO STATS (get_repo_summary)
-- ============================================================
MATCH (r:Repo {repo: $repo})
OPTIONAL MATCH (r)-[:CONTAINS]->(f:File)
OPTIONAL MATCH (f)-[:DEFINES]->(fn:Function)
OPTIONAL MATCH (r)-[:DEPENDS_ON]->(pkg:Package)
OPTIONAL MATCH (pkg)<-[:AFFECTS]-(v:Vuln)
RETURN
    r.ingested_at                    AS ingested_at,
    count(DISTINCT f)                AS file_count,
    count(DISTINCT fn)               AS function_count,
    count(DISTINCT pkg)              AS package_count,
    count(DISTINCT v)                AS vuln_count;

-- Entry point count (get_entry_point_count)
MATCH (fn:Function {repo: $repo, is_entry: true})
RETURN count(fn) AS n;

-- ============================================================
-- 4. MOST-IMPORTED FILES (most_imported_files)
-- ============================================================
MATCH (a:File {repo: $repo})-[:IMPORTS]->(b:File {repo: $repo})
RETURN b.path AS path, count(a) AS importers
ORDER BY importers DESC
LIMIT $limit;

-- ============================================================
-- 5. BLAST RADIUS — file dependents (find_file_dependents)
-- ============================================================
MATCH (f:File {repo: $repo, path: $path})<-[:IMPORTS*1..6]-(d:File {repo: $repo})
RETURN DISTINCT d.path AS path
ORDER BY path;

-- ============================================================
-- 6. TRANSITIVE DEPENDENCIES — file deps (find_file_dependencies)
-- ============================================================
MATCH p = (f:File {repo: $repo, path: $path})-[:IMPORTS*1..6]->(dep:File {repo: $repo})
RETURN DISTINCT dep.path AS path, min(length(p)) AS depth
ORDER BY depth, path;

-- ============================================================
-- 7. CIRCULAR IMPORTS (find_circular_imports)
-- ============================================================
MATCH p = (a:File {repo: $repo})-[:IMPORTS*2..6]->(a)
RETURN DISTINCT a.path AS path
LIMIT $limit;

-- ============================================================
-- 8. VULNERABILITY LIST (list_vulnerabilities)
-- ============================================================
MATCH (r:Repo {repo: $repo})-[:DEPENDS_ON]->(pkg:Package)
MATCH (v:Vuln)-[:AFFECTS]->(pkg)
RETURN v.id       AS vuln_id,
       v.severity AS severity,
       v.summary  AS summary,
       pkg.name   AS package,
       pkg.version AS version
ORDER BY
    CASE v.severity
        WHEN 'critical' THEN 0
        WHEN 'high'     THEN 1
        WHEN 'medium'   THEN 2
        WHEN 'low'      THEN 3
        ELSE                 4
    END,
    pkg.name
LIMIT $limit;

-- ============================================================
-- 9a. REACHABLE VULNERABILITIES via call graph (reachable_vulns)
-- ============================================================
MATCH (e:Function {repo: $repo, is_entry: true})
MATCH p = (e)-[:CALLS*0..8]->(fn:Function {repo: $repo})
MATCH (f:File {repo: $repo, path: fn.file})-[:USES]->(pkg:Package {repo: $repo})
MATCH (v:Vuln)-[:AFFECTS]->(pkg)
RETURN DISTINCT
       v.id           AS vuln_id,
       v.severity     AS severity,
       v.summary      AS summary,
       pkg.name       AS package,
       f.path         AS file_path,
       e.qualname     AS entry_qualname,
       length(p)      AS call_depth
ORDER BY
    CASE v.severity
        WHEN 'critical' THEN 0
        WHEN 'high'     THEN 1
        WHEN 'medium'   THEN 2
        WHEN 'low'      THEN 3
        ELSE                 4
    END,
    call_depth
LIMIT $limit;

-- ============================================================
-- 9b. IMPORT-ONLY EXPOSURE fallback (import_only_vulns)
-- ============================================================
MATCH (f:File {repo: $repo})-[:USES]->(pkg:Package {repo: $repo})
MATCH (v:Vuln)-[:AFFECTS]->(pkg)
RETURN DISTINCT
       v.id       AS vuln_id,
       v.severity AS severity,
       pkg.name   AS package,
       f.path     AS file_path
ORDER BY
    CASE v.severity
        WHEN 'critical' THEN 0
        WHEN 'high'     THEN 1
        WHEN 'medium'   THEN 2
        WHEN 'low'      THEN 3
        ELSE                 4
    END
LIMIT $limit;

-- ============================================================
-- 10. SHORTEST PATH between two files (shortest_path_between)
-- ============================================================
MATCH (a:File {repo: $repo, path: $from_path}),
      (b:File {repo: $repo, path: $to_path})
MATCH p = shortestPath((a)-[*..10]-(b))
RETURN [n IN nodes(p) | {label: labels(n)[0], path: n.path, qualname: n.qualname}]
       AS path_nodes;

-- ============================================================
-- 11. RISK SCORING helpers
-- ============================================================

-- Package blast radius (package_blast_radius)
MATCH (pkg:Package {repo: $repo, name: $package_name})
MATCH (f:File {repo: $repo})-[:USES]->(pkg)
RETURN count(DISTINCT f) AS blast_radius;

-- Package reachability count (package_reachability_count)
MATCH (pkg:Package {repo: $repo, name: $package_name})
MATCH (f:File {repo: $repo})-[:USES]->(pkg)
MATCH (fn:Function {repo: $repo, file: f.path})
MATCH (caller:Function {repo: $repo})-[:CALLS*0..8]->(fn)
RETURN count(DISTINCT caller) AS reachable_fns;

-- Package import count (package_import_count)
MATCH (f:File {repo: $repo})-[:USES]->(pkg:Package {repo: $repo, name: $package_name})
RETURN count(f) AS import_count;

-- ============================================================
-- 12. INGEST JOB STATUS
-- ============================================================

-- Get ingest job (get_ingest_job)
MATCH (j:IngestJob {id: $job_id})
RETURN j.id          AS id,
       j.repo        AS repo,
       j.status      AS status,
       j.step        AS step,
       j.error       AS error,
       j.started_at  AS started_at,
       j.finished_at AS finished_at;

-- List all repos (list_repos)
MATCH (r:Repo)
RETURN r.repo           AS repo,
       r.url            AS url,
       r.ingested_at    AS ingested_at,
       r.file_count     AS file_count,
       r.function_count AS function_count
ORDER BY r.ingested_at DESC;
