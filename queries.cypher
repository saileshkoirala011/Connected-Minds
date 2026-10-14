// ============================================================
// queries.cypher — GraphSentinel submission artifact
//
// Every query the product depends on, in one file.
// These are the exact parameterised strings from queries.py.
// Node model: Repo, File, Function, Package, Vuln, IngestJob
// Relationships: CONTAINS, DEFINES, IMPORTS, USES, CALLS,
//                DEPENDS_ON, AFFECTS
// FalkorDB syntax: openCypher, parameters as $name.
// ============================================================


// ------------------------------------------------------------
// SECTION 1: INDEXES (run once at startup)
// ------------------------------------------------------------

CREATE INDEX FOR (n:File)      ON (n.repo, n.path);
CREATE INDEX FOR (n:Function)  ON (n.repo, n.qualname);
CREATE INDEX FOR (n:Package)   ON (n.repo, n.name);
CREATE INDEX FOR (n:Vuln)      ON (n.id);
CREATE INDEX FOR (n:IngestJob) ON (n.id);
CREATE INDEX FOR (n:Repo)      ON (n.repo);


// ------------------------------------------------------------
// SECTION 2: HEALTH CHECK
// ------------------------------------------------------------

RETURN 1 AS ok;


// ------------------------------------------------------------
// SECTION 3: REPO STATS
// tool: get_repo_summary($repo)
// ------------------------------------------------------------

MATCH (r:Repo {repo: $repo})
OPTIONAL MATCH (r)-[:CONTAINS]->(f:File)
OPTIONAL MATCH (f)-[:DEFINES]->(fn:Function)
OPTIONAL MATCH (r)-[:DEPENDS_ON]->(pkg:Package)
OPTIONAL MATCH (pkg)<-[:AFFECTS]-(v:Vuln)
RETURN
    r.ingested_at             AS ingested_at,
    count(DISTINCT f)         AS file_count,
    count(DISTINCT fn)        AS function_count,
    count(DISTINCT pkg)       AS package_count,
    count(DISTINCT v)         AS vuln_count;


// ------------------------------------------------------------
// SECTION 4: MOST-IMPORTED FILES (structural hotspots)
// tool: most_imported($repo, $limit)
// ------------------------------------------------------------

MATCH (a:File {repo: $repo})-[:IMPORTS]->(b:File {repo: $repo})
RETURN b.path AS path, count(a) AS importers
ORDER BY importers DESC
LIMIT $limit;


// ------------------------------------------------------------
// SECTION 5: BLAST RADIUS — file dependents
// tool: find_dependents($repo, $path)
// Answers: "What breaks if I change this file?"
// ------------------------------------------------------------

MATCH (f:File {repo: $repo, path: $path})<-[:IMPORTS*1..6]-(d:File {repo: $repo})
RETURN DISTINCT d.path AS path
ORDER BY path;


// ------------------------------------------------------------
// SECTION 6: TRANSITIVE FILE DEPENDENCIES
// tool: find_dependencies($repo, $path)
// ------------------------------------------------------------

MATCH p = (f:File {repo: $repo, path: $path})-[:IMPORTS*1..6]->(dep:File {repo: $repo})
RETURN DISTINCT dep.path AS path, min(length(p)) AS depth
ORDER BY depth, path;


// ------------------------------------------------------------
// SECTION 7: CIRCULAR IMPORTS
// tool: find_cycles($repo)
// Answers: "Are there circular imports?"
// ------------------------------------------------------------

MATCH p = (a:File {repo: $repo})-[:IMPORTS*2..6]->(a)
RETURN DISTINCT a.path AS path
LIMIT 50;


// ------------------------------------------------------------
// SECTION 8: ALL VULNERABILITIES FOR A REPO
// tool: list_vulns($repo, $limit)
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// SECTION 9: REACHABLE VULNERABILITIES (via call graph)
// tool: reachable_vulns($repo, $limit)
// Answers: "Which vulnerabilities are reachable from entry points?"
// This is the demo money query — chains Function → File → Package → Vuln.
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// SECTION 9b: IMPORT-ONLY EXPOSURE (fallback, no call graph)
// tool: reachable_vulns fallback when CALLS are unresolved
// ------------------------------------------------------------

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


// ------------------------------------------------------------
// SECTION 10: SHORTEST PATH between two files
// tool: explain_path($repo, $from_path, $to_path)
// ------------------------------------------------------------

MATCH (a:File {repo: $repo, path: $from_path}),
      (b:File {repo: $repo, path: $to_path})
MATCH p = shortestPath((a)-[*..10]-(b))
RETURN [n IN nodes(p) | {label: labels(n)[0], path: n.path, qualname: n.qualname}]
       AS path_nodes;


// ------------------------------------------------------------
// SECTION 11: RISK SCORING INPUTS (graph-derived, not Python-calc)
// used by ingest/risk_scorer.py
// Rule 3: scoring must come from graph queries, not parsed data alone.
// ------------------------------------------------------------

// 11a: Blast radius — files that use a package
MATCH (pkg:Package {repo: $repo, name: $package_name})
MATCH (f:File {repo: $repo})-[:USES]->(pkg)
RETURN count(DISTINCT f) AS blast_radius;

// 11b: Reachability count — functions that can reach this package
MATCH (pkg:Package {repo: $repo, name: $package_name})
MATCH (f:File {repo: $repo})-[:USES]->(pkg)
MATCH (fn:Function {repo: $repo, file: f.path})
MATCH (caller:Function {repo: $repo})-[:CALLS*0..8]->(fn)
RETURN count(DISTINCT caller) AS reachable_fns;

// 11c: Direct import count (shallow exposure)
MATCH (f:File {repo: $repo})-[:USES]->(pkg:Package {repo: $repo, name: $package_name})
RETURN count(f) AS import_count;


// ------------------------------------------------------------
// SECTION 12: INGEST WRITE PATTERNS
// (used by ingest/graph_writer.py; idempotent via MERGE)
// ------------------------------------------------------------

// Upsert Repo node
MERGE (r:Repo {repo: $repo})
SET r.url = $url, r.ingested_at = $ingested_at,
    r.file_count = $file_count, r.function_count = $function_count;

// Batch-upsert File nodes
UNWIND $files AS f
MERGE (n:File {repo: $repo, path: f.path})
SET n.loc = f.loc, n.parse_ok = f.parse_ok;

// Batch-upsert Function nodes
UNWIND $functions AS fn
MERGE (n:Function {repo: $repo, qualname: fn.qualname})
SET n.file = fn.file, n.lineno = fn.lineno, n.is_entry = fn.is_entry;

// Batch-create CONTAINS edges (Repo → File)
UNWIND $files AS f
MATCH (r:Repo {repo: $repo}), (n:File {repo: $repo, path: f.path})
MERGE (r)-[:CONTAINS]->(n);

// Batch-create DEFINES edges (File → Function)
UNWIND $functions AS fn
MATCH (f:File {repo: $repo, path: fn.file}),
      (n:Function {repo: $repo, qualname: fn.qualname})
MERGE (f)-[:DEFINES]->(n);

// Batch-create IMPORTS edges (File → File, internal)
UNWIND $edges AS e
MATCH (a:File {repo: $repo, path: e.src}),
      (b:File {repo: $repo, path: e.dst})
MERGE (a)-[:IMPORTS]->(b);

// Batch-create USES edges (File → Package)
UNWIND $uses AS u
MATCH (f:File {repo: $repo, path: u.file}),
      (p:Package {repo: $repo, name: u.package})
MERGE (f)-[:USES]->(p);

// Batch-create CALLS edges (Function → Function)
UNWIND $calls AS c
MATCH (a:Function {repo: $repo, qualname: c.caller}),
      (b:Function {repo: $repo, qualname: c.callee})
MERGE (a)-[:CALLS {resolved: c.resolved}]->(b);

// Upsert Package node
MERGE (p:Package {repo: $repo, name: $name})
SET p.version = $version, p.ecosystem = $ecosystem;

// DEPENDS_ON edge (Repo → Package)
MATCH (r:Repo {repo: $repo}), (p:Package {repo: $repo, name: $name})
MERGE (r)-[:DEPENDS_ON {declared_in: $declared_in}]->(p);

// Upsert Vuln node (shared across repos — keyed by id only)
MERGE (v:Vuln {id: $vuln_id})
SET v.summary  = $summary,
    v.severity = $severity,
    v.aliases  = $aliases,
    v.fixed_in = $fixed_in;

// AFFECTS edge (Vuln → Package) — note direction matches backend-schema.md
MATCH (v:Vuln {id: $vuln_id}),
      (p:Package {repo: $repo, name: $pkg_name})
MERGE (v)-[:AFFECTS {versions: $versions}]->(p);

// Re-ingest: delete all repo-scoped nodes (Vuln nodes shared, do NOT delete)
MATCH (n {repo: $repo}) DETACH DELETE n;


// ------------------------------------------------------------
// SECTION 13: INGEST JOB STATUS
// ------------------------------------------------------------

MATCH (j:IngestJob {id: $job_id})
RETURN j.id AS id, j.repo AS repo, j.status AS status,
       j.step AS step, j.error AS error,
       j.started_at AS started_at, j.finished_at AS finished_at;

MATCH (r:Repo)
RETURN r.repo AS repo, r.url AS url, r.ingested_at AS ingested_at,
       r.file_count AS file_count, r.function_count AS function_count
ORDER BY r.ingested_at DESC;
