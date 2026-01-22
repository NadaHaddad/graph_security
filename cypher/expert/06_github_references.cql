// CVEs whose references contain the word 'github'
MATCH (c:CVE)-[:HAS_LINK_TO]->(r:Reference)
WHERE toLower(r.url) CONTAINS "github"
RETURN c.id AS cve_id, r.url AS reference;