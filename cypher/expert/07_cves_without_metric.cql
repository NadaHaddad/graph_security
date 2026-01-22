// CVEs missing a severity metric
MATCH (c:CVE)
WHERE NOT (c)-[:HAS_METRIC]->(:Metric)
RETURN c.id AS cve_id
ORDER BY cve_id;