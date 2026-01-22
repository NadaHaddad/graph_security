// Most frequent CWE categories
MATCH (c:CVE)-[:HAS_WEAKNESS]->(w:CWE)
RETURN w.id AS cwe, COUNT(DISTINCT c) AS freq
ORDER BY freq DESC
LIMIT 5;