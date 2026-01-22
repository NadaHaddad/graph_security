// CVEs with base score >= 9 and their affected products
MATCH (c:CVE)-[:HAS_METRIC]->(m:Metric)
WHERE m.baseScore >= 9
MATCH (c)-[:AFFECTS]->(p:Product)
RETURN DISTINCT c.id AS cve_id, p.name AS product
ORDER BY cve_id;