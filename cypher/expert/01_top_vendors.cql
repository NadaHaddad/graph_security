// Top vendors by number of distinct CVEs affecting their products
MATCH (v:Vendor)-[:OWN]->(p:Product)<-[:AFFECTS]-(c:CVE)
WITH v, COUNT(DISTINCT c) AS cve_count
RETURN v.name AS vendor, cve_count
ORDER BY cve_count DESC
LIMIT 10;