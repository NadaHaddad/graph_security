// CVEs that affect products from more than one vendor
MATCH (cve:CVE)-[:AFFECTS]->(p:Product)<-[:OWN]-(v:Vendor)
WITH cve, COUNT(DISTINCT v) AS vendorCount
WHERE vendorCount > 1
RETURN cve.id AS cveID, vendorCount
ORDER BY vendorCount DESC, cveID;