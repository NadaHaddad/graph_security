// Count CVEs per publication year
MATCH (c:CVE)
RETURN substring(c.published, 0, 4) AS year, COUNT(*) AS total
ORDER BY year;