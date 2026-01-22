// CVEs from 1999 whose description contains 'buffer'
MATCH (c:CVE)
WHERE
  c.published STARTS WITH "1999" AND toLower(c.description) CONTAINS "buffer"
RETURN c.id AS cve_id, c.description
ORDER BY cve_id;