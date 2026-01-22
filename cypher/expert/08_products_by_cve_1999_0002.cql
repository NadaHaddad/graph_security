// Products affected by CVE-1999-0002
MATCH (c:CVE {id: "CVE-1999-0002"})-[:AFFECTS]->(p:Product)
RETURN p.name AS product
ORDER BY product;