// For each vendor, count distinct products and CVEs affecting them
MATCH (v:Vendor)-[:OWN]->(p:Product)
OPTIONAL MATCH (p)<-[:AFFECTS]-(c:CVE)
WITH
  v,
  COUNT(DISTINCT p) AS productsOwned,
  COUNT(DISTINCT c) AS cvesAffectingProducts
RETURN v.name AS vendorName, productsOwned, cvesAffectingProducts
ORDER BY cvesAffectingProducts DESC;