# ingest_to_neo4j.py
import json
from neo4j import GraphDatabase

# Connexion Neo4j
URI = "bolt://localhost:7687"
USER = "neo4j"
PASSWORD = "12345678"

driver = GraphDatabase.driver(URI, auth=(USER, PASSWORD))


# ----------------------------------------------------------
# 1) CREATION DES NOEUDS
# ----------------------------------------------------------

def create_cve(tx, cve_id, description, published, modified):
    tx.run("""
    MERGE (c:CVE {id:$cve_id})
    SET c.description = $description,
        c.published = $published,
        c.lastModified = $modified
    """, cve_id=cve_id, description=description,
         published=published, modified=modified)


def create_metric(tx, cve_id, base, exploit, impact, vector):
    tx.run("""
    MERGE (m:Metric {id:$cve_id})
    SET m.baseScore=$base,
        m.exploitabilityScore=$exploit,
        m.impactScore=$impact,
        m.vector=$vector
    WITH m
    MATCH (c:CVE {id:$cve_id})
    MERGE (c)-[:HAS_METRIC]->(m)
    """, cve_id=cve_id, base=base, exploit=exploit, impact=impact, vector=vector)


def create_product(tx, cve_id, product):
    tx.run("""
    MERGE (p:Product {name:$product})
    WITH p
    MATCH (c:CVE {id:$cve})
    MERGE (c)-[:AFFECTS]->(p)
    """, cve=cve_id, product=product)


def create_vendor(tx, vendor):
    tx.run("""
    MERGE (v:Vendor {name:$vendor})
    """, vendor=vendor)


def link_vendor_product(tx, vendor, product):
    tx.run("""
    MATCH (v:Vendor {name:$vendor})
    MATCH (p:Product {name:$product})
    MERGE (v)-[:OWN]->(p)
    """, vendor=vendor, product=product)


def create_reference(tx, cve_id, url, source):
    tx.run("""
    MERGE (r:Reference {url:$url})
    SET r.source=$source
    WITH r
    MATCH (c:CVE {id:$cve_id})
    MERGE (c)-[:HAS_LINK_TO]->(r)
    """, cve_id=cve_id, url=url, source=source)


def create_cwe(tx, cve_id, cwe_id):
    tx.run("""
    MERGE (w:CWE {id:$cwe_id})
    WITH w
    MATCH (c:CVE {id:$cve_id})
    MERGE (c)-[:HAS_WEAKNESS]->(w)
    """, cve_id=cve_id, cwe_id=cwe_id)


# ----------------------------------------------------------
# 2) EXTRACTION DES DONNEES
# ----------------------------------------------------------

def extract_cvss(item):
    try:
        metrics = item["cve"]["metrics"]
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
            if key in metrics:
                d = metrics[key][0]
                cvss = d.get("cvssData") or d.get("cvssV2")
                return (
                    cvss.get("baseScore"),
                    cvss.get("exploitabilityScore", None),
                    cvss.get("impactScore", None),
                    cvss.get("vectorString")
                )
    except:
        pass
    return None, None, None, None


def extract_products_and_vendors(item):
    products = []
    vendors = []
    try:
        nodes = item["cve"]["configurations"][0]["nodes"]
        for node in nodes:
            for match in node.get("cpeMatch", []):
                cpe = match["criteria"]  # ex: cpe:2.3:a:microsoft:office:16.0
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = parts[3]
                    product = parts[4]
                    vendors.append(vendor)
                    products.append(product)
    except:
        pass
    return products, vendors


def extract_references(item):
    refs = []
    try:
        for r in item["cve"]["references"]:
            refs.append((r["url"], r.get("source", "")))
    except:
        pass
    return refs


def extract_cwes(item):
    cwes = []
    try:
        for w in item["cve"]["weaknesses"]:
            cwes.append(w["description"][0]["value"])
    except:
        pass
    return cwes


# ----------------------------------------------------------
# 3) IMPORTATION DANS NEO4J
# ----------------------------------------------------------

with open("cve_data.json", encoding="utf-8") as f:
    data = json.load(f)

vulns = data.get("vulnerabilities", [])

with driver.session() as session:
    for item in vulns:
        cve = item["cve"]

        cve_id = cve["id"]
        description = cve["descriptions"][0]["value"]
        published = cve["published"]
        modified = cve["lastModified"]

        session.execute_write(create_cve, cve_id, description, published, modified)

        # Metrics
        base, exploit, impact, vector = extract_cvss(item)
        if base is not None:
            session.execute_write(create_metric, cve_id, base, exploit, impact, vector)

        # Produits + Vendors
        products, vendors = extract_products_and_vendors(item)
        for p in products:
            session.execute_write(create_product, cve_id, p)
        for v in vendors:
            session.execute_write(create_vendor, v)
            for p in products:
                session.execute_write(link_vendor_product, v, p)

        # Références
        for url, source in extract_references(item):
            session.execute_write(create_reference, cve_id, url, source)

        # CWE weaknesses
        for cwe in extract_cwes(item):
            session.execute_write(create_cwe, cve_id, cwe)

print("IMPORT TERMINÉ AVEC VENDOR, REFERENCE, CWE, METRICS COMPLETS !")
