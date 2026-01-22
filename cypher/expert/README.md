# Cypher Query Collection (Expert Version)

This folder contains the expert-written Cypher queries used in the article  
**"Graph-Based Security Analysis Using Neo4j Aura and Natural Language Queries"**.

These queries represent the correct and validated Cypher expressions that were
used as the ground-truth reference for evaluating the accuracy of Neo4j Aura’s
AI-assisted natural language querying. Each query corresponds to one of the
prompts tested in the Results section of the article.

The queries cover:

- vulnerability lookup by severity
- product–vendor relationships
- CWE weakness analysis
- CVE publication statistics
- presence or absence of severity metrics
- multi-vendor impact analysis
- keyword filtering in descriptions
- product lists per CVE
- CVE counts per vendor

All queries follow best practices for Neo4j, including:
- correct use of `DISTINCT` when needed
- accurate relationship directions
- proper handling of optional matches
- correct aggregation semantics

These files ensure full reproducibility of the experimental results presented in the article.

## File Structure

- `01_top_vendors.cql` — Vendors ranked by number of CVEs affecting their products  
- `02_high_severity_products.cql` — Products affected by high-severity CVEs  
- `03_multi_vendor_cves.cql` — CVEs impacting products from multiple vendors  
- `04_cves_per_year.cql` — Number of CVEs published per year  
- `05_top_cwe_categories.cql` — Most common CWE weakness categories  
- `06_github_references.cql` — CVEs referencing GitHub URLs  
- `07_cves_without_metric.cql` — CVEs missing a severity metric  
- `08_products_by_cve_1999_0002.cql` — Products affected by CVE-1999-0002  
- `09_buffer_cves_1999.cql` — CVEs from 1999 with “buffer” in the description  
- `10_vendor_products_vs_cves.cql` — Vendor product counts and associated CVEs

Each file can be executed directly in Neo4j Browser, Neo4j Desktop, or Neo4j Aura.

This repository is intended to support transparency and reproducibility for the
evaluation experiment described in the article.
