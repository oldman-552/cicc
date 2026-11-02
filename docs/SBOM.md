# SBOM correlation and version comparison

SBOMs are analyst-supplied data; no package is downloaded, opened as executable, executed, or automatically remediated. CycloneDX and SPDX JSON imports handle at most 500 top-level components and a 1 MiB document, within a 1,100,000-byte HTTP envelope. Nested dependencies, SBOM signatures and a sandboxed parser are not implemented.

At import time the service compares supported purl package identities with the **currently cached GitHub advisories**. Matching source records, source collection time, original reported ranges and the comparison result are stored as snapshots; they are not automatically recomputed when advisory data or the algorithm changes. Older imports without a comparison remain unknown and must be re-imported for a new snapshot.

The `cicc-range-subset-1` comparison deliberately supports only a subset:

- PyPI/Python: stable numeric versions and bounds with one to four numeric segments; comparison uses Python `packaging`.
- npm: stable numeric three-part versions and bounds; comparison uses `semantic-version`.
- Ranges must contain only `<`, `<=`, `>`, `>=` or `=` comparisons, joined by commas (AND). Multiple source entries for the same package/advisory are treated as alternatives (OR).
- Prereleases, local/build versions, wildcards, complex syntax, unsupported ecosystems, missing values, conflicting purl/component versions and unparseable ranges are **UNKNOWN**. If any range matches, the result is within a reported range; otherwise an unknown alternative makes the result unknown.

An in-range result is **not a confirmed vulnerability** and requires manual verification of the package, version, applicability and source. An out-of-range result concerns only the evaluated source ranges; it does not establish safety. No identity candidates also does not establish safety, because the cache and supported SBOM fields are incomplete. Source records are source-reported and not independently verified.
