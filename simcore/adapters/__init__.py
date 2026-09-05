"""
Report adapters — safe ingestion of external BAS / adversary-emulation output.

AttackSimPro validates controls; it does not, in this engine, *run* offensive
adversary-emulation tooling. Instead an authorized engagement runs that tooling on the
dedicated ASP host, and its **operation report** is ingested here and normalized into
Iron City findings mapped to MITRE ATT&CK. That keeps two properties:

  * no live offensive execution happens inside this engine (the report already exists),
  * every external tool's output lands in the one findings schema the dashboard reads,
    tagged with ATT&CK technique ids, and white-labeled (the tool is never named on a
    client-facing surface).

This mirrors the shared module_framework FileModule contract (passive ingest of an
export) rather than the active SimulationScenario contract.
"""
