# Cloud Attack Simulation — Runner (for Bill)

Internal name: **Stratus Red Team** (`DataDog/stratus-red-team`). White-labeled
client-facing as "Cloud Attack Simulation". This directory *describes* a containerized
runner; it is **not built or run by CI or any agent**. No detonation happens in this repo.

## What this adds

Granular, ATT&CK-mapped cloud attack techniques (AWS / Azure / GCP / Kubernetes) that
detonate against a **disposable cloud sandbox** an engagement is authorized to use. The
runner emits a results JSON; that JSON — not live detonation — enters the product:

```
authorized engagement against a disposable cloud sandbox (signed ROE)
  → detonate techniques → results JSON (deploy/stratus/results/<op>.json)
    → python -m simcore ingest --adapter stratus --file <results> \
         --client "<client>" --scan-id <op-id> --out evidence/<op-id> --post <STORE_URL>
      → normalized findings + ATT&CK cloud coverage → dashboard
```

## Safety / scope

- **Disposable sandbox only.** Techniques run against a throwaway sandbox cloud account
  created for the engagement — never a client production tenant, never without a signed
  ROE. Revert and tear down the sandbox after the run.
- **Not default-on / gated**, consistent with ASP's existing offensive-tool posture.
- **Least privilege.** The runner's cloud credentials are scoped to the sandbox account
  only.

## Secrets (by name only — never commit values)

Provide cloud credentials to the runner via the environment on the host / runner:

```
AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN   # sandbox account only
AZURE_* / GOOGLE_APPLICATION_CREDENTIALS                        # as applicable
```

## Run (Bill, on an authorized runner — not from CI)

```bash
# build the runner image (pin the tool version first)
docker build -t asp-cloud-sim deploy/stratus
# detonate an authorized technique set against the sandbox, then export results JSON:
docker run --rm -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN \
  asp-cloud-sim detonate aws.credential-access.ec2-get-password-data
docker run --rm ... status --output json > deploy/stratus/results/<op>.json
# then ingest (command above), and clean up the sandbox:
docker run --rm ... cleanup --all
```

## Left for Bill

- Pin the tool version in the Dockerfile.
- Provision the disposable sandbox account(s) + scoped credentials.
- Wire `STORE_SCAN_RESULTS_URL` / `INGEST_TOKEN` for the ingest POST.
