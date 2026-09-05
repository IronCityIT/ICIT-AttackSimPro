// AttackSimPro — CI pipeline (Jenkins).
//
// Runs the full quality gate for the safe-simulation engine and the ingest function:
// lint → unit → integration → security → end-to-end → build (evidence artifacts).
// Everything runs locally against loopback fixtures; no secrets, no deploy, no
// external targets. Deploy stays in .github/workflows/deploy-functions.yml (Bill only).
//
// Requires agent tools: python3 (3.11+), node 20, npm, bash, curl, jq.

pipeline {
  agent any

  options {
    timestamps()
    timeout(time: 30, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  environment {
    PYTHONUNBUFFERED = '1'
    PIP_DISABLE_PIP_VERSION_CHECK = '1'
  }

  stages {
    stage('Setup') {
      steps {
        sh '''
          set -eu
          python3 --version
          node --version
          python3 -m pip install --quiet --user pyyaml || pip install --quiet --user pyyaml
          ( cd functions && npm install --no-audit --no-fund )
        '''
      }
    }

    stage('Lint') {
      steps {
        sh '''
          set -eu
          # Byte-compile every engine module (syntax gate).
          python3 -m compileall -q simcore
          # Node source syntax gate.
          ( cd functions && npm run lint )
        '''
      }
    }

    stage('Unit + Integration + Security tests') {
      steps {
        // The engine suite spans unit, integration (runner+scope+audit+evidence),
        // and security (scope refusal, audit/evidence tamper, report escaping).
        sh 'python3 -m unittest discover -s simcore/tests -p "test_*.py" -v'
      }
    }

    stage('Ingest tests') {
      steps {
        sh '( cd functions && npm test )'
      }
    }

    stage('Ingest smoke') {
      steps {
        sh 'bash scripts/smoke.sh'
      }
    }

    stage('End-to-end simulation (sandbox)') {
      steps {
        sh 'bash scripts/e2e/simulation_e2e.sh'
      }
    }

    stage('Security gate') {
      steps {
        sh '''
          set -eu
          # No hardcoded private keys / bearer tokens committed.
          if git grep -nE "BEGIN (RSA|EC|OPENSSH|PRIVATE) KEY" -- . ; then
            echo "ERROR: private key material committed"; exit 1
          fi
          # The default posture must load zero external authorizations.
          python3 -c "from simcore.scope import Scope; assert len(Scope.from_dir('authorizations').records)==0, 'external authorizations must not ship'"
          echo "security gate ok"
        '''
      }
    }

    stage('Build artifacts') {
      steps {
        sh '''
          set -eu
          mkdir -p build
          python3 -m simcore catalog > build/catalog.json
          python3 -m simcore remediation > build/remediation.json
          python3 -m json.tool build/catalog.json > /dev/null
          # Regenerate a sample evidence bundle + report as a build artifact.
          python3 scripts/attack-sim/targets.py --self-test >/dev/null 2>&1 || true
        '''
        archiveArtifacts artifacts: 'build/*.json', allowEmptyArchive: true, fingerprint: true
      }
    }
  }

  post {
    always {
      echo 'AttackSimPro pipeline complete.'
    }
    failure {
      echo 'AttackSimPro pipeline FAILED — a gate is red; do not merge.'
    }
  }
}
