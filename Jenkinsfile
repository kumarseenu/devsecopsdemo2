// ============================================================
//  DevSecOps Container Security Scanner – Jenkins Pipeline
//  Tools: Trivy (container CVEs) · Bandit (SAST) · pip-audit (SCA)
// ============================================================
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '10'))
        ansiColor('xterm')
    }

    // ── Parameters ────────────────────────────────────────────────────────
    parameters {

        choice(
            name: 'SCAN_TARGET',
            choices: [
                'Build Vulnerable Image (default)',
                'Build Fixed Image',
                'Pull from Registry',
                'Scan Local Image by Name',
                'Load from Tarball Path'
            ],
            description: '''Which Docker image to scan?
  • Build Vulnerable Image  – pygoat from Dockerfile  (old base + packages)
  • Build Fixed Image       – pygoat from Dockerfile.fixed (patched)
  • Pull from Registry      – any public image  →  fill REGISTRY_IMAGE below
  • Scan Local Image by Name – already loaded in Docker  →  fill REGISTRY_IMAGE below
  • Load from Tarball Path  – .tar on disk  →  fill TARBALL_PATH below'''
        )

        string(
            name: 'REGISTRY_IMAGE',
            defaultValue: '',
            description: 'Image name:tag to pull or scan. Examples: nginx:1.21  python:3.9  ubuntu:22.04'
        )

        string(
            name: 'TARBALL_PATH',
            defaultValue: '',
            description: 'Full path to a Docker image .tar file. Example: C:\\Images\\myapp.tar'
        )

        choice(
            name: 'SEVERITY',
            choices: [
                'CRITICAL,HIGH',
                'CRITICAL,HIGH,MEDIUM',
                'CRITICAL',
                'CRITICAL,HIGH,MEDIUM,LOW'
            ],
            description: 'Trivy severity levels to include in the scan'
        )
    }

    environment {
        SCAN_TAG    = "devsecops-scan:build-${BUILD_NUMBER}"
        REPORTS_DIR = "${WORKSPACE}\\scan-reports"
        REPO_DIR    = "D:\\Claude\\Sast\\devsecopsdemo2"
        TRIVY_BIN   = "C:\\trivy-bin\\trivy.exe"
        TRIVY_VER   = "0.50.4"
    }

    // ══════════════════════════════════════════════════════════════════════
    stages {

        // ── 0. Init ───────────────────────────────────────────────────────
        stage('Init') {
            steps {
                bat """
                    @echo off
                    echo ============================================================
                    echo   DevSecOps Container Security Scanner
                    echo   Build      : %BUILD_NUMBER%
                    echo   Target     : %SCAN_TARGET%
                    echo   Severity   : %SEVERITY%
                    echo ============================================================
                    if not exist "%REPORTS_DIR%" mkdir "%REPORTS_DIR%"
                """
            }
        }

        // ── 1. Prepare image ──────────────────────────────────────────────
        stage('Prepare Image') {
            steps {
                script {
                    def t = params.SCAN_TARGET

                    if (t.startsWith('Build Vulnerable')) {
                        bat "docker build -f \"%REPO_DIR%\\Dockerfile\" -t %SCAN_TAG% \"%REPO_DIR%\""

                    } else if (t.startsWith('Build Fixed')) {
                        bat "docker build -f \"%REPO_DIR%\\Dockerfile.fixed\" -t %SCAN_TAG% \"%REPO_DIR%\""

                    } else if (t.startsWith('Pull from Registry')) {
                        if (!params.REGISTRY_IMAGE?.trim()) {
                            error("Set REGISTRY_IMAGE when pulling from registry (e.g. nginx:1.21)")
                        }
                        bat """
                            docker pull ${params.REGISTRY_IMAGE}
                            docker tag  ${params.REGISTRY_IMAGE} %SCAN_TAG%
                        """

                    } else if (t.startsWith('Scan Local Image')) {
                        if (!params.REGISTRY_IMAGE?.trim()) {
                            error("Set REGISTRY_IMAGE with the local image name:tag to scan")
                        }
                        bat "docker tag ${params.REGISTRY_IMAGE} %SCAN_TAG%"

                    } else if (t.startsWith('Load from Tarball')) {
                        if (!params.TARBALL_PATH?.trim()) {
                            error("Set TARBALL_PATH to the .tar file path")
                        }
                        // Load tar, capture the image name, re-tag it
                        def loadOut = bat(
                            script: "docker load -i \"${params.TARBALL_PATH}\"",
                            returnStdout: true
                        ).trim()
                        echo "docker load output: ${loadOut}"
                        def m = loadOut =~ /Loaded image[^:]*:\s*(\S+)/
                        if (m) {
                            def loadedTag = m[0][1]
                            echo "Loaded image tag: ${loadedTag}"
                            bat "docker tag \"${loadedTag}\" %SCAN_TAG%"
                        } else {
                            echo "Could not parse image tag from load output – using image as-is"
                        }
                    }

                    bat "docker images %SCAN_TAG%"
                }
            }
        }

        // ── 2. SAST – Bandit ──────────────────────────────────────────────
        stage('SAST - Bandit') {
            steps {
                bat """
                    @echo off
                    echo ============================================================
                    echo   SAST: Bandit Python Source Code Analysis
                    echo ============================================================
                    cd /d "%REPO_DIR%"
                    pip install bandit --quiet
                    bandit -ll -ii -r . --exclude .git,venv,.venv ^
                        -f json -o "%REPORTS_DIR%\\bandit-report.json" ^
                        || echo Bandit completed (findings above)

                    echo.
                    echo --- Bandit Summary ---
                    python -c "
import json, sys
try:
    with open(r'%REPORTS_DIR%\\bandit-report.json') as f:
        d = json.load(f)
    r = d.get('results', [])
    c = {}
    for x in r:
        s = x.get('issue_severity','?')
        c[s] = c.get(s,0) + 1
    print('  Total  :', len(r))
    for sev in ['HIGH','MEDIUM','LOW']:
        print('  %-8s:' % sev, c.get(sev,0))
    print()
    print('  High Severity Findings:')
    for x in [v for v in r if v.get('issue_severity')=='HIGH'][:8]:
        print('  [HIGH]', x.get('issue_text','')[:70])
        print('        ', x.get('filename','')[-50:], ':', x.get('line_number',''))
except Exception as e:
    print('Could not parse report:', e)
"
                """
            }
        }

        // ── 3. SCA – pip-audit ────────────────────────────────────────────
        stage('SCA - pip-audit') {
            steps {
                bat """
                    @echo off
                    echo ============================================================
                    echo   SCA: pip-audit Python Dependency CVE Scan
                    echo ============================================================
                    cd /d "%REPO_DIR%"
                    pip install pip-audit --quiet
                    pip-audit -r requirements.txt ^
                        --format json ^
                        --output "%REPORTS_DIR%\\pip-audit-report.json" ^
                        --progress-spinner off ^
                        || echo pip-audit completed (findings above)

                    echo.
                    echo --- pip-audit Summary ---
                    python -c "
import json
try:
    with open(r'%REPORTS_DIR%\\pip-audit-report.json') as f:
        d = json.load(f)
    deps = d.get('dependencies', [])
    total = sum(len(x.get('vulns',[])) for x in deps)
    print('  Packages scanned:', len(deps))
    print('  CVEs found      :', total)
    print()
    for dep in deps:
        for v in dep.get('vulns',[]):
            print(' ', dep['name'] + '==' + dep['version'], ' ', v['id'])
            print('   ', v.get('description','')[:80])
except Exception as e:
    print('Could not parse report:', e)
"
                """
            }
        }

        // ── 4. Container Scan – Trivy ─────────────────────────────────────
        stage('Container Scan - Trivy') {
            steps {
                bat """
                    @echo off
                    echo ============================================================
                    echo   Container Scan: Trivy  ^|  Image: %SCAN_TAG%
                    echo   Severity filter: %SEVERITY%
                    echo ============================================================

                    :: Install Trivy if missing
                    if not exist "%TRIVY_BIN%" (
                        echo Trivy not found – downloading v%TRIVY_VER%...
                        if not exist "C:\\trivy-bin" mkdir "C:\\trivy-bin"
                        powershell -NoProfile -Command ^
                            "Invoke-WebRequest -Uri 'https://github.com/aquasecurity/trivy/releases/download/v%TRIVY_VER%/trivy_%TRIVY_VER%_Windows-64bit.zip' -OutFile '%TEMP%\\trivy.zip'; Expand-Archive '%TEMP%\\trivy.zip' -DestinationPath 'C:\\trivy-bin' -Force"
                        echo Trivy installed.
                    )

                    "%TRIVY_BIN%" --version

                    echo.
                    echo === Table output (CRITICAL + HIGH) ===
                    "%TRIVY_BIN%" image ^
                        --severity %SEVERITY% ^
                        --vuln-type os,library ^
                        --format table ^
                        --timeout 15m ^
                        %SCAN_TAG%

                    echo.
                    echo === Saving JSON report ===
                    "%TRIVY_BIN%" image ^
                        --severity CRITICAL,HIGH,MEDIUM,LOW ^
                        --vuln-type os,library ^
                        --format json ^
                        --output "%REPORTS_DIR%\\trivy-report.json" ^
                        --timeout 15m ^
                        %SCAN_TAG%

                    echo.
                    echo --- Trivy Summary ---
                    python -c "
import json
try:
    with open(r'%REPORTS_DIR%\\trivy-report.json') as f:
        d = json.load(f)
    c = {}
    for r in d.get('Results', []):
        for v in (r.get('Vulnerabilities') or []):
            s = v.get('Severity','UNKNOWN')
            c[s] = c.get(s,0) + 1
    total = sum(c.values())
    print('  Image :', d.get('ArtifactName','?'))
    print('  Total :', total)
    for s in ['CRITICAL','HIGH','MEDIUM','LOW']:
        n = c.get(s,0)
        bar = '#' * min(n // 5, 50)
        print('  %-10s %4d  %s' % (s+':', n, bar))
except Exception as e:
    print('Could not parse report:', e)
"
                """
            }
        }

        // ── 5. HTML Report ────────────────────────────────────────────────
        stage('Generate Report') {
            steps {
                bat """
                    @echo off
                    echo Generating HTML security report...
                    python "%REPO_DIR%\\jenkins\\generate-report.py" ^
                        --bandit    "%REPORTS_DIR%\\bandit-report.json" ^
                        --pip-audit "%REPORTS_DIR%\\pip-audit-report.json" ^
                        --trivy     "%REPORTS_DIR%\\trivy-report.json" ^
                        --image     "%SCAN_TAG%" ^
                        --output    "%REPORTS_DIR%\\security-report.html"
                    echo Done.
                """
                // Publish as a Jenkins HTML report (requires HTML Publisher plugin)
                publishHTML(target: [
                    allowMissing         : false,
                    alwaysLinkToLastBuild: true,
                    keepAll              : true,
                    reportDir            : "${env.REPORTS_DIR}",
                    reportFiles          : 'security-report.html',
                    reportName           : 'Security Scan Report',
                    reportTitles         : 'DevSecOps Security Report'
                ])
            }
        }

    }
    // ══════════════════════════════════════════════════════════════════════

    post {
        always {
            archiveArtifacts(
                artifacts        : 'scan-reports\\*.json,scan-reports\\*.html',
                allowEmptyArchive: true
            )
            bat "docker rmi %SCAN_TAG% 2>nul || echo cleanup done"
        }
        success {
            echo "Scan complete. Open 'Security Scan Report' in the left nav for the HTML report."
        }
        failure {
            echo "Pipeline failed at: ${env.STAGE_NAME}"
        }
    }
}
