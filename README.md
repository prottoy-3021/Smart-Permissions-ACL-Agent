Smart Permissions & ACL Agent

Natural-language permission planning and access-control analysis for Windows and Linux
Project status: Windows plan-only prototype implemented and demonstrated; Linux ACL parsing and mock-based planner tests implemented, with real Ubuntu/WSL testing and main-application integration still pending.

Safety notice: This project generates advisory permission plans. It does not execute proposed icacls, chmod, chown, or setfacl changes. A generated plan is not proof that the requested permission policy is satisfied.

Overview
The Smart Permissions & ACL Agent is a Python command-line prototype that turns supported natural-language permission requests into structured policies, inspects existing file-system permissions, highlights potential ACL risks, and generates proposed permission-management commands for review.

Example request (use a folder that actually exists):
Make C:\path\to\www accessible to IIS_IUSRS, but read-only for everyone else
For this supported policy, the Windows planner proposes read/execute (RX) access for IIS_IUSRS, inspects existing ACL entries, and flags potentially conflicting write permissions. It does not make “everyone else” read-only; achieving and verifying that policy requires more analysis and an explicitly authorized application workflow.

The current natural-language parser is rule-based, not LLM-driven. It supports a defined set of phrasing patterns and rejects unsupported requests.
Features and implementation status
Feature	Status
Natural-language parsing for supported permission requests	Implemented and tested
Request and target-path validation	Implemented and tested
Windows ACL inspection with icacls	Demonstrated on a real Windows folder
Preliminary and structured Windows ACL parsing/risk analysis	Implemented and tested
Detection of visible write-capable, deny, and inherited ACL entries	Implemented (preliminary findings)
Windows current-user/group inspection and SID matching	Modules implemented; real-system coverage varies
Native Windows security-descriptor inspection	Module implemented; verify locally
Current-process Windows AccessCheck diagnostics	Experimental; do not equate with full policy verification
Windows read-only policy-gap and exception reports	Implemented as advisory analysis
Proposed Windows permission-plan generation	Demonstrated (PLAN_ONLY)
Linux getfacl parsing, mask handling, and default-ACL analysis	Implemented; 14 unit tests passed in the reported run
Linux planner integration using mocked getfacl output	Implemented; corrected integration test requires final rerun confirmation
Real Linux inspection in Ubuntu/WSL	Pending
Linux requests routed through the main CLI/engine	Pending; currently blocked for safety
Real permission modification / policy enforcement	Not implemented; intentionally disabled
Verified effective access for IIS_IUSRS or all other users	Not established


Architecture
Natural-language request
          |
          v
      Parser + validation
          |
          v
    Engine safety checks
          |
          v
   Platform-specific planner
        /         \
       /           \
  Windows           Linux
 `icacls`         `getfacl`
       \           /
        \         /
    ACL parsing and risk review
          |
          v
 Proposed command + warnings
          |
          v
      JSON plan report
  PLAN_ONLY / no changes applied

Windows-only optional diagnostic modules can add current-token, SID, native ACL, or policy-gap information. They do not replace a complete account-specific authorization check.

Project layout
The main project modules developed to date include:
SmartPermissionsAgent/
├── main.py                        # Interactive CLI
├── requirements.txt
├── run_evaluation.py              # Mock-based evaluation runner
├── evaluation_report.json         # Generated evaluation output
├── permission_agent/
│   ├── __init__.py
│   ├── parser.py
│   ├── validator.py
│   ├── engine.py
│   ├── planner.py
│   ├── acl_inspector.py
│   ├── acl_parser.py
│   ├── risk_analyzer.py
│   ├── windows_backend.py
│   ├── linux_backend.py
│   ├── windows_effective_access.py
│   ├── windows_identity.py
│   ├── windows_token_analysis.py
│   ├── windows_sid_analysis.py
│   ├── windows_native_acl.py
│   ├── windows_access_check.py
│   ├── windows_policy_audit.py
│   ├── windows_policy_review.py
│   └── linux_acl_analysis.py
└── tests/
    ├── test_parser.py
    ├── test_planner.py
    ├── test_engine.py
    ├── test_evaluation.py
    ├── test_windows_*.py
    └── test_linux_*.py

The list reflects the modules developed during this project; confirm the actual repository contents before publishing. Wildcard names above denote groups of test files, not files literally named with *.

Requirements
- Python 3 (development and reported Windows tests used Python 3.14.7).
- pytest for automated testing.
- Windows 11 for icacls inspection and optional Windows security modules.
- pywin32 for optional native Windows security inspection and SID-based functionality; it is Windows-only.
- Ubuntu/Linux, getfacl, and Python for the Linux backend; real Linux verification is pending.

On Windows PowerShell:
cd "C:\path\to\SmartPermissionsAgent"
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m pip install pytest
If you use optional Windows security modules and pywin32 is not installed:
python -m pip install pywin32
Keep Windows-only dependencies conditional in requirements.txt when installing the same project on Linux (for example, pywin32; platform_system == "Windows").
Run the application on Windows

Start the interactive CLI:
python main.py
Create a disposable test directory if needed:
New-Item -ItemType Directory -Force -Path "$env:TEMP\ACL-Agent-Test"
At the prompt, submit a supported request using the actual path of an existing test directory, for example:
Make C:\Users\<your-windows-user>\AppData\Local\Temp\ACL-Agent-Test accessible to IIS_IUSRS, but read-only for everyone else
The placeholder <your-windows-user> must be replaced with the actual username/path. The planner inspects the ACL and returns a JSON report with sections such as:
- existing_permissions
- acl_analysis
- structured_acl_analysis
- proposed_plan
- decision: "PLAN_ONLY"
- permissions_changed: false
- policy_verified: false
For a real temporary folder in the reported demonstration, the analysis flagged three visible potentially write-capable Full Control entries. That is an observed example, not a universal result.

Type exit to leave the application.
Optional Windows diagnostics
These features depend on the corresponding modules being present and integrated in planner.py:
$env:SMART_PERMISSIONS_INSPECT_IDENTITY = "1"
$env:SMART_PERMISSIONS_POLICY_AUDIT = "1"
$env:SMART_PERMISSIONS_ACCESS_CHECK = "1"
python main.py
The reports are diagnostics for the current process/security context or the inspected security descriptor. They do not establish effective access for the intended IIS worker process or every other user. Some native API diagnostics may require additional runtime troubleshooting.

After testing:
Remove-Item Env:SMART_PERMISSIONS_INSPECT_IDENTITY -ErrorAction SilentlyContinue
Remove-Item Env:SMART_PERMISSIONS_POLICY_AUDIT -ErrorAction SilentlyContinue
Remove-Item Env:SMART_PERMISSIONS_ACCESS_CHECK -ErrorAction SilentlyContinue
Testing and evaluation
Run the full suite from the repository root:
python -m pytest -v
Run Windows-specific tests from PowerShell (explicitly expand filenames; pytest tests/test_windows*.py alone does not expand the glob correctly in this shell):
python -m pytest (Get-ChildItem .\tests\test_windows*.py | Select-Object -ExpandProperty FullName) -v
Run Linux ACL unit and mocked integration tests on Windows:
python -m pytest tests/test_linux_acl_analysis.py tests/test_linux_planner_integration.py -v
Run the evaluation runner:
python run_evaluation.py

Reported results (not a final consolidated benchmark)
- An earlier full regression run reported 46 passed; later modules added more tests, so do not treat 46 as the final suite total.
- An earlier mock-based evaluation reported 8 passed, 0 failed (100% within those eight scenarios).
- A reported Linux ACL analysis run showed 14 unit tests passed.
- A mocked Linux planner integration test had a sample-count assertion (6 versus the actual 5 entries); the correction was provided, but a final corrected result was not supplied here.
- Windows ACL inspection was exercised on an existing temporary directory, and the planner reported no ACL modifications.
Before submitting the project, rerun the full suite and the evaluation runner, save the latest terminal summaries, and update this section with only confirmed results. Pytest suite duration is not a per-request latency benchmark; intent accuracy and average time-to-plan have not yet been separately measured.


Linux support — implemented versus remaining
The Linux analyzer currently supports parsing representative getfacl output, distinguishing access versus default ACL entries, applying visible ACL masks to affected entries, and flagging potential write access. A platform-specific Linux planner is present, but the main engine intentionally blocks Linux requests until real Linux tests validate it.
Test inside Ubuntu/WSL (still to be completed)
1. Install Ubuntu in WSL2, if not already available.
2. Inside Ubuntu, install Python and ACL utilities:
   sudo apt update
   sudo apt install -y python3 python3-venv python3-pip acl
3. Work from a Linux filesystem path (for example, ~/SmartPermissionsAgent), rather than using a Windows-mounted folder for Linux ACL evaluation. Copy the repository source without the Windows .venv.
4. Create a Linux virtual environment and install dependencies:
   cd ~/SmartPermissionsAgent
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   python -m pip install pytest
5. Run the Linux parser and planner tests:
   python -m pytest tests/test_linux_acl_analysis.py tests/test_linux_planner_integration.py -v
6. Inspect a disposable Linux directory:
   mkdir -p ~/acl-agent-test
   getfacl -p ~/acl-agent-test
7. Run the real Linux integration tests (tests/test_linux_real_integration.py, if present) and verify the ACL before and after generating a plan is unchanged:
   python -m pytest tests/test_linux_real_integration.py -v
8. Only after successful real Linux validation: safely enable Linux plan-only routing through permission_agent/engine.py, then test Linux requests through main.py.
None of these steps requires applying the generated permission commands to a real folder.


Limitations and security model
- This is a rule-based, supported-intent prototype, not a general-purpose LLM command executor.
- No proposed permission-changing command is executed.
- PLAN_ONLY is not evidence that the policy has been applied.
- Existing write grants, inherited ACEs, group memberships, privileges, and deny rules can affect Windows effective access.
- Matching an ACL SID or obtaining a current-process AccessCheck result does not prove authorization for IIS_IUSRS or all users.
- Linux mask analysis and default ACL inspection do not fully establish access for arbitrary users, parent directory traversal, or child objects.
- Privileged Windows principals (including SYSTEM and Administrators) must not be automatically removed or denied access; exceptions require explicit policy design and review.
- Do not run proposed icacls, chmod, chown, or setfacl commands against important directories without separate verification, authorization, and recovery procedures.


Remaining work / roadmap
- [ ] Verify all optional native Windows security modules on an actual test directory.
- [ ] Confirm a passing consolidated Windows and Linux mock-based regression suite.
- [ ] Complete Ubuntu/WSL real-folder Linux integration tests.
- [ ] Enable plan-only Linux requests through engine.py and validate via main.py.
- [ ] Add dedicated intent-translation accuracy, time-to-plan, and error-handling benchmarks.
- [ ] Finalize policy exceptions and authorization requirements for comprehensive read-only policy verification (separate from this prototype).
- [ ] Capture genuine Windows/Linux screenshots, update test results, and complete the academic report.
- [ ] Publish the latest verified source and documentation on GitHub.

Educational/research prototype. Use only on directories you own or are authorized to inspect. No real permission modifications are performed by the current application. The generated commands and ACL assessments are advisory and require independent verification before use in production.
