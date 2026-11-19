# VulnReach test projects

These tiny Python projects exist only to demonstrate VulnReach behavior. Their
package names and advisories are fictional; they are not real vulnerabilities.
Each project pins its sample dependency version so scans do not need that
fictional package installed.

Do not run the sample `app.py` files as applications. Their imports name
fictional packages and are only meant to be read by VulnReach's static scanner.

## Try the cases from PowerShell

Run these commands from the VulnReach repository root:

```powershell
$advisories = "examples/test_projects/advisories"
vulnreach scan examples/test_projects/reachable --offline --advisories $advisories
vulnreach scan examples/test_projects/not_reachable --offline --advisories $advisories
vulnreach scan examples/test_projects/uncertain --offline --advisories $advisories
vulnreach scan examples/test_projects/dynamic --offline --advisories $advisories
```

If the `vulnreach` command is not on PATH, use the repository environment:

```powershell
.\.venv\Scripts\python.exe -m vulnreach scan examples/test_projects/reachable --offline --advisories examples/test_projects/advisories
```

Expected outcomes:

| Folder | Expected verdict | What it demonstrates |
| --- | --- | --- |
| `reachable` | Reachable | A direct call path reaches the advisory's vulnerable symbol. |
| `not_reachable` | Not reachable | The package is called, but the named vulnerable function is not. |
| `uncertain` | Uncertain | The advisory contains no vulnerable-function information. |
| `dynamic` | Uncertain | `getattr` makes the call target dynamic. |

You can also open `vulnreach gui`, choose one of the project folders, enable
**Offline mode**, and select `examples/test_projects/advisories` under **Local
advisories**.
