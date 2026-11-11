# Detection catalogue and Sigma subset

## Native rules

| ID | Detection | Reason | ATT&CK |
|---|---|---|---|
| SX-002 | Failed root authentication | Triage signal; a single failure does not prove brute force | No direct mapping |
| SX-003 | TCP destination port 4444 | Lab-specific uncommon-port heuristic | T1571 context only |
| SX-004 | File creation below Users/Public | Writable path may be abused, but path alone is not persistence | No direct mapping |
| SX-005 | Bash launched by nginx | Web server spawning shell deserves review | T1059.004 context only |
| SX-006 | Connection to SSH/RDP port | Remote-service hunt context; common benign activity expected | T1021 |

## Sigma example

rules/sigma/encoded-powershell.yml detects encoded PowerShell launched by an Office process. Three selectors must match.

Supported syntax: selector maps (AND across fields), OR value lists, all modifier, boolean and/or/not, parentheses, 1 of/all of selection patterns and them, wildcard matching, contains, startswith, endswith, re, exists, cidr, gt/gte/lt/lte and windash.

Not supported: Sigma correlation rules, filters, field references, base64 transformations, backend pipelines, keyword searches and all unlisted constructs. Unsupported modifiers/conditions raise errors. This is not full pySigma compatibility.

ATT&CK tags describe investigative context only. Risk scores are heuristic rankings, not calibrated probabilities.
