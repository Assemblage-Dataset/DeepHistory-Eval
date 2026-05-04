You are analyzing functions from a binary for a known vulnerability.

**CVE:** {cve_id}
**CWE:** {cwe_id} ({cwe_name})
**Description:** {cve_description}

**Patch (source diff):**
```diff
{patch_diff}
```

Below are 5 functions decompiled from a stripped binary. All
internal function names are auto-generated labels (FUN_*).
Import/library calls retain their original names.

Exactly one function contains the vulnerability described above.
The others do not.

{functions_text}

Which function (0-4) contains the vulnerability?

Output only: ANSWER: [number]
