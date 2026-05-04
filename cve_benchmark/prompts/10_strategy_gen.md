You are a binary security researcher. Your task is to write
a clear, step-by-step analysis strategy that a follower agent
can execute to locate a known vulnerability in a stripped binary.

The follower agent has access to binary-analysis tools (decompiler,
call graph, string and import enumeration, p-code) but no prior
knowledge of this specific CVE. Your strategy describes a search
procedure, not an answer -- assume the agent does not know which
function is vulnerable until your strategy guides them to it.

## Vulnerability Information

**CVE:** {cve_id}
**CWE:** {cwe_id} ({cwe_name})

**Description:**
{cve_description}

**Patch Diff:**
```diff
{patch_diff}
```

NOTE: The patch diff shows source-level function names like
`{example_source_function}`. These names will NOT exist in stripped
binaries -- your strategy must describe the function by its behavior
(imports it calls, strings it references, control flow), not its
source name.

## Binary Analysis of Affected Function(s)

Two builds of the same vulnerable function are shown below. Your
strategy must rely on properties stable across both -- imported
function names, string literals, call-graph relationships, semantic
data and control-flow patterns.

### Reference build ({reference_build_key})
{reference_analysis}

### Cross-build variant ({variant_build_key})
{variant_analysis}

## Your Task

Write a strategy that a follower agent will execute against
stripped binaries. The same vulnerability exists in every target,
but compiled form -- function boundaries, register allocation,
inlining, control-flow shape -- differs between builds. The strategy
must identify the vulnerable function in *all* targets, including
builds with different operating systems (Linux, Windows), compilers
(GCC, Clang, MSVC), optimization levels (O0-O3), and software
versions.

Some target binaries are PATCHED (vulnerability fixed). Your
strategy must include a check that distinguishes vulnerable code
from patched code, so the follower agent does not produce false
positives on fixed binaries.

## Output Format

### Vulnerability Summary
One paragraph: what the vulnerability is and why it occurs.

### Search Strategy
Use as many steps as the vulnerability requires (typically 2-4).
Each step should narrow the candidate pool.

**Step 1: [Name]**
- What to search for and why
- What results to expect

**Step 2: [Name]** (and so on)

### Verification Checklist
A list of yes/no facts the follower agent should confirm to
distinguish a vulnerable candidate from a similar but patched
function. e.g.,
- "Calls `memcpy` with size argument derived from attacker input:
  yes/no"
- "Has a bounds check before the dereference: yes/no"

### Fallback
If the primary approach fails (e.g. expected strings or imports
are missing in a particular build), describe an alternative
search strategy.

### Final Output
The follower agent must return exactly {num_candidates} candidate
functions, ranked by confidence. Describe how to produce that
many candidates -- if the primary approach yields fewer, the
fallback or weaker signals should supply backup candidates.