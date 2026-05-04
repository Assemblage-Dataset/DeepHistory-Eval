# BinaryAPI Reference

Read-only query interface for a stripped binary executable. All analysis is pre-computed; every method is a pure lookup.

Stripped binaries have auto-generated function names like `sub_401234`. Imported library symbols (e.g., `malloc`, `memcpy`) retain their original names.

## Construction

```python
api = BinaryAPI("/path/to/binary")
```

Accepts ELF or PE binaries. Analysis is cached by SHA-256 hash.

---

## Enumeration

### `list_functions() -> list[FunctionInfo]`

List all internal functions in the binary, sorted by address.

Each entry is a dict:
```python
{
    "name": "sub_4012a0",    # auto-generated identifier
    "address": "0x4012a0",   # hex entry point
    "size_bytes": 342,       # raw binary size
    "num_blocks": 12         # basic block count
}
```

### `get_imports() -> list[str]`

List all imported library function names, sorted alphabetically.

Example: `["free", "malloc", "memcpy", "printf", "strlen"]`

### `get_strings() -> list[str]`

List all string literals (>= 4 characters) found in the binary, sorted alphabetically.

---

## Property-Based Discovery

### `find_callers_of_import(import_name: str) -> list[str]`

Return internal functions that directly call the given imported function.

```python
api.find_callers_of_import("malloc")
# ["sub_401230", "sub_4015a0", "sub_401bc0"]
```

Returns `[]` if the import does not exist in this binary.

### `find_functions_referencing_string(s: str, case_sensitive: bool = False) -> list[str]`

Return functions that reference a string containing `s` (substring match). **Case-insensitive by default** -- `s="XPM"` matches strings like `"xpm_load_image"`. Pass `case_sensitive=True` to require exact case (the literal bytes in the binary).

```python
api.find_functions_referencing_string("error")
# ["sub_401a00", "sub_402100"]

api.find_functions_referencing_string("XPM")               # -> finds xpm_*, XPM_*, Xpm_*, ...
api.find_functions_referencing_string("XPM", case_sensitive=True)  # -> only the exact 'XPM' bytes
```

Returns `[]` if no string contains the substring.

---

## Call-Graph Navigation

### `get_callees(func: str) -> list[str]`

Return all functions directly called by `func` (both imports and internal functions).

```python
api.get_callees("sub_401230")
# ["malloc", "memcpy", "sub_401100", "sub_401500"]
```

### `get_callers(func: str) -> list[str]`

Return all functions that contain a direct call to `func`.

```python
api.get_callers("sub_401230")
# ["sub_400f00", "sub_401800"]
```

---

## Code Inspection

### `decompile(func: str) -> str`

Return Ghidra-decompiled C pseudocode for `func`.

Variable names, expression order, and control-flow structure vary across compilers and optimization levels. Useful for human-readable understanding but less stable across builds than p-code.

```python
api.decompile("sub_401230")
# "void sub_401230(long param_1, int param_2) {\n  ..."
```

### `get_pcode(func: str) -> str`

Return high p-code (post-SSA intermediate representation) for `func`, grouped by basic block.

P-code uses:
- Sequential SSA variable names: `v0`, `v1`, `v2`, ...
- Architecture-independent operations: `LOAD`, `STORE`, `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_AND`, `INT_OR`, `INT_XOR`, `INT_LEFT`, `INT_RIGHT`, `INT_SRIGHT`, `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `INT_SLESS`, `INT_LESSEQUAL`, `INT_SLESSEQUAL`, `BOOL_NEGATE`, `BOOL_AND`, `BOOL_OR`, `FLOAT_ADD`, `FLOAT_SUB`, `FLOAT_MULT`, `FLOAT_DIV`, `CALL`, `CALLIND`, `CBRANCH`, `BRANCH`, `BRANCHIND`, `RETURN`, `COPY`, `CAST`, `SUBPIECE`, `INT_ZEXT`, `INT_SEXT`, `PIECE`, `PTRADD`, `PTRSUB`
- Labelled blocks: `blk_0`, `blk_1`, ... (consistent with `get_cfg`)
- Phi nodes at merge points: `PHI(v3, v7)`

**Annotation format** (every operand is a self-describing token):
- `:N` width suffix in bytes -- `v0:4` is a 4-byte SSA value, `0x10:8` is an 8-byte constant.
- `@REG` / `@stack[off]` location suffix on SSA values that live in a non-unique address space -- e.g. `v0:8@RCX` is the SSA value occupying the RCX register (typical Win64 first arg), `v3:8@stack[-0x10]` is a stack slot.  RAM-space globals skip the SSA name entirely and render as `0x{addr}:N` since the address is the identity.
- `<type>` suffix when the decompiler inferred a non-undefined data type -- `v0:8<longlong *>` is an 8-byte SSA value typed as a pointer to longlong.
- Signedness is preserved through the opcode (`INT_DIV` vs `INT_SDIV`, `INT_LESS` vs `INT_SLESS`) and the condition operator (`<u` for unsigned, `<` for signed).

More stable across build variants than decompiled C, but watch for type/register noise -- the SSA `vN` numbering and the operation skeleton are the most robust elements.

Example output:
```
blk_0:
    v1:1@ZF<bool> = INT_EQUAL v0:8@RCX<longlong>, 0:8
    CBRANCH blk_2, v0:8@RCX<longlong> == 0:8

blk_1:
    v2:8@RAX = PTRSUB 0:8, 0x18004a908:8
    BRANCH blk_3

blk_2:
    v3:8<longlong> = INT_ADD v0:8@RCX<longlong>, 24:8
    v4:8<longlong *> = CAST v3:8<longlong>
    v5:8<longlong> = LOAD [v4:8<longlong *>]

blk_3:
    v9:8@RAX = PHI(v2:8@RAX, v5:8<longlong>)
    RETURN v9:8@RAX
```

Reading the example: `v0:8@RCX<longlong>` is the first argument (Win64 calling convention puts arg0 in RCX), 8 bytes wide, typed `longlong`.  The PHI in `blk_3` merges two distinct SSA generations that both happen to live in RAX -- the SSA names (`v2`, `v9`) keep the generations separate even though they share the register.

### `get_assembly(func: str) -> str`

Return raw disassembly (one instruction per line) for `func`. Architecture-native
mnemonics (x86/x64/ARM/...); operands use the native register set and
addressing syntax.

Use this when decompiled C hides architecturally-relevant detail: timing
side-channels, constant-time violations, calling-convention issues,
register clobbering, or compiler-emitted branch layout. For most bugs
decompiled C is sufficient -- prefer `decompile` or `get_pcode` first.

```python
api.get_assembly("sub_401230")
# "0x401230  PUSH RBP\n0x401231  MOV RBP,RSP\n0x401234  SUB RSP,0x30\n..."
```

---

## Control-Flow Graph

### `get_cfg(func: str) -> CFGResult`

Return the intra-procedural control-flow graph of `func`.

```python
{
    "function": "sub_401230",
    "blocks": ["blk_0", "blk_1", "blk_2", "blk_3"],
    "entry_block": "blk_0",
    "edges": [
        {"source": "blk_0", "target": "blk_1", "edge_type": "branch_false"},
        {"source": "blk_0", "target": "blk_2", "edge_type": "branch_true"},
        {"source": "blk_1", "target": "blk_3", "edge_type": "fallthrough"},
        {"source": "blk_2", "target": "blk_3", "edge_type": "unconditional"}
    ]
}
```

Edge types: `fallthrough`, `branch_true`, `branch_false`, `unconditional`.

Block labels match those in `get_pcode()` output.

---

## Regex Search

### `search_decompiled(pattern: str, limit: int = 200) -> SearchResults`

Apply a Python regex `pattern` line-by-line across all decompiled output. Returns matches grouped by function, capped at `limit` total matches.

```python
api.search_decompiled(r"memcpy\(.*,.*,.*\)")
# {
#   "results": [
#     {
#       "function": "sub_401230",
#       "match_count": 2,
#       "matches": [
#         {"function": "sub_401230", "line_number": 15,
#          "line_content": "  memcpy(local_buf, param_1, param_2);",
#          "match_text": "memcpy(local_buf, param_1, param_2)"},
#         ...
#       ]
#     }
#   ],
#   "total_match_count": 2,
#   "truncated": false,
#   "limit": 200
# }
```

When `truncated` is `true`, the search stopped at `limit` matches and there may be more. Refine the pattern (more specific regex) or raise `limit` on the next call. Note that `match_count` for the last function in `results` may understate its true count when truncation hit mid-function.

### `search_pcode(pattern: str, limit: int = 200) -> SearchResults`

Apply a Python regex `pattern` line-by-line across all p-code output. Same return shape and truncation contract as `search_decompiled`.

```python
api.search_pcode(r"CALL memcpy")
# Functions that call memcpy, with exact p-code lines
```

### `search_assembly(pattern: str, limit: int = 200) -> SearchResults`

Apply a Python regex `pattern` line-by-line across all disassembly. Same return shape and truncation contract as `search_decompiled`.

```python
api.search_assembly(r"^[^;]*\bRDTSC\b")
# Functions that contain RDTSC (time-stamp counter reads)
```

---

## Error Handling

| Scenario | Exception |
|----------|-----------|
| Function name not found | `KeyError` |
| Method called on an imported function (e.g., `decompile("malloc")`) | `KeyError` |
| Invalid regex pattern | `ValueError` |
| Import not in binary (`find_callers_of_import`) | Returns `[]` |
| No string match (`find_functions_referencing_string`) | Returns `[]` |

No other exceptions during normal query operation. I/O and analysis errors surface only at construction time.

---

## What Survives Stripping

| Property | Survives? | Stability Across Builds |
|----------|-----------|------------------------|
| Imported function names | Yes | High |
| String literals | Yes | High |
| Call graph structure | Yes | Moderate |
| P-code operations | Yes | High (arch-independent) |
| CFG structure | Yes | Moderate |
| Internal function names | **No** (auto-generated) | None |
| Addresses/offsets | Yes but **change every build** | None |
| Decompiled C variable names | Yes but **vary by compiler** | Low |
