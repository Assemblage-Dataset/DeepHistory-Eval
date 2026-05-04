"""BinaryAPI -- queryable interface for stripped binary analysis (read-only Ghidra wrapper)."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import warnings
from typing import TypedDict


class FunctionInfo(TypedDict):
    """Metadata about a single function in the binary."""
    name: str
    address: str
    size_bytes: int
    num_blocks: int


class CFGEdge(TypedDict):
    """A single edge in a function's control flow graph."""
    source: str
    target: str
    edge_type: str


class CFGResult(TypedDict):
    """Control flow graph of a single function."""
    function: str
    blocks: list[str]
    entry_block: str
    edges: list[CFGEdge]


class SearchMatch(TypedDict):
    """A single search result from search_decompiled or search_pcode."""
    function: str
    line_number: int
    line_content: str
    match_text: str


class SearchResult(TypedDict):
    """Aggregated search results for one function."""
    function: str
    match_count: int
    matches: list[SearchMatch]


class SearchResults(TypedDict):
    """Top-level search response: matches plus a truncation indicator."""
    results: list[SearchResult]
    total_match_count: int
    truncated: bool
    limit: int

_GHIDRA_HOME = os.environ.get(
    'GHIDRA_HOME', os.environ.get('GHIDRA_INSTALL_DIR', '')
)
if not _GHIDRA_HOME:
    raise RuntimeError(
        "Set GHIDRA_INSTALL_DIR (or GHIDRA_HOME) to your Ghidra install "
        "before importing binaryapi."
    )
_CACHE_DIR = os.environ.get(
    'BINARYAPI_CACHE_DIR',
    os.path.join(os.path.expanduser('~'), '.cache', 'binaryapi'),
)

log = logging.getLogger(__name__)


_ghidra_started = False


def _ensure_ghidra() -> None:
    """Start the Ghidra JVM if not already running (process-global singleton)."""
    global _ghidra_started
    if _ghidra_started:
        return
    try:
        import pyghidra
    except ImportError:
        raise RuntimeError(
            "pyghidra is required.  Install with:  pip install pyghidra"
        )
    import sys as _sys
    if _sys.getrecursionlimit() < 50000:
        _sys.setrecursionlimit(50000)
    pyghidra.start(install_dir=_GHIDRA_HOME)
    _ghidra_started = True
    log.info("Ghidra JVM started (install_dir=%s)", _GHIDRA_HOME)


class BinaryAPI:
    """Read-only query interface to a single binary executable."""

    def __init__(self, binary_path: str) -> None:
        self._binary_path = os.path.abspath(binary_path)
        if not os.path.isfile(self._binary_path):
            raise FileNotFoundError(f"Binary not found: {self._binary_path}")

        with open(self._binary_path, 'rb') as f:
            magic = f.read(4)
        if magic[:4] != b'\x7fELF' and magic[:2] != b'MZ':
            raise ValueError(
                f"Not a valid ELF or PE binary: {self._binary_path}"
            )

        sha = hashlib.sha256()
        with open(self._binary_path, 'rb') as f:
            for chunk in iter(lambda: f.read(1 << 20), b''):
                sha.update(chunk)
        file_hash = sha.hexdigest()

        cache_path = os.path.join(_CACHE_DIR, f"{file_hash}.json")

        data = None
        if os.path.isfile(cache_path):
            log.info("Loading cached analysis: %s", cache_path)
            with open(cache_path, 'r') as f:
                data = json.load(f)
            if 'assembly' not in data:
                log.info("Cached analysis lacks 'assembly' -- re-running")
                data = None
            elif int(data.get('format_version', 1)) < 2:
                log.info("Cached p-code predates annotations -- re-running")
                data = None

        if data is None:
            log.info("Running Ghidra analysis on %s", self._binary_path)
            data = self._run_ghidra_analysis()
            os.makedirs(_CACHE_DIR, exist_ok=True)
            with open(cache_path, 'w') as f:
                json.dump(data, f)
            log.info("Cached analysis -> %s", cache_path)

        self._populate(data)

    def _run_ghidra_analysis(self) -> dict:
        """Run Ghidra auto-analysis and extract all queryable data into a plain dict."""
        _ensure_ghidra()

        import pyghidra
        from ghidra.app.decompiler import DecompInterface
        from ghidra.program.model.pcode import PcodeOp
        from ghidra.program.model.block import BasicBlockModel
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            ctx = pyghidra.open_program(self._binary_path)

        with ctx as flat_api:
            program = flat_api.getCurrentProgram()
            fm = program.getFunctionManager()
            listing = program.getListing()
            ref_mgr = program.getReferenceManager()

            result: dict = {
                'format_version': 2,
                'functions': [],
                'imports': [],
                'strings': [],
                'string_refs': {},
                'call_graph': {},
                'decompiled': {},
                'pcode': {},
                'assembly': {},
                'cfg': {},
            }

            def norm_name(func) -> str:
                name = func.getName()
                if name.startswith('FUN_'):
                    h = name[4:].lstrip('0').lower() or '0'
                    return 'sub_' + h
                return name

            def resolve_target(offset: int, fname_map, imp_addrs) -> str:
                if offset in imp_addrs:
                    return imp_addrs[offset]
                if offset in fname_map:
                    return fname_map[offset]
                return f'sub_{offset:x}'

            def fmt_const(val: int, size: int) -> str:
                if val < 0:
                    mask = ((1 << (size * 8)) - 1) if size > 0 else 0xFFFFFFFFFFFFFFFF
                    val = val & mask
                body = str(int(val)) if val <= 4096 else f'0x{val:x}'
                return f'{body}:{size}' if size > 0 else body

            def namer_factory():
                cache: dict[int, str] = {}
                counter = [0]

                def ssa_name(vn) -> str:
                    try:
                        uid = int(vn.getUniqueId())
                    except Exception:
                        uid = id(vn)
                    if uid not in cache:
                        cache[uid] = f'v{counter[0]}'
                        counter[0] += 1
                    return cache[uid]

                def type_suffix(vn) -> str:
                    try:
                        hv = vn.getHigh()
                        if hv is not None:
                            dt = hv.getDataType()
                            if dt is not None:
                                tname = str(dt.getName())
                                if tname and not tname.startswith('undefined'):
                                    return f'<{tname}>'
                    except Exception:
                        pass
                    return ''

                def namer(vn) -> str:
                    if vn is None:
                        return '?'

                    size = int(vn.getSize())

                    if vn.isConstant():
                        return fmt_const(int(vn.getOffset()), size)

                    sz_suffix = f':{size}' if size > 0 else ''

                    if (not vn.isRegister()) and vn.isAddress():
                        addr = vn.getAddress()
                        try:
                            space_name = str(addr.getAddressSpace().getName())
                        except Exception:
                            space_name = 'ram'
                        off = int(addr.getOffset())
                        if space_name == 'ram':
                            return f'0x{off:x}{sz_suffix}'
                        if space_name == 'stack':
                            return (f'{ssa_name(vn)}{sz_suffix}'
                                    f'@stack[{off:#x}]{type_suffix(vn)}')
                        return (f'{ssa_name(vn)}{sz_suffix}'
                                f'@{space_name}[{off:#x}]{type_suffix(vn)}')

                    if vn.isRegister():
                        regname = None
                        try:
                            reg = program.getRegister(vn.getAddress(), size)
                            if reg is not None:
                                regname = reg.getName()
                        except Exception:
                            pass
                        if regname is None:
                            off = int(vn.getAddress().getOffset())
                            regname = f'reg_{off:x}'
                        return (f'{ssa_name(vn)}{sz_suffix}'
                                f'@{regname}{type_suffix(vn)}')

                    return f'{ssa_name(vn)}{sz_suffix}{type_suffix(vn)}'

                return namer

            CMP_OPS = {
                int(PcodeOp.INT_EQUAL): '==',
                int(PcodeOp.INT_NOTEQUAL): '!=',
                int(PcodeOp.INT_LESS): '<u',
                int(PcodeOp.INT_SLESS): '<',
                int(PcodeOp.INT_LESSEQUAL): '<=u',
                int(PcodeOp.INT_SLESSEQUAL): '<=',
                int(PcodeOp.FLOAT_EQUAL): '==',
                int(PcodeOp.FLOAT_NOTEQUAL): '!=',
                int(PcodeOp.FLOAT_LESS): '<',
                int(PcodeOp.FLOAT_LESSEQUAL): '<=',
            }

            def fmt_condition(vn, namer_fn) -> str:
                defop = vn.getDef()
                if defop is not None:
                    opc = int(defop.getOpcode())
                    if opc in CMP_OPS:
                        a = namer_fn(defop.getInput(0))
                        b = namer_fn(defop.getInput(1))
                        return f'{a} {CMP_OPS[opc]} {b}'
                    if opc == int(PcodeOp.BOOL_NEGATE):
                        return f'!({fmt_condition(defop.getInput(0), namer_fn)})'
                    if opc == int(PcodeOp.BOOL_AND):
                        return (f'({fmt_condition(defop.getInput(0), namer_fn)}) && '
                                f'({fmt_condition(defop.getInput(1), namer_fn)})')
                    if opc == int(PcodeOp.BOOL_OR):
                        return (f'({fmt_condition(defop.getInput(0), namer_fn)}) || '
                                f'({fmt_condition(defop.getInput(1), namer_fn)})')
                return namer_fn(vn)

            _opnames: dict[int, str] = {}
            for attr in dir(PcodeOp):
                val = getattr(PcodeOp, attr, None)
                if isinstance(val, int) and attr.isupper() and not attr.startswith('_'):
                    _opnames[val] = attr

            def get_terminator(block):
                last = None
                it = block.getIterator()
                while it.hasNext():
                    op = it.next()
                    opc = int(op.getOpcode())
                    if opc in (int(PcodeOp.BRANCH), int(PcodeOp.CBRANCH),
                               int(PcodeOp.BRANCHIND), int(PcodeOp.RETURN)):
                        last = op
                return last

            def process_high_function(hf, fname_map, imp_addrs):
                blocks = list(hf.getBasicBlocks())
                if not blocks:
                    return '', {'blocks': [], 'entry_block': '', 'edges': []}, []

                blocks.sort(key=lambda b: (int(b.getStart().getOffset()),
                                           int(b.hashCode())))

                hash_to_label: dict[int, str] = {}
                labels: list[str] = []
                for i, blk in enumerate(blocks):
                    lbl = f'blk_{i}'
                    hash_to_label[int(blk.hashCode())] = lbl
                    labels.append(lbl)

                blk_branch: dict[int, dict] = {}
                for blk in blocks:
                    bh = int(blk.hashCode())
                    term = get_terminator(blk)
                    info: dict[str, str] = {}
                    n_out = int(blk.getOutSize())
                    if term and int(term.getOpcode()) == int(PcodeOp.CBRANCH):
                        cb_addr = int(term.getInput(0).getAddress().getOffset())
                        true_lbl = false_lbl = None
                        for j in range(n_out):
                            tb = blk.getOut(j)
                            tl = hash_to_label.get(int(tb.hashCode()), 'blk_?')
                            if int(tb.getStart().getOffset()) == cb_addr and true_lbl is None:
                                true_lbl = tl
                            else:
                                false_lbl = tl
                        if true_lbl is None and n_out >= 2:
                            false_lbl = hash_to_label.get(int(blk.getOut(0).hashCode()))
                            true_lbl = hash_to_label.get(int(blk.getOut(1).hashCode()))
                        info['true'] = true_lbl or 'blk_?'
                        info['false'] = false_lbl or 'blk_?'
                    elif (term and int(term.getOpcode()) in
                          (int(PcodeOp.BRANCH), int(PcodeOp.BRANCHIND))):
                        if n_out > 0:
                            info['uncond'] = hash_to_label.get(
                                int(blk.getOut(0).hashCode()), 'blk_?')
                    blk_branch[bh] = info

                namer_fn = namer_factory()
                pcode_lines: list[str] = []
                edges: list[dict] = []
                callees: set[str] = set()
                _PcodeOp = PcodeOp

                for blk in blocks:
                    bh = int(blk.hashCode())
                    lbl = hash_to_label[bh]
                    binfo = blk_branch.get(bh, {})
                    pcode_lines.append(f'{lbl}:')

                    it = blk.getIterator()
                    while it.hasNext():
                        op = it.next()
                        opc = int(op.getOpcode())

                        if opc == int(_PcodeOp.INDIRECT):
                            continue

                        out = op.getOutput()
                        ni = int(op.getNumInputs())

                        if opc == int(_PcodeOp.CALL):
                            taddr = int(op.getInput(0).getAddress().getOffset())
                            tname = resolve_target(taddr, fname_map, imp_addrs)
                            callees.add(tname)
                            args = ', '.join(namer_fn(op.getInput(j))
                                             for j in range(1, ni))
                            prefix = f'{namer_fn(out)} = ' if out else ''
                            pcode_lines.append(
                                f'    {prefix}CALL {tname}({args})')

                        elif opc == int(_PcodeOp.CALLIND):
                            tgt = namer_fn(op.getInput(0))
                            args = ', '.join(namer_fn(op.getInput(j))
                                             for j in range(1, ni))
                            prefix = f'{namer_fn(out)} = ' if out else ''
                            pcode_lines.append(
                                f'    {prefix}CALLIND [{tgt}]({args})')

                        elif opc == int(_PcodeOp.BRANCH):
                            target = binfo.get('uncond', 'blk_?')
                            pcode_lines.append(f'    BRANCH {target}')

                        elif opc == int(_PcodeOp.CBRANCH):
                            target = binfo.get('true', 'blk_?')
                            cond = fmt_condition(op.getInput(1), namer_fn)
                            pcode_lines.append(
                                f'    CBRANCH {target}, {cond}')

                        elif opc == int(_PcodeOp.BRANCHIND):
                            pcode_lines.append(
                                f'    BRANCHIND {namer_fn(op.getInput(0))}')

                        elif opc == int(_PcodeOp.RETURN):
                            if ni > 1:
                                pcode_lines.append(
                                    f'    RETURN {namer_fn(op.getInput(1))}')
                            else:
                                pcode_lines.append('    RETURN')

                        elif opc == int(_PcodeOp.LOAD):
                            addr_vn = op.getInput(1) if ni >= 2 else op.getInput(0)
                            prefix = f'{namer_fn(out)} = ' if out else ''
                            pcode_lines.append(
                                f'    {prefix}LOAD [{namer_fn(addr_vn)}]')

                        elif opc == int(_PcodeOp.STORE):
                            addr_vn = op.getInput(1) if ni >= 2 else op.getInput(0)
                            val_vn = op.getInput(2) if ni >= 3 else op.getInput(1)
                            pcode_lines.append(
                                f'    STORE [{namer_fn(addr_vn)}] = {namer_fn(val_vn)}')

                        elif opc == int(_PcodeOp.MULTIEQUAL):
                            args = ', '.join(namer_fn(op.getInput(j))
                                             for j in range(ni))
                            prefix = f'{namer_fn(out)} = ' if out else ''
                            pcode_lines.append(
                                f'    {prefix}PHI({args})')

                        else:
                            opname = _opnames.get(opc, f'OP_{opc}')
                            ins = ', '.join(namer_fn(op.getInput(j))
                                            for j in range(ni))
                            prefix = f'{namer_fn(out)} = ' if out else ''
                            pcode_lines.append(
                                f'    {prefix}{opname} {ins}')

                    pcode_lines.append('')

                    for j in range(int(blk.getOutSize())):
                        tblk = blk.getOut(j)
                        tlbl = hash_to_label.get(
                            int(tblk.hashCode()), 'blk_?')
                        if 'true' in binfo:
                            etype = ('branch_true' if tlbl == binfo['true']
                                     else 'branch_false')
                        elif 'uncond' in binfo:
                            etype = 'unconditional'
                        else:
                            etype = 'fallthrough'
                        edges.append({'source': lbl, 'target': tlbl,
                                      'edge_type': etype})

                ptext = '\n'.join(pcode_lines)
                cfg = {'blocks': labels,
                       'entry_block': labels[0],
                       'edges': edges}
                return ptext, cfg, sorted(callees)

            import_names: set[str] = set()
            imp_addrs: dict[int, str] = {}

            for func in fm.getExternalFunctions():
                import_names.add(str(func.getName()))

            for func in fm.getFunctions(True):
                if func.isThunk():
                    th = func.getThunkedFunction(True)
                    if th and th.isExternal():
                        imp_addrs[int(func.getEntryPoint().getOffset())] = str(th.getName())

            result['imports'] = sorted(import_names)

            fname_map: dict[int, str] = {}
            internal_funcs = []

            for func in fm.getFunctions(True):
                if func.isExternal():
                    continue
                off = int(func.getEntryPoint().getOffset())
                if func.isThunk():
                    th = func.getThunkedFunction(True)
                    fname_map[off] = str(th.getName()) if th else norm_name(func)
                    continue
                name = norm_name(func)
                fname_map[off] = name
                internal_funcs.append(func)

            log.info("Extracting strings...")
            strings_set: set[str] = set()
            str_addr_to_text: dict = {}

            for data in listing.getDefinedData(True):
                dt = data.getDataType()
                if dt is None:
                    continue
                dtname = str(dt.getName()).lower()
                if 'string' not in dtname:
                    continue
                try:
                    val = data.getValue()
                    if val is None:
                        continue
                    s = str(val).replace('\x00', '')
                    if len(s) >= 4:
                        strings_set.add(s)
                        str_addr_to_text[data.getAddress()] = s
                except Exception:
                    pass

            result['strings'] = sorted(strings_set)

            log.info("Resolving string references...")
            string_refs: dict[str, list[str]] = {}
            for addr, text in str_addr_to_text.items():
                refs = ref_mgr.getReferencesTo(addr)
                funcs_set: set[str] = set()
                for ref in refs:
                    from_addr = ref.getFromAddress()
                    f = fm.getFunctionContaining(from_addr)
                    if f and not f.isExternal() and not f.isThunk():
                        funcs_set.add(norm_name(f))
                if funcs_set:
                    if text not in string_refs:
                        string_refs[text] = []
                    for fn in sorted(funcs_set):
                        if fn not in string_refs[text]:
                            string_refs[text].append(fn)
            result['string_refs'] = string_refs

            log.info("Decompiling %d functions...", len(internal_funcs))
            decomp = DecompInterface()
            decomp.openProgram(program)
            bbm = BasicBlockModel(program)

            total = len(internal_funcs)
            for idx, func in enumerate(internal_funcs):
                if idx % 100 == 0 and idx > 0:
                    log.info("  %d / %d functions...", idx, total)

                name = norm_name(func)
                body = func.getBody()

                finfo: dict = {
                    'name': name,
                    'address': f'0x{int(func.getEntryPoint().getOffset()):x}',
                    'size_bytes': int(body.getNumAddresses()),
                    'num_blocks': 0,
                }

                try:
                    bi = bbm.getCodeBlocksContaining(body, monitor)
                    cnt = 0
                    while bi.hasNext():
                        bi.next()
                        cnt += 1
                    finfo['num_blocks'] = cnt
                except Exception:
                    pass

                try:
                    asm_lines = []
                    for inst in listing.getInstructions(body, True):
                        addr = f"0x{int(inst.getAddress().getOffset()):x}"
                        asm_lines.append(f"{addr}  {inst.toString()}")
                    if asm_lines:
                        result['assembly'][name] = "\n".join(asm_lines)
                except Exception as exc:
                    log.debug("Disassembly failed for %s: %s", name, exc)

                try:
                    dr = decomp.decompileFunction(func, 120, monitor)
                    if dr and dr.decompileCompleted():
                        dc = dr.getDecompiledFunction()
                        if dc:
                            result['decompiled'][name] = str(dc.getC())

                        hf = dr.getHighFunction()
                        if hf:
                            ptext, cfg, clist = process_high_function(
                                hf, fname_map, imp_addrs)
                            result['pcode'][name] = ptext
                            if cfg['blocks']:
                                finfo['num_blocks'] = len(cfg['blocks'])
                                cfg['function'] = name
                                result['cfg'][name] = cfg
                            result['call_graph'][name] = clist
                        else:
                            result['call_graph'][name] = (
                                self._callees_from_refs(
                                    func, fm, listing, fname_map, imp_addrs,
                                    norm_name))
                    else:
                        result['call_graph'][name] = (
                            self._callees_from_refs(
                                func, fm, listing, fname_map, imp_addrs,
                                norm_name))
                except Exception as exc:
                    log.debug("Decompile failed for %s: %s", name, exc)
                    result['call_graph'][name] = (
                        self._callees_from_refs(
                            func, fm, listing, fname_map, imp_addrs,
                            norm_name))

                result['functions'].append(finfo)

            decomp.dispose()

            result['functions'].sort(key=lambda f: int(f['address'], 16))

            log.info("Extraction complete: %d functions", total)
            return result

    @staticmethod
    def _callees_from_refs(func, fm, listing, fname_map, imp_addrs,
                           norm_name) -> list[str]:
        """Extract callees via instruction-level flow references (decompilation fallback)."""
        callees: set[str] = set()
        try:
            for inst in listing.getInstructions(func.getBody(), True):
                if inst.getFlowType().isCall():
                    for addr in inst.getFlows():
                        off = int(addr.getOffset())
                        if off in imp_addrs:
                            callees.add(imp_addrs[off])
                        elif off in fname_map:
                            callees.add(fname_map[off])
                        else:
                            cf = fm.getFunctionAt(addr)
                            if cf:
                                callees.add(norm_name(cf))
        except Exception:
            pass
        return sorted(callees)

    def _populate(self, data: dict) -> None:
        """Hydrate internal indexes from the serialised analysis dict."""
        self._functions_list: list[FunctionInfo] = data.get('functions', [])
        self._functions: dict[str, FunctionInfo] = {
            fi['name']: fi for fi in self._functions_list
        }
        self._imports: list[str] = data.get('imports', [])
        self._import_set: set[str] = set(self._imports)
        self._strings: list[str] = data.get('strings', [])
        self._string_refs: dict[str, list[str]] = data.get('string_refs', {})
        self._callees: dict[str, list[str]] = data.get('call_graph', {})

        self._callers: dict[str, list[str]] = {}
        for caller, callees in self._callees.items():
            for callee in callees:
                self._callers.setdefault(callee, []).append(caller)
        for k in self._callers:
            self._callers[k] = sorted(set(self._callers[k]))

        self._decompiled: dict[str, str] = data.get('decompiled', {})
        self._pcode: dict[str, str] = data.get('pcode', {})
        self._assembly: dict[str, str] = data.get('assembly', {})
        self._cfg: dict[str, CFGResult] = data.get('cfg', {})
        self._all_names: set[str] = set(self._functions.keys()) | self._import_set

    def _check_func(self, func: str) -> None:
        if func not in self._all_names:
            raise KeyError(
                f"Function '{func}' not found. "
                "Use list_functions() or get_imports() to see available names."
            )

    def _check_internal(self, func: str) -> None:
        if func not in self._functions:
            if func in self._import_set:
                raise KeyError(
                    f"'{func}' is an imported function, not internal."
                )
            raise KeyError(
                f"Function '{func}' not found. "
                "Use list_functions() to see available names."
            )

    def list_functions(self) -> list[FunctionInfo]:
        """List all functions identified in the binary, sorted by address."""
        return list(self._functions_list)

    def get_imports(self) -> list[str]:
        """List all imported library function names, sorted alphabetically."""
        return list(self._imports)

    def get_strings(self) -> list[str]:
        """List all string literals (>= 4 chars), sorted alphabetically."""
        return list(self._strings)

    def find_callers_of_import(self, import_name: str) -> list[str]:
        """Return internal functions that directly call *import_name*."""
        if import_name not in self._import_set:
            return []
        return list(self._callers.get(import_name, []))

    def find_functions_referencing_string(
            self, s: str, case_sensitive: bool = False) -> list[str]:
        """Return functions that reference a string containing *s* (substring match, case-insensitive by default)."""
        funcs: set[str] = set()
        if case_sensitive:
            needle = s
            for full_string, ref_funcs in self._string_refs.items():
                if needle in full_string:
                    funcs.update(ref_funcs)
        else:
            needle = s.lower()
            for full_string, ref_funcs in self._string_refs.items():
                if needle in full_string.lower():
                    funcs.update(ref_funcs)
        return sorted(funcs)

    def get_callees(self, func: str) -> list[str]:
        """Return all functions directly called by *func* (imports and internal)."""
        self._check_func(func)
        return list(self._callees.get(func, []))

    def get_callers(self, func: str) -> list[str]:
        """Return all functions that contain a direct call to *func*."""
        self._check_func(func)
        return list(self._callers.get(func, []))

    def get_cfg(self, func: str) -> CFGResult:
        """Return the intra-procedural control-flow graph of *func*."""
        self._check_internal(func)
        if func in self._cfg:
            return dict(self._cfg[func])
        return CFGResult(function=func, blocks=[], entry_block='', edges=[])

    def decompile(self, func: str) -> str:
        """Return Ghidra-decompiled C pseudocode for *func*."""
        self._check_internal(func)
        return self._decompiled.get(func, f'// Decompilation unavailable for {func}')

    def get_pcode(self, func: str) -> str:
        """Return high p-code (post-SSA) for *func*, grouped by basic block."""
        self._check_internal(func)
        return self._pcode.get(func, f'// P-code unavailable for {func}')

    def get_assembly(self, func: str) -> str:
        """Return raw disassembly (one instruction per line) for *func*."""
        self._check_internal(func)
        return self._assembly.get(
            func, f'; Assembly unavailable for {func}')

    DEFAULT_SEARCH_LIMIT = 200

    def _search_corpus(self, corpus: dict[str, str],
                       pattern: str, limit: int) -> SearchResults:
        try:
            regex = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"Invalid regex pattern: {e}") from e

        if limit <= 0:
            limit = self.DEFAULT_SEARCH_LIMIT

        results: list[SearchResult] = []
        total = 0
        truncated = False
        for func_name in sorted(corpus.keys()):
            if truncated:
                break
            text = corpus[func_name]
            matches: list[SearchMatch] = []
            for line_num, line in enumerate(text.split('\n'), start=1):
                m = regex.search(line)
                if m:
                    if total >= limit:
                        truncated = True
                        break
                    matches.append(SearchMatch(
                        function=func_name,
                        line_number=line_num,
                        line_content=line,
                        match_text=m.group(),
                    ))
                    total += 1
            if matches:
                results.append(SearchResult(
                    function=func_name,
                    match_count=len(matches),
                    matches=matches,
                ))
        return SearchResults(
            results=results,
            total_match_count=total,
            truncated=truncated,
            limit=limit,
        )

    def search_decompiled(self, pattern: str,
                          limit: int = DEFAULT_SEARCH_LIMIT) -> SearchResults:
        """Apply *pattern* (Python regex) line-by-line across all decompiled output."""
        return self._search_corpus(self._decompiled, pattern, limit)

    def search_pcode(self, pattern: str,
                     limit: int = DEFAULT_SEARCH_LIMIT) -> SearchResults:
        """Apply *pattern* (Python regex) line-by-line across all p-code output."""
        return self._search_corpus(self._pcode, pattern, limit)

    def search_assembly(self, pattern: str,
                        limit: int = DEFAULT_SEARCH_LIMIT) -> SearchResults:
        """Apply *pattern* (Python regex) line-by-line across all disassembly."""
        return self._search_corpus(self._assembly, pattern, limit)
