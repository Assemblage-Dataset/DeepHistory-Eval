"""Read-only DuckDB binary query layer for the benchmark pipeline."""

import os
import sys
from dataclasses import dataclass

import duckdb

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import _paths

DB_PATH = _paths.DUCKDB_PATH
BINARY_BASE_DIR = _paths.BINARY_BASE_DIR


@dataclass
class BinaryRecord:
    binary_id: int
    file_name: str
    platform: str
    build_mode: str
    toolset_version: str
    optimization: str
    package_name: str
    version: str
    path: str
    binary_format: str

    @property
    def full_path(self):
        return os.path.join(BINARY_BASE_DIR, self.path)

    @property
    def exists(self):
        return os.path.isfile(self.full_path)

    @property
    def os_label(self):
        if self.platform == "linux":
            return "linux"
        return "windows"

    @property
    def compiler_label(self):
        tv = self.toolset_version or ""
        if self.platform == "linux":
            return tv if tv else "gcc"
        return tv if tv else "unknown"

    @property
    def opt_label(self):
        opt = self.optimization or "O0"
        return opt.lstrip("-")

    @property
    def build_key(self):
        return f"{self.os_label}_{self.compiler_label}_{self.opt_label}"


_COLS = ("id, file_name, platform, build_mode, toolset_version, "
         "optimization, package_name, version, path, binary_format")


def _row_to_record(row):
    return BinaryRecord(
        binary_id=row[0], file_name=row[1], platform=row[2],
        build_mode=row[3], toolset_version=row[4], optimization=row[5],
        package_name=row[6], version=row[7], path=row[8], binary_format=row[9],
    )


def _conn():
    return duckdb.connect(DB_PATH, read_only=True)


def get_binary_by_id(binary_id):
    with _conn() as c:
        row = c.execute(
            f"SELECT {_COLS} FROM binaries WHERE id = ?", [binary_id]
        ).fetchone()
    return _row_to_record(row) if row else None


def get_binaries_for_package(package_name):
    with _conn() as c:
        rows = c.execute(
            f"SELECT {_COLS} FROM binaries WHERE package_name = ?",
            [package_name],
        ).fetchall()
    return [_row_to_record(r) for r in rows]


def get_distinct_configs(package_name):
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT platform, toolset_version, optimization "
            "FROM binaries WHERE package_name = ?",
            [package_name],
        ).fetchall()
    return [{"platform": r[0], "toolset_version": r[1], "optimization": r[2]}
            for r in rows]


def get_distinct_versions(package_name):
    with _conn() as c:
        rows = c.execute(
            "SELECT DISTINCT version FROM binaries "
            "WHERE package_name = ? ORDER BY version",
            [package_name],
        ).fetchall()
    return [r[0] for r in rows]


def get_source_codes(binary_id, func_names, platform=None):
    """Return {func_name: source_code} for each requested name with non-empty source."""
    if not func_names:
        return {}
    placeholders = ",".join("?" * len(func_names))
    with _conn() as c:
        rows = c.execute(
            f"SELECT name, source_codes FROM functions "
            f"WHERE binary_id = ? AND name IN ({placeholders})",
            [binary_id, *func_names],
        ).fetchall()
    out = {}
    for name, src in rows:
        if src:
            out.setdefault(name, src)
    return out


def get_pdb_paths(binary_id):
    """Return absolute paths to PDB files for a binary."""
    with _conn() as c:
        rows = c.execute(
            "SELECT pdb_path FROM pdbs WHERE binary_id = ?", [binary_id]
        ).fetchall()
    paths = [os.path.join(BINARY_BASE_DIR, r[0]) for r in rows]
    return [p for p in paths if os.path.exists(p)]


def get_function_names_present(binary_id, func_names):
    """Return the subset of `func_names` that exist in the `functions` table for `binary_id`."""
    if not func_names:
        return set()
    placeholders = ",".join("?" * len(func_names))
    with _conn() as c:
        rows = c.execute(
            f"SELECT DISTINCT name FROM functions "
            f"WHERE binary_id = ? AND name IN ({placeholders})",
            [binary_id, *func_names],
        ).fetchall()
    return {r[0] for r in rows}


def bids_with_any_function(bids, func_names):
    """Return {binary_id} for bids whose `functions` table contains any of the listed names."""
    if not bids or not func_names:
        return set()
    qb = ",".join("?" * len(bids))
    qf = ",".join("?" * len(func_names))
    with _conn() as c:
        rows = c.execute(
            f"SELECT DISTINCT binary_id FROM functions "
            f"WHERE binary_id IN ({qb}) AND name IN ({qf})",
            [*bids, *func_names],
        ).fetchall()
    return {r[0] for r in rows}


def find_binary(package_name, version=None, file_name=None, **filters):
    clauses = ["package_name = ?"]
    params = [package_name]
    if version is not None:
        clauses.append("version = ?")
        params.append(version)
    if file_name is not None:
        clauses.append("file_name = ?")
        params.append(file_name)
    for col, val in filters.items():
        if val is not None:
            clauses.append(f"{col} = ?")
            params.append(val)
    sql = f"SELECT {_COLS} FROM binaries WHERE " + " AND ".join(clauses)
    with _conn() as c:
        rows = c.execute(sql, params).fetchall()
    return [_row_to_record(r) for r in rows]
