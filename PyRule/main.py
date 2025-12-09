#!/usr/bin/env python3
"""
Inline CodeQL dataflow dependency modules into entry rule files.

Goal: expand imports in CodeQL rule entry files so each rule file contains
the content of its dependencies (from the dataflow library), making a single
self-contained rule file easier to migrate.

Behavior summary:
1) Read all `.ql` and `.qll` files under `ENTRY_DIR` as entry files.
2) Parse `import` lines and ignore `import python` and imports that contain
   `::` (framework flow imports such as `PathInjectionFlow::PathGraph`).
3) Maintain an `import_filepath` index built from `DATAFLOW_DIR` mapping
   module names like `semmle.python.security.dataflow.PathInjectionQuery`
   (and basenames) to actual file paths.
4) For imports that map to files under `DATAFLOW_DIR`, comment out the
   original import line and inline the dependency file contents right after
   it (preserving the import line's indentation). Recursively process the
   inlined file's imports in the same way.

The script writes processed files to `OUTPUT_DIR`, preserving directory
structure. It also writes `import_filepaths.json` in the output directory
containing the mapping used.
"""
import json
import argparse
import os
import re
from pathlib import Path


DEFAULT_ENTRY_DIR = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql/python/ql/src/Security/CWE-022"
# DEFAULT_ENTRY_DIR = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql/python/ql/src/Security"
DEFAULT_DATAFLOW_DIR = "/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow"
DEFAULT_OUTPUT_DIR = "/home/cbb/SAST-Rule-Migrate/PyRule/CWE-022"


IMPORT_RE = re.compile(r"^(?P<indent>\s*)(?P<prefix>private\s+)?import\s+(?P<mod>.+?)\s*$")


def build_dataflow_index(dataflow_dir: str):
    """Scan DATAFLOW_DIR and return a mapping:
    - full module name -> filepath, where full module name is
      `semmle.python.security.dataflow.<rel-with-dots>`
    - basename -> filepath (for fallback by last token)
    """
    dataflow_dir = os.path.abspath(dataflow_dir)
    index = {}
    for root, _, files in os.walk(dataflow_dir):
        for f in files:
            name, ext = os.path.splitext(f)
            if ext not in ('.ql', '.qll'):
                continue
            full_rel = os.path.relpath(os.path.join(root, f), dataflow_dir)
            rel_noext = os.path.splitext(full_rel)[0]
            module = 'semmle.python.security.dataflow.' + rel_noext.replace(os.sep, '.')
            # prefer explicit module mapping
            if module not in index:
                index[module] = os.path.join(root, f)
            # also map basename
            if name not in index:
                index[name] = os.path.join(root, f)
    return index


def resolve_import(import_name: str, df_index: dict, dataflow_dir: str) -> str:
    """Resolve an import name to a file path under dataflow_dir using the
    pre-built index as primary source. Returns file path or empty string.
    """
    import_name = import_name.strip()
    if not import_name:
        return ''

    # Direct full-module match
    if import_name in df_index:
        return df_index[import_name]

    # If the import_name starts with the package prefix try mapping its tail
    prefix = 'semmle.python.security.dataflow'
    if import_name.startswith(prefix):
        tail = import_name[len(prefix):].lstrip('.')
        if tail:
            rel_path = tail.replace('.', os.sep)
            for ext in ('.qll', '.ql'):
                candidate = os.path.join(dataflow_dir, rel_path + ext)
                if os.path.isfile(candidate):
                    return candidate

    # fallback: match by last token (basename)
    last = import_name.split('.')[-1]
    if last in df_index:
        return df_index[last]

    return ''


def process_file(path: str, df_index: dict, dataflow_dir: str, inserted: set, import_map: dict, depth=0, max_depth=10):
    """Return processed content (string) for file `path` with dataflow imports
    inlined. `inserted` is a set of absolute paths already inlined into the
    current top-level file to prevent duplicates. `import_map` is updated with
    mappings from import name to chosen file path.
    """
    if depth > max_depth:
        try:
            return open(path, 'r', encoding='utf-8', errors='ignore').read()
        except Exception:
            return ''

    out_lines = []
    try:
        with open(path, 'r', encoding='utf-8', errors='ignore') as fh:
            lines = fh.readlines()
    except Exception:
        return ''

    for line in lines:
        m = IMPORT_RE.match(line)
        if not m:
            out_lines.append(line)
            continue

        indent = m.group('indent') or ''
        mod_raw = m.group('mod').strip()

        # Handle special import forms
        if mod_raw == 'python':
            out_lines.append(line)
            continue

        # If the import uses '::' (framework/customization/flow scoping),
        # treat differently:
        # - If the part before '::' ends with 'Flow', comment it out and
        #   do not attempt to inline (these refer to runtime/framework flow modules).
        # - Otherwise (e.g. '...Customizations::...'), only consider the
        #   part before '::' when resolving against the dataflow file index.
        if '::' in mod_raw:
            pre = mod_raw.split('::', 1)[0].strip()
            if pre.endswith('Flow'):
                commented = indent + '// ' + line.lstrip()
                out_lines.append(commented)
                continue
            # resolve using the prefix before '::'
            mod_to_resolve = pre
        else:
            mod_to_resolve = mod_raw

        # try to resolve to a dataflow file using the selected module name
        dep = resolve_import(mod_to_resolve, df_index, dataflow_dir)
        if not dep:
            out_lines.append(line)
            continue

        dep_abs = os.path.abspath(dep)
        if dep_abs in inserted:
            # comment out original import and skip inlining (already added)
            commented = indent + '// ' + line.lstrip()
            out_lines.append(commented)
            continue

        # comment out original import
        commented = indent + '// ' + line.lstrip()
        out_lines.append(commented)

        # read and recursively process dep file
        processed = process_file(dep, df_index, dataflow_dir, inserted, import_map, depth + 1, max_depth)

        # insert begin marker and processed content with same indent
        out_lines.append(indent + '// --- begin inlined: %s ---\n' % os.path.relpath(dep))
        for pl in processed.splitlines(True):
            # prefix with indent
            out_lines.append(indent + pl)
        out_lines.append(indent + '// --- end inlined: %s ---\n' % os.path.relpath(dep))

        inserted.add(dep_abs)
        import_map[mod_raw] = dep_abs

    return ''.join(out_lines)


def process_all(entry_dir: str, dataflow_dir: str, output_dir: str):
    entry_dir = os.path.abspath(entry_dir)
    dataflow_dir = os.path.abspath(dataflow_dir)
    output_dir = os.path.abspath(output_dir)

    df_index = build_dataflow_index(dataflow_dir)
    overall_import_map = {}

    for root, _, files in os.walk(entry_dir):
        for f in files:
            if not (f.endswith('.ql') or f.endswith('.qll')):
                continue

            src_path = os.path.join(root, f)
            rel = os.path.relpath(src_path, entry_dir)
            out_path = os.path.join(output_dir, rel)
            os.makedirs(os.path.dirname(out_path), exist_ok=True)

            print(f"Processing {rel} -> {os.path.relpath(out_path)}")

            inserted = set()
            import_map = {}
            new_content = process_file(src_path, df_index, dataflow_dir, inserted, import_map)

            with open(out_path, 'w', encoding='utf-8') as outfh:
                outfh.write(new_content)

            # merge import maps
            overall_import_map.update(import_map)

    # write import_filepath list for inspection
    os.makedirs(output_dir, exist_ok=True)
    map_path = os.path.join(output_dir, 'import_filepaths.json')
    try:
        with open(map_path, 'w', encoding='utf-8') as mf:
            json.dump(overall_import_map, mf, indent=2, ensure_ascii=False)
        print(f"Wrote import map to {map_path}")
    except Exception as e:
        print(f"Failed to write import map: {e}")


def main(argv=None):
    p = argparse.ArgumentParser(description="Inline dataflow dependency files into .ql entry files")
    p.add_argument('--entry-dir', default=DEFAULT_ENTRY_DIR, help='Source entry .ql files directory')
    p.add_argument('--dataflow-dir', default=DEFAULT_DATAFLOW_DIR, help='Directory containing dataflow dependency files')
    p.add_argument('--output-dir', default=DEFAULT_OUTPUT_DIR, help='Output directory to write processed files')
    args = p.parse_args(argv)

    process_all(args.entry_dir, args.dataflow_dir, args.output_dir)


if __name__ == '__main__':
    main()
# 目标：将CodeQL规则的入口文件中的import语句所依赖的模块内容全部展开，形成一个完整的规则文件，方便后续的规则迁移工作。
# 步骤：
# 1.读取"/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql/python/ql/src/Security"这个文件夹下的所有.ql文件是作为规则的入口文件并解析import语句。
# 类似于下面的内容忽略import python、和import ....Flow::...
# import python
# import semmle.python.security.dataflow.PathInjectionQuery
# import PathInjectionFlow::PathGraph
# 2.import模块的内容都在"/home/cbb/SAST-Rule-Migrate/CaseBenchmark/sast_tools/codeql/python/ql/lib/semmle/python/security/dataflow"，维护一个import_filepath的list
# 如何找import模块内容举个例子：semmle.python.security.dataflow.PathInjectionQuery转为semmle/python/security/dataflow/PathInjectionQuery然后看import_filepathlist中是否存在该路径对应的.qll文件
# 3.如果在则将这些依赖文件的内容添加到import语句的后面，保持缩进一致。并将原import语句注释掉