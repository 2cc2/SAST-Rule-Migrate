#!/usr/bin/env python3
"""
Qualify type references inside modules that implement `DataFlow::StateConfigSig`
or `DataFlow::ConfigSig`.

Problem: after inlining imports, types like `Source`/`Sink` defined in helper
modules (for example `module PathInjection`) are referenced unqualified inside
the config module, leading to "could not resolve type Source".

Approach:
- Find modules that implement `DataFlow::StateConfigSig` in each .ql file.
- Collect class names defined in other modules in the same file.
- Inside each config module, prefix unqualified references to those class names
  with the defining module name (e.g., `Source` -> `PathInjection::Source`).
- Emit a JSON summary indicating which files were touched.
"""

import argparse
import json
import os
import re
from collections import defaultdict
from typing import Dict, List, Tuple

MODULE_DEF_RE = re.compile(r"\bmodule\s+([A-Za-z_][\w]*)\b(.*)")
CLASS_DEF_RE = re.compile(r"\b(?:abstract\s+)?class\s+([A-Za-z_][\w]*)\b")
TARGET_SIGS = ("DataFlow::StateConfigSig", "DataFlow::ConfigSig")


def parse_modules(lines: List[str]):
	"""Parse modules and class definitions with brace tracking."""
	modules = []  # each: dict(name,start,end,implements,brace)
	type_map: Dict[str, str] = {}
	stack: List[dict] = []

	for idx, line in enumerate(lines):
		module_match = MODULE_DEF_RE.search(line)
		if module_match:
			name = module_match.group(1)
			rest = module_match.group(2) or ""
			implements = any(sig in rest for sig in TARGET_SIGS)
			brace_delta = line.count("{") - line.count("}")
			ctx = {
				"name": name,
				"implements": implements,
				"start": idx,
				"end": None,
				"brace": brace_delta,
			}
			stack.append(ctx)
			modules.append(ctx)

		current = stack[-1] if stack else None

		if current and not current["implements"]:
			class_match = CLASS_DEF_RE.search(line)
			if class_match:
				cls = class_match.group(1)
				type_map.setdefault(cls, current["name"])

		delta = line.count("{") - line.count("}")
		if not module_match and current:
			current["brace"] += delta

		while stack and stack[-1]["brace"] <= 0:
			stack[-1]["end"] = idx
			stack.pop()

	for m in modules:
		if m["end"] is None:
			m["end"] = len(lines) - 1
	return modules, type_map


def qualify_config_modules(lines: List[str], modules: List[dict], type_map: Dict[str, str]):
	"""Within config modules, qualify type names defined in other modules."""
	changed = False
	patterns: List[Tuple[re.Pattern, str]] = []
	for cls, mod in type_map.items():
		pat = re.compile(rf"(?<!::)\b{re.escape(cls)}\b")
		patterns.append((pat, f"{mod}::{cls}"))

	new_lines = list(lines)

	for mod in modules:
		if not mod["implements"]:
			continue
		start, end = mod["start"], mod["end"]
		for i in range(start, end + 1):
			line = new_lines[i]
			updated = line
			for pat, repl in patterns:
				updated = pat.sub(repl, updated)
			if updated != line:
				new_lines[i] = updated
				changed = True

	return new_lines, changed


def process_file(path: str) -> dict:
	result = {
		"path": path,
		"has_target_sig": False,
		"has_state_config": False,
		"changed": False,
	}
	try:
		with open(path, "r", encoding="utf-8", errors="ignore") as fh:
			lines = fh.readlines()
	except OSError:
		return result

	modules, type_map = parse_modules(lines)
	has_target_sig = any(m["implements"] for m in modules)
	result["has_target_sig"] = has_target_sig
	result["has_state_config"] = has_target_sig  # backward compatible field name
	if not has_target_sig or not type_map:
		return result

	new_lines, changed = qualify_config_modules(lines, modules, type_map)
	if changed:
		with open(path, "w", encoding="utf-8") as fh:
			fh.writelines(new_lines)
	result["changed"] = changed
	return result


def process_root(root: str, summary_path: str):
	report = []
	for dirpath, _, filenames in os.walk(root):
		for fname in filenames:
			if not fname.endswith(".ql"):
				continue
			fpath = os.path.join(dirpath, fname)
			info = process_file(fpath)
			report.append(info)

	os.makedirs(os.path.dirname(summary_path), exist_ok=True)
	with open(summary_path, "w", encoding="utf-8") as sf:
		json.dump(report, sf, indent=2, ensure_ascii=False)
	print(f"Wrote summary to {summary_path}")


def main(argv=None):
	parser = argparse.ArgumentParser(description="Qualify types in DataFlow::StateConfigSig modules")
	parser.add_argument("--root", default="/home/cbb/SAST-Rule-Migrate/PyRule/temp/CWE-022", help="Root directory containing .ql files to fix")
	parser.add_argument("--summary", default="/home/cbb/SAST-Rule-Migrate/PyRule/temp/stateconfig_summary.json", help="Path to write summary JSON")
	args = parser.parse_args(argv)

	process_root(args.root, args.summary)


if __name__ == "__main__":
	main()