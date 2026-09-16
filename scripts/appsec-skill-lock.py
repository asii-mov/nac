#!/usr/bin/env python3
"""Regenerate or check the source-review bootstrap skill lock."""

import argparse
import hashlib
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1] / "skills" / "appsec"
    skills = {}
    for name in ["evidence", "recon", "discovery", "validation", "synthesis", "controlled-experiment"]:
        files = sorted((root / "skills" / name).rglob("*"))
        if any(path.is_symlink() for path in files):
            raise SystemExit("skill resources must not be symlinks")
        skills[name] = {
            "version": "1.0.0",
            "stages": ["*"] if name == "evidence" else (["discovery", "validation"] if name == "controlled-experiment" else [name]),
            "entry": f"skills/{name}/SKILL.md",
            "dependencies": [] if name == "evidence" else ["evidence"],
            "files": {
                path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in files if path.is_file()
            },
        }
    lock = {
        "schema_version": 1,
        "compatibility": "nac-source-review-v1",
        "registry_sha256": hashlib.sha256((root / "skills.md").read_bytes()).hexdigest(),
        "skills": skills,
    }
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    output = root / "skills.lock.json"
    if args.check:
        if output.read_text() != text:
            raise SystemExit("appsec skill lock drift; run scripts/appsec-skill-lock.py")
    else:
        output.write_text(text)


if __name__ == "__main__":
    main()
