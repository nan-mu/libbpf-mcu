# PR #7 candidate verification

The [mirror index](index.json) records 14 assets and their ordered base64 parts. To restore the candidate, set `mirror` to this directory and `scratch` to a new directory. The verification input will contain the 12 program archives and `release.json`. The evidence archive is restored alongside that directory.

```sh
python3 - "$mirror" "$scratch" <<'PY'
import base64
import hashlib
import json
import sys
from pathlib import Path

mirror, scratch = map(Path, sys.argv[1:])
index = json.loads((mirror / "index.json").read_bytes())
scratch.mkdir()
archives = scratch / "archives"
archives.mkdir()
for asset in index["assets"]:
    data = b"".join(
        base64.b64decode(b"".join((mirror / part).read_bytes().split()), validate=True)
        for part in asset["parts"]
    )
    if len(data) != asset["size_bytes"] or hashlib.sha256(data).hexdigest() != asset["sha256"]:
        raise ValueError(f"candidate digest or size mismatch: {asset['name']}")
    directory = scratch if asset["name"] == "evidence.7z" else archives
    (directory / asset["name"]).write_bytes(data)
PY
pixi run verify-release --archive-dir "$scratch/archives" --unpack-dir "$scratch/unpacked"
7z x "$scratch/evidence.7z" "-o$scratch/evidence"
```

Use the release ledger to check exact candidate archive bytes. Independent rebuilds in different absolute directories matched the portable images and layouts. Archive digests can differ because archived compiler objects and reports include build paths.

## Historical replay

The evidence contains the v0.1.1 program archives, their published asset manifest and a portable copy of the historical layout ledger. Derive the archive filenames from the program names before using the comparison or negative-check scripts.

```sh
legacy="$scratch/evidence/v0.1.1-archives"
python3 - "$legacy" <<'PY'
import json
import sys
from pathlib import Path

legacy = Path(sys.argv[1])
ledger = json.loads((legacy / "layout-ledger.json").read_bytes())
for archive in ledger["archives"]:
    archive["archive"] = f"{archive['program']}.7z"
(legacy / "release.json").write_text(json.dumps(ledger, indent=2) + "\n")
PY
pixi run python "$scratch/evidence/negative-check.py" "$PWD" "$scratch" "$legacy"
```

For the two-layout comparison, provide the same `$legacy` directory, `$scratch/evidence/v0.1.1-assets.json` and a prebuilt `xpost-mcu-elf` to `make/compare_release.py`. The historical ledger retains the original archive SHA-256 values. The negative-check script writes its repacked fixtures and results within the scratch directory.

The candidate prerelease uses a dedicated tag such as `v0.1.2-rc.1`, checked against remote refs before authorized publication. The stable `next-release-tag` command still allocates numeric patch tags. This candidate is available from the mirror while direct prerelease publication is blocked.
