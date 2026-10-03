"""Export the validation corpus to files (ТЗ 1.0.1 §10).

Writes the synthetic corpus into the layout the specification describes::

    corpus/
      legitimate/
      phishing/
      bec/
      impersonation/
      spam/
      malware-simulated/
      malformed/
      gateway-headers/

The files are *generated*, not committed: the corpus lives as code in ``tests/fixtures/corpus.py``
so it stays deterministic, reviewable in a diff, and impossible to contaminate with real mail by
accident. Export it when a human needs to open the messages in a mail client, or when a pilot
needs the corpus alongside anonymised real samples.

Real messages added by hand must be anonymised first, or handled under the organisation's own
policy for retaining mail; ``corpus/README.md`` states the rules and the export never overwrites
a directory it did not create.

Usage::

    python scripts/export_corpus.py                 # writes ./corpus
    python scripts/export_corpus.py --out /tmp/c    # elsewhere
    python scripts/export_corpus.py --manifest-only # just the manifest
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "tests"))

from fixtures.corpus import CATEGORIES, CORPUS, by_category  # noqa: E402

#: Written into every generated directory so a later export knows what it may replace.
MARKER = ".msp-generated"

README = """# Validation corpus (ТЗ 1.0.1 §10)

These files are **generated** by `scripts/export_corpus.py` from `tests/fixtures/corpus.py`.
Do not edit them: the next export overwrites anything carrying the `.msp-generated` marker.

## What is here

Synthetic, inert fixtures. The only "malicious" payload is the EICAR test string, and every
indicator points at a reserved `.example` or `.test` name that resolves nowhere. Nothing in this
directory is live malware, and nothing in it is real correspondence.

## Adding real messages

Real mail may be added for validation only when it is either anonymised or retained under the
organisation's own policy for message content (ТЗ 1.0.1 §10, ТЗ 27). Put such messages in a
directory of their own — not next to the generated ones — so an export cannot delete them and a
reviewer can tell them apart. At minimum, anonymising means replacing recipient addresses,
internal hostnames and any identifiers in URLs; the subject and body usually have to stay, since
they are what the detection is being validated against.

## Categories

| Directory | What it validates |
|---|---|
| `legitimate/` | ordinary business mail that must not be flagged |
| `phishing/` | credential harvesting, fake login pages |
| `bec/` | payment redirection, invoice fraud, CEO fraud |
| `impersonation/` | display-name spoofing, lookalike and punycode domains |
| `spam/` | unwanted bulk mail, which is not the same as an attack |
| `malware-simulated/` | dangerous attachment shapes, archives, EICAR |
| `malformed/` | broken MIME, oversized messages, parser limits |
| `gateway-headers/` | verdicts from an upstream gateway, genuine and forged |

The `gateway-headers` set is the one worth reading as a pair: `21_gateway_clean_verified` and
`23_spoofed_ksmg_header` carry almost the same headers and differ only in the delivery chain,
which is what decides whether those headers mean anything.
"""


def export(out_dir: Path, *, manifest_only: bool = False) -> dict[str, object]:
    grouped = by_category()
    # ``categories`` is held in its own name so the manifest stays typed end to end: with it
    # inlined, every read of manifest["categories"] is an ``object`` and needs a cast at the
    # call site, which is how this file ended up with two silencing comments and a latent error.
    categories: dict[str, list[dict[str, object]]] = {}
    manifest: dict[str, object] = {
        "total": len(CORPUS),
        "categories": categories,
        "generated_by": "scripts/export_corpus.py",
    }

    for category in CATEGORIES:
        fixtures = grouped.get(category, [])
        entries = [
            {
                "name": fixture.name,
                "file": f"{category}/{fixture.name}.eml",
                "description": fixture.description,
                "expect_min_level": fixture.expect_min_level,
                "expect_rules": list(fixture.expect_rules),
                "expect_facts": list(fixture.expect_facts),
                "requires_enrichment": fixture.requires_enrichment,
                "tags": list(fixture.tags),
                "size_bytes": len(fixture.raw),
            }
            for fixture in fixtures
        ]
        categories[category] = entries

        if manifest_only:
            continue
        directory = out_dir / category
        if directory.exists() and not (directory / MARKER).exists():
            raise SystemExit(
                f"{directory} exists but was not created by this script: refusing to overwrite "
                "files that may be real, anonymised samples"
            )
        directory.mkdir(parents=True, exist_ok=True)
        (directory / MARKER).write_text("generated by scripts/export_corpus.py\n", encoding="utf-8")
        for fixture in fixtures:
            (directory / f"{fixture.name}.eml").write_bytes(fixture.raw)

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    if not manifest_only:
        (out_dir / "README.md").write_text(README, encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Экспорт валидационного корпуса (ТЗ 1.0.1 §10)")
    parser.add_argument("--out", default=str(REPO_ROOT / "corpus"), help="каталог для экспорта")
    parser.add_argument("--manifest-only", action="store_true", help="записать только manifest.json")
    args = parser.parse_args()

    out_dir = Path(args.out)
    manifest = export(out_dir, manifest_only=args.manifest_only)
    categories = manifest["categories"]
    assert isinstance(categories, dict)
    print(f"Корпус: {manifest['total']} писем -> {out_dir}")
    for category, entries in categories.items():
        print(f"  {category}: {len(entries)}")
    print(
        "\nВсе письма синтетические и инертные. Реальные письма добавляйте только "
        "обезличенными и в отдельный каталог: см. corpus/README.md."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
