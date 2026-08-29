"""Repairs UTF-8 -> CP1252 mojibake in template files.

The favicon insertion script read the UTF-8 files with the ANSI codepage,
turning every multi-byte UTF-8 sequence into latin mojibake chars (e.g.
'▼' -> 'â–¼'). This reverses the corruption by re-encoding the mojibake
chunks via cp1252 and decoding the result as UTF-8 again.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = [
    "app/templates/dashboard.html",
    "app/templates/login.html",
    "app/templates/settings.html",
    "app/templates/actions.html",
    "app/templates/admin.html",
    "app/templates/nav.html",
]


def repair_text(text: str) -> str:
    out = []
    i = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ord(ch) < 128:
            out.append(ch)
            i += 1
            continue
        repaired = None
        consumed = 1
        # Greedy: try to map 1..6 mojibake chars back to a real UTF-8 sequence
        for k in range(1, 7):
            if i + k > n:
                break
            try:
                b = text[i:i + k].encode("cp1252")
            except UnicodeEncodeError:
                break
            try:
                dec = b.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if any(ord(c2) > 127 for c2 in dec):
                repaired = dec
                consumed = k
                break
        if repaired is not None:
            out.append(repaired)
            i += consumed
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def main():
    changed = 0
    for rel in FILES:
        path = ROOT / rel
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        fixed = repair_text(text)
        if fixed != text:
            path.write_bytes(fixed.encode("utf-8"))
            changed += 1
            print(f"REPAIRED: {rel}")
        else:
            print(f"clean: {rel}")
    # sanity: no mojibake leftovers
    leftovers = 0
    for rel in FILES:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for bad in ("â", "Ã", "Â·", "ï¸", "â€"):
            if bad in text:
                leftovers += text.count(bad)
                print(f"  leftover {bad!r} in {rel}: {text.count(bad)}")
    print(f"changed={changed} leftovers={leftovers}")
    sys.exit(1 if leftovers else 0)


if __name__ == "__main__":
    main()
