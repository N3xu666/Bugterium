#!/usr/bin/env python3
import json
import os
import re
import shutil
import urllib.parse as _u
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SITE = ROOT / "site"
DST = SITE / "docs"
REPO_WEB = "https://github.com/N3xu666/Bugterium"

REF = [
    ("APPLICATIONS", "applications", "Applications", 1),
    ("AI", "ai", "AI", 2),
    ("CLOUD", "cloud", "Cloud", 3),
    ("INFRASTRUCTURE", "infrastructure", "Infrastructure", 4),
    ("NETWORKS", "networks", "Networks", 5),
    ("VIRTUALIZATION", "virtualization", "Virtualization", 6),
    ("INFORMATION_SECURITY", "information-security", "Information Security", 7),
    ("OSINT", "osint", "OSINT", 8),
    ("ANONYMITY-PRIVACY-OPSEC", "anonymity-privacy-opsec", "Anonymity & OpSec", 9),
]

LANG = {"01 Az", "02 En", "03 Ru"}
PREF = "02 En"


def slug(n):
    return re.sub(r"[^a-z0-9]+", "-", n.lower()).strip("-")


def parse(n):
    m = re.match(r"^(\d+)\s+(.+)$", n)
    if m:
        num = m.group(1)
        rest = re.sub(r"\s*\(.*?\)\s*$", "", m.group(2)).strip()
        return (slug(rest), f"{num} {rest}", int(num))
    return (slug(n), n, 999)

def h1(c):
    for l in c.split("\n"):
        m = re.match(r"^#\s+(.+?)\s*$", l)
        if m:
            return m.group(1)
    return None


def meta(c):
    d = {}
    for l in c.split("\n")[:20]:
        m = re.match(r"^>\s*([^:]+):\s*(.+?)\s*$", l)
        if m:
            d[m.group(1).strip()] = m.group(2).strip()
    return d

def para(c):
    lines = c.split("\n")
    inf = False
    seen = False
    buf = []
    for l in lines:
        s = l.strip()
        if s.startswith("```"):
            inf = not inf
            continue
        if inf:
            continue
        if not seen:
            if s.startswith("# "):
                seen = True
            continue
        if not s:
            if buf:
                break
            continue
        if s.startswith(("#", ">", "|", "---")):
            if buf:
                break
            continue
        buf.append(s)
    t = " ".join(buf)
    return (t[:150] + "...") if len(t) > 150 else t


def num(f):
    m = re.match(r"^(\d+)", f)
    return int(m.group(1)) if m else 999


def yq(s):
    return "'" + s.replace("'", "''") + "'"


def fm(sl, ti, de, po, ht):
    L = ["---"] + ([f"slug: {sl}"] if sl else []) + [f"title: {yq(ti)}", f"sidebar_label: {yq(ti)}", f"sidebar_position: {po}"]
    if de:
        L.append(f"description: {yq(de)}")
    if ht:
        L.append("hide_title: true")
    L.append("---")
    return "\n".join(L) + "\n\n"

def pf(md, dd, pos=None, inst="", doc_root=None, src_map=None, src_to_out=None, src_to_route=None):
    raw = md.read_text(encoding="utf-8-sig").replace("\r\n", "\n").replace("\r", "\n")
    if md.name.lower() == "readme.md":
        raw = raw.replace("](./Certificate.pdf)", f"](/pdf/{dd.name}/Certificate.pdf)")
        _pdf_url = f"/pdf/{dd.name}/Certificate.pdf"
        _pdf_png = f"/pdf/{dd.name}/Certificate.png"
        _pdf_link = f"**[Open Certificate (PDF)]({_pdf_url})**"
        if _pdf_link in raw:
            _thumb = f'<a href="{_pdf_url}" target="_blank"><img src="{_pdf_png}" width="200" alt="Certificate" style="display:inline-block;border:1px solid #1a1a1a;vertical-align:top"></a>'
            raw = raw.replace(_pdf_link, _thumb)
        t = h1(raw) or "Overview"
        out_path = (dd / "index.md").resolve()
        out_path.write_text(fm(None, t, "", 0, False) + raw, encoding="utf-8")
        if src_map is not None:
            src_map[out_path] = md.resolve()
        if src_to_out is not None:
            src_to_out[md.resolve()] = out_path
            src_to_out[md.parent.resolve()] = out_path
        if src_to_route is not None and doc_root is not None:
            dpath = dd.relative_to(doc_root).as_posix()
            route = f"/{inst}/{dpath}/" if dpath != "." else f"/{inst}/"
            src_to_route[md.resolve()] = route
            src_to_route[md.parent.resolve()] = route
        return
    h = h1(raw) or md.stem
    ti = re.sub(r"\s*\(HTB\)\s*$", "", h).strip() or md.stem
    if pos is None:
        pos = num(md.name)
    if not re.match(r"^\d", ti):
        ti = f"{pos:02d} {ti}"
    base = re.sub(r"^(\d+)\s+", "", md.stem)
    base = re.sub(r"\s*\(.*?\)\s*$", "", base).strip() or base
    sl = slug(base) or slug(md.stem)
    m = meta(raw)
    if "OS" in m and "Difficulty" in m:
        de = f"{m.get('OS','')} / {m.get('Difficulty','')} - {m.get('Result','')}".strip(" / -")
    else:
        de = para(raw)
    out_path = (dd / f"{sl}.md").resolve()
    out_path.write_text(fm(sl, ti, de, pos, True) + raw, encoding="utf-8")
    if src_map is not None:
        src_map[out_path] = md.resolve()
    if src_to_out is not None:
        src_to_out[md.resolve()] = out_path
    if src_to_route is not None and doc_root is not None:
        dpath = dd.relative_to(doc_root).as_posix()
        route = f"/{inst}/{dpath}/{sl}" if dpath != "." else f"/{inst}/{sl}"
        src_to_route[md.resolve()] = route

def walk(src, dst, inst, root, src_map=None, src_to_out=None, src_to_route=None):
    dst.mkdir(parents=True, exist_ok=True)
    for pdf in src.glob("*.pdf"):
        _pdf_dst = SITE / "static" / "pdf" / dst.name
        _pdf_dst.mkdir(parents=True, exist_ok=True)
        shutil.copy2(pdf, _pdf_dst / pdf.name)
        try:
            import pymupdf
            _doc = pymupdf.open(str(_pdf_dst / pdf.name))
            _pix = _doc[0].get_pixmap(dpi=150)
            _pix.save(str(_pdf_dst / (pdf.stem + ".png")))
            _doc.close()
        except Exception as _e:
            print(f"PDF->PNG failed: {pdf.name}: {_e}")
    files = sorted(src.glob("*.md"))
    readmes = [f for f in files if f.name.lower() == "readme.md"]
    others = [f for f in files if f.name.lower() != "readme.md"]
    for md in readmes:
        pf(md, dst, None, inst, root, src_map, src_to_out, src_to_route)
    max_num = 0
    for md in others:
        n = num(md.name)
        if n == 999:
            max_num += 1
            pf(md, dst, max_num, inst, root, src_map, src_to_out, src_to_route)
        else:
            max_num = max(max_num, n)
            pf(md, dst, n, inst, root, src_map, src_to_out, src_to_route)
    for s in sorted(src.iterdir()):
        if not s.is_dir() or s.name.startswith("."):
            continue
        if s.name in LANG:
            if s.name != PREF:
                continue
            walk(s, dst, inst, root, src_map, src_to_out, src_to_route)
            continue
        sl, lb, po = parse(s.name)
        nd = dst / sl
        nd.mkdir(parents=True, exist_ok=True)
        cat = {"label": lb, "position": po}
        if (s / "README.md").exists():
            cat["link"] = {"type": "doc", "id": f"{nd.relative_to(root).as_posix()}/index"}
        (nd / "_category_.json").write_text(json.dumps(cat, indent=2), encoding="utf-8")
        walk(s, nd, inst, root, src_map, src_to_out, src_to_route)

CODE_SECURITY_RE = re.compile(r"`(?:\.{1,2}/)+(SECURITY\.md|LICENSE|CHEATSHEET\.md|METHODOLOGY\.md)`")


def _clean_link_label(text):
    return re.sub(r"^(?:\.{1,2}/)+", "", text)


def _github_url(target):
    rel = target.resolve().relative_to(ROOT.resolve())
    quoted = "/".join(_u.quote(part, safe="-._~") for part in rel.parts)
    kind = "tree" if target.is_dir() else "blob"
    return f"{REPO_WEB}/{kind}/main/{quoted}"


def _doc_plugin_root(out_file):
    rel = out_file.resolve().relative_to(DST.resolve())
    return DST / rel.parts[0]


def _match_name(p, siblings):
    if p in siblings:
        return p
    if p.lower() == "readme.md" and "index.md" in siblings:
        return "index.md"
    stripped = re.sub(r"^\d+[\s%20]+", "", p)
    if p.endswith(".md"):
        cand = slug(stripped[:-3]) + ".md"
        if cand in siblings:
            return cand
    cand = slug(stripped)
    if cand in siblings:
        return cand
    if p.endswith(".md"):
        cand = slug(p[:-3]) + ".md"
        if cand in siblings:
            return cand
    cand = slug(p)
    if cand in siblings:
        return cand
    return None


def _rel_doc_link(out_md, target_out, anchor):
    if target_out.resolve() == out_md.resolve():
        return anchor if anchor else f"./{out_md.name}"
    rel = os.path.relpath(target_out, out_md.parent).replace("\\", "/")
    if not rel.startswith("."):
        rel = f"./{rel}"
    return f"{rel}{anchor}"


def fix_links(root, src_map, src_to_out, src_to_route):
    repo_resolved = ROOT.resolve()
    dst_resolved = root.resolve()
    machine_row_re = re.compile(r"^(\|\s*\d+\s*\|\s*)([^|\[\]]+?)(\s*\|\s*.*?\|\s*\[En\]\(([^)]+)\)\s*\|\s*.*)$")
    for md in root.rglob("*.md"):
        md_resolved = md.resolve()
        src_md = src_map.get(md_resolved)
        content = md.read_text(encoding="utf-8")
        original = content
        md_plugin = _doc_plugin_root(md_resolved)

        def repl(m):
            text = _clean_link_label(m.group(1))
            target = m.group(2)
            if target.startswith(("http", "#", "mailto:", "/")):
                return f"[{text}]({target})"
            path_part = target.split("#")[0]
            anchor = target[len(path_part):]
            try:
                path_part = _u.unquote(path_part)
            except Exception:
                pass
            path_part = path_part.rstrip("/")
            if not path_part:
                return f"[{text}]({target})"

            # 1. Exact resolution against original repo source path -> mapped Docusaurus output/route
            if src_md is not None:
                try:
                    resolved_src = (src_md.parent / path_part).resolve()
                    resolved_src.relative_to(repo_resolved)
                except (OSError, ValueError):
                    resolved_src = None
                if resolved_src is not None:
                    if resolved_src in src_to_out:
                        target_out = src_to_out[resolved_src]
                        if _doc_plugin_root(target_out) == md_plugin:
                            return f"[{text}]({_rel_doc_link(md_resolved, target_out, anchor)})"
                        return f"[{text}]({src_to_route[resolved_src]}{anchor})"
                    if resolved_src.exists():
                        return f"[{text}]({_github_url(resolved_src)}{anchor})"

            # 2. Fallback matching within built Docusaurus tree
            decoded_for_dst = re.sub(r"(?:^|/)02 En/", "/", path_part).lstrip("/") if "02 En/" in path_part else path_part
            parts = decoded_for_dst.split("/")
            current = md_resolved.parent
            ok = True
            for p in parts:
                if p in ("", "."):
                    continue
                if p == "..":
                    current = current.parent
                    try:
                        current.resolve().relative_to(dst_resolved)
                    except ValueError:
                        ok = False
                        break
                    continue
                try:
                    siblings = [f.name for f in current.iterdir()]
                except OSError:
                    ok = False
                    break
                matched = _match_name(p, siblings)
                if matched is None:
                    ok = False
                    break
                current = current / matched
            if ok:
                target_out = (current / "index.md") if (current.is_dir() and (current / "index.md").exists()) else (current if current.is_file() else None)
                if target_out is not None and _doc_plugin_root(target_out) == md_plugin:
                    return f"[{text}]({_rel_doc_link(md_resolved, target_out, anchor)})"
            return text

        lines = content.split("\n")
        out_lines = []
        in_code = False
        for ln in lines:
            stripped = ln.lstrip()
            if stripped.startswith("```"):
                in_code = not in_code
                out_lines.append(ln)
                continue
            if not in_code:
                ln = CODE_SECURITY_RE.sub(
                    lambda cm: f"[{cm.group(1)}]({REPO_WEB}/blob/main/{cm.group(1)})",
                    ln,
                )
                ln = re.sub(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", repl, ln)
                if md.name == "index.md":
                    ln = machine_row_re.sub(
                        lambda rm: f"{rm.group(1)}[{rm.group(2).strip()}]({rm.group(4)}){rm.group(3)}",
                        ln,
                    )
            out_lines.append(ln)
        new = "\n".join(out_lines)
        if new != original:
            md.write_text(new, encoding="utf-8")

def main():
    if DST.exists():
        shutil.rmtree(DST)
    DST.mkdir(parents=True)
    src_map = {}
    src_to_out = {}
    src_to_route = {}
    wd = DST / "writeups"
    wd.mkdir(parents=True)
    w = ROOT / "WRITEUPS"
    if w.exists():
        walk(w, wd, "writeups", wd, src_map, src_to_out, src_to_route)
    rd = DST / "reference"
    rd.mkdir(parents=True)
    rows = []
    for sn, dn, lb, po in REF:
        sd = ROOT / sn
        if not sd.exists():
            continue
        cnt = len(list(sd.rglob("*.md")))
        rows.append(f"| {po} | [{lb}](/reference/{dn}) | {cnt} |")
    ref_idx = "---\ntitle: Reference\nsidebar_label: Overview\nsidebar_position: 0\n---\n\n# Reference\n\nSecurity reference material: applications, infrastructure, cloud, AI, networks, virtualization, information security, OSINT, and anonymity/privacy/opsec.\n\n| # | Category | Files |\n|---|----------|-------|\n" + "\n".join(rows) + "\n"
    (rd / "index.md").write_text(ref_idx, encoding="utf-8")
    for sn, dn, lb, po in REF:
        sd = ROOT / sn
        if not sd.exists():
            print(f"SKIP: {sn}")
            continue
        nd = rd / dn
        nd.mkdir(parents=True, exist_ok=True)
        cat = {"label": lb, "position": po}
        if (sd / "README.md").exists():
            cat["link"] = {"type": "doc", "id": f"{dn}/index"}
        (nd / "_category_.json").write_text(json.dumps(cat, indent=2), encoding="utf-8")
        walk(sd, nd, "reference", rd, src_map, src_to_out, src_to_route)
    fix_links(DST, src_map, src_to_out, src_to_route)
    t = sum(1 for _ in DST.rglob("*.md"))
    c = sum(1 for _ in DST.rglob("_category_.json"))
    print(f"Generated: {t} md, {c} categories")


if __name__ == "__main__":
    main()