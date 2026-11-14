import json
import re
from pathlib import Path
from collections import Counter

SITE = Path(__file__).resolve().parents[1]
DOCS = SITE / "docs"
OUT = SITE / "static" / "graph.json"
BASES = {"reference": "/reference", "writeups": "/writeups"}

TOOLS = ["nmap", "gobuster", "ffuf", "feroxbuster", "dirb", "nikto", "sqlmap", "burp", "metasploit", "hydra", "john", "hashcat", "impacket", "bloodhound", "mimikatz", "chisel", "netcat", "curl", "wget", "python", "bash", "powershell", "wmiexec", "psexec", "smbexec", "evil-winrm", "responder", "crackmapexec", "netexec", "enum4linux", "ldapsearch", "rpcclient", "smbclient", "ssh", "ftp", "telnet", "redis-cli", "mysql", "psql", "docker", "kubernetes", "jenkins", "jira", "gitlab", "tomcat", "apache", "nginx", "iis", "wordpress", "drupal", "joomla", "node.js", "express", "django", "flask", "spring", "laravel", "php", "ruby", "go", "rust", "react", "angular", "vue"]
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
MITRE_ATTACK_RE = re.compile(r"(?<!AML\.)(?<!\.)\bT(?:08\d{2}|1\d{3})(?:\.\d{3})?\b")
MITRE_ATLAS_RE = re.compile(r"\bAML\.T\d{4}(?:\.\d{3})?\b")

def fm(path):
    try:
        t = path.read_text(encoding="utf-8")
    except Exception:
        return {}
    if not t.startswith("---"):
        return {}
    e = t.find("\n---", 3)
    if e == -1:
        return {}
    d = {}
    for ln in t[3:e].split("\n"):
        s = ln.strip()
        if not s or s.startswith("#") or ":" not in s:
            continue
        k, v = s.split(":", 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
            v = v[1:-1]
        d[k.strip()] = v
    return d

def extract_entities(text):
    low = text.lower()
    tools = set()
    for t in TOOLS:
        if re.search(r"\b" + re.escape(t) + r"\b", low):
            tools.add(t)
    cves = set(c.upper() for c in CVE_RE.findall(text))
    mitre_attack = set(m.upper() for m in MITRE_ATTACK_RE.findall(text))
    mitre_atlas = set(m.upper() for m in MITRE_ATLAS_RE.findall(text))
    return tools, cves, mitre_attack, mitre_atlas

def walk():
    if not DOCS.exists():
        print("ERROR: docs/ missing. Run build-docs.py first.")
        return
    files = sorted(DOCS.rglob("*.md"))
    print("Scanning", len(files), "files for tools and CVEs...")
    
    nodes = []
    links = []
    tree = {}
    neural_nodes = {}
    neural_links = []
    for p in files:
        parts = p.relative_to(DOCS).parts
        if len(parts) < 2 or parts[0] not in BASES:
            continue
        top = parts[0]
        inner = list(parts[1:])
        is_index = inner[-1] == "index.md"
        dirs = inner[:-1]
        name = "index" if is_index else inner[-1][:-3]
        ips = [top] + dirs + ([] if is_index else [name])
        nid = "/".join(ips)
        depth = len(ips) - 1
        parent = "/".join(ips[:-1]) if len(ips) > 1 else None
        ancestors = ["/".join(ips[:i]) for i in range(1, len(ips))]
        m = fm(p)
        label = m.get("sidebar_label") or m.get("title") or (dirs[-1] if is_index and dirs else name)
        slug = m.get("slug") or name
        dpath = "/".join(dirs)
        if is_index:
            url = (BASES[top] + "/" + dpath + "/") if dpath else (BASES[top] + "/")
        else:
            url = (BASES[top] + "/" + dpath + "/" + slug) if dpath else (BASES[top] + "/" + slug)
        
        nodes.append({
            "id": nid, "label": label, "depth": depth,
            "parent": parent, "ancestors": ancestors,
            "url": url, "file": str(p.relative_to(SITE)).replace("\\", "/"),
            "top": top, "is_index": is_index, "slug": slug,
        })
        
        # 1. Добавляем связи иерархии в нейронный граф (чтобы был скелет)
        if parent:
            neural_links.append({"source": nid, "target": parent})
        else:
            neural_links.append({"source": nid, "target": "_home"})
            
        # 2. Извлекаем инструменты и CVE (только для файлов, не для папок)
        if not is_index:
            try:
                text = p.read_text(encoding="utf-8")
            except Exception:
                text = ""
            tools, cves, mitre_attack, mitre_atlas = extract_entities(text)
            
            # Связи с инструментами
            for t in tools:
                tid = "tool:" + t
                if tid not in neural_nodes:
                    neural_nodes[tid] = {"id": tid, "label": t.upper(), "group": "tool", "val": 2}
                neural_links.append({"source": nid, "target": tid})
                
            # Связи с CVE
            for cve in cves:
                cid = "cve:" + cve
                if cid not in neural_nodes:
                    neural_nodes[cid] = {"id": cid, "label": cve, "group": "cve", "val": 1.5, "url": f"https://nvd.nist.gov/vuln/detail/{cve}"}
                neural_links.append({"source": nid, "target": cid})

            # Связи с MITRE ATT&CK
            for tech in mitre_attack:
                mid = "mitre:" + tech
                if mid not in neural_nodes:
                    tech_clean = tech.replace(".", "/")
                    neural_nodes[mid] = {"id": mid, "label": tech, "group": "mitre", "val": 1.6, "url": f"https://attack.mitre.org/techniques/{tech_clean}/"}
                neural_links.append({"source": nid, "target": mid})

            # Связи с MITRE ATLAS
            for tech in mitre_atlas:
                mid = "mitre:" + tech
                if mid not in neural_nodes:
                    neural_nodes[mid] = {"id": mid, "label": tech, "group": "mitre", "val": 1.6, "url": f"https://atlas.mitre.org/techniques/{tech}"}
                neural_links.append({"source": nid, "target": mid})
    tree = {}
    for n in nodes:
        tree[n["id"]] = {
            "id": n["id"], "label": n["label"], "depth": n["depth"],
            "parent": n["parent"], "top": n["top"], "url": n["url"],
            "is_index": n["is_index"], "children": [],
        }
    links = []
    for n in nodes:
        if n["parent"] and n["parent"] in tree:
            tree[n["parent"]]["children"].append(n["id"])
            links.append({"source": n["id"], "target": n["parent"]})
        elif n["parent"] is None:
            links.append({"source": n["id"], "target": "_home"})
    roots = [t for t in ("writeups", "reference") if t in tree]
    home = {"id": "_home", "label": "Bugterium", "depth": -1,
            "parent": None, "top": None, "url": "/", "is_index": True,
            "children": list(roots)}
    nodes.append({"id": "_home", "label": "Bugterium", "depth": -1,
                  "parent": None, "ancestors": [], "url": "/",
                  "file": "", "top": None, "is_index": True, "slug": "home"})
    tree["_home"] = home

    brain_nodes = list(nodes)
    for tid, tn in neural_nodes.items():
        brain_nodes.append(tn)

    seen_links = set()
    brain_links = []
    for l in neural_links:
        k = f"{l['source']}->{l['target']}"
        if k not in seen_links:
            seen_links.add(k)
            brain_links.append(l)

    depth_counts = Counter(n["depth"] for n in nodes)
    print("Hierarchy Nodes:", len(nodes), "Links:", len(links))
    print("Brain Nodes:", len(brain_nodes), "Links:", len(brain_links))
    print("Depth counts:", dict(sorted(depth_counts.items())))
    print("Roots:", roots)
    for r in roots:
        print("  ", r, "children:", len(tree[r]["children"]))
        
    payload = {
        "hierarchy": {"nodes": nodes, "links": links, "tree": tree, "roots": roots, "home": "_home"},
        "brain": {"nodes": brain_nodes, "links": brain_links},
        "meta": {"total": len(nodes), "brain_total": len(brain_nodes), "depth_counts": dict(depth_counts)}
    }
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print("Wrote", OUT, "size:", OUT.stat().st_size, "bytes")

if __name__ == "__main__":
    walk()