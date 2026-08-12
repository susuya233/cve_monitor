"""生成可点击切换 CVE 详情的静态 HTML 报告。"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LEVEL_CN = {
    "Critical": "严重",
    "High": "高危",
    "Medium": "中危",
    "Low": "低危",
    "严重": "严重",
    "高危": "高危",
    "中危": "中危",
    "低危": "低危",
}
LEVEL_RANK = {"Critical": 0, "严重": 0, "High": 1, "高危": 1, "Medium": 2, "中危": 2}


def _now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def collect_vulns(data_dir: Path) -> list[dict[str, Any]]:
    vulns_dir = data_dir / "vulns"
    items: list[dict[str, Any]] = []
    if not vulns_dir.exists():
        return items
    for path in vulns_dir.glob("*.json"):
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        detail = envelope.get("detail") if isinstance(envelope, dict) else None
        if not isinstance(detail, dict):
            continue
        item = dict(detail)
        item["_saved_at"] = envelope.get("saved_at")
        item["_first_saved_at"] = envelope.get("first_saved_at")
        item["_source_page"] = envelope.get("source_page") or (
            f"https://www.oscs1024.com/hd/{item.get('mps_id', '')}"
        )
        items.append(item)

    def sort_key(x: dict[str, Any]) -> tuple:
        level = str(x.get("level") or "")
        pub = str(x.get("published_time") or "")
        score = x.get("cvss_score")
        try:
            score_n = -float(score)
        except (TypeError, ValueError):
            score_n = 0.0
        return (LEVEL_RANK.get(level, 9), pub and pub or "0000", score_n, str(x.get("mps_id")))

    items.sort(key=sort_key)
    return items


def build_payload(data_dir: Path, retention_days: int, cutoff: str) -> dict[str, Any]:
    items = collect_vulns(data_dir)
    return {
        "generated_at": _now_iso(),
        "retention_days": retention_days,
        "cutoff_date": cutoff,
        "source": "https://www.oscs1024.com/hl",
        "count": len(items),
        "level_labels": LEVEL_CN,
        "items": items,
    }


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OSCS 严重/高危情报</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&family=Syne:wght@600;700;800&display=swap" rel="stylesheet" />
  <style>
    :root {
      --bg0: #071015;
      --bg1: #0d1a20;
      --bg2: #12242c;
      --panel: rgba(14, 28, 34, 0.88);
      --line: rgba(140, 190, 170, 0.16);
      --text: #e7f2ec;
      --muted: #8aa39a;
      --accent: #2fd3a2;
      --accent-dim: rgba(47, 211, 162, 0.14);
      --crit: #ff5a4e;
      --crit-bg: rgba(255, 90, 78, 0.14);
      --high: #ff9a3c;
      --high-bg: rgba(255, 154, 60, 0.14);
      --shadow: 0 20px 50px rgba(0, 0, 0, 0.35);
      --radius: 16px;
    }
    * { box-sizing: border-box; }
    html, body {
      margin: 0; min-height: 100%;
      color: var(--text);
      font-family: "IBM Plex Sans", system-ui, sans-serif;
      background:
        radial-gradient(1200px 600px at 10% -10%, rgba(47, 211, 162, 0.16), transparent 55%),
        radial-gradient(900px 500px at 100% 0%, rgba(255, 90, 78, 0.10), transparent 50%),
        linear-gradient(160deg, var(--bg0), var(--bg1) 45%, #0a151b);
    }
    body::before {
      content: "";
      position: fixed; inset: 0; pointer-events: none; opacity: 0.35;
      background-image:
        linear-gradient(rgba(140, 190, 170, 0.05) 1px, transparent 1px),
        linear-gradient(90deg, rgba(140, 190, 170, 0.05) 1px, transparent 1px);
      background-size: 28px 28px;
      mask-image: radial-gradient(ellipse at center, black 30%, transparent 75%);
    }
    .shell {
      position: relative;
      max-width: 1280px;
      margin: 0 auto;
      padding: 28px 20px 40px;
      display: grid;
      gap: 18px;
      min-height: 100vh;
    }
    header.hero {
      display: grid;
      gap: 10px;
      padding: 22px 24px;
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: linear-gradient(135deg, rgba(18, 36, 44, 0.95), rgba(10, 22, 28, 0.9));
      box-shadow: var(--shadow);
    }
    .brand {
      font-family: Syne, sans-serif;
      font-weight: 800;
      font-size: clamp(1.6rem, 3vw, 2.2rem);
      letter-spacing: -0.03em;
      line-height: 1.1;
    }
    .brand span { color: var(--accent); }
    .sub {
      color: var(--muted);
      font-size: 0.95rem;
      max-width: 62ch;
    }
    .meta {
      display: flex; flex-wrap: wrap; gap: 8px 14px;
      font-family: "JetBrains Mono", monospace;
      font-size: 0.78rem;
      color: var(--muted);
    }
    .meta b { color: var(--text); font-weight: 500; }
    .layout {
      display: grid;
      grid-template-columns: minmax(280px, 360px) 1fr;
      gap: 16px;
      min-height: 70vh;
    }
    @media (max-width: 900px) {
      .layout { grid-template-columns: 1fr; }
    }
    .panel {
      border: 1px solid var(--line);
      border-radius: var(--radius);
      background: var(--panel);
      backdrop-filter: blur(10px);
      box-shadow: var(--shadow);
      overflow: hidden;
      display: flex;
      flex-direction: column;
      min-height: 520px;
    }
    .panel-hd {
      padding: 14px 16px;
      border-bottom: 1px solid var(--line);
      display: flex; align-items: center; justify-content: space-between; gap: 10px;
    }
    .panel-hd h2 {
      margin: 0; font-size: 0.92rem; font-weight: 600; letter-spacing: 0.02em;
    }
    .search {
      width: 100%;
      margin: 0 16px 12px;
      padding: 10px 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: rgba(0,0,0,0.25);
      color: var(--text);
      font: inherit;
      outline: none;
    }
    .search:focus { border-color: rgba(47, 211, 162, 0.5); box-shadow: 0 0 0 3px var(--accent-dim); }
    .list {
      overflow: auto;
      padding: 0 8px 12px;
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .item {
      text-align: left;
      width: 100%;
      border: 1px solid transparent;
      border-radius: 12px;
      padding: 12px;
      background: transparent;
      color: inherit;
      cursor: pointer;
      transition: background .15s, border-color .15s, transform .15s;
    }
    .item:hover { background: rgba(255,255,255,0.03); border-color: var(--line); }
    .item.active {
      background: var(--accent-dim);
      border-color: rgba(47, 211, 162, 0.35);
    }
    .item-top {
      display: flex; align-items: center; justify-content: space-between; gap: 8px;
      margin-bottom: 6px;
    }
    .cve {
      font-family: "JetBrains Mono", monospace;
      font-size: 0.82rem;
      font-weight: 600;
    }
    .title {
      font-size: 0.86rem;
      color: #c8ddd4;
      line-height: 1.35;
      display: -webkit-box;
      -webkit-line-clamp: 2;
      -webkit-box-orient: vertical;
      overflow: hidden;
    }
    .item-foot {
      margin-top: 8px;
      display: flex; gap: 8px; flex-wrap: wrap;
      font-family: "JetBrains Mono", monospace;
      font-size: 0.72rem;
      color: var(--muted);
    }
    .badge {
      display: inline-flex; align-items: center;
      padding: 2px 8px;
      border-radius: 999px;
      font-size: 0.72rem;
      font-weight: 600;
      letter-spacing: 0.02em;
    }
    .badge.crit { color: #ffb4ad; background: var(--crit-bg); }
    .badge.high { color: #ffd0a3; background: var(--high-bg); }
    .badge.other { color: var(--muted); background: rgba(255,255,255,0.06); }
    .detail {
      overflow: auto;
      padding: 18px 20px 28px;
    }
    .empty {
      margin: auto; color: var(--muted); text-align: center; padding: 40px 20px;
    }
    .d-head {
      display: flex; flex-wrap: wrap; gap: 10px; align-items: flex-start;
      justify-content: space-between;
      margin-bottom: 14px;
    }
    .d-title {
      font-family: Syne, sans-serif;
      font-size: clamp(1.25rem, 2.2vw, 1.7rem);
      font-weight: 700;
      letter-spacing: -0.02em;
      margin: 0 0 8px;
      line-height: 1.2;
    }
    .ids {
      display: flex; flex-wrap: wrap; gap: 8px;
      font-family: "JetBrains Mono", monospace;
      font-size: 0.82rem;
    }
    .chip {
      padding: 4px 10px;
      border-radius: 8px;
      background: rgba(255,255,255,0.04);
      border: 1px solid var(--line);
      color: #cfe4da;
    }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; }
    .btn {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 8px 12px;
      border-radius: 10px;
      border: 1px solid var(--line);
      background: rgba(255,255,255,0.03);
      color: var(--text);
      text-decoration: none;
      font-size: 0.85rem;
      transition: border-color .15s, background .15s;
    }
    .btn:hover { border-color: rgba(47,211,162,.45); background: var(--accent-dim); }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 10px;
      margin: 16px 0 20px;
    }
    .stat {
      padding: 12px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(0,0,0,0.18);
    }
    .stat .k { color: var(--muted); font-size: 0.75rem; margin-bottom: 6px; }
    .stat .v {
      font-family: "JetBrains Mono", monospace;
      font-size: 0.95rem;
      font-weight: 600;
      word-break: break-all;
    }
    .section { margin-top: 18px; }
    .section h3 {
      margin: 0 0 8px;
      font-size: 0.9rem;
      color: #b7d0c6;
      letter-spacing: 0.04em;
      text-transform: uppercase;
    }
    .box {
      padding: 14px 16px;
      border-radius: 12px;
      border: 1px solid var(--line);
      background: rgba(0,0,0,0.2);
      line-height: 1.65;
      white-space: pre-wrap;
      word-break: break-word;
      font-size: 0.92rem;
      color: #d7e8e0;
    }
    .refs { display: flex; flex-direction: column; gap: 8px; }
    .refs a {
      color: var(--accent);
      text-decoration: none;
      font-family: "JetBrains Mono", monospace;
      font-size: 0.8rem;
      word-break: break-all;
    }
    .refs a:hover { text-decoration: underline; }
    .article {
      margin-top: 10px;
      padding: 12px 14px;
      border-left: 3px solid rgba(47,211,162,.45);
      background: rgba(47,211,162,.05);
      border-radius: 0 10px 10px 0;
    }
    .article h4 { margin: 0 0 6px; font-size: 0.92rem; }
    .article p { margin: 0; color: #c5d8cf; font-size: 0.88rem; white-space: pre-wrap; }
    .hint { color: var(--muted); font-size: 0.78rem; }
    .count-pill {
      font-family: "JetBrains Mono", monospace;
      font-size: 0.75rem;
      padding: 3px 8px;
      border-radius: 999px;
      background: rgba(255,255,255,0.06);
      color: var(--muted);
    }
  </style>
</head>
<body>
  <div class="shell">
    <header class="hero">
      <div class="brand">OSCS <span>CVE Radar</span></div>
      <p class="sub">最近严重 / 高危漏洞情报（自动译为中文）。左侧点击切换 CVE，右侧查看完整详情。</p>
      <div class="meta">
        <span>生成时间 <b id="generatedAt">-</b></span>
        <span>保留 <b id="retention">-</b> 天</span>
        <span>截止 <b id="cutoff">-</b></span>
        <span>条目 <b id="count">0</b></span>
        <span><a class="btn" style="padding:4px 8px" href="https://www.oscs1024.com/hl" target="_blank" rel="noopener">OSCS /hl</a></span>
      </div>
    </header>

    <div class="layout">
      <aside class="panel">
        <div class="panel-hd">
          <h2>漏洞列表</h2>
          <span class="count-pill" id="listCount">0</span>
        </div>
        <input class="search" id="search" type="search" placeholder="搜索 CVE / MPS / 标题 / 类型…" />
        <div class="list" id="list"></div>
      </aside>

      <main class="panel">
        <div class="panel-hd">
          <h2>详情</h2>
          <span class="hint">↑↓ 切换 · / 聚焦搜索</span>
        </div>
        <div class="detail" id="detail">
          <div class="empty">暂无数据</div>
        </div>
      </main>
    </div>
  </div>

  <script id="payload" type="application/json">__PAYLOAD__</script>
  <script>
    const payload = JSON.parse(document.getElementById("payload").textContent);
    const levelLabels = payload.level_labels || {};
    const items = payload.items || [];
    let filtered = items.slice();
    let activeId = null;

    const $ = (id) => document.getElementById(id);
    $("generatedAt").textContent = payload.generated_at || "-";
    $("retention").textContent = payload.retention_days ?? "-";
    $("cutoff").textContent = payload.cutoff_date || "-";
    $("count").textContent = String(payload.count ?? items.length);

    function levelClass(level) {
      const cn = levelLabels[level] || level || "";
      if (level === "Critical" || cn === "严重") return "crit";
      if (level === "High" || cn === "高危") return "high";
      return "other";
    }
    function levelText(level) {
      return levelLabels[level] || level || "-";
    }
    function esc(s) {
      return String(s ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;");
    }
    function scoreText(v) {
      if (v === null || v === undefined || v === "" || v === -1) return "-";
      return String(v);
    }

    function renderList() {
      const list = $("list");
      $("listCount").textContent = String(filtered.length);
      if (!filtered.length) {
        list.innerHTML = '<div class="empty">没有匹配项</div>';
        return;
      }
      list.innerHTML = filtered.map((it) => {
        const id = it.mps_id || it.cve_id;
        const active = id === activeId ? " active" : "";
        return `
          <button class="item${active}" data-id="${esc(id)}" type="button">
            <div class="item-top">
              <span class="cve">${esc(it.cve_id || it.mps_id || "-")}</span>
              <span class="badge ${levelClass(it.level)}">${esc(levelText(it.level))}</span>
            </div>
            <div class="title">${esc(it.title || "-")}</div>
            <div class="item-foot">
              <span>CVSS ${esc(scoreText(it.cvss_score))}</span>
              <span>${esc(it.published_time || "-")}</span>
              ${it.poc ? "<span>POC</span>" : ""}
            </div>
          </button>`;
      }).join("");
      list.querySelectorAll(".item").forEach((btn) => {
        btn.addEventListener("click", () => selectById(btn.dataset.id));
      });
    }

    function refsHtml(it) {
      const refs = Array.isArray(it.reference_url_list) ? it.reference_url_list : [];
      const links = [];
      if (it._source_page) links.push({ url: it._source_page, name: "OSCS 详情" });
      if (it.cve_id) links.push({ url: `https://nvd.nist.gov/vuln/detail/${it.cve_id}`, name: "NVD" });
      refs.forEach((r) => {
        if (r && r.url) links.push({ url: r.url, name: r.name || r.url });
      });
      const seen = new Set();
      const uniq = [];
      for (const l of links) {
        if (seen.has(l.url)) continue;
        seen.add(l.url);
        uniq.push(l);
      }
      if (!uniq.length) return '<div class="box">无参考链接</div>';
      return `<div class="refs">${uniq.map((l) =>
        `<a href="${esc(l.url)}" target="_blank" rel="noopener">${esc(l.name || l.url)}</a>`
      ).join("")}</div>`;
    }

    function articlesHtml(it) {
      const arts = Array.isArray(it.articles) ? it.articles : [];
      if (!arts.length) return "";
      return `<div class="section"><h3>相关说明</h3>${arts.map((a) => `
        <div class="article">
          <h4>${esc(a.title || "说明")}</h4>
          <p>${esc(a.content || "")}</p>
        </div>`).join("")}</div>`;
    }

    function renderDetail(it) {
      const detail = $("detail");
      if (!it) {
        detail.innerHTML = '<div class="empty">暂无数据</div>';
        return;
      }
      const pocUrls = Array.isArray(it.poc_url) ? it.poc_url : [];
      detail.innerHTML = `
        <div class="d-head">
          <div>
            <h1 class="d-title">${esc(it.title || "-")}</h1>
            <div class="ids">
              <span class="badge ${levelClass(it.level)}">${esc(levelText(it.level))}</span>
              <span class="chip">${esc(it.cve_id || "无 CVE")}</span>
              <span class="chip">${esc(it.mps_id || "-")}</span>
              ${it.poc ? '<span class="chip">有 POC</span>' : ""}
              ${it.exp ? '<span class="chip">有 EXP</span>' : ""}
            </div>
          </div>
          <div class="actions">
            ${it._source_page ? `<a class="btn" href="${esc(it._source_page)}" target="_blank" rel="noopener">OSCS</a>` : ""}
            ${it.cve_id ? `<a class="btn" href="https://nvd.nist.gov/vuln/detail/${esc(it.cve_id)}" target="_blank" rel="noopener">NVD</a>` : ""}
          </div>
        </div>
        <div class="grid">
          <div class="stat"><div class="k">CVSS</div><div class="v">${esc(scoreText(it.cvss_score))}</div></div>
          <div class="stat"><div class="k">向量</div><div class="v">${esc(it.cvss_vector || "-")}</div></div>
          <div class="stat"><div class="k">CWE</div><div class="v">${esc(it.cwe || "-")}</div></div>
          <div class="stat"><div class="k">类型</div><div class="v">${esc(it.kind || it.kind_en || "-")}</div></div>
          <div class="stat"><div class="k">公开</div><div class="v">${esc(it.published_time || "-")}</div></div>
          <div class="stat"><div class="k">利用成本</div><div class="v">${esc(it.exploit_requirement_cost || "-")}</div></div>
          <div class="stat"><div class="k">可利用性</div><div class="v">${esc(it.exploitability || "-")}</div></div>
          <div class="stat"><div class="k">修复建议</div><div class="v">${esc(it.fix_suggestion || "-")}</div></div>
        </div>
        <div class="section"><h3>描述</h3><div class="box">${esc(it.description || "无描述")}</div></div>
        ${it.scope_influence ? `<div class="section"><h3>影响范围</h3><div class="box">${esc(it.scope_influence)}</div></div>` : ""}
        ${pocUrls.length ? `<div class="section"><h3>POC 链接</h3><div class="refs">${pocUrls.map((u) => `<a href="${esc(u)}" target="_blank" rel="noopener">${esc(u)}</a>`).join("")}</div></div>` : ""}
        <div class="section"><h3>参考链接</h3>${refsHtml(it)}</div>
        ${articlesHtml(it)}
      `;
    }

    function selectById(id) {
      const it = filtered.find((x) => (x.mps_id || x.cve_id) === id) ||
                 items.find((x) => (x.mps_id || x.cve_id) === id);
      if (!it) return;
      activeId = it.mps_id || it.cve_id;
      renderList();
      renderDetail(it);
      const btn = document.querySelector(`.item[data-id="${CSS.escape(activeId)}"]`);
      if (btn) btn.scrollIntoView({ block: "nearest" });
      history.replaceState(null, "", "#" + encodeURIComponent(activeId));
    }

    function applyFilter(q) {
      const query = (q || "").trim().toLowerCase();
      filtered = !query ? items.slice() : items.filter((it) => {
        const blob = [
          it.cve_id, it.mps_id, it.title, it.kind, it.kind_en, it.cwe, it.description, it.level
        ].map((x) => String(x || "").toLowerCase()).join(" ");
        return blob.includes(query);
      });
      renderList();
      if (filtered.length) {
        const still = filtered.some((x) => (x.mps_id || x.cve_id) === activeId);
        selectById(still ? activeId : (filtered[0].mps_id || filtered[0].cve_id));
      } else {
        activeId = null;
        renderDetail(null);
      }
    }

    $("search").addEventListener("input", (e) => applyFilter(e.target.value));

    document.addEventListener("keydown", (e) => {
      if (e.key === "/" && document.activeElement !== $("search")) {
        e.preventDefault();
        $("search").focus();
        return;
      }
      if (!filtered.length) return;
      const idx = filtered.findIndex((x) => (x.mps_id || x.cve_id) === activeId);
      if (e.key === "ArrowDown") {
        e.preventDefault();
        const next = filtered[Math.min(filtered.length - 1, Math.max(0, idx) + 1)];
        selectById(next.mps_id || next.cve_id);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        const prev = filtered[Math.max(0, idx - 1)];
        selectById(prev.mps_id || prev.cve_id);
      }
    });

    const hashId = decodeURIComponent((location.hash || "").replace(/^#/, ""));
    if (hashId && items.some((x) => (x.mps_id || x.cve_id) === hashId)) {
      activeId = hashId;
      renderList();
      selectById(hashId);
    } else if (items.length) {
      selectById(items[0].mps_id || items[0].cve_id);
    } else {
      renderList();
      renderDetail(null);
    }
  </script>
</body>
</html>
"""


def write_html_report(
    data_dir: Path,
    retention_days: int,
    cutoff: str,
    extra_paths: list[Path] | None = None,
) -> list[Path]:
    payload = build_payload(data_dir, retention_days, cutoff)
    # 避免 </script> 打断嵌入
    raw = json.dumps(payload, ensure_ascii=False)
    raw = raw.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    content = HTML_TEMPLATE.replace("__PAYLOAD__", raw)

    outputs: list[Path] = []
    paths = [data_dir / "index.html"]
    if extra_paths:
        paths.extend(extra_paths)
    for path in paths:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(content, encoding="utf-8")
        tmp.replace(path)
        outputs.append(path)
    return outputs
