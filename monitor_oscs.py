#!/usr/bin/env python3
"""OSCS 漏洞情报 (/hl) 严重/高危监控。

数据源与页面一致：
  GET https://www.oscs1024.com/oscs/v1/vdb/vuln_info          # 滚动最新列表
  GET https://www.oscs1024.com/oscs/v1/vdb/vuln_info/{mps_id}  # 详情

默认只保留最近 3 天数据，过期自动删除。

用法:
  python3 monitor_oscs.py              # 持续监控，默认 60 秒一轮
  python3 monitor_oscs.py --once       # 只跑一轮（适合 CI）
  python3 monitor_oscs.py -i 30        # 30 秒一轮
  python3 monitor_oscs.py --retention-days 3
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from html_report import write_html_report
from translate_zh import Translator, needs_translate, translate_detail

BASE_URL = "https://www.oscs1024.com"
LIST_URL = f"{BASE_URL}/oscs/v1/vdb/vuln_info"
DETAIL_URL = f"{BASE_URL}/oscs/v1/vdb/vuln_info/{{mps_id}}"
PAGE_URL = f"{BASE_URL}/hd/{{mps_id}}"

# /hl 页面 level 字段为英文；intelligence 等接口可能是中文
TARGET_LEVELS = {"Critical", "High", "严重", "高危"}
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

DEFAULT_INTERVAL = 60
DEFAULT_RETENTION_DAYS = 3
DEFAULT_DATA_DIR = Path(__file__).resolve().parent / "data"
ROOT_DIR = Path(__file__).resolve().parent
USER_AGENT = (
    "Mozilla/5.0 (compatible; OSCS-Vuln-Monitor/1.0; +https://www.oscs1024.com/hl)"
)


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def today_local() -> date:
    return datetime.now(timezone.utc).astimezone().date()


def parse_date(value: Any) -> date | None:
    """解析 published_time / ISO 时间，失败返回 None。"""
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    # 2026-08-12
    if len(text) >= 10 and text[4] == "-" and text[7] == "-":
        try:
            return date.fromisoformat(text[:10])
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except ValueError:
        return None


def cutoff_date(retention_days: int) -> date:
    return today_local() - timedelta(days=max(0, retention_days) - 1)


def http_get_json(url: str, timeout: float = 30.0) -> Any:
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Referer": f"{BASE_URL}/hl",
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
    return json.loads(raw)


def unwrap_payload(payload: Any) -> Any:
    """兼容裸数组 / {code,data} 两种返回。"""
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def fetch_latest_list() -> list[dict[str, Any]]:
    data = unwrap_payload(http_get_json(LIST_URL))
    if not isinstance(data, list):
        raise RuntimeError(f"列表接口返回异常: {type(data).__name__}")
    return [x for x in data if isinstance(x, dict)]


def fetch_detail(mps_id: str) -> dict[str, Any]:
    data = unwrap_payload(http_get_json(DETAIL_URL.format(mps_id=mps_id)))
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        raise RuntimeError(f"详情接口返回异常: {mps_id}")
    return data


def is_target(item: dict[str, Any]) -> bool:
    return str(item.get("level") or "") in TARGET_LEVELS


def within_retention(item: dict[str, Any], retention_days: int) -> bool:
    """按公开日期判断是否在保留窗口内；无日期时按“今天”处理（先收下）。"""
    cutoff = cutoff_date(retention_days)
    pub = parse_date(item.get("published_time"))
    if pub is None:
        return True
    return pub >= cutoff


def ensure_dirs(data_dir: Path) -> tuple[Path, Path, Path]:
    vulns = data_dir / "vulns"
    vulns.mkdir(parents=True, exist_ok=True)
    index_path = data_dir / "index.jsonl"
    state_path = data_dir / "seen.json"
    return vulns, index_path, state_path


def load_seen(state_path: Path) -> set[str]:
    if not state_path.exists():
        return set()
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return set(map(str, data))
        if isinstance(data, dict):
            return set(map(str, data.get("seen", [])))
    except (json.JSONDecodeError, OSError):
        logging.warning("seen 状态文件损坏，将重建: %s", state_path)
    return set()


def save_seen(state_path: Path, seen: set[str]) -> None:
    payload = {
        "updated_at": now_iso(),
        "count": len(seen),
        "seen": sorted(seen),
    }
    tmp = state_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(state_path)


def rewrite_index(index_path: Path, records: list[dict[str, Any]]) -> None:
    tmp = index_path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    tmp.replace(index_path)


def load_index(index_path: Path) -> list[dict[str, Any]]:
    if not index_path.exists():
        return []
    records: list[dict[str, Any]] = []
    try:
        for line in index_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                records.append(obj)
    except OSError:
        logging.warning("无法读取 index: %s", index_path)
    return records


def append_index(index_path: Path, record: dict[str, Any]) -> None:
    with index_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


def envelope_keep_date(envelope: dict[str, Any]) -> date | None:
    detail = envelope.get("detail") if isinstance(envelope.get("detail"), dict) else {}
    for key in ("published_time",):
        d = parse_date(detail.get(key))
        if d:
            return d
    for key in ("first_saved_at", "saved_at"):
        d = parse_date(envelope.get(key))
        if d:
            return d
    return None


def cleanup_old_data(data_dir: Path, retention_days: int) -> int:
    """删除超过保留期的漏洞文件，并同步清理 index / seen。"""
    vulns_dir, index_path, state_path = ensure_dirs(data_dir)
    cutoff = cutoff_date(retention_days)
    deleted = 0
    kept_ids: set[str] = set()

    for path in sorted(vulns_dir.glob("*.json")):
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logging.warning("损坏文件，删除: %s", path.name)
            path.unlink(missing_ok=True)
            deleted += 1
            continue

        keep_day = envelope_keep_date(envelope) if isinstance(envelope, dict) else None
        mps_id = path.stem
        if keep_day is not None and keep_day < cutoff:
            path.unlink(missing_ok=True)
            deleted += 1
            logging.info(
                "过期删除 %s (日期 %s < 截止 %s)",
                path.name,
                keep_day.isoformat(),
                cutoff.isoformat(),
            )
            continue
        kept_ids.add(mps_id)

    # 重建 index：只保留仍存在的文件，且按公开日在窗口内
    records = load_index(index_path)
    kept_records: list[dict[str, Any]] = []
    for rec in records:
        mps_id = str(rec.get("mps_id") or "")
        if mps_id not in kept_ids:
            continue
        pub = parse_date(rec.get("published_time")) or parse_date(rec.get("detected_at"))
        if pub is not None and pub < cutoff:
            continue
        kept_records.append(rec)
    rewrite_index(index_path, kept_records)

    # seen 与磁盘对齐，避免去重集合无限膨胀
    save_seen(state_path, kept_ids)

    if deleted:
        logging.info(
            "保留最近 %d 天（自 %s 起），删除 %d 个过期文件，剩余 %d 条",
            retention_days,
            cutoff.isoformat(),
            deleted,
            len(kept_ids),
        )
    else:
        logging.info(
            "保留最近 %d 天（自 %s 起），无过期文件，当前 %d 条",
            retention_days,
            cutoff.isoformat(),
            len(kept_ids),
        )
    return deleted


def save_vuln(
    vulns_dir: Path,
    detail: dict[str, Any],
    first_seen: bool,
    detail_original: dict[str, Any] | None = None,
) -> Path:
    mps_id = str(detail.get("mps_id") or "unknown")
    path = vulns_dir / f"{mps_id}.json"
    envelope: dict[str, Any] = {
        "saved_at": now_iso(),
        "first_seen": first_seen,
        "translated": True,
        "source_list": LIST_URL,
        "source_page": PAGE_URL.format(mps_id=mps_id),
        "detail": detail,
    }
    if detail_original is not None:
        envelope["detail_original"] = detail_original
    # 已存在则保留首次入库时间，更新正文
    if path.exists():
        try:
            old = json.loads(path.read_text(encoding="utf-8"))
            envelope["first_saved_at"] = old.get("first_saved_at") or old.get("saved_at")
            envelope["first_seen"] = False
            if detail_original is None and isinstance(old.get("detail_original"), dict):
                envelope["detail_original"] = old["detail_original"]
        except (json.JSONDecodeError, OSError):
            envelope["first_saved_at"] = envelope["saved_at"]
    else:
        envelope["first_saved_at"] = envelope["saved_at"]

    tmp = path.with_suffix(".tmp")
    tmp.write_text(
        json.dumps(envelope, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    tmp.replace(path)
    return path


def ensure_vulns_translated(data_dir: Path, translator: Translator) -> int:
    """把已有未翻译条目补翻成中文。"""
    vulns_dir = data_dir / "vulns"
    if not vulns_dir.exists():
        return 0
    updated = 0
    for path in sorted(vulns_dir.glob("*.json")):
        try:
            envelope = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if not isinstance(envelope, dict):
            continue
        detail = envelope.get("detail")
        if not isinstance(detail, dict):
            continue
        # 已有中文描述且标记 translated，跳过
        if envelope.get("translated") and detail.get("_translated"):
            desc = str(detail.get("description") or "")
            if desc and not needs_translate(desc):
                continue
        original = envelope.get("detail_original")
        if not isinstance(original, dict):
            original = {k: v for k, v in detail.items() if not str(k).startswith("_")}
        zh = translate_detail(original, translator)
        envelope["detail"] = zh
        envelope["detail_original"] = original
        envelope["translated"] = True
        envelope["saved_at"] = now_iso()
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(envelope, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(path)
        updated += 1
        logging.info("已翻译入库: %s", path.name)
    translator.save()
    return updated


def summarize(item: dict[str, Any]) -> str:
    level = LEVEL_CN.get(str(item.get("level")), str(item.get("level")))
    mps = item.get("mps_id") or "-"
    cve = item.get("cve_id") or "-"
    title = item.get("title") or "-"
    pub = item.get("published_time") or "-"
    score = item.get("cvss_score")
    score_s = f" CVSS:{score}" if score not in (None, "", -1) else ""
    poc = " [POC]" if item.get("poc") else ""
    return f"[{level}] {mps} | {cve} | {title} | 公开:{pub}{score_s}{poc}"


def process_once(
    data_dir: Path,
    fetch_full_detail: bool = True,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> int:
    vulns_dir, index_path, state_path = ensure_dirs(data_dir)
    cleanup_old_data(data_dir, retention_days)
    seen = load_seen(state_path)
    translator = Translator(data_dir / "translations.json")

    items = fetch_latest_list()
    targets = [
        x
        for x in items
        if is_target(x) and within_retention(x, retention_days)
    ]
    skipped_old = sum(
        1 for x in items if is_target(x) and not within_retention(x, retention_days)
    )
    logging.info(
        "拉取 %d 条最新情报，其中严重/高危且近 %d 天 %d 条（跳过过期 %d）",
        len(items),
        retention_days,
        len(targets),
        skipped_old,
    )

    new_count = 0
    for item in targets:
        mps_id = str(item.get("mps_id") or "").strip()
        if not mps_id:
            continue

        first_seen = mps_id not in seen
        detail = item
        if fetch_full_detail:
            try:
                detail = fetch_detail(mps_id) or item
            except Exception as exc:  # noqa: BLE001 — 详情失败时退回列表字段
                logging.warning("详情拉取失败，使用列表字段 %s: %s", mps_id, exc)

        # 详情里的公开日也可能超出窗口
        if not within_retention(detail, retention_days):
            logging.debug("详情公开日超出保留期，跳过 %s", mps_id)
            continue

        detail_original = detail
        try:
            detail_zh = translate_detail(detail_original, translator)
        except Exception as exc:  # noqa: BLE001
            logging.warning("翻译失败，保留原文 %s: %s", mps_id, exc)
            detail_zh = detail_original

        path = save_vuln(
            vulns_dir,
            detail_zh,
            first_seen=first_seen,
            detail_original=detail_original,
        )
        if first_seen:
            new_count += 1
            seen.add(mps_id)
            append_index(
                index_path,
                {
                    "detected_at": now_iso(),
                    "mps_id": mps_id,
                    "cve_id": detail_zh.get("cve_id"),
                    "level": detail_zh.get("level"),
                    "level_cn": LEVEL_CN.get(str(detail_zh.get("level")), detail_zh.get("level")),
                    "title": detail_zh.get("title"),
                    "published_time": detail_zh.get("published_time"),
                    "cvss_score": detail_zh.get("cvss_score"),
                    "poc": bool(detail_zh.get("poc")),
                    "page": PAGE_URL.format(mps_id=mps_id),
                    "file": str(path.relative_to(data_dir)),
                },
            )
            logging.info("NEW %s -> %s", summarize(detail_zh), path)
        else:
            logging.debug("UPDATE %s", summarize(detail_zh))

    save_seen(state_path, seen)
    translator.save()

    # 补翻历史未翻译条目
    backfilled = ensure_vulns_translated(data_dir, translator)
    if backfilled:
        logging.info("补翻历史条目 %d 条", backfilled)

    # 便于快速查看本轮命中
    snapshot = {
        "polled_at": now_iso(),
        "retention_days": retention_days,
        "cutoff_date": cutoff_date(retention_days).isoformat(),
        "latest_total": len(items),
        "target_total": len(targets),
        "new_count": new_count,
        "translated": True,
        "targets": [
            {
                "mps_id": x.get("mps_id"),
                "cve_id": x.get("cve_id"),
                "level": x.get("level"),
                "title": x.get("title"),
                "published_time": x.get("published_time"),
            }
            for x in targets
        ],
    }
    snap_path = data_dir / "last_poll.json"
    snap_path.write_text(
        json.dumps(snapshot, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    html_paths = write_html_report(
        data_dir,
        retention_days=retention_days,
        cutoff=cutoff_date(retention_days).isoformat(),
        extra_paths=[ROOT_DIR / "index.html"],
    )
    logging.info("已生成 HTML 报告: %s", ", ".join(str(p) for p in html_paths))
    return new_count


def setup_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="监控 OSCS /hl 严重与高危漏洞情报")
    p.add_argument(
        "-i",
        "--interval",
        type=int,
        default=DEFAULT_INTERVAL,
        help=f"轮询间隔秒数，默认 {DEFAULT_INTERVAL}",
    )
    p.add_argument(
        "-d",
        "--data-dir",
        type=Path,
        default=DEFAULT_DATA_DIR,
        help=f"数据目录，默认 {DEFAULT_DATA_DIR}",
    )
    p.add_argument(
        "--retention-days",
        type=int,
        default=DEFAULT_RETENTION_DAYS,
        help=f"只保留最近 N 天，默认 {DEFAULT_RETENTION_DAYS}",
    )
    p.add_argument("--once", action="store_true", help="只执行一轮后退出")
    p.add_argument(
        "--no-detail",
        action="store_true",
        help="不二次请求详情接口（列表本身已含主要字段）",
    )
    p.add_argument("-v", "--verbose", action="store_true", help="调试日志")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    setup_logging(args.verbose)
    data_dir = args.data_dir.expanduser().resolve()
    data_dir.mkdir(parents=True, exist_ok=True)
    retention_days = max(1, args.retention_days)

    logging.info("监控 OSCS 漏洞情报: %s/hl", BASE_URL)
    logging.info("保存目录: %s", data_dir)
    logging.info("过滤级别: %s", ", ".join(sorted(TARGET_LEVELS)))
    logging.info(
        "数据保留: 最近 %d 天（自 %s）",
        retention_days,
        cutoff_date(retention_days).isoformat(),
    )

    while True:
        try:
            new_count = process_once(
                data_dir,
                fetch_full_detail=not args.no_detail,
                retention_days=retention_days,
            )
            logging.info("本轮新增 %d 条", new_count)
        except urllib.error.HTTPError as exc:
            logging.error("HTTP 错误: %s %s", exc.code, exc.reason)
        except urllib.error.URLError as exc:
            logging.error("网络错误: %s", exc.reason)
        except Exception:  # noqa: BLE001
            logging.exception("本轮失败")

        if args.once:
            break
        time.sleep(max(5, args.interval))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
