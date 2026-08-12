"""英文字段翻译为中文（带本地缓存，无第三方依赖）。"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

FIX_SUGGESTION_CN = {
    "StrongRecommend": "强烈建议修复",
    "Recommend": "建议修复",
    "Optional": "可选修复",
}

# 需要尝试翻译的顶层字段
TEXT_FIELDS = (
    "title",
    "description",
    "scope_influence",
    "exploit_requirement",
    "kind_en",
)

USER_AGENT = (
    "Mozilla/5.0 (compatible; OSCS-Vuln-Monitor/1.0; +https://www.oscs1024.com/hl)"
)

_CJK_RE = re.compile(r"[\u4e00-\u9fff]")
_LATIN_RE = re.compile(r"[A-Za-z]")


def _sha1(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8")).hexdigest()


def looks_chinese(text: str) -> bool:
    if not text or not text.strip():
        return True
    cjk = len(_CJK_RE.findall(text))
    latin = len(_LATIN_RE.findall(text))
    if cjk == 0:
        return False
    # 中文占比够高，或几乎没有拉丁字母
    return cjk >= max(3, latin * 0.35)


def needs_translate(text: str) -> bool:
    t = (text or "").strip()
    if len(t) < 2:
        return False
    return not looks_chinese(t)


class Translator:
    def __init__(self, cache_path: Path, sleep_s: float = 0.35) -> None:
        self.cache_path = cache_path
        self.sleep_s = sleep_s
        self.cache: dict[str, str] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not self.cache_path.exists():
            return
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                self.cache = {str(k): str(v) for k, v in data.items()}
        except (json.JSONDecodeError, OSError):
            logging.warning("翻译缓存损坏，将重建: %s", self.cache_path)

    def save(self) -> None:
        if not self._dirty:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.cache_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(self.cache, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        tmp.replace(self.cache_path)
        self._dirty = False

    def translate(self, text: str) -> str:
        raw = text or ""
        if not needs_translate(raw):
            return raw
        key = _sha1(raw)
        if key in self.cache:
            return self.cache[key]

        translated = self._translate_google(raw)
        if translated and translated.strip():
            self.cache[key] = translated
            self._dirty = True
            return translated
        return raw

    def _translate_google(self, text: str) -> str:
        """使用 Google 公开 gtx 接口，长文本分片。"""
        chunks = _split_text(text, max_len=4200)
        out: list[str] = []
        for i, chunk in enumerate(chunks):
            if i:
                time.sleep(self.sleep_s)
            part = self._translate_chunk(chunk)
            if part is None:
                logging.warning("翻译失败，保留原文（长度 %d）", len(chunk))
                return text
            out.append(part)
            time.sleep(self.sleep_s)
        return "".join(out)

    def _translate_chunk(self, text: str) -> str | None:
        params = urllib.parse.urlencode(
            {
                "client": "gtx",
                "sl": "auto",
                "tl": "zh-CN",
                "dt": "t",
                "q": text,
            }
        )
        url = f"https://translate.googleapis.com/translate_a/single?{params}"
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=40) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError) as exc:
            logging.warning("翻译请求异常: %s", exc)
            return None

        # 结构: [[[translated, original, ...], ...], ...]
        try:
            parts = data[0]
            return "".join(p[0] for p in parts if p and p[0])
        except (TypeError, IndexError, KeyError):
            logging.warning("翻译响应结构异常")
            return None


def _split_text(text: str, max_len: int) -> list[str]:
    if len(text) <= max_len:
        return [text]
    chunks: list[str] = []
    buf = ""
    for para in re.split(r"(\n+)", text):
        if len(buf) + len(para) <= max_len:
            buf += para
            continue
        if buf:
            chunks.append(buf)
            buf = ""
        while len(para) > max_len:
            chunks.append(para[:max_len])
            para = para[max_len:]
        buf = para
    if buf:
        chunks.append(buf)
    return chunks or [text]


def translate_detail(detail: dict[str, Any], translator: Translator) -> dict[str, Any]:
    """返回中文版详情（不修改入参）。"""
    zh = json.loads(json.dumps(detail, ensure_ascii=False))

    for field in TEXT_FIELDS:
        val = zh.get(field)
        if isinstance(val, str) and val.strip():
            zh[field] = translator.translate(val)

    fix = zh.get("fix_suggestion")
    if isinstance(fix, str) and fix in FIX_SUGGESTION_CN:
        zh["fix_suggestion"] = FIX_SUGGESTION_CN[fix]

    articles = zh.get("articles")
    if isinstance(articles, list):
        new_arts = []
        for art in articles:
            if not isinstance(art, dict):
                new_arts.append(art)
                continue
            a = dict(art)
            if isinstance(a.get("title"), str):
                a["title"] = translator.translate(a["title"])
            if isinstance(a.get("content"), str):
                a["content"] = translator.translate(a["content"])
            new_arts.append(a)
        zh["articles"] = new_arts

    # 标题若仍是英文 CVE 编号式，尽量保留；描述必须中文
    zh["_translated"] = True
    return zh
