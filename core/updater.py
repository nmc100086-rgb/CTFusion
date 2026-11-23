"""GitHub 版本检查。

只做“检查并提示”，不自动下载或覆盖当前程序。更新检查从 v2.3 起启用；
v2.3 之前的版本即使设置了更新地址也不会请求网络。
"""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass

from core.version import (
    REPOSITORY_URL,
    UPDATE_START_VERSION,
    VERSION,
)

API_LATEST = "https://api.github.com/repos/nmc100086-rgb/CTFusion/releases/latest"
API_TAGS = "https://api.github.com/repos/nmc100086-rgb/CTFusion/tags?per_page=30"
USER_AGENT = f"CTFusion/{'.'.join(str(x) for x in VERSION)}"

_VERSION_RE = re.compile(
    r"^\s*[vV]?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?\s*$")


class UpdateError(Exception):
    """更新检查失败，message 面向用户。"""


@dataclass(frozen=True)
class UpdateInfo:
    current: tuple[int, int, int]
    latest: tuple[int, int, int] | None = None
    tag: str = ""
    url: str = REPOSITORY_URL
    error: str = ""
    ignored: bool = False

    @property
    def available(self) -> bool:
        return bool(
            self.latest and self.latest > self.current and not self.error)

    @property
    def status(self) -> str:
        if self.ignored:
            return "ignored"
        if self.error:
            return "error"
        return "available" if self.available else "current"


def parse_version(value: str) -> tuple[int, int, int] | None:
    match = _VERSION_RE.match(str(value or ""))
    if not match:
        return None
    parts = [int(item or 0) for item in match.groups()]
    return (parts[0], parts[1], parts[2])


def version_text(version: tuple[int, int, int]) -> str:
    return ".".join(str(item) for item in version)


def _request_json(url: str, timeout: float = 8.0,
                  opener=None) -> object:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": USER_AGENT,
        },
    )
    open_func = opener or urllib.request.urlopen
    try:
        with open_func(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise UpdateError(f"GitHub 返回 HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise UpdateError(f"无法连接 GitHub:{exc}") from exc
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpdateError("GitHub 返回的数据格式不正确") from exc


def _latest_from_release(payload: object) -> tuple[str, tuple[int, int, int]] | None:
    if not isinstance(payload, dict):
        return None
    tag = str(payload.get("tag_name") or payload.get("name") or "")
    parsed = parse_version(tag)
    return (tag, parsed) if parsed else None


def _latest_from_tags(payload: object) -> tuple[str, tuple[int, int, int]] | None:
    if not isinstance(payload, list):
        return None
    found: list[tuple[str, tuple[int, int, int]]] = []
    for item in payload:
        if not isinstance(item, dict):
            continue
        tag = str(item.get("name") or "")
        parsed = parse_version(tag)
        if parsed:
            found.append((tag, parsed))
    if not found:
        return None
    return max(found, key=lambda item: item[1])


def check_for_update(current: tuple[int, int, int] = VERSION,
                     timeout: float = 8.0, opener=None) -> UpdateInfo:
    """检查是否有比 current 更新的版本。

    current 小于 v2.3 时直接返回 ignored，不发起网络请求。
    """
    if current < UPDATE_START_VERSION:
        return UpdateInfo(current=current, ignored=True)

    tag = ""
    latest: tuple[int, int, int] | None = None
    try:
        payload = _request_json(API_LATEST, timeout=timeout, opener=opener)
        found = _latest_from_release(payload)
        if found:
            tag, latest = found
    except UpdateError:
        # 没有 release 时退回 tags；网络错误也在 tags 请求中统一报告。
        pass

    # release 还没有发布、或 release 落后于标签时，再用 tags 兜底。
    if latest is None or latest <= current:
        try:
            payload = _request_json(API_TAGS, timeout=timeout, opener=opener)
            found = _latest_from_tags(payload)
            if found and (latest is None or found[1] > latest):
                tag, latest = found
        except UpdateError as exc:
            if latest is None:
                return UpdateInfo(current=current, error=str(exc))

    if latest is None:
        return UpdateInfo(
            current=current, error="GitHub 上没有找到可用的版本标签")
    return UpdateInfo(current=current, latest=latest, tag=tag)
