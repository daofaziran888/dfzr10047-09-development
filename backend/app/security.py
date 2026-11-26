"""共享凭据签发与校验：服务端用 HMAC 对带渠道范围的载荷签名，令牌不可伪造、不可篡改。

单位归一系数跨渠道共享时，凭据必须由服务端签发：渠道范围、受让人、系数、关联批次
都写在签名载荷里，任何一侧被改写都会校验失败。撤回状态不写进令牌，而由数据仓库中的
凭据记录裁决，这样撤回可以立即生效，而历史令牌仍可用于追溯当年授权的原始范围。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

# 本地单机部署的签名密钥；真实部署应从密钥管理服务注入，不应固化在代码里。
SIGNING_KEY = b"jiegou-gongfang-unit-share-v1"
TOKEN_PREFIX = "ugs1"


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def build_credential_payload(*, grant_no: Any, field: Any, source_unit: Any,
                             target_unit: Any, multiplier: Any,
                             grantor: Any, grantee: Any, batches: Any,
                             request_kind: Any, issued_at: Any) -> dict[str, Any]:
    """统一构造共享凭据载荷：签发端与校验端都从这里取字段名，避免两边漂移。"""
    return {
        "v": 1,
        "grant_no": grant_no,
        "field": field,
        "source_unit": source_unit,
        "target_unit": target_unit,
        "multiplier": float(multiplier),
        "grantor": grantor,
        "grantee": grantee,
        "channels": [grantor, grantee],
        "batches": str(batches or ""),
        "request_kind": request_kind,
        "issued_at": issued_at,
    }


def sign_credential(payload: dict[str, Any]) -> str:
    """按规范序列化载荷后签名，返回 `ugs1.<载荷>.<签名>` 形式的共享凭据令牌。"""
    body = _canonical(payload)
    signature = hmac.new(SIGNING_KEY, body, hashlib.sha256).hexdigest()
    return f"{TOKEN_PREFIX}.{_b64encode(body)}.{signature}"


def verify_credential_token(token: str) -> tuple[bool, dict[str, Any] | None, str]:
    """校验令牌签名并还原载荷；签名不符或缺段时拒绝，不返回任何载荷。"""
    text = str(token or "").strip()
    if not text:
        return False, None, "共享凭据令牌为空"
    parts = text.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        return False, None, "共享凭据令牌格式不合法"
    try:
        body = _b64decode(parts[1])
    except (ValueError, TypeError):
        return False, None, "共享凭据令牌载荷无法解码"
    expected = hmac.new(SIGNING_KEY, body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, parts[2]):
        return False, None, "共享凭据令牌签名不符，疑似被篡改"
    try:
        payload = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return False, None, "共享凭据令牌载荷不是合法 JSON"
    if not isinstance(payload, dict):
        return False, None, "共享凭据令牌载荷结构不合法"
    return True, payload, ""
