"""通用接口契约；模块字段由领域服务持有，不再为每个模块复制一份模型类。"""
from __future__ import annotations

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class PageResult(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int = 1
    size: int = 20


class ActionResult(BaseModel):
    ok: bool
    message: str
    entry: dict[str, Any] | None = None


class EntryPayload(BaseModel):
    values: dict[str, Any] = Field(default_factory=dict)
    remark: str | None = None


class ActionPayload(BaseModel):
    action: str
    remark: str | None = None


class IPayload(BaseModel):
    """系数共享相关列表接口的统一返回。"""
    items: list[dict[str, Any]] = Field(default_factory=list)


class EligibilityResult(BaseModel):
    """服务端给出的共享资格：在途申请与下一笔新申请分开给结论。"""
    model_config = {"extra": "allow"}


class UnitShareGrantPayload(BaseModel):
    grant_no: str = ""
    field: str
    source_unit: str
    target_unit: str
    multiplier: float
    grantor_channel: str
    grantee_channel: str
    batch: str = "*"
    request_kind: str = "新批次"
    grantor_name: str = ""
    grantee_name: str = ""
    issued_at: str = ""
    remark: str = ""


class RevokePayload(BaseModel):
    revoked_at: str = ""
    reason: str = ""


class CredentialPayload(BaseModel):
    credential: str


class CastPayload(BaseModel):
    channel: str
    field: str
    raw_value: Any
    source_unit: str = ""
    batch: str = ""
    grant_no: str = ""
    actor: str = ""
    request_kind: str = ""
    credential: str = ""
    cast_no: str = ""
    preferred: str = ""
    operated_at: str = ""


class OwnFactorPayload(BaseModel):
    channel: str
    field: str
    source_unit: str
    target_unit: str
    multiplier: float
    batch: str = ""
    submitted_at: str = ""
    actor: str = ""


class ConflictResolvePayload(BaseModel):
    keep: str = "自有系数"
    resolved_at: str = ""


class WithdrawInFlightPayload(BaseModel):
    channel: str
    field: str
    batch: str
    withdrawn_at: str = ""
    reason: str = ""
