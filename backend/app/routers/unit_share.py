"""系数共享接口：授权/撤回、资格核对、取值转型回执与输出契约系数出处复核。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, Query

from app.schemas import (
    ActionResult,
    WithdrawInFlightPayload,
    CastPayload,
    ConflictResolvePayload,
    CredentialPayload,
    EligibilityResult,
    IPayload,
    OwnFactorPayload,
    RevokePayload,
    UnitShareGrantPayload,
)
from app.services import service_for

router = APIRouter(prefix="/api/unit-share", tags=["系数共享"])


def _service():
    service = service_for("unit_share")
    if service is None:
        raise HTTPException(status_code=500, detail="共享授权服务未注册")
    return service


@router.get("/eligibility", response_model=EligibilityResult)
def eligibility(
    channel: str = Query(description="请求渠道"),
    field: str = Query(description="字段名称"),
    batch: str = Query(default="", description="关联批次"),
    grant_no: str = Query(default=""),
    source_unit: str = Query(default=""),
) -> EligibilityResult:
    """转型表单打开时向服务端核对资格：在途申请与下一笔新申请分开给结论。"""
    service = _service()
    return EligibilityResult(**service.eligibility(
        requester_channel=channel, field=field, batch_no=batch,
        grant_no=grant_no, source_unit=source_unit))


@router.post("/cast", response_model=ActionResult)
def cast(payload: CastPayload) -> ActionResult:
    """取值转型按授权换算成单位归一字段值，并落一条可回查的转型回执。"""
    service = _service()
    result = service.cast(
        channel=payload.channel, field=payload.field,
        raw_value=payload.raw_value, source_unit=payload.source_unit,
        batch_no=payload.batch, grant_no=payload.grant_no,
        actor=payload.actor, request_kind=payload.request_kind,
        credential=payload.credential, cast_no=payload.cast_no,
        preferred=payload.preferred, created_at=payload.operated_at,
    )
    return ActionResult(
        ok=bool(result.get("ok")), message=str(result.get("message") or ""),
        entry=result,
    )


@router.post("/own-factor", response_model=ActionResult)
def submit_own_factor(payload: OwnFactorPayload) -> ActionResult:
    """受让渠道提交自有换算系数；与在途共享系数并存时登记同批来源规则冲突。"""
    service = _service()
    result = service.submit_own_factor(
        channel=payload.channel, field=payload.field,
        source_unit=payload.source_unit, target_unit=payload.target_unit,
        multiplier=payload.multiplier, batch_no=payload.batch,
        submitted_at=payload.submitted_at, actor=payload.actor,
    )
    return ActionResult(
        ok=bool(result.get("ok")), message=str(result.get("message") or ""),
        entry=result,
    )


@router.get("/receipts", response_model=IPayload)
def receipts(batch: str = Query(default=""), field: str = Query(default=""),
             channel: str = Query(default="")) -> IPayload:
    """历史转型回执：已确认与已拒绝都在，可按批次/字段/渠道筛选。"""
    service = _service()
    return IPayload(items=service.receipts(
        batch_no=batch, field=field, channel=channel))


@router.get("/receipts/{receipt_no}", response_model=dict)
def receipt(receipt_no: str) -> dict[str, Any]:
    service = _service()
    row = service.receipt(receipt_no)
    if row is None:
        raise HTTPException(status_code=404, detail=f"转型回执 {receipt_no} 不存在")
    return row


@router.get("/conflicts", response_model=IPayload)
def conflicts(batch: str = Query(default="")) -> IPayload:
    service = _service()
    return IPayload(items=service.conflicts(batch_no=batch))


@router.post("/conflicts/{conflict_no}/resolve", response_model=ActionResult)
def resolve_conflict(conflict_no: str, payload: ConflictResolvePayload) -> ActionResult:
    service = _service()
    ok, message, row = service.resolve_conflict(
        conflict_no, payload.keep, payload.resolved_at)
    return ActionResult(ok=ok, message=message, entry=row)


@router.get("/provenance", response_model=dict)
def provenance(batch: str = Query(...), field: str = Query(default="")) -> dict[str, Any]:
    """归一结果实际取用的系数出处，供输出契约接收时复核。"""
    service = _service()
    return service.provenance(batch, field)


@router.get("/contract-check", response_model=dict)
def contract_check(contract_no: str = Query(...), batch: str = Query(default="")) -> dict[str, Any]:
    """复核输出契约接收的字段系数出处；结论同时回写契约条目。"""
    service = _service()
    contract_svc = service_for("output_contract")
    record = None
    if contract_svc is not None and hasattr(contract_svc, "review_unit_provenance"):
        _ok, _message, record = contract_svc.review_unit_provenance(contract_no, batch)
    result = service.check_contract_provenance(contract_no, batch)
    if record is not None:
        result["契约条目"] = record
    return result


@router.get("/grants", response_model=IPayload)
def grants(channel: str = Query(default=""), field: str = Query(default="")) -> IPayload:
    """授权页列表：按受让方渠道/字段查看已签发凭据与状态。"""
    service = _service()
    rows = [
        r for r in service.list_entries(page=1, size=1_000_000)[0]
        if (not channel or str(r.get("受让方渠道")) == channel)
        and (not field or str(r.get("字段名称")) == field)
    ]
    return IPayload(items=rows)


@router.post("/grants", response_model=ActionResult)
def grant(payload: UnitShareGrantPayload) -> ActionResult:
    """来源负责人授权：由服务端签发带渠道范围的共享凭据。"""
    service = _service()
    ok, message, row = service.grant_share(
        grant_no=payload.grant_no, field=payload.field,
        source_unit=payload.source_unit, target_unit=payload.target_unit,
        multiplier=payload.multiplier, grantor_channel=payload.grantor_channel,
        grantee_channel=payload.grantee_channel, batch_no=payload.batch,
        request_kind=payload.request_kind, grantor_name=payload.grantor_name,
        grantee_name=payload.grantee_name, issued_at=payload.issued_at,
        remark=payload.remark,
    )
    return ActionResult(ok=ok, message=message, entry=row)


@router.post("/grants/{grant_no}/revoke", response_model=ActionResult)
def revoke(grant_no: str, payload: RevokePayload) -> ActionResult:
    """来源负责人撤回授权：在途已确认字段不被刷新，新申请不得再引用。"""
    service = _service()
    ok, message, row = service.revoke(
        grant_no, revoked_at=payload.revoked_at, reason=payload.reason)
    return ActionResult(ok=ok, message=message, entry=row)


@router.post("/grants/{grant_no}/issue", response_model=ActionResult)
def issue(grant_no: str) -> ActionResult:
    service = _service()
    ok, message, row = service.issue_credential(grant_no)
    return ActionResult(ok=ok, message=message, entry=row)


@router.post("/credentials/verify", response_model=ActionResult)
def verify_credential(payload: CredentialPayload) -> ActionResult:
    """核对共享凭据：签名与授权记录逐项一致才算通过。"""
    service = _service()
    ok, message, row = service.verify_credential(payload.credential)
    return ActionResult(ok=ok, message=message, entry=row)


@router.post("/in-flight/withdraw", response_model=ActionResult)
def withdraw_in_flight(payload: WithdrawInFlightPayload) -> ActionResult:
    """受让渠道撤回在途申请：已确认回执仍可回查，重进表单按新资格执行。"""
    service = _service()
    result = service.withdraw_in_flight(
        channel=payload.channel, field=payload.field, batch_no=payload.batch,
        withdrawn_at=payload.withdrawn_at, reason=payload.reason)
    return ActionResult(
        ok=bool(result.get("ok")), message=str(result.get("消息") or ""),
        entry=result,
    )
