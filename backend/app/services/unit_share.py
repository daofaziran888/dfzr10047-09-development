"""系数共享授权领域服务：由来源负责人授权/撤回带渠道范围的换算系数共享凭据，产出共享授权数据集。

共享的三条硬约束：
- 凭据由服务端对渠道范围载荷签名，令牌被篡改或串用时校验不通过；
- 撤回只影响后续新申请，在途已确认字段保留当次原单位、因子和来源；
- 未获授权的新批次不得采用跨渠道来源系数，越权提交要能回指授权归属与被拒值。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from app.security import build_credential_payload, sign_credential, verify_credential_token
from app.services.base import BaseModuleService
from app.store import store

RECEIPT_TABLE = "unit_share_receipt"
CONFLICT_TABLE = "unit_share_conflict"
FACTOR_TABLE = "unit_normalize"

RECEIPT_CONFIRMED = "已确认"
RECEIPT_REJECTED = "已拒绝"
RECEIPT_CONFLICT = "系数冲突"
RECEIPT_PENDING = "待确认"

GRANTED = "已授权"
REVOKED = "已撤回"
PENDING = "待签发"
EXPIRED = "已失效"

ACTOR_IN_FLIGHT = "在途批次"
ACTOR_NEW = "新批次"

OWN_RULE = "自有规则"
SHARED_RULE = "授权共享"


def _now() -> str:
    return datetime.now().isoformat(timespec="seconds")


def _fmt(value: Any) -> str:
    """系数与取值统一用最短可读形式落库：1000.0 显示为 1000，1024.5 保持小数。"""
    text = str(value).strip()
    try:
        return f"{float(text):g}"
    except (TypeError, ValueError):
        return text


def _to_float(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


class UnitShareService(BaseModuleService):
    MODULE = "unit_share"
    ENTITY = "共享授权"
    OPERATION_TERM = "授权"
    LIST_FIELDS = [
        "授权编号", "字段名称", "原始单位", "目标单位", "换算系数",
        "授予方渠道", "受让方渠道", "关联批次", "申请类别", "签发时间",
    ]
    REQUIRED_FIELDS = ["授权编号", "字段名称", "原始单位", "目标单位", "换算系数", "受让方渠道"]
    STATUS_ORDER = [PENDING, GRANTED, REVOKED, EXPIRED]
    ACTION_RULES = {"签发共享": GRANTED, "撤回授权": REVOKED, "登记失效": EXPIRED}
    NEGATIVE_ACTIONS = ["撤回授权", "登记失效"]

    # ---------- 基础查询 ----------

    def _find(self, grant_no: str) -> dict[str, Any] | None:
        for row in store.rows(self.MODULE):
            if row.get("授权编号") == grant_no:
                return row
        return None

    @staticmethod
    def _factor_float(row: dict[str, Any] | None, field: str = "换算系数") -> float:
        if not row:
            return 0.0
        return _to_float(row.get(field)) or 0.0

    def _next_no(self, table: str, prefix: str, field: str) -> str:
        indexes = []
        for row in store.rows(table):
            text = str(row.get(field) or "")
            if text.startswith(prefix) and text[len(prefix):].isdigit():
                indexes.append(int(text[len(prefix):]))
        return f"{prefix}{(max(indexes) if indexes else 0) + 1:03d}"

    def _next_id(self, table: str) -> int:
        return max((int(r.get("id", 0)) for r in store.rows(table)), default=0) + 1

    # ---------- 授权与撤回 ----------

    def _payload_of(self, row: dict[str, Any]) -> dict[str, Any]:
        """原样还原签发时的签名载荷，供校验令牌与授权记录是否一致。"""
        return build_credential_payload(
            grant_no=row.get("授权编号"),
            field=row.get("字段名称"),
            source_unit=row.get("原始单位"),
            target_unit=row.get("目标单位"),
            multiplier=self._factor_float(row),
            grantor=row.get("授予方渠道"),
            grantee=row.get("受让方渠道"),
            batches=row.get("关联批次"),
            request_kind=row.get("申请类别"),
            issued_at=row.get("签发时间"),
        )

    def grant_share(self, *, grant_no: str = "", field: str = "",
                    source_unit: str = "", target_unit: str = "",
                    multiplier: Any = 0, grantor_channel: str = "",
                    grantee_channel: str = "", batch_no: str = "",
                    request_kind: str = ACTOR_NEW, grantor_name: str = "",
                    grantee_name: str = "", issued_at: str = "",
                    remark: str = "") -> tuple[bool, str, dict[str, Any] | None]:
        """登记并签发共享授权：载荷写入渠道范围后由服务端签名，令牌不可伪造。"""
        field = str(field or "").strip()
        source_unit = str(source_unit or "").strip()
        target_unit = str(target_unit or "").strip()
        grantor_channel = str(grantor_channel or "").strip()
        grantee_channel = str(grantee_channel or "").strip()
        batch_no = str(batch_no or "").strip() or "*"
        request_kind = str(request_kind or ACTOR_NEW).strip()

        if not field or not source_unit or not target_unit:
            return False, "字段名称、原始单位、目标单位均为必填项", None
        if not grantor_channel:
            return False, "授予方渠道为必填项，来源负责人必须明确", None
        if not grantee_channel:
            return False, "受让方渠道为必填项，共享凭据必须带渠道范围", None
        if grantor_channel == grantee_channel:
            return False, (
                f"授予方渠道与受让方渠道同为 {grantor_channel}，不属于跨渠道共享"
            ), None
        factor = _to_float(multiplier)
        if factor is None:
            return False, f"换算系数 {multiplier!r} 不是数值", None
        if factor <= 0:
            return False, f"换算系数 {_fmt(factor)} 必须大于 0", None
        if request_kind not in (ACTOR_IN_FLIGHT, ACTOR_NEW):
            return False, (
                f"申请类别「{request_kind}」不在允许范围 {[ACTOR_IN_FLIGHT, ACTOR_NEW]}"
            ), None

        if not grant_no:
            grant_no = self._next_no(self.MODULE, "US-", "授权编号")
        if self._find(grant_no) is not None:
            return False, f"共享授权 {grant_no} 已存在，不得重复签发", None

        rows = store.rows(self.MODULE)
        entry: dict[str, Any] = {
            "id": self._next_id(self.MODULE),
            "status": GRANTED,
            "pending": False,
            "abnormal": False,
            "授权编号": grant_no,
            "字段名称": field,
            "原始单位": source_unit,
            "目标单位": target_unit,
            "换算系数": _fmt(factor),
            "授予方渠道": grantor_channel,
            "受让方渠道": grantee_channel,
            "授予人": str(grantor_name or grantor_channel),
            "受让人": str(grantee_name or grantee_channel),
            "渠道范围": f"{grantor_channel}→{grantee_channel}",
            "关联批次": batch_no,
            "申请类别": request_kind,
            "授权依据": str(remark or "来源负责人共享换算系数"),
            "签发时间": str(issued_at or _now()),
            "撤回时间": "",
            "撤回原因": "",
            "最近使用": "",
        }
        entry["共享凭据"] = sign_credential(self._payload_of(entry))
        rows.append(entry)
        self._ensure_shared_factor(entry)
        return True, (
            f"共享授权 {grant_no} 已签发：{field} {source_unit}→{target_unit} ×{_fmt(factor)}，"
            f"渠道范围 {entry['渠道范围']}，关联批次 {batch_no}"
        ), dict(entry)

    def revoke(self, grant_no: str, revoked_at: str = "",
               reason: str = "") -> tuple[bool, str, dict[str, Any] | None]:
        """撤回授权：只改授权状态与共享系数可用性，不动已确认回执。"""
        grant = self._find(grant_no)
        if grant is None:
            return False, f"共享授权 {grant_no} 不存在", None
        if grant.get("status") == REVOKED:
            return False, f"共享授权 {grant_no} 已处于撤回状态", dict(grant)
        if grant.get("status") == EXPIRED:
            return False, f"共享授权 {grant_no} 已失效，无需撤回", dict(grant)

        grant["status"] = REVOKED
        grant["pending"] = False
        grant["abnormal"] = False
        grant["撤回时间"] = str(revoked_at or _now())
        grant["撤回原因"] = str(reason or "来源负责人撤回授权")
        for factor in store.rows(FACTOR_TABLE):
            if str(factor.get("共享授权") or "") != grant_no:
                continue
            if factor.get("status") == "已生效":
                factor["status"] = "已停用"
                factor["pending"] = False
                factor["abnormal"] = False
                factor["停用原因"] = f"共享授权 {grant_no} 已撤回，后续新批次不得采用"
        return True, (
            f"共享授权 {grant_no} 已撤回：渠道范围 {grant.get('渠道范围')}，"
            f"在途已确认字段保留当次系数，下一笔新申请不得再引用"
        ), dict(grant)

    def revoke_grant(self, grant_no: str, revoked_at: str = "",
                     reason: str = "") -> tuple[bool, str, dict[str, Any] | None]:
        """撤回授权的显式别名，便于调用方按业务语义命名。"""
        return self.revoke(grant_no, revoked_at, reason)

    def expire(self, grant_no: str, reason: str = "") -> tuple[bool, str, dict[str, Any] | None]:
        grant = self._find(grant_no)
        if grant is None:
            return False, f"共享授权 {grant_no} 不存在", None
        if grant.get("status") == EXPIRED:
            return False, f"共享授权 {grant_no} 已失效", dict(grant)
        grant["status"] = EXPIRED
        grant["pending"] = False
        grant["abnormal"] = True
        grant["撤回原因"] = str(reason or "授权到期失效")
        return True, f"共享授权 {grant_no} 已登记失效", dict(grant)

    def issue_credential(self, grant_no: str,
                         credential: str = "") -> tuple[bool, str, dict[str, Any] | None]:
        """签发/接收凭据：服务端按当前授权载荷重新签名，签发后状态转为已授权。"""
        grant = self._find(grant_no)
        if grant is None:
            return False, f"共享授权 {grant_no} 不存在", None
        if grant.get("status") == REVOKED:
            return False, f"共享授权 {grant_no} 已撤回，不得重新签发", dict(grant)
        if credential:
            ok, message, _payload = verify_credential_token(credential)
            if not ok:
                return False, message, dict(grant)
        grant["签发时间"] = grant.get("签发时间") or _now()
        grant["共享凭据"] = sign_credential(self._payload_of(grant))
        grant["status"] = GRANTED
        grant["pending"] = False
        grant["abnormal"] = False
        return True, f"共享授权 {grant_no} 凭据已由服务端签发", dict(grant)

    # ---------- 共享系数落库 ----------

    def _shared_factor(self, grant: dict[str, Any]) -> dict[str, Any] | None:
        for row in store.rows(FACTOR_TABLE):
            if str(row.get("共享授权") or "") == str(grant.get("授权编号")):
                return row
        return None

    def _ensure_shared_factor(self, grant: dict[str, Any]) -> dict[str, Any]:
        """把授权物化到单位归一系数表，给归一结果一个可回查的归一编号。"""
        existing = self._shared_factor(grant)
        if existing is not None:
            return existing
        rows = store.rows(FACTOR_TABLE)
        entry: dict[str, Any] = {
            "id": max((int(r.get("id", 0)) for r in rows), default=0) + 1,
            "status": "已生效",
            "pending": False,
            "abnormal": False,
            "归一编号": self._next_no(FACTOR_TABLE, "UN-", "归一编号"),
            "字段名称": grant.get("字段名称"),
            "原始单位": grant.get("原始单位"),
            "目标单位": grant.get("目标单位"),
            "换算系数": grant.get("换算系数"),
            "适用来源": grant.get("受让方渠道"),
            "生效起日": str(grant.get("签发时间") or _now())[:10],
            "最近命中": "",
            "关联批次": grant.get("关联批次"),
            "来源类型": SHARED_RULE,
            "共享授权": grant.get("授权编号"),
            "系数出处": f"授权共享 {grant.get('授权编号')}",
        }
        rows.append(entry)
        return entry

    # ---------- 自有系数提交 ----------

    def _own_factor(self, channel: str, field: str,
                    source_unit: str = "") -> dict[str, Any] | None:
        for row in store.rows(FACTOR_TABLE):
            if str(row.get("字段名称")) != field:
                continue
            if str(row.get("适用来源")) != channel:
                continue
            if str(row.get("来源类型") or OWN_RULE) != OWN_RULE:
                continue
            if source_unit and str(row.get("原始单位")) != source_unit:
                continue
            return row
        return None

    def _active_own_factor(self, channel: str, field: str,
                           source_unit: str = "") -> dict[str, Any] | None:
        row = self._own_factor(channel, field, source_unit)
        if row is None or row.get("status") != "已生效":
            return None
        return row

    def _register_own_factor(self, channel: str, field: str, source_unit: str,
                             target_unit: str, multiplier: float,
                             batch_no: str, submitted_at: str) -> dict[str, Any]:
        existing = self._own_factor(channel, field, source_unit)
        if existing is not None:
            existing["目标单位"] = target_unit
            existing["关联批次"] = batch_no
            existing["最近提交"] = submitted_at
            # 系数值不在登记时直接覆盖：交给调用方判断冲突，避免静默改写已生效规则
            existing["待确认系数"] = _fmt(multiplier)
            return existing
        rows = store.rows(FACTOR_TABLE)
        entry: dict[str, Any] = {
            "id": max((int(r.get("id", 0)) for r in rows), default=0) + 1,
            "status": "已生效",
            "pending": False,
            "abnormal": False,
            "归一编号": self._next_no(FACTOR_TABLE, "UN-", "归一编号"),
            "字段名称": field,
            "原始单位": source_unit,
            "目标单位": target_unit,
            "换算系数": _fmt(multiplier),
            "适用来源": channel,
            "生效起日": submitted_at[:10],
            "最近命中": "",
            "关联批次": batch_no,
            "来源类型": OWN_RULE,
            "共享授权": "",
            "系数出处": f"自有规则",
            "最近提交": submitted_at,
        }
        entry["系数出处"] = f"自有规则 {entry['归一编号']}"
        rows.append(entry)
        return entry

    def _confirmed_receipt(self, batch_no: str, field: str,
                           requester: str = "") -> dict[str, Any] | None:
        for row in store.rows(RECEIPT_TABLE):
            if (str(row.get("关联批次")) == str(batch_no)
                    and str(row.get("字段名称")) == str(field)
                    and row.get("确认标记") == "是"):
                if requester and str(row.get("请求渠道")) != requester:
                    continue
                return row
        return None

    def _conflict_of(self, batch_no: str, field: str) -> dict[str, Any] | None:
        for row in store.rows(CONFLICT_TABLE):
            if (str(row.get("关联批次")) == str(batch_no)
                    and str(row.get("字段名称")) == str(field)
                    and row.get("status") == "待裁决"):
                return row
        return None

    def _record_receipt(self, *, batch_no: str, field: str, requester: str,
                        actor: str, request_kind: str, rule_source: str,
                        factor_value: Any, source_unit: str, target_unit: str,
                        raw_value: Any, result_value: Any, source_label: str,
                        grant_no: str = "", factor_no: str = "",
                        status: str = RECEIPT_CONFIRMED,
                        confirmed: bool = True,
                        reject_owner: str = "", reject_reason: str = "",
                        rejected_value: Any = None, cast_no: str = "",
                        note: str = "", created_at: str = "") -> dict[str, Any]:
        rows = store.rows(RECEIPT_TABLE)
        receipt_no = self._next_no(RECEIPT_TABLE, "RCT-", "回执编号")
        entry: dict[str, Any] = {
            "id": self._next_id(RECEIPT_TABLE),
            "status": status,
            "pending": not confirmed,
            "abnormal": status in (RECEIPT_REJECTED, RECEIPT_CONFLICT),
            "回执编号": receipt_no,
            "关联批次": batch_no,
            "字段名称": field,
            "请求渠道": requester,
            "操作者": actor or requester,
            "申请类别": request_kind,
            "规则来源": rule_source,
            "引用授权": grant_no,
            "归一编号": factor_no,
            "换算系数": _fmt(factor_value) if factor_value is not None else "",
            "原始单位": source_unit,
            "目标单位": target_unit,
            "原始取值": "" if raw_value is None else str(raw_value),
            "归一取值": "" if result_value is None else _fmt(result_value),
            "系数出处": source_label,
            "确认标记": "是" if confirmed else "否",
            "提交时间": created_at or _now(),
            "确认时间": (created_at or _now()) if confirmed else "",
            "备注": note,
        }
        if reject_owner:
            entry["拒绝归属"] = reject_owner
        if reject_reason:
            entry["拒绝原因"] = reject_reason
        if rejected_value is not None:
            entry["被拒值"] = str(rejected_value)
        if cast_no:
            entry["转型编号"] = cast_no
        rows.append(entry)
        return entry

    # ---------- 批内规则冲突 ----------

    def _record_conflict(self, *, batch_no: str, field: str, grant: dict[str, Any] | None,
                         shared_factor: dict[str, Any] | None, own_factor: dict[str, Any],
                         grant_factor: Any, own_multiplier: float,
                         confirmed: dict[str, Any] | None,
                         created_at: str = "") -> dict[str, Any]:
        existing = self._conflict_of(batch_no, field)
        if existing is not None:
            return existing
        conflict_no = self._next_no(CONFLICT_TABLE, "CFT-", "冲突编号")
        entry: dict[str, Any] = {
            "id": self._next_id(CONFLICT_TABLE),
            "status": "待裁决",
            "pending": True,
            "abnormal": True,
            "冲突编号": conflict_no,
            "关联批次": batch_no,
            "字段名称": field,
            "来源渠道": str(own_factor.get("适用来源") or ""),
            "授权编号": str(grant.get("授权编号") or "") if grant else "",
            "共享系数": _fmt(grant_factor) if grant_factor is not None else "",
            "自有系数": _fmt(own_multiplier),
            "共享出处": (
                confirmed.get("系数出处") if confirmed else
                f"授权共享 {grant.get('授权编号')}" if grant else "共享来源"
            ),
            "自有出处": own_factor.get("系数出处"),
            "共享归一编号": (
                confirmed.get("归一编号") if confirmed else
                (shared_factor or {}).get("归一编号", "")
            ),
            "自有归一编号": own_factor.get("归一编号"),
            "在途取值": (
                confirmed.get("归一取值") if confirmed else ""
            ),
            "已确认取值": (
                confirmed.get("归一取值") if confirmed else ""
            ),
            "冲突说明": (
                f"批次 {batch_no} 已按共享系数 {_fmt(grant_factor) if grant_factor is not None else '?'}"
                f"确认在途取值 {confirmed.get('归一取值') if confirmed else '?'}，"
                f"又提交自有系数 {_fmt(own_multiplier)}，同一批出现两个来源规则"
            ),
            "裁决建议": "在途已确认字段保留当次系数，新申请改用自有规则或重新申请共享",
            "登记时间": created_at or _now(),
        }
        store.rows(CONFLICT_TABLE).append(entry)
        return entry

    def resolve_conflict(self, conflict_no: str, keep: str = "自有系数",
                         resolved_at: str = "") -> tuple[bool, str, dict[str, Any] | None]:
        """裁决同一批的两条来源规则：保留共享或自有，规则条目状态随裁决落定。"""
        conflict = next(
            (r for r in store.rows(CONFLICT_TABLE)
             if r.get("冲突编号") == conflict_no), None)
        if conflict is None:
            return False, f"冲突 {conflict_no} 不存在", None
        if conflict.get("status") != "待裁决":
            return False, f"冲突 {conflict_no} 已裁决，无需重复处理", dict(conflict)
        if keep not in ("共享系数", "自有系数"):
            return False, f"保留项「{keep}」不在允许范围 ['共享系数', '自有系数']", None

        own_no = str(conflict.get("自有归一编号") or "")
        shared_no = str(conflict.get("共享归一编号") or "")
        keep_no = own_no if keep == "自有系数" else shared_no
        drop_no = shared_no if keep == "自有系数" else own_no
        for factor in store.rows(FACTOR_TABLE):
            if str(factor.get("归一编号")) == keep_no:
                factor["status"] = "已生效"
                factor["pending"] = False
                factor["abnormal"] = False
                factor["冲突系数编号"] = ""
                factor.pop("停用原因", None)
            elif str(factor.get("归一编号")) == drop_no:
                # 共享系数被自有规则取代时，授权本身不改状态：其他批次仍可能在用。
                factor["status"] = "已停用"
                factor["pending"] = False
                factor["abnormal"] = False
                factor["停用原因"] = f"冲突 {conflict_no} 裁决未保留"
                factor["冲突系数编号"] = ""

        conflict["status"] = "已裁决"
        conflict["pending"] = False
        conflict["abnormal"] = False
        conflict["裁决结论"] = f"保留{keep}"
        conflict["裁决时间"] = resolved_at or _now()
        return True, f"冲突 {conflict_no} 已裁决：保留{keep}", dict(conflict)

    # ---------- 凭据校验 ----------

    def verify_credential(self, token: str) -> tuple[bool, str, dict[str, Any] | None]:
        """校验共享凭据：签名必须有效，且载荷与授权记录逐项一致。"""
        ok, payload, reason = verify_credential_token(token)
        if not ok or payload is None:
            return False, reason, None
        grant = self._find(str(payload.get("grant_no") or ""))
        if grant is None:
            return False, f"凭据指向的共享授权 {payload.get('grant_no')} 不存在", None
        if str(grant.get("共享凭据") or "") != str(token).strip():
            return False, (
                f"凭据不是共享授权 {grant.get('授权编号')} 当前签发的令牌，疑似串用"
            ), None
        for key, field in (("field", "字段名称"), ("source_unit", "原始单位"),
                           ("target_unit", "目标单位"), ("grantee", "受让方渠道"),
                           ("grantor", "授予方渠道")):
            if str(payload.get(key) or "") != str(grant.get(field) or ""):
                return False, (
                    f"凭据载荷 {key}={payload.get(key)!r} 与授权记录 {field}="
                    f"{grant.get(field)!r} 不一致，凭据已失效"
                ), None
        if abs((_to_float(payload.get("multiplier")) or 0.0)
               - self._factor_float(grant)) > 1e-9:
            return False, "凭据载荷换算系数与授权记录不一致，凭据已失效", None
        if str(payload.get("batches") or "") != str(grant.get("关联批次") or ""):
            return False, (
                f"凭据载荷批次范围 {payload.get('batches')!r} 与授权记录 "
                f"{grant.get('关联批次')!r} 不一致，凭据已失效"
            ), None
        if str(payload.get("request_kind") or "") != str(grant.get("申请类别") or ""):
            return False, (
                "凭据载荷申请类别与授权记录不一致，凭据已失效"
            ), None
        return True, f"共享凭据 {grant.get('授权编号')} 校验通过", dict(grant)

    # ---------- 适用性查询 ----------

    @staticmethod
    def _scope_batches(grant: dict[str, Any]) -> list[str]:
        text = str(grant.get("关联批次") or "").strip()
        if not text or text == "*":
            return ["*"]
        return [part.strip() for part in text.split(",") if part.strip()]

    def batch_in_scope(self, grant: dict[str, Any], batch_no: str) -> bool:
        scope = self._scope_batches(grant)
        return "*" in scope or str(batch_no) in scope

    def revoked_in_flight_allowed(self, grant: dict[str, Any] | None,
                                  requester: str, field: str,
                                  batch_no: str) -> bool:
        """撤回后仍可核对原请求，只限撤回前已明确领办的那一批在途数据。

        授权必须是「在途批次」且点名了具体批次；通配授权或新批次在撤回后不得再沿用，
        否则调用方只要自报「在途」就能绕过撤回。
        """
        if grant is None or str(grant.get("status")) != REVOKED:
            return False
        if str(grant.get("申请类别")) != ACTOR_IN_FLIGHT:
            return False
        scope = self._scope_batches(grant)
        if "*" in scope or str(batch_no) not in scope:
            return False
        return not self.in_flight_withdrawn(requester, field, batch_no)

    def _attribution(self, grant: dict[str, Any], requester: str) -> str:
        grant_no = grant.get("授权编号")
        if str(grant.get("受让方渠道")) == requester:
            return (
                f"共享授权 {grant_no} 归属受让方渠道 {grant.get('受让方渠道')}"
                f"（{grant.get('受让人')}），授权渠道范围 "
                f"{self._scope_batches(grant)} 不含请求渠道 {requester} 的这批数据或已撤回"
            )
        return (
            f"共享授权 {grant_no} 归属受让方渠道 {grant.get('受让方渠道')}"
            f"（{grant.get('受让人')}），请求渠道 {requester} 无权引用"
        )

    def _deny_owner(self, grant_no: str, target: dict[str, Any] | None,
                    grants: list[dict[str, Any]], requester: str,
                    batch_no: str = "") -> str:
        if target is not None:
            return self._attribution(target, requester)
        # 没有命中任何授权时，优先指出请求渠道自己名下那条为什么不能用
        own_grants = [g for g in grants if str(g.get("受让方渠道")) == requester]
        if own_grants:
            return "；".join(self._attribution(g, requester) for g in own_grants)
        # 越权引用时只指向真正覆盖这批数据的授权，避免把无关授权一起甩出来
        scoped = [g for g in grants
                  if batch_no and self.batch_in_scope(g, batch_no)]
        cited = scoped or grants
        if cited:
            return "；".join(self._attribution(g, requester) for g in cited)
        return f"字段未登记任何共享授权，请求渠道 {requester} 不得采用跨渠道来源系数"

    def _deny_reason(self, target: dict[str, Any] | None, requester: str,
                     field: str) -> str:
        if target is None:
            return (
                f"字段 {field} 没有可用于渠道 {requester} 的共享授权，"
                f"且该渠道未登记自有规则，不得采用跨渠道来源系数"
            )
        if str(target.get("受让方渠道")) != requester:
            return self._attribution(target, requester) + "，不得采用该来源系数"
        if target.get("status") == REVOKED:
            return (
                f"共享授权 {target.get('授权编号')} 已撤回，且渠道 {requester} 无可用自有规则，"
                f"不得继续采用共享系数"
            )
        if target.get("status") == EXPIRED:
            return f"共享授权 {target.get('授权编号')} 已失效"
        if target.get("status") == PENDING:
            return f"共享授权 {target.get('授权编号')} 尚未签发，不得引用"
        return f"共享授权 {target.get('授权编号')} 当前不适用于渠道 {requester}"

    def _grants_of_field(self, field: str) -> list[dict[str, Any]]:
        return [
            r for r in store.rows(self.MODULE)
            if not field or str(r.get("字段名称")) == str(field)
        ]

    def _pick_grant(self, requester: str, field: str, batch_no: str,
                    grant_no: str = "") -> dict[str, Any] | None:
        """挑出请求渠道自己的授权：显式指定优先，否则先按批次范围匹配。

        未指定授权且没有覆盖该批次的授权时返回 None，让调用方回落到自有规则；
        授权页需要讲清「哪条授权没覆盖」时另用 _candidate_grant。
        """
        if grant_no:
            return self._find(grant_no)
        grants = [
            g for g in self._grants_of_field(field)
            if str(g.get("受让方渠道")) == requester
        ]
        if batch_no:
            scoped = [g for g in grants if self.batch_in_scope(g, batch_no)]
            if not scoped:
                return None
            granted = [g for g in scoped if g.get("status") == GRANTED]
            return (granted or scoped)[0]
        return grants[0] if grants else None

    def _candidate_grant(self, requester: str, field: str,
                         grant_no: str = "") -> dict[str, Any] | None:
        """请求渠道名下最近的一条授权，仅用于资格说明与归属展示，不参与取值。"""
        if grant_no:
            return self._find(grant_no)
        grants = [
            g for g in self._grants_of_field(field)
            if str(g.get("受让方渠道")) == requester
        ]
        if not grants:
            return None
        grants.sort(key=lambda g: str(g.get("签发时间") or ""), reverse=True)
        return grants[0]

    def eligibility(self, requester_channel: str, field: str,
                    batch_no: str, grant_no: str = "",
                    source_unit: str = "") -> dict[str, Any]:
        """给转型表单返回服务端资格：在途申请与下一笔新申请分别给出结论和系数出处。"""
        requester = str(requester_channel or "").strip()
        field = str(field or "").strip()
        batch_no = str(batch_no or "").strip()

        grants = self._grants_of_field(field)
        target = self._pick_grant(requester, field, batch_no, grant_no)
        # 授权页要讲清归属：优先展示请求渠道自己名下那条授权，即使它没覆盖当前批次；
        # 该渠道名下没有授权时，展示真正覆盖这批数据的那条，让越权方看到归属。
        candidate = target or self._candidate_grant(requester, field, grant_no)
        if candidate is None:
            candidate = next(
                (g for g in grants
                 if batch_no and self.batch_in_scope(g, batch_no)), None)
        confirmed = (
            self._confirmed_receipt(batch_no, field, requester) if batch_no else None
        )
        own = self._own_factor(requester, field, source_unit)
        active_own = own if own is not None and own.get("status") == "已生效" else None

        own_view = None
        if own is not None:
            own_view = {
                "归一编号": own.get("归一编号"),
                "系数值": own.get("换算系数"),
                "系数出处": own.get("系数出处") or f"自有规则 {own.get('归一编号')}",
                "原始单位": own.get("原始单位"),
                "目标单位": own.get("目标单位"),
                "status": own.get("status"),
            }

        is_grantee = target is not None and str(target.get("受让方渠道")) == requester
        grant_active = is_grantee and target is not None and target.get("status") == GRANTED
        in_scope = bool(
            target is not None and batch_no and self.batch_in_scope(target, batch_no)
        )
        in_flight_scope = bool(
            is_grantee and batch_no and target is not None
            and self.batch_in_scope(target, batch_no)
        )

        options: list[dict[str, Any]] = []

        # ---- 在途申请：优先已确认快照，其次撤回前授权，最后自有规则 ----
        if confirmed is not None and not self.in_flight_withdrawn(
                requester, field, batch_no):
            in_flight = {
                "申请类别": ACTOR_IN_FLIGHT,
                "关联批次": batch_no,
                "可用": True,
                "采用方式": "继续核对原请求（已确认快照）",
                "原因": "已确认字段保留当次原单位、因子和来源，不随授权变更刷新成新值",
                "系数值": confirmed.get("换算系数"),
                "系数出处": confirmed.get("系数出处"),
                "归一编号": confirmed.get("归一编号"),
                "引用授权": confirmed.get("引用授权"),
                "规则来源": confirmed.get("规则来源"),
                "原始单位": confirmed.get("原始单位"),
                "目标单位": confirmed.get("目标单位"),
                "归一取值": confirmed.get("归一取值"),
                "回执编号": confirmed.get("回执编号"),
            }
            options.append({
                "方式": "继续核对原请求",
                "可用": True,
                "系数值": confirmed.get("换算系数"),
                "系数出处": confirmed.get("系数出处"),
            })
        elif grant_active and in_scope:
            in_flight = {
                "申请类别": ACTOR_IN_FLIGHT,
                "关联批次": batch_no,
                "可用": True,
                "采用方式": "按授权继续核对原请求",
                "原因": f"授权 {target.get('授权编号')} 在有效期内且覆盖批次 {batch_no}",
                "系数值": target.get("换算系数"),
                "系数出处": f"授权共享 {target.get('授权编号')}",
                "归一编号": (self._shared_factor(target) or {}).get("归一编号", ""),
                "引用授权": target.get("授权编号"),
                "规则来源": SHARED_RULE,
                "原始单位": target.get("原始单位"),
                "目标单位": target.get("目标单位"),
            }
            options.append({
                "方式": "继续核对原请求",
                "可用": True,
                "系数值": target.get("换算系数"),
                "系数出处": f"授权共享 {target.get('授权编号')}",
            })
        elif (target is not None and in_flight_scope
              and self.revoked_in_flight_allowed(
                  target, requester, field, batch_no)):
            # 撤回前已经领办的在途批次，允许沿用撤回前授权核对原请求。
            in_flight = {
                "申请类别": ACTOR_IN_FLIGHT,
                "关联批次": batch_no,
                "可用": True,
                "采用方式": "继续核对原请求（沿用撤回前授权）",
                "原因": (
                    f"授权 {target.get('授权编号')} 已撤回，但批次 {batch_no} 为撤回前领办的在途数据，"
                    f"可按撤回前授权核对原请求"
                ),
                "系数值": target.get("换算系数"),
                "系数出处": f"授权共享 {target.get('授权编号')}（撤回前在途）",
                "归一编号": (self._shared_factor(target) or {}).get("归一编号", ""),
                "引用授权": target.get("授权编号"),
                "规则来源": SHARED_RULE,
                "原始单位": target.get("原始单位"),
                "目标单位": target.get("目标单位"),
                "授权状态": REVOKED,
            }
            options.append({
                "方式": "继续核对原请求",
                "可用": True,
                "系数值": target.get("换算系数"),
                "系数出处": f"授权共享 {target.get('授权编号')}（撤回前在途）",
            })
        elif (own is not None and target is not None and is_grantee
              and target.get("status") in (REVOKED, EXPIRED)):
            # 授权已撤回/失效：在途申请改按自有规则继续核对，不再沿用旧授权。
            in_flight = {
                "申请类别": ACTOR_IN_FLIGHT,
                "关联批次": batch_no,
                "可用": own.get("status") == "已生效",
                "采用方式": "使用自有规则" if own.get("status") == "已生效" else "拒绝",
                "原因": (
                    f"共享授权 {target.get('授权编号')} 已{target.get('status')}，"
                    f"在途申请改按自有规则 {own.get('归一编号')} 继续核对"
                ) if own.get("status") == "已生效" else (
                    f"共享授权 {target.get('授权编号')} 已撤回，自有规则 "
                    f"{own.get('归一编号')} 处于系数冲突待裁决"
                ),
                **{k: own_view[k] for k in ("系数值", "系数出处", "归一编号",
                                            "原始单位", "目标单位")},
                "引用授权": "",
                "规则来源": OWN_RULE,
            }
            if own.get("status") == "已生效":
                options.append({
                    "方式": "使用自有规则",
                    "可用": True,
                    "系数值": own_view["系数值"],
                    "系数出处": own_view["系数出处"],
                })
        elif active_own is not None:
            in_flight = {
                "申请类别": ACTOR_IN_FLIGHT,
                "关联批次": batch_no,
                "可用": True,
                "采用方式": "使用自有规则",
                "原因": "无可用共享授权，使用本渠道自有规则",
                **{k: own_view[k] for k in ("系数值", "系数出处", "归一编号",
                                            "原始单位", "目标单位")},
                "引用授权": "",
                "规则来源": OWN_RULE,
            }
            options.append({
                "方式": "使用自有规则",
                "可用": True,
                "系数值": own_view["系数值"],
                "系数出处": own_view["系数出处"],
            })
        else:
            in_flight = {
                "申请类别": ACTOR_IN_FLIGHT,
                "关联批次": batch_no,
                "可用": False,
                "采用方式": "拒绝",
                "原因": self._deny_reason(target, requester, field),
                "拒绝归属": self._deny_owner(
                    grant_no, target, grants, requester, batch_no),
            }

        if active_own is not None and not any(
                option["方式"] == "使用自有规则" for option in options):
            options.append({
                "方式": "使用自有规则",
                "可用": True,
                "系数值": own_view["系数值"],
                "系数出处": own_view["系数出处"],
            })
        if own is not None and own.get("status") == "系数冲突" and not any(
                option["方式"] == "使用自有规则" for option in options):
            options.append({
                "方式": "使用自有规则",
                "可用": False,
                "系数值": own_view["系数值"],
                "系数出处": own_view["系数出处"],
                "原因": f"自有规则 {own.get('归一编号')} 处于系数冲突待裁决",
            })

        # ---- 下一笔新申请：撤回后不得沿用旧授权 ----
        if grant_active:
            next_application = {
                "申请类别": ACTOR_NEW,
                "可用": True,
                "采用方式": "按授权采用共享系数",
                "原因": f"授权 {target.get('授权编号')} 有效，可继续用于新申请",
                "系数值": target.get("换算系数"),
                "系数出处": f"授权共享 {target.get('授权编号')}",
                "归一编号": (self._shared_factor(target) or {}).get("归一编号", ""),
                "引用授权": target.get("授权编号"),
                "规则来源": SHARED_RULE,
                "原始单位": target.get("原始单位"),
                "目标单位": target.get("目标单位"),
            }
        elif active_own is not None:
            reason = "使用自有规则"
            if is_grantee and target is not None and target.get("status") == REVOKED:
                reason = "授权已撤回，下一笔新申请改用自有规则"
            next_application = {
                "申请类别": ACTOR_NEW,
                "可用": True,
                "采用方式": "使用自有规则",
                "原因": reason,
                **{k: own_view[k] for k in ("系数值", "系数出处", "归一编号",
                                            "原始单位", "目标单位")},
                "引用授权": "",
                "规则来源": OWN_RULE,
            }
        else:
            next_application = {
                "申请类别": ACTOR_NEW,
                "可用": False,
                "采用方式": "拒绝",
                "原因": self._deny_reason(target, requester, field),
                "拒绝归属": self._deny_owner(
                    grant_no, target, grants, requester, batch_no),
            }

        # 展示用授权：没有命中自己的授权时，把渠道名下那条也报出来讲清归属，
        # 但「是否可引用」只认 target，避免把别人的授权当成可用资格。
        display = target or candidate
        can_quote = bool(target is not None and str(target.get("受让方渠道")) == requester)
        return {
            "请求渠道": requester,
            "字段名称": field,
            "关联批次": batch_no,
            "授权编号": display.get("授权编号") if display else "",
            "授权状态": display.get("status") if display else "",
            "授权归属": (
                f"{display.get('授予方渠道')}→{display.get('受让方渠道')}"
                if display else ""
            ),
            "可引用": can_quote,
            "归属说明": (
                self._attribution(display, requester) if display else ""
            ),
            "在途申请": in_flight,
            "下一笔新申请": next_application,
            "可选方式": options,
            "自有规则": own_view,
            "可用授权": [
                {
                    "授权编号": g.get("授权编号"),
                    "渠道范围": g.get("渠道范围"),
                    "关联批次": g.get("关联批次"),
                    "申请类别": g.get("申请类别"),
                    "换算系数": g.get("换算系数"),
                    "共享凭据": g.get("共享凭据"),
                    "status": g.get("status"),
                }
                for g in grants
            ],
        }

    check_eligibility = eligibility

    def has_rule(self, channel: str, field: str, batch_no: str = "") -> bool:
        """该渠道该字段是否有可用的换算规则（授权共享或自有），供管线判断是否接管。"""
        requester = str(channel or "")
        grant = self._pick_grant(requester, field, batch_no)
        if (grant is not None and grant.get("status") == GRANTED
                and str(grant.get("受让方渠道")) == requester
                and (not batch_no or self.batch_in_scope(grant, batch_no))):
            return True
        return self._own_factor(requester, field) is not None

    # ---------- 取值转型 + 单位归一 ----------

    def _reject(self, *, requester: str, actor: str, field: str, batch_no: str,
                request_kind: str, raw_value: Any, source_unit: str,
                target: dict[str, Any] | None, grants: list[dict[str, Any]],
                grant_no: str, reason: str, owner: str,
                cast_no: str = "", created_at: str = "") -> dict[str, Any]:
        receipt = self._record_receipt(
            batch_no=batch_no, field=field, requester=requester, actor=actor,
            request_kind=request_kind, rule_source="拒绝",
            factor_value=None, source_unit=source_unit, target_unit="",
            raw_value=raw_value, result_value=None, source_label="",
            grant_no=grant_no, status=RECEIPT_REJECTED, confirmed=False,
            reject_owner=owner, reject_reason=reason,
            rejected_value=raw_value, cast_no=cast_no, created_at=created_at,
        )
        return {
            "ok": False,
            "status": RECEIPT_REJECTED,
            "message": f"{reason}；被拒值 {raw_value} {source_unit}",
            "拒绝归属": owner,
            "被拒值": str(raw_value),
            "系数值": "",
            "系数出处": "",
            "归一编号": "",
            "引用授权": grant_no,
            "归一取值": None,
            "回执": receipt,
            "授权编号": target.get("授权编号") if target else grant_no,
        }

    def cast(self, *, channel: str, field: str, raw_value: Any,
             source_unit: str, batch_no: str, grant_no: str = "",
             actor: str = "", request_kind: str = "",
             credential: str = "", cast_no: str = "",
             preferred: str = "",
             created_at: str = "") -> dict[str, Any]:
        """按服务端资格把转型后的数值换算成目标单位，并落一条可回查的转型回执。

        已确认字段直接返回当次快照，不因授权撤回或新系数提交而刷新；重复提交同一字段
        不会重复确认。未授权的渠道/批次一律拒绝，并写清授权归属与被拒值。

        preferred 用于在服务端给出的两种可用方式里做选择：`继续核对原请求` 或
        `使用自有规则`；不传时按资格默认顺序（原请求优先）。
        """
        preferred = str(preferred or "").strip()
        if preferred and preferred not in ("继续核对原请求", "使用自有规则"):
            return {
                "ok": False, "status": RECEIPT_REJECTED,
                "message": (
                    f"换算方式「{preferred}」不在允许范围 "
                    f"['继续核对原请求', '使用自有规则']"
                ),
                "被拒值": str(raw_value), "归一取值": None,
            }
        requester = str(channel or "").strip()
        field = str(field or "").strip()
        batch_no = str(batch_no or "").strip()
        source_unit = str(source_unit or "").strip()
        raw_number = _to_float(raw_value)
        if raw_number is None:
            return {
                "ok": False, "status": RECEIPT_REJECTED,
                "message": f"原始取值 {raw_value!r} 转型后不是数值，无法做单位归一",
                "被拒值": str(raw_value), "归一取值": None,
            }

        # 1) 已确认字段：保留当次快照，重复提交只返回原确认，不再记新回执。
        confirmed = self._confirmed_receipt(batch_no, field, requester)
        if confirmed is not None:
            return {
                "ok": True,
                "status": RECEIPT_CONFIRMED,
                "message": (
                    f"字段 {field} 在批次 {batch_no} 已确认："
                    f"{confirmed.get('原始取值')} {confirmed.get('原始单位')} ×"
                    f"{confirmed.get('换算系数')} = {confirmed.get('归一取值')} "
                    f"{confirmed.get('目标单位')}；保留当次系数出处 "
                    f"{confirmed.get('系数出处')}，不随授权变更刷新"
                ),
                "重复提交": True,
                "系数值": confirmed.get("换算系数"),
                "系数出处": confirmed.get("系数出处"),
                "归一编号": confirmed.get("归一编号"),
                "引用授权": confirmed.get("引用授权"),
                "归一取值": (
                    _to_float(confirmed.get("归一取值"))
                    if confirmed.get("归一取值") not in (None, "") else None
                ),
                "目标单位": confirmed.get("目标单位"),
                "回执": confirmed,
                "授权编号": confirmed.get("引用授权"),
            }

        # 2) 解析授权：显式指定优先，否则按受让方 + 批次范围自动匹配。
        #    选择「使用自有规则」时不再解析共享授权，直接落到自有规则分支。
        if preferred == "使用自有规则" and self._active_own_factor(
                requester, field, source_unit) is not None:
            grant_no = ""
            grant = None
        else:
            grant = self._pick_grant(requester, field, batch_no, grant_no)
        grants = self._grants_of_field(field)
        owner = self._deny_owner(grant_no, grant, grants, requester, batch_no)
        kind = str(request_kind or "").strip() or (
            grant.get("申请类别") if grant else ACTOR_NEW
        )

        if credential:
            ok, cred_message, cred_grant = self.verify_credential(credential)
            if not ok:
                return self._reject(
                    requester=requester, actor=actor, field=field, batch_no=batch_no,
                    request_kind=kind, raw_value=raw_value, source_unit=source_unit,
                    target=grant, grants=grants, grant_no=grant_no,
                    reason=f"共享凭据校验不通过：{cred_message}", owner=owner,
                    cast_no=cast_no, created_at=created_at,
                )

        if grant is not None:
            if str(grant.get("受让方渠道")) != requester:
                return self._reject(
                    requester=requester, actor=actor, field=field, batch_no=batch_no,
                    request_kind=kind, raw_value=raw_value, source_unit=source_unit,
                    target=grant, grants=grants, grant_no=grant_no,
                    reason=self._attribution(grant, requester) + "，不得采用该来源系数",
                    owner=owner, cast_no=cast_no, created_at=created_at,
                )
            if str(grant.get("字段名称")) != field:
                return self._reject(
                    requester=requester, actor=actor, field=field, batch_no=batch_no,
                    request_kind=kind, raw_value=raw_value, source_unit=source_unit,
                    target=grant, grants=grants, grant_no=grant_no,
                    reason=(
                        f"共享授权 {grant.get('授权编号')} 只覆盖字段 "
                        f"{grant.get('字段名称')}，不能用于字段 {field}"
                    ),
                    owner=owner, cast_no=cast_no, created_at=created_at,
                )
            if source_unit and source_unit != str(grant.get("原始单位")):
                return self._reject(
                    requester=requester, actor=actor, field=field, batch_no=batch_no,
                    request_kind=kind, raw_value=raw_value, source_unit=source_unit,
                    target=grant, grants=grants, grant_no=grant_no,
                    reason=(
                        f"共享授权 {grant.get('授权编号')} 的原始单位为 "
                        f"{grant.get('原始单位')}，与提交的 {source_unit} 不一致"
                    ),
                    owner=owner, cast_no=cast_no, created_at=created_at,
                )
            if not self.batch_in_scope(grant, batch_no):
                return self._reject(
                    requester=requester, actor=actor, field=field, batch_no=batch_no,
                    request_kind=kind, raw_value=raw_value, source_unit=source_unit,
                    target=grant, grants=grants, grant_no=grant_no,
                    reason=(
                        f"批次 {batch_no} 不在共享授权 {grant.get('授权编号')} 的渠道范围 "
                        f"{self._scope_batches(grant)} 内，未授权的新批次不得采用跨渠道来源系数"
                    ),
                    owner=owner, cast_no=cast_no, created_at=created_at,
                )

            status = str(grant.get("status"))
            revoked_in_flight = (
                kind == ACTOR_IN_FLIGHT
                and self.revoked_in_flight_allowed(
                    grant, requester, field, batch_no)
            )
            if status != GRANTED and not revoked_in_flight:
                reason = self._deny_reason(grant, requester, field)
                if status == REVOKED:
                    reason = (
                        f"共享授权 {grant.get('授权编号')} 已撤回，批次 {batch_no} 不是"
                        f"撤回前领办的在途申请，不得采用跨渠道来源系数"
                    )
                return self._reject(
                    requester=requester, actor=actor, field=field, batch_no=batch_no,
                    request_kind=kind, raw_value=raw_value, source_unit=source_unit,
                    target=grant, grants=grants, grant_no=grant_no,
                    reason=reason, owner=owner,
                    cast_no=cast_no, created_at=created_at,
                )

            shared_factor = self._ensure_shared_factor(grant)
            if revoked_in_flight:
                shared_label = f"授权共享 {grant.get('授权编号')}（撤回前在途）"
                rule_source = SHARED_RULE
                note = "在途申请沿用撤回前授权，已确认后不随撤回刷新"
            else:
                shared_label = f"授权共享 {grant.get('授权编号')}"
                rule_source = SHARED_RULE
                note = "按来源负责人共享授权换算"
                shared_factor["status"] = "已生效"
                shared_factor["pending"] = False
                shared_factor["最近命中"] = created_at or _now()
                grant["最近使用"] = created_at or _now()

            multiplier = self._factor_float(grant)
            result = round(raw_number * multiplier, 6)
            receipt = self._record_receipt(
                batch_no=batch_no, field=field, requester=requester, actor=actor,
                request_kind=kind, rule_source=rule_source,
                factor_value=multiplier, source_unit=str(grant.get("原始单位")),
                target_unit=str(grant.get("目标单位")), raw_value=raw_value,
                result_value=result, source_label=shared_label,
                grant_no=str(grant.get("授权编号")),
                factor_no=str(shared_factor.get("归一编号")),
                status=RECEIPT_CONFIRMED, confirmed=True,
                cast_no=cast_no, note=note, created_at=created_at,
            )
            return {
                "ok": True,
                "status": RECEIPT_CONFIRMED,
                "message": (
                    f"字段 {field} 在批次 {batch_no} 按{shared_label} ×{_fmt(multiplier)} "
                    f"由 { _fmt(raw_number)} {grant.get('原始单位')} 归一为 "
                    f"{_fmt(result)} {grant.get('目标单位')}"
                ),
                "重复提交": False,
                "系数值": _fmt(multiplier),
                "系数出处": shared_label,
                "归一编号": shared_factor.get("归一编号"),
                "引用授权": grant.get("授权编号"),
                "规则来源": rule_source,
                "原始单位": grant.get("原始单位"),
                "目标单位": grant.get("目标单位"),
                "归一取值": result,
                "回执": receipt,
                "授权编号": grant.get("授权编号"),
                "授权状态": status,
            }

        # 3) 没有可用共享授权：只允许本渠道已生效的自有规则。
        own = self._active_own_factor(requester, field, source_unit)
        if own is not None:
            multiplier = self._factor_float(own)
            result = round(raw_number * multiplier, 6)
            label = own.get("系数出处") or f"自有规则 {own.get('归一编号')}"
            own["最近命中"] = created_at or _now()
            receipt = self._record_receipt(
                batch_no=batch_no, field=field, requester=requester, actor=actor,
                request_kind=kind, rule_source=OWN_RULE,
                factor_value=multiplier, source_unit=str(own.get("原始单位")),
                target_unit=str(own.get("目标单位")), raw_value=raw_value,
                result_value=result, source_label=label,
                factor_no=str(own.get("归一编号")),
                status=RECEIPT_CONFIRMED, confirmed=True,
                cast_no=cast_no, note="本渠道自有换算规则", created_at=created_at,
            )
            return {
                "ok": True,
                "status": RECEIPT_CONFIRMED,
                "message": (
                    f"字段 {field} 在批次 {batch_no} 按{label} ×{_fmt(multiplier)} "
                    f"归一为 {_fmt(result)} {own.get('目标单位')}"
                ),
                "重复提交": False,
                "系数值": _fmt(multiplier),
                "系数出处": label,
                "归一编号": own.get("归一编号"),
                "引用授权": "",
                "规则来源": OWN_RULE,
                "原始单位": own.get("原始单位"),
                "目标单位": own.get("目标单位"),
                "归一取值": result,
                "回执": receipt,
                "授权编号": "",
                "授权状态": "",
            }

        own_conflicted = self._own_factor(requester, field, source_unit)
        if own_conflicted is not None and own_conflicted.get("status") == "系数冲突":
            reason = (
                f"渠道 {requester} 的自有规则 {own_conflicted.get('归一编号')} 处于系数冲突待裁决，"
                f"不得直接采用"
            )
        else:
            reason = self._deny_reason(grant, requester, field)
        return self._reject(
            requester=requester, actor=actor, field=field, batch_no=batch_no,
            request_kind=kind, raw_value=raw_value, source_unit=source_unit,
            target=grant, grants=grants, grant_no=grant_no,
            reason=reason, owner=owner,
            cast_no=cast_no, created_at=created_at,
        )

    cast_unit_value = cast

    def submit_own_factor(self, *, channel: str, field: str, source_unit: str,
                          target_unit: str, multiplier: Any, batch_no: str = "",
                          submitted_at: str = "",
                          actor: str = "") -> dict[str, Any]:
        """登记本渠道自有系数；与在途共享系数同批并存时登记为来源规则冲突。"""
        requester = str(channel or "").strip()
        field = str(field or "").strip()
        source_unit = str(source_unit or "").strip()
        target_unit = str(target_unit or "").strip()
        batch_no = str(batch_no or "").strip()
        factor = _to_float(multiplier)
        if not requester or not field or not source_unit or not target_unit:
            return {"ok": False, "status": "拒绝",
                    "message": "渠道、字段名称、原始单位、目标单位均为必填项"}
        if factor is None or factor <= 0:
            return {"ok": False, "status": "拒绝",
                    "message": f"换算系数 {multiplier!r} 必须为大于 0 的数值"}

        now = submitted_at or _now()
        # 记录提交前的状态，避免登记函数覆盖掉要拿来比对的原系数
        prior = self._own_factor(requester, field, source_unit)
        prior_multiplier = self._factor_float(prior) if prior else None
        prior_status = prior.get("status") if prior else ""
        own = self._register_own_factor(
            requester, field, source_unit, target_unit, factor, batch_no, now)

        # 同批已确认的在途共享系数：两条来源规则并存，登记冲突且不刷新已确认值。
        confirmed = self._confirmed_receipt(batch_no, field, requester) if batch_no else None
        grant_no = str((confirmed or {}).get("引用授权") or "")
        grant = self._find(grant_no) if grant_no else None
        grant_factor = (
            (confirmed or {}).get("换算系数") if confirmed else
            (grant.get("换算系数") if grant else None)
        )
        # 先按「同渠道同字段已有生效自有系数」登记冲突，再落定本次提交的系数值。
        previous = None
        if (prior is not None and prior_status == "已生效"
                and prior_multiplier is not None
                and abs(prior_multiplier - factor) > 1e-9):
            previous = prior
        if previous is None:
            previous = next((
                row for row in store.rows(FACTOR_TABLE)
                if row is not own
                and str(row.get("字段名称")) == field
                and str(row.get("适用来源")) == requester
                and str(row.get("来源类型") or OWN_RULE) == OWN_RULE
                and row.get("status") == "已生效"
                and abs(self._factor_float(row) - factor) > 1e-9
            ), None)
        if previous is not None:
            own["status"] = "系数冲突"
            own["pending"] = True
            own["abnormal"] = True
            own["冲突系数编号"] = previous.get("归一编号")
            return {
                "ok": False,
                "status": "系数冲突",
                "message": (
                    f"渠道 {requester} 字段 {field} 已有生效系数 "
                    f"{previous.get('换算系数')}（{previous.get('归一编号')}），"
                    f"与新提交 {_fmt(factor)} 冲突，本次提交未生效"
                ),
                "自有规则": dict(own),
                "冲突系数编号": previous.get("归一编号"),
            }
        own["换算系数"] = _fmt(factor)
        own.pop("待确认系数", None)

        if confirmed is not None and grant_factor is not None and abs(
                (_to_float(grant_factor) or 0.0) - factor) > 1e-9:
            shared_factor = self._shared_factor(grant) if grant else None
            # 冲突登记在批次维度：自有规则本身仍可生效，冲突只表达「同一批两条规则并存」。
            own["冲突系数编号"] = confirmed.get("归一编号")
            conflict = self._record_conflict(
                batch_no=batch_no, field=field, grant=grant,
                shared_factor=shared_factor, own_factor=own,
                grant_factor=_to_float(grant_factor), own_multiplier=factor,
                confirmed=confirmed, created_at=now,
            )
            return {
                "ok": True,
                "status": RECEIPT_CONFLICT,
                "message": (
                    f"自有系数 {_fmt(factor)} 已登记，但与批次 {batch_no} 在途共享系数 "
                    f"{_fmt(grant_factor)}（{confirmed.get('系数出处')}）冲突；"
                    f"已确认取值 {confirmed.get('归一取值')} {confirmed.get('目标单位')} 保留不刷新，"
                    f"冲突 {conflict.get('冲突编号')} 待裁决"
                ),
                "冲突": conflict,
                "冲突编号": conflict.get("冲突编号"),
                "在途回执": confirmed,
                "自有规则": dict(own),
                "系数值": _fmt(factor),
                "系数出处": own.get("系数出处"),
                "共享系数": _fmt(grant_factor),
            }

        # 新申请口径同步更新：撤回后若无其他生效授权，自有规则即可承接后续换算。
        return {
            "ok": True,
            "status": "已生效",
            "message": (
                f"渠道 {requester} 自有系数已登记：{field} {source_unit}→{target_unit} "
                f"×{_fmt(factor)}（{own.get('归一编号')}）"
            ),
            "申请类别": ACTOR_NEW,
            "自有规则": dict(own),
            "系数值": _fmt(factor),
            "系数出处": own.get("系数出处"),
        }

    submit_own_rule = submit_own_factor

    def withdraw_in_flight(self, *, channel: str, field: str, batch_no: str,
                           withdrawn_at: str = "",
                           reason: str = "") -> dict[str, Any]:
        """受让渠道撤回在途申请：不删除已确认快照，但撤回后重进表单不再按原请求核对。"""
        requester = str(channel or "").strip()
        field = str(field or "").strip()
        batch_no = str(batch_no or "").strip()
        if not requester or not field or not batch_no:
            return {"ok": False, "消息": "渠道、字段名称、关联批次均为必填项"}
        now = withdrawn_at or _now()

        touched: list[str] = []
        for row in store.rows(RECEIPT_TABLE):
            if (str(row.get("关联批次")) == batch_no
                    and str(row.get("字段名称")) == field
                    and str(row.get("请求渠道")) == requester
                    and row.get("确认标记") == "是"
                    and not row.get("撤回时间")):
                row["撤回时间"] = now
                row["撤回原因"] = str(reason or "受让渠道撤回在途申请")
                touched.append(str(row.get("回执编号")))

        for grant in self._grants_of_field(field):
            if (str(grant.get("受让方渠道")) == requester
                    and str(grant.get("申请类别")) == ACTOR_IN_FLIGHT
                    and self.batch_in_scope(grant, batch_no)
                    and not grant.get("在途撤回时间")):
                grant["在途撤回时间"] = now
                grant["在途撤回原因"] = str(reason or "受让渠道撤回在途申请")

        # 已确认快照保留可回查，但资格判断从此不再按原请求核对。
        return {
            "ok": True,
            "申请类别": ACTOR_IN_FLIGHT,
            "关联批次": batch_no,
            "字段名称": field,
            "请求渠道": requester,
            "撤回回执": touched,
            "消息": (
                f"批次 {batch_no} 的在途申请已撤回，已确认回执 {touched or '无'} 仍可回查，"
                f"重进转型表单按服务端重新给出的资格执行"
            ),
        }

    def in_flight_withdrawn(self, channel: str, field: str, batch_no: str) -> bool:
        """该批该字段的在途申请是否已被受让渠道主动撤回。"""
        requester = str(channel or "")
        for row in store.rows(RECEIPT_TABLE):
            if (str(row.get("关联批次")) == str(batch_no)
                    and str(row.get("字段名称")) == str(field)
                    and str(row.get("请求渠道")) == requester
                    and row.get("撤回时间")):
                return True
        return False

    # ---------- 回执与契约复核 ----------

    def receipts(self, batch_no: str = "", field: str = "",
                 channel: str = "") -> list[dict[str, Any]]:
        """历史转型回执：已确认与已拒绝都保留，按提交顺序返回。"""
        rows = list(store.rows(RECEIPT_TABLE))
        if batch_no:
            rows = [r for r in rows if str(r.get("关联批次")) == str(batch_no)]
        if field:
            rows = [r for r in rows if str(r.get("字段名称")) == str(field)]
        if channel:
            rows = [r for r in rows if str(r.get("请求渠道")) == str(channel)]
        return rows

    receipt_history = receipts

    def receipt(self, receipt_no: str) -> dict[str, Any] | None:
        for row in store.rows(RECEIPT_TABLE):
            if row.get("回执编号") == receipt_no:
                return row
        return None

    def conflicts(self, batch_no: str = "") -> list[dict[str, Any]]:
        rows = list(store.rows(CONFLICT_TABLE))
        if batch_no:
            rows = [r for r in rows if str(r.get("关联批次")) == str(batch_no)]
        return rows

    def provenance(self, batch_no: str, field: str = "") -> dict[str, Any]:
        """输出该批次实际取用的系数出处，供输出契约接收时复核。"""
        confirmed = [
            r for r in self.receipts(batch_no=batch_no, field=field)
            if r.get("确认标记") == "是"
        ]
        fields: dict[str, dict[str, Any]] = {}
        for receipt in confirmed:
            name = str(receipt.get("字段名称"))
            fields[name] = {
                "字段名称": name,
                "归一编号": receipt.get("归一编号"),
                "系数值": receipt.get("换算系数"),
                "系数出处": receipt.get("系数出处"),
                "引用授权": receipt.get("引用授权"),
                "规则来源": receipt.get("规则来源"),
                "原始单位": receipt.get("原始单位"),
                "目标单位": receipt.get("目标单位"),
                "原始取值": receipt.get("原始取值"),
                "归一取值": receipt.get("归一取值"),
                "回执编号": receipt.get("回执编号"),
                "确认时间": receipt.get("确认时间"),
            }
        return {
            "关联批次": batch_no,
            "字段": fields,
            "已确认字段数": len(fields),
            "回执编号": [f["回执编号"] for f in fields.values()],
        }

    def check_contract_provenance(self, contract_no: str, batch_no: str = "",
                                  fields: list[str] | None = None) -> dict[str, Any]:
        """复核输出契约接收的字段是否都有可回查的系数出处。"""
        contract = next(
            (r for r in store.rows("output_contract")
             if r.get("契约编号") == contract_no), None)
        if contract is None:
            return {"ok": False, "message": f"输出契约 {contract_no} 不存在",
                    "failures": [f"契约 {contract_no} 不存在"]}
        linked_batch = batch_no or str(contract.get("关联批次") or "")
        provenance = self.provenance(linked_batch)
        expected = fields or [
            part.strip() for part in str(contract.get("输出列集合") or "").split(",")
            if part.strip()
        ]
        failures: list[str] = []
        checked: list[dict[str, Any]] = []
        for name in expected:
            info = provenance["字段"].get(name)
            if info is None:
                failures.append(f"字段 {name} 缺少已确认的系数出处回执")
                continue
            if not info.get("系数出处"):
                failures.append(f"字段 {name} 的归一结果未说明系数出处")
                continue
            checked.append(info)
        return {
            "ok": not failures,
            "message": (
                f"契约 {contract_no} 的 {len(checked)} 个字段系数出处与回执一致"
                if not failures else "；".join(failures)
            ),
            "contract_id": contract_no,
            "关联批次": linked_batch,
            "fields": checked,
            "failures": failures,
        }

    # ---------- 通用接口适配 ----------

    def create_entry(self, values: dict[str, Any]) -> tuple[dict[str, Any] | None, list[str]]:
        """通用登记入口：校验通过即由服务端签发凭据，不落到无凭据的半成品。"""
        missing = [
            field for field in self.REQUIRED_FIELDS
            if not str(values.get(field) or "").strip()
        ]
        if missing:
            return None, missing
        ok, message, entry = self.grant_share(
            grant_no=str(values.get("授权编号") or "").strip(),
            field=str(values.get("字段名称") or ""),
            source_unit=str(values.get("原始单位") or ""),
            target_unit=str(values.get("目标单位") or ""),
            multiplier=values.get("换算系数"),
            grantor_channel=str(values.get("授予方渠道") or ""),
            grantee_channel=str(values.get("受让方渠道") or ""),
            batch_no=str(values.get("关联批次") or ""),
            request_kind=str(values.get("申请类别") or ACTOR_NEW),
            grantor_name=str(values.get("授予人") or ""),
            grantee_name=str(values.get("受让人") or ""),
            remark=str(values.get("授权依据") or ""),
        )
        if not ok:
            return None, [message]
        return entry, []

    def run_action(self, entry_id: int, action: str) -> tuple[dict[str, Any] | None, str]:
        entry = store.find(self.MODULE, entry_id)
        if entry is None:
            return None, f"{self.ENTITY} {entry_id} 不存在或已归档"
        if action not in self.ACTION_RULES:
            return None, f"动作「{action}」不属于{self.MODULE}可执行范围"
        grant_no = str(entry.get("授权编号") or "")
        if action == "签发共享":
            ok, message, _row = self.issue_credential(grant_no)
            return (dict(entry) if ok else None), message
        if action == "撤回授权":
            ok, message, _row = self.revoke(grant_no)
            return (dict(entry) if ok else None), message
        if action == "登记失效":
            ok, message, _row = self.expire(grant_no)
            return (dict(entry) if ok else None), message
        return entry, f"{self.ENTITY}已{action}"
