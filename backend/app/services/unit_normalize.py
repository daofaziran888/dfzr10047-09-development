"""单位归一领域服务：按来源维护字段单位换算系数并消除系数冲突，产出归一系数数据集。

共享系数由 `unit_share` 授权后物化到本表（来源类型=授权共享），因此这里的启效/归一
都要尊重授权范围和批次，避免未授权的新批次命中跨渠道来源系数。
"""
from __future__ import annotations

from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class UnitNormalizeService(BaseModuleService):
    MODULE = "unit_normalize"
    ENTITY = "归一系数"
    OPERATION_TERM = "标准化"
    LIST_FIELDS = ["归一编号", "字段名称", "原始单位", "目标单位", "换算系数", "适用来源", "生效起日", "最近命中"]
    REQUIRED_FIELDS = ["归一编号", "字段名称", "原始单位"]
    STATUS_ORDER = ["草稿", "已生效", "已停用", "系数冲突"]
    ACTION_RULES = {"启效系数": "已生效", "停用系数": "已停用", "登记冲突": "系数冲突"}
    NEGATIVE_ACTIONS = ["停用系数", "登记冲突"]

    def _find(self, factor_no: str) -> dict[str, Any] | None:
        for row in store.rows(self.MODULE):
            if row.get("归一编号") == factor_no:
                return row
        return None

    @staticmethod
    def _float(value: Any) -> float:
        try:
            return float(str(value).strip())
        except (ValueError, AttributeError):
            return 0.0

    def activate_factor(self, factor_no: str, effective_from: str) -> tuple[bool, str]:
        """启效系数：同字段同来源同原始单位已有不同系数时判定冲突，不得直接生效。"""
        target = self._find(factor_no)
        if target is None:
            return False, f"归一系数 {factor_no} 不存在"
        if target.get("status") == "已生效":
            return False, f"归一系数 {factor_no} 已处于生效状态"
        if target.get("来源类型") == "授权共享":
            return False, (
                f"归一系数 {factor_no} 由共享授权 {target.get('共享授权')} 物化，"
                f"只能随授权签发/撤回变更，不能单独启效"
            )

        field = str(target.get("字段名称") or "")
        source = str(target.get("适用来源") or "")
        source_unit = str(target.get("原始单位") or "")
        multiplier = self._float(target.get("换算系数"))

        conflict = None
        for row in store.rows(self.MODULE):
            if row is target or row.get("status") != "已生效":
                continue
            # 共享授权系数与自有规则是两条来源规则，由共享冲突流程单独裁决
            if str(row.get("来源类型") or "自有规则") != "自有规则":
                continue
            if (str(row.get("字段名称")) == field
                    and str(row.get("适用来源")) == source
                    and str(row.get("原始单位")) == source_unit
                    and abs(self._float(row.get("换算系数")) - multiplier) > 1e-9):
                conflict = row
                break

        if conflict is not None:
            target["status"] = "系数冲突"
            target["pending"] = True
            target["abnormal"] = True
            target["冲突系数编号"] = conflict.get("归一编号")
            conflict["status"] = "系数冲突"
            conflict["pending"] = True
            conflict["abnormal"] = True
            conflict["冲突系数编号"] = factor_no
            return False, (
                f"字段 {field} 在来源 {source} 下 {source_unit} 已生效系数 "
                f"{conflict.get('换算系数')}（{conflict.get('归一编号')}），"
                f"与新系数 {multiplier} 冲突，两条均标记系数冲突待裁决"
            )

        target["status"] = "已生效"
        target["pending"] = False
        target["abnormal"] = False
        target["生效起日"] = effective_from
        return True, (
            f"归一系数 {factor_no} 已生效：{field} {source_unit}→"
            f"{target.get('目标单位')} ×{multiplier}（来源 {source}）"
        )

    def resolve_conflict(self, keep_factor_no: str) -> tuple[bool, str]:
        """裁决系数冲突：保留一条生效，另一条停用，归一才可继续。"""
        keep = self._find(keep_factor_no)
        if keep is None:
            return False, f"归一系数 {keep_factor_no} 不存在"
        if keep.get("status") != "系数冲突":
            return False, f"归一系数 {keep_factor_no} 不处于冲突状态，无需裁决"

        rival_no = str(keep.get("冲突系数编号") or "")
        rival = self._find(rival_no) if rival_no else None

        keep["status"] = "已生效"
        keep["pending"] = False
        keep["abnormal"] = False
        keep["冲突系数编号"] = ""
        if rival is not None:
            rival["status"] = "已停用"
            rival["pending"] = False
            rival["abnormal"] = False
            rival["冲突系数编号"] = ""
            rival["停用原因"] = f"与 {keep_factor_no} 冲突，裁决后停用"
        return True, (
            f"冲突已裁决：保留 {keep_factor_no}（系数 {keep.get('换算系数')}）生效，"
            f"{rival_no or '无对手条目'} 停用"
        )

    @staticmethod
    def _batch_in_scope(row: dict[str, Any], batch_no: str) -> bool:
        """共享系数只在授权的批次范围内可用；通配或未限定批次才算全程可用。"""
        text = str(row.get("关联批次") or "").strip()
        if not text or text == "*":
            return True
        if not batch_no:
            return False
        return str(batch_no) in [p.strip() for p in text.split(",") if p.strip()]

    def normalize_value(self, field: str, channel: str, raw_value: float,
                        hit_date: str,
                        batch_no: str = "") -> tuple[bool, float | None, str]:
        """按来源查生效系数执行归一；冲突或缺系数时拒绝归一并保留原始取值。

        共享系数还要满足批次范围：未授权的新批次不会被跨渠道来源系数命中。
        """
        candidates = [
            r for r in store.rows(self.MODULE)
            if str(r.get("字段名称")) == field
            and str(r.get("适用来源")) in (channel, "*")
            and (
                str(r.get("来源类型") or "自有规则") != "授权共享"
                or (batch_no and self._batch_in_scope(r, batch_no))
            )
        ]
        conflicted = [
            r for r in candidates
            if r.get("status") == "系数冲突"
            and str(r.get("来源类型") or "自有规则") == "自有规则"
        ]
        if conflicted:
            return False, None, (
                f"字段 {field} 在来源 {channel} 存在系数冲突 "
                f"{[r.get('归一编号') for r in conflicted]}，拒绝归一并保留原始取值 {raw_value}"
            )

        active = [r for r in candidates if r.get("status") == "已生效"]
        if not active:
            return False, None, (
                f"字段 {field} 在来源 {channel} 没有已生效的归一系数，保留原始取值"
            )
        # 生效起日不晚于命中日期的最新一条
        eligible = [
            r for r in active
            if str(r.get("生效起日") or "") and str(r.get("生效起日")) <= hit_date
        ]
        chosen = max(eligible or active, key=lambda r: str(r.get("生效起日") or ""))
        multiplier = self._float(chosen.get("换算系数"))
        chosen["最近命中"] = hit_date
        source_label = str(
            chosen.get("系数出处")
            or ("授权共享 " + str(chosen.get("共享授权")) if chosen.get("共享授权") else "")
        )
        return True, round(raw_value * multiplier, 6), (
            f"字段 {field} 按系数 {chosen.get('归一编号')} ×{multiplier} 归一为 "
            f"{round(raw_value * multiplier, 6)} {chosen.get('目标单位')}"
            + (f"（系数出处 {source_label}）" if source_label else "")
        )

    def conflicts(self) -> list[dict[str, Any]]:
        """列出全部系数冲突条目，供治理看板消费。"""
        return [
            {
                "归一编号": r.get("归一编号"),
                "字段名称": r.get("字段名称"),
                "适用来源": r.get("适用来源"),
                "原始单位": r.get("原始单位"),
                "换算系数": r.get("换算系数"),
                "来源类型": r.get("来源类型") or "自有规则",
                "共享授权": r.get("共享授权") or "",
                "冲突系数编号": r.get("冲突系数编号"),
            }
            for r in store.rows(self.MODULE)
            if r.get("status") == "系数冲突"
        ]
