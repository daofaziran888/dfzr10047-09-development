"""输出契约领域服务：校验解析结果是否满足列集约定与行数下限，产出契约条目数据集。"""
from __future__ import annotations

from typing import Any

from app.services.base import BaseModuleService
from app.store import store


class OutputContractService(BaseModuleService):
    MODULE = "output_contract"
    ENTITY = "契约条目"
    OPERATION_TERM = "校验"
    LIST_FIELDS = ["契约编号", "关联批次", "输出列集合", "列顺序约定", "必填列", "行数下限", "契约校验结论", "校验时间"]
    REQUIRED_FIELDS = ["契约编号", "关联批次", "输出列集合"]
    STATUS_ORDER = ["待校验", "校验中", "已通过", "未通过"]
    ACTION_RULES = {"启动校验": "校验中", "确认通过": "已通过", "登记未通过": "未通过"}
    NEGATIVE_ACTIONS = ["登记未通过"]

    @staticmethod
    def _split(text: Any) -> list[str]:
        return [p.strip() for p in str(text or "").split(",") if p.strip()]

    def _find(self, contract_no: str) -> dict[str, Any] | None:
        for row in store.rows(self.MODULE):
            if row.get("契约编号") == contract_no:
                return row
        return None

    def validate_batch(self, contract_no: str, actual_columns: list[str],
                       actual_rows: int, check_time: str) -> tuple[bool, list[str], dict[str, Any] | None]:
        """执行契约校验：列集合、列顺序、必填列、行数下限逐项比对。

        校验前必须先确认坏行隔离与抽样复核都没有阻断该批次；
        任一前置阻断成立时契约直接判未通过并记录原因。
        """
        contract = self._find(contract_no)
        if contract is None:
            return False, [f"契约 {contract_no} 不存在"], None

        intake_batch = str(contract.get("关联批次") or "")
        failures: list[str] = []

        quarantine_blocked, quarantine_msg = self._quarantine_block(intake_batch)
        if quarantine_blocked:
            failures.append(quarantine_msg)

        review_blocked, review_msg = self._review_block(intake_batch)
        if review_blocked:
            failures.append(review_msg)

        expected = self._split(contract.get("输出列集合"))
        missing = [c for c in expected if c not in actual_columns]
        extra = [c for c in actual_columns if c not in expected]
        if missing:
            failures.append(f"缺少约定列 {missing}")
        if extra:
            failures.append(f"多出未约定列 {extra}")

        order = self._split(contract.get("列顺序约定"))
        if order and not missing and not extra:
            if actual_columns != order:
                failures.append(
                    f"列顺序与约定不一致，期望 {order} 实际 {actual_columns}"
                )

        mandatory = self._split(contract.get("必填列"))
        absent = [c for c in mandatory if c not in actual_columns]
        if absent:
            failures.append(f"必填列缺失 {absent}")

        min_rows_text = str(contract.get("行数下限") or "").strip()
        min_rows = int(min_rows_text) if min_rows_text.isdigit() else 0
        if actual_rows < min_rows:
            failures.append(f"实际行数 {actual_rows} 低于下限 {min_rows}")

        passed = not failures
        contract["契约校验结论"] = "通过" if passed else ";".join(failures)
        contract["校验时间"] = check_time
        contract["实际行数"] = str(actual_rows)
        contract["status"] = "已通过" if passed else "未通过"
        contract["pending"] = not passed
        contract["abnormal"] = not passed
        return passed, failures, dict(contract)

    def _quarantine_block(self, intake_batch: str) -> tuple[bool, str]:
        """未复核隔离行阻断契约。"""
        rows = store.rows("row_quarantine")
        # 批次记录里存的是关联投递批次，隔离行里存的是关联批次（同为投递批次编号）
        candidates = {intake_batch}
        for batch in store.rows("parse_batch"):
            if batch.get("批次记录编号") == intake_batch:
                candidates.add(str(batch.get("关联投递批次") or ""))
        pending = [
            r for r in rows
            if r.get("关联批次") in candidates
            and r.get("status") in ("已隔离", "复核中")
        ]
        if pending:
            return True, (
                f"存在 {len(pending)} 行隔离未复核"
                f"（行号 {[p.get('原始行号') for p in pending][:5]}），契约不得通过"
            )
        return False, ""

    def _review_block(self, intake_batch: str) -> tuple[bool, str]:
        """抽样复核驳回阻断契约。"""
        candidates = {intake_batch}
        for batch in store.rows("parse_batch"):
            if batch.get("批次记录编号") == intake_batch:
                candidates.add(str(batch.get("关联投递批次") or ""))
        for sample in store.rows("sample_review"):
            if sample.get("关联批次") in candidates and sample.get("status") == "已驳回":
                return True, (
                    f"抽样复核已驳回（{sample.get('复核结论')}），契约不得通过"
                )
        return False, ""

    def contract_result_for_deliver(self, contract_no: str) -> tuple[bool, str]:
        """结果投递前置：只有已通过的契约才允许创建投递记录。"""
        contract = self._find(contract_no)
        if contract is None:
            return False, f"契约 {contract_no} 不存在，不得投递"
        if contract.get("status") != "已通过":
            return False, (
                f"契约 {contract_no} 状态为 {contract.get('status')}，"
                f"未通过的契约不得进入结果投递"
            )
        return True, f"契约 {contract_no} 已通过，允许投递"

    def revalidate_after_reinstate(self, contract_no: str, actual_columns: list[str],
                                   actual_rows: int, check_time: str) -> tuple[bool, list[str], dict[str, Any] | None]:
        """隔离行回补后重新校验：已通过的契约不得被重复校验改写结论。"""
        contract = self._find(contract_no)
        if contract is None:
            return False, [f"契约 {contract_no} 不存在"], None
        if contract.get("status") == "已通过":
            return True, ["契约已通过，保留原校验结论不重复校验"], dict(contract)
        return self.validate_batch(contract_no, actual_columns, actual_rows, check_time)

    def pass_ratio(self) -> float:
        """契约通过率：已通过 / 全部契约条目。"""
        rows = store.rows(self.MODULE)
        if not rows:
            return 0.0
        return sum(1 for r in rows if r.get("status") == "已通过") / len(rows)

    def review_unit_provenance(self, contract_no: str,
                               batch_no: str = "") -> tuple[bool, str, dict[str, Any] | None]:
        """接收契约时复核实际取用的系数出处：每个约定列都要有已确认回执可查。"""
        from app.services import service_for

        share = service_for("unit_share")
        contract = self._find(contract_no)
        if share is None or contract is None:
            return False, f"契约 {contract_no} 不存在", None
        batch = batch_no or str(contract.get("关联批次") or "")
        check = share.check_contract_provenance(contract_no, batch)
        contract["系数出处复核"] = "通过" if check["ok"] else ";".join(check["failures"])
        contract["系数出处复核批次"] = batch
        return bool(check["ok"]), str(check["message"]), dict(contract)
