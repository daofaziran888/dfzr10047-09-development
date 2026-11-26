"""内存数据仓库：给每个业务模块准备一份可筛选、可流转的示例数据。

真实项目里这里会换成数据库访问层；当前实现只依赖标准库，保证克隆下来就能起。
"""
from __future__ import annotations

from typing import Any

from app.seed import SEED_ROWS
from app.security import build_credential_payload, sign_credential


RECEIPT_TABLE = "unit_share_receipt"
CONFLICT_TABLE = "unit_share_conflict"

# 这两张是共享授权的回执/冲突明细表，不是独立业务模块：不进运营概览与模块列表。
AUXILIARY_TABLES = frozenset({RECEIPT_TABLE, CONFLICT_TABLE})


def _with_signed_credentials(
    tables: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    """种子里的共享授权只写业务字段，凭据统一在这里由服务端补签。

    这样示例数据不会出现「有授权但没凭据」的半成品，也让签名逻辑只有一处。
    """
    for row in tables.get("unit_share", []):
        if row.get("共享凭据"):
            continue
        try:
            multiplier = float(str(row.get("换算系数")).strip())
        except (TypeError, ValueError):
            continue
        row["共享凭据"] = sign_credential(build_credential_payload(
            grant_no=row.get("授权编号"),
            field=row.get("字段名称"),
            source_unit=row.get("原始单位"),
            target_unit=row.get("目标单位"),
            multiplier=multiplier,
            grantor=row.get("授予方渠道"),
            grantee=row.get("受让方渠道"),
            batches=row.get("关联批次"),
            request_kind=row.get("申请类别"),
            issued_at=row.get("签发时间"),
        ))
    return tables


class Store:
    def __init__(self) -> None:
        self._tables: dict[str, list[dict[str, Any]]] = _with_signed_credentials({
            name: [dict(row) for row in rows] for name, rows in SEED_ROWS.items()
        })

    def module_names(self) -> list[str]:
        """业务模块列表，回执与冲突明细表只随共享授权页展示，不单列为模块。"""
        return sorted(
            name for name in self._tables if name not in AUXILIARY_TABLES
        )

    def reload_seed(self) -> None:
        """把全部表恢复成 seed.py 的初始示例数据，供本地重置与测试隔离使用。"""
        self._tables = _with_signed_credentials({
            name: [dict(row) for row in rows] for name, rows in SEED_ROWS.items()
        })

    def rows(self, module: str) -> list[dict[str, Any]]:
        return self._tables.setdefault(module, [])

    def find(self, module: str, entry_id: int) -> dict[str, Any] | None:
        for row in self.rows(module):
            if int(row.get("id", 0)) == entry_id:
                return row
        return None

    def overview(self) -> dict[str, object]:
        modules: list[dict[str, object]] = []
        for name in self.module_names():
            rows = self.rows(name)
            modules.append({
                "name": name,
                "created": len(rows),
                "pending": sum(1 for row in rows if row.get("pending")),
                "abnormal": sum(1 for row in rows if row.get("abnormal")),
            })
        cards = [
            {"label": "业务模块", "value": len(modules)},
            {"label": "今日新增", "value": sum(int(item["created"]) for item in modules)},
            {"label": "待处理", "value": sum(int(item["pending"]) for item in modules)},
            {"label": "异常量", "value": sum(int(item["abnormal"]) for item in modules)},
        ]
        return {"cards": cards, "modules": modules}


store = Store()
