"""业务路由汇总：所有模块共用一套资源路由，由领域服务完成分派。

系数共享接口必须先于通用资源路由注册：通用路由含 `/api/{module}/{entry_id}`，
否则 `/api/unit-share/eligibility` 这类固定路径会被动态路径抢先匹配。
"""
from __future__ import annotations

from app.routers import resource, unit_share

ROUTERS = [unit_share, resource]
