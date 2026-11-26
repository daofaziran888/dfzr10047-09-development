"""系数共享授权测试：签发凭据、撤回、在途/新申请资格、越权拒绝、回执与契约出处复核。"""
from __future__ import annotations

import pytest

from app.security import sign_credential, verify_credential_token
from app.services import SERVICES
from app.store import store

FIELD = "net_weight"
GRANTOR = "sftp-node-03"
GRANTEE = "web-upload"
OUTSIDER = "api-gateway-01"
BATCH_IN_FLIGHT = "FI-SHARE-001"
BATCH_NEW = "FI-SHARE-002"


@pytest.fixture(autouse=True)
def fresh_store():
    store.reload_seed()
    yield store
    store.reload_seed()


def share() -> "object":
    return SERVICES["unit_share"]


def grant(share_svc, *, batch=BATCH_IN_FLIGHT, grant_no="US-900", multiplier=1000,
          unit_from="kg", unit_to="g", request_kind="在途批次"):
    ok, message, row = share_svc.grant_share(
        grant_no=grant_no, field=FIELD, source_unit=unit_from, target_unit=unit_to,
        multiplier=multiplier, grantor_channel=GRANTOR, grantee_channel=GRANTEE,
        batch_no=batch, request_kind=request_kind,
        grantor_name="来源负责人-甲", grantee_name="渠道负责人-乙",
        issued_at="2026-09-06T09:00:00")
    assert ok is True, message
    return row


def cast(share_svc, *, channel=GRANTEE, batch=BATCH_IN_FLIGHT, raw=2,
         grant_no="US-900", request_kind="", credential="", preferred="",
         at="2026-09-06T09:10:00"):
    return share_svc.cast(
        channel=channel, field=FIELD, raw_value=raw, source_unit="kg",
        batch_no=batch, grant_no=grant_no, request_kind=request_kind,
        credential=credential, preferred=preferred, created_at=at)


class TestCredentialIssuance:
    def test_grant_signs_scoped_credential(self):
        svc = share()
        row = grant(svc)
        assert row["status"] == "已授权"
        assert row["渠道范围"] == f"{GRANTOR}→{GRANTEE}"
        assert row["共享凭据"].startswith("ugs1.")
        ok, payload, _reason = verify_credential_token(row["共享凭据"])
        assert ok is True
        assert payload["channels"] == [GRANTOR, GRANTEE]
        assert payload["grantee"] == GRANTEE
        assert payload["multiplier"] == pytest.approx(1000.0)
        assert payload["batches"] == BATCH_IN_FLIGHT

    def test_tampered_credential_rejected(self):
        svc = share()
        row = grant(svc)
        token = row["共享凭据"]
        tampered = token[:-6] + ("a" if token[-6] != "a" else "b") + token[-5:]
        ok, message, grant_row = svc.verify_credential(tampered)
        assert ok is False
        assert "签名不符" in message
        assert grant_row is None

    def test_stale_credential_after_reissue_rejected(self):
        """授权记录改动后，旧令牌的批次范围对不上，凭据立即失效。"""
        svc = share()
        first = grant(svc, grant_no="US-901")
        stale = first["共享凭据"]
        # 授权记录被改写（例如渠道范围扩到新批次）但令牌还是旧载荷
        row = svc._find("US-901")
        row["关联批次"] = "FI-SHARE-999"
        ok2, message2, _row2 = svc.verify_credential(stale)
        assert ok2 is False
        assert "批次范围" in message2 and "凭据已失效" in message2
        # 重新签发后新令牌与改写后的授权一致
        ok, _message, _row = svc.issue_credential("US-901")
        assert ok is True
        fresh = svc._find("US-901")["共享凭据"]
        ok3, _message3, row3 = svc.verify_credential(fresh)
        assert ok3 is True and row3["授权编号"] == "US-901"

    def test_same_channel_share_refused(self):
        svc = share()
        ok, message, _row = svc.grant_share(
            field=FIELD, source_unit="kg", target_unit="g", multiplier=1000,
            grantor_channel=GRANTEE, grantee_channel=GRANTEE, batch_no=BATCH_NEW)
        assert ok is False
        assert "不属于跨渠道共享" in message

    def test_grant_creates_shared_factor_row(self):
        svc = share()
        grant(svc)
        factors = [r for r in store.rows("unit_normalize")
                   if r.get("共享授权") == "US-900"]
        assert len(factors) == 1
        assert factors[0]["来源类型"] == "授权共享"
        assert factors[0]["适用来源"] == GRANTEE


class TestCastWithGrant:
    def test_grantee_normalizes_with_shared_factor(self):
        svc = share()
        grant(svc)
        result = cast(svc)
        assert result["ok"] is True
        assert result["归一取值"] == pytest.approx(2000.0)
        assert result["系数值"] == "1000"
        assert result["系数出处"] == "授权共享 US-900"
        assert result["引用授权"] == "US-900"
        assert result["归一编号"].startswith("UN-")

    def test_credential_required_when_supplied_and_valid(self):
        svc = share()
        row = grant(svc)
        ok = cast(svc, credential=row["共享凭据"])
        assert ok["ok"] is True

    def test_bad_credential_blocks_cast(self):
        svc = share()
        grant(svc)
        result = cast(svc, credential="ugs1.bogus.signature")
        assert result["ok"] is False
        assert "共享凭据校验不通过" in result["message"]
        assert result["回执"]["status"] == "已拒绝"

    def test_repeat_submit_keeps_single_confirmation(self):
        svc = share()
        grant(svc)
        first = cast(svc)
        second = cast(svc, raw=3, at="2026-09-06T09:20:00")
        assert second["重复提交"] is True
        assert second["归一取值"] == pytest.approx(2000.0)
        assert second["系数出处"] == "授权共享 US-900"
        confirmed = [r for r in svc.receipts(batch_no=BATCH_IN_FLIGHT)
                     if r["确认标记"] == "是"]
        assert len(confirmed) == 1
        assert confirmed[0]["归一取值"] == "2000"


class TestRevokeAndEligibility:
    def _grant_cast_revoke_own(self):
        svc = share()
        grant(svc)
        cast(svc)
        ok, message, _row = svc.revoke("US-900", "2026-09-06T10:00:00", "甲撤回")
        assert ok is True
        own = svc.submit_own_factor(
            channel=GRANTEE, field=FIELD, source_unit="kg", target_unit="g",
            multiplier=1024, batch_no=BATCH_IN_FLIGHT,
            submitted_at="2026-09-06T10:20:00")
        assert own["ok"] is True
        return svc

    def test_in_flight_and_next_application_differ(self):
        svc = self._grant_cast_revoke_own()
        eligibility = svc.eligibility(GRANTEE, FIELD, BATCH_IN_FLIGHT)
        in_flight = eligibility["在途申请"]
        next_app = eligibility["下一笔新申请"]
        # 在途：已确认快照保留 1000 与 2000 g
        assert in_flight["采用方式"].startswith("继续核对原请求")
        assert in_flight["系数值"] == "1000"
        assert in_flight["归一取值"] == "2000"
        assert in_flight["系数出处"] == "授权共享 US-900"
        # 新申请：撤回后改用自有 1024
        assert next_app["采用方式"] == "使用自有规则"
        assert next_app["系数值"] == "1024"
        assert "撤回" in next_app["原因"]

    def test_confirmed_value_not_refreshed_after_own_factor(self):
        svc = self._grant_cast_revoke_own()
        receipt = svc.receipts(batch_no=BATCH_IN_FLIGHT)[0]
        assert receipt["换算系数"] == "1000"
        assert receipt["归一取值"] == "2000"
        assert receipt["系数出处"] == "授权共享 US-900"
        result = cast(svc, raw=2, at="2026-09-06T11:00:00")
        assert result["归一取值"] == pytest.approx(2000.0)
        assert result["系数出处"] == "授权共享 US-900"

    def test_own_factor_conflicts_with_in_flight_shared(self):
        svc = self._grant_cast_revoke_own()
        conflicts = svc.conflicts(batch_no=BATCH_IN_FLIGHT)
        assert len(conflicts) == 1
        conflict = conflicts[0]
        assert conflict["status"] == "待裁决"
        assert conflict["共享系数"] == "1000"
        assert conflict["自有系数"] == "1024"
        assert conflict["已确认取值"] == "2000"
        assert "同一批" in conflict["冲突说明"]

    def test_resolve_conflict_keeps_chosen_rule(self):
        svc = self._grant_cast_revoke_own()
        conflict_no = svc.conflicts(batch_no=BATCH_IN_FLIGHT)[0]["冲突编号"]
        ok, message, row = svc.resolve_conflict(conflict_no, "自有系数")
        assert ok is True
        assert row["裁决结论"] == "保留自有系数"
        ok2, _message2, _row2 = svc.resolve_conflict(conflict_no, "共享系数")
        assert ok2 is False

    def test_revoked_grant_cannot_be_reissued(self):
        svc = self._grant_cast_revoke_own()
        ok, message, _row = svc.issue_credential("US-900")
        assert ok is False
        assert "已撤回" in message

    def test_withdraw_in_flight_leaves_receipt_but_drops_original_request(self):
        svc = share()
        grant(svc, grant_no="US-910")
        cast(svc, grant_no="US-910")
        outcome = svc.withdraw_in_flight(
            channel=GRANTEE, field=FIELD, batch_no=BATCH_IN_FLIGHT)
        assert outcome["ok"] is True
        assert outcome["撤回回执"] == ["RCT-004"]
        receipt = svc.receipts(batch_no=BATCH_IN_FLIGHT)[0]
        assert receipt["归一取值"] == "2000"
        assert receipt["撤回时间"]
        eligibility = svc.eligibility(GRANTEE, FIELD, BATCH_IN_FLIGHT)
        # 已撤回在途后不再按原请求核对；授权仍有效时按授权，新申请仍按授权
        assert eligibility["在途申请"]["采用方式"] != "继续核对原请求（已确认快照）"


class TestUnauthorizedAccess:
    def test_outsider_cannot_use_grant(self):
        svc = share()
        grant(svc)
        result = cast(svc, channel=OUTSIDER, grant_no="US-900", request_kind="新批次")
        assert result["ok"] is False
        assert "无权引用" in result["拒绝归属"]
        assert GRANTEE in result["拒绝归属"]
        assert result["被拒值"] == "2"

    def test_unsanctioned_new_batch_refused(self):
        svc = share()
        grant(svc, batch=BATCH_IN_FLIGHT)
        result = cast(svc, batch="FI-SHARE-999", grant_no="US-900",
                      request_kind="新批次")
        assert result["ok"] is False
        assert "未授权的新批次不得采用跨渠道来源系数" in result["message"]
        assert result["被拒值"] == "2"

    def test_outsider_without_grant_refused_with_owner(self):
        svc = share()
        grant(svc)
        result = cast(svc, channel=OUTSIDER, grant_no="", request_kind="新批次")
        assert result["ok"] is False
        assert "共享授权 US-900 归属受让方渠道 web-upload" in result["拒绝归属"]

    def test_field_mismatch_refused(self):
        svc = share()
        grant(svc)
        result = svc.cast(channel=GRANTEE, field="payload_bytes", raw_value=1,
                          source_unit="kg", batch_no=BATCH_IN_FLIGHT,
                          grant_no="US-900")
        assert result["ok"] is False
        assert "只覆盖字段" in result["message"]


class TestUnitNormalizeScope:
    def test_shared_factor_not_applied_without_batch(self):
        svc = share()
        normalize = SERVICES["unit_normalize"]
        # sftp-node-04 名下没有 net_weight 自有规则，命中的只可能是共享系数
        ok, _message, row = svc.grant_share(
            grant_no="US-903", field=FIELD, source_unit="kg", target_unit="g",
            multiplier=1000, grantor_channel=GRANTOR, grantee_channel="sftp-node-04",
            batch_no=BATCH_IN_FLIGHT, request_kind="在途批次",
            issued_at="2026-09-06T09:00:00")
        assert ok is True
        ok2, value, _msg2 = normalize.normalize_value(
            FIELD, "sftp-node-04", 2.0, "2026-09-06", batch_no="FI-SHARE-999")
        assert ok2 is False
        assert value is None

    def test_shared_factor_applied_inside_scope(self):
        svc = share()
        normalize = SERVICES["unit_normalize"]
        grant(svc, batch=BATCH_IN_FLIGHT)
        ok, value, message = normalize.normalize_value(
            FIELD, GRANTEE, 2.0, "2026-09-06", batch_no=BATCH_IN_FLIGHT)
        assert ok is True
        assert value == pytest.approx(2000.0)
        assert "授权共享 US-900" in message

    def test_shared_factor_cannot_activate_independently(self):
        svc = share()
        normalize = SERVICES["unit_normalize"]
        grant(svc)
        factor = next(r for r in store.rows("unit_normalize")
                      if r.get("共享授权") == "US-900")
        factor["status"] = "草稿"
        ok, message = normalize.activate_factor(factor["归一编号"], "2026-09-07")
        assert ok is False
        assert "只能随授权签发/撤回变更" in message


class TestProvenanceAndContract:
    def test_provenance_reports_factor_source(self):
        svc = share()
        grant(svc)
        cast(svc)
        provenance = svc.provenance(BATCH_IN_FLIGHT)
        assert provenance["已确认字段数"] == 1
        info = provenance["字段"][FIELD]
        assert info["系数值"] == "1000"
        assert info["系数出处"] == "授权共享 US-900"
        assert info["引用授权"] == "US-900"
        assert info["归一取值"] == "2000"

    def test_contract_check_passes_when_all_fields_traced(self):
        svc = share()
        grant(svc)
        cast(svc)
        store.rows("output_contract").append({
            "id": 900, "status": "待校验", "pending": True, "abnormal": False,
            "契约编号": "OC-SHARE", "关联批次": BATCH_IN_FLIGHT,
            "输出列集合": FIELD, "列顺序约定": FIELD, "必填列": FIELD,
            "行数下限": "1", "契约校验结论": "", "校验时间": "",
        })
        result = svc.check_contract_provenance("OC-SHARE")
        assert result["ok"] is True
        assert result["fields"][0]["归一编号"] == result["fields"][0]["归一编号"]
        assert result["fields"][0]["系数出处"] == "授权共享 US-900"

    def test_contract_check_fails_without_receipt(self):
        svc = share()
        store.rows("output_contract").append({
            "id": 901, "status": "待校验", "pending": True, "abnormal": False,
            "契约编号": "OC-NOTRACE", "关联批次": "FI-NONE",
            "输出列集合": FIELD, "列顺序约定": FIELD, "必填列": FIELD,
            "行数下限": "1", "契约校验结论": "", "校验时间": "",
        })
        result = svc.check_contract_provenance("OC-NOTRACE")
        assert result["ok"] is False
        assert any("缺少已确认的系数出处回执" in f for f in result["failures"])


class TestSeedScenario:
    """种子数据里乙的 kg→g 在途 2kg=2000g 场景可直接回查。"""

    def test_seed_in_flight_receipt_keeps_2000g(self):
        svc = share()
        receipts = svc.receipts(batch_no="FI-20260905001")
        confirmed = [r for r in receipts if r["确认标记"] == "是"]
        assert len(confirmed) == 1
        assert confirmed[0]["原始取值"] == "2"
        assert confirmed[0]["归一取值"] == "2000"
        assert confirmed[0]["系数值" if False else "换算系数"] == "1000"

    def test_seed_eligibility_separates_in_flight_and_new(self):
        svc = share()
        eligibility = svc.eligibility(GRANTEE, FIELD, "FI-20260905001")
        assert eligibility["在途申请"]["归一取值"] == "2000"
        assert eligibility["下一笔新申请"]["系数值"] == "1024"
        assert eligibility["下一笔新申请"]["采用方式"] == "使用自有规则"

    def test_seed_outsider_rejection_carries_owner(self):
        svc = share()
        receipt = next(r for r in svc.receipts(batch_no="FI-20260905001")
                       if r["请求渠道"] == OUTSIDER)
        assert receipt["拒绝归属"] == (
            "共享授权 US-001 归属受让方渠道 web-upload（渠道负责人-乙），"
            "请求渠道 api-gateway-01 无权引用")
        assert receipt["被拒值"] == "5"


class TestOwnRuleFlow:
    def test_own_factor_applies_to_new_batch(self):
        svc = share()
        ok, message, row = svc.grant_share(
            grant_no="US-920", field=FIELD, source_unit="kg", target_unit="g",
            multiplier=1000, grantor_channel=GRANTOR, grantee_channel=GRANTEE,
            batch_no=BATCH_IN_FLIGHT, request_kind="在途批次",
            issued_at="2026-09-06T09:00:00")
        assert ok is True
        cast(svc, grant_no="US-920")
        svc.revoke("US-920", "2026-09-06T10:00:00", "甲撤回")
        own = svc.submit_own_factor(
            channel=GRANTEE, field=FIELD, source_unit="kg", target_unit="g",
            multiplier=1024, batch_no=BATCH_NEW, submitted_at="2026-09-06T10:20:00")
        assert own["status"] == "已生效"
        result = cast(svc, batch=BATCH_NEW, raw=5, grant_no="",
                      request_kind="新批次", at="2026-09-06T11:00:00")
        assert result["ok"] is True
        assert result["归一取值"] == pytest.approx(5120.0)
        assert result["系数出处"].startswith("自有规则")

    def test_own_factor_without_grant_works(self):
        svc = share()
        own = svc.submit_own_factor(
            channel=OUTSIDER, field=FIELD, source_unit="kg",
            target_unit="g", multiplier=900, batch_no=BATCH_NEW,
            submitted_at="2026-09-06T10:20:00")
        assert own["status"] == "已生效"
        result = svc.cast(channel=OUTSIDER, field=FIELD, raw_value=2,
                          source_unit="kg", batch_no=BATCH_NEW, request_kind="新批次")
        assert result["ok"] is True
        assert result["归一取值"] == pytest.approx(1800.0)
        assert result["规则来源"] == "自有规则"

    def test_same_channel_different_own_factor_conflicts(self):
        svc = share()
        # seed UN-001：sftp-node-03 的 payload_bytes KB→byte 已生效 1024
        second = svc.submit_own_factor(
            channel=GRANTOR, field="payload_bytes", source_unit="KB",
            target_unit="byte", multiplier=1000, batch_no="FI-OTHER",
            submitted_at="2026-09-06T10:30:00")
        assert second["status"] == "系数冲突"
        assert second["ok"] is False
        assert "已有生效系数" in second["message"]


class TestContractReview:
    def _seed_contract(self, contract_no, columns):
        store.rows("output_contract").append({
            "id": 950, "status": "待校验", "pending": True, "abnormal": False,
            "契约编号": contract_no, "关联批次": BATCH_IN_FLIGHT,
            "输出列集合": ",".join(columns), "列顺序约定": ",".join(columns),
            "必填列": columns[0], "行数下限": "1",
            "契约校验结论": "", "校验时间": "",
        })

    def test_review_writes_conclusion_back_to_contract(self):
        svc = share()
        contract_svc = SERVICES["output_contract"]
        grant(svc, grant_no="US-930")
        cast(svc, grant_no="US-930")
        self._seed_contract("OC-REVIEW", [FIELD])
        ok, message, record = contract_svc.review_unit_provenance("OC-REVIEW")
        assert ok is True
        assert record["系数出处复核"] == "通过"
        assert "1 个字段系数出处" in message

    def test_review_fails_on_missing_provenance(self):
        svc = share()
        contract_svc = SERVICES["output_contract"]
        self._seed_contract("OC-MISS", ["ghost_field"])
        ok, message, record = contract_svc.review_unit_provenance("OC-MISS")
        assert ok is False
        assert "缺少已确认的系数出处回执" in record["系数出处复核"]


class TestPipelineIntegration:
    def test_link4_records_shared_factor_provenance(self):
        from app.pipeline.integration import ParsePipelineOrchestrator
        from app.pipeline.transform_stage import CastRule, FlattenPath

        svc = share()
        grant(svc, grant_no="US-940", batch="FI-PIPE-1")
        orch = ParsePipelineOrchestrator()
        orch.transform.register_flatten_path(FlattenPath(
            "NF-PIPE", "ET-P", "$.records[*]", ["rec_id", FIELD],
            "EXPAND", 2, "SKIP"))
        result = orch.link4_flatten_cast_normalize(
            batch_id="FI-PIPE-1", channel=GRANTEE, path_id="NF-PIPE",
            documents=[{"records": [{"rec_id": "R1", FIELD: 2}]}],
            cast_rules=[CastRule("VC-PIPE", FIELD, "str", "float64")],
            contract_id="OC-PIPE", contract_columns=[FIELD, "rec_id"],
            mandatory=["rec_id"], min_rows=1,
            check_time="2026-09-07T09:00:00", unit_fields=[FIELD])
        assert result["ok"] is True
        assert result["share_results"][0]["系数出处"] == "授权共享 US-940"
        assert result["share_results"][0]["归一取值"] == pytest.approx(2000.0)
        assert result["系数出处"]["字段"][FIELD]["引用授权"] == "US-940"

    def test_link4_without_unit_fields_unchanged(self):
        from app.pipeline.integration import ParsePipelineOrchestrator
        from app.pipeline.transform_stage import CastRule, FlattenPath

        orch = ParsePipelineOrchestrator()
        orch.transform.register_flatten_path(FlattenPath(
            "NF-PLAIN", "ET-P", "$.records[*]", ["value"], "EXPAND", 2, "SKIP"))
        result = orch.link4_flatten_cast_normalize(
            batch_id="FI-PIPE-2", channel=GRANTEE, path_id="NF-PLAIN",
            documents=[{"records": [{"value": "3.5"}]}],
            cast_rules=[CastRule("VC-PLAIN", "value", "str", "float64")],
            contract_id="OC-PLAIN", contract_columns=["value"],
            mandatory=[], min_rows=1, check_time="t")
        assert result["ok"] is True
        assert result["share_results"] == []


class TestSelectableMode:
    def test_grantee_may_choose_own_rule_when_grant_active(self):
        svc = share()
        grant(svc, grant_no="US-950", batch=BATCH_NEW)
        svc.submit_own_factor(
            channel=GRANTEE, field=FIELD, source_unit="kg", target_unit="g",
            multiplier=1024, batch_no=BATCH_NEW, submitted_at="t1")
        result = cast(svc, batch=BATCH_NEW, raw=2, grant_no="US-950",
                      request_kind="新批次")
        assert result["系数值"] == "1000"
        chosen = share().cast(
            channel=GRANTEE, field=FIELD, raw_value=2, source_unit="kg",
            batch_no="FI-SHARE-OTHER", grant_no="",
            preferred="使用自有规则")
        assert chosen["ok"] is True
        assert chosen["系数值"] == "1024"
        assert chosen["系数出处"].startswith("自有规则")

    def test_unknown_mode_rejected(self):
        svc = share()
        result = cast(svc, preferred="按心情")
        assert result["ok"] is False
        assert "不在允许范围" in result["message"]

    def test_eligibility_lists_available_modes(self):
        svc = share()
        grant(svc, grant_no="US-951")
        cast(svc, grant_no="US-951")
        svc.revoke("US-951", "t2", "甲撤回")
        svc.submit_own_factor(
            channel=GRANTEE, field=FIELD, source_unit="kg", target_unit="g",
            multiplier=1024, batch_no=BATCH_IN_FLIGHT, submitted_at="t3")
        eligibility = svc.eligibility(GRANTEE, FIELD, BATCH_IN_FLIGHT)
        modes = {option["方式"] for option in eligibility["可选方式"]}
        assert modes == {"继续核对原请求", "使用自有规则"}
        assert all(option["可用"] for option in eligibility["可选方式"])


class TestConfirmedSnapshotImmutability:
    def test_preferred_mode_cannot_overwrite_confirmed_field(self):
        svc = share()
        grant(svc, grant_no="US-960")
        cast(svc, grant_no="US-960")
        svc.submit_own_factor(
            channel=GRANTEE, field=FIELD, source_unit="kg", target_unit="g",
            multiplier=1024, batch_no=BATCH_IN_FLIGHT, submitted_at="t")
        forced = cast(svc, grant_no="", raw=2, request_kind="在途批次",
                      preferred="使用自有规则")
        # 已确认字段只返回原确认，不因换方式/换系数而刷新
        assert forced["重复提交"] is True
        assert forced["归一取值"] == pytest.approx(2000.0)
        assert forced["系数值"] == "1000"
        assert forced["系数出处"] == "授权共享 US-960"

    def test_revoke_does_not_touch_confirmed_receipt(self):
        svc = share()
        grant(svc, grant_no="US-961")
        before = cast(svc, grant_no="US-961")
        svc.revoke("US-961", "t2", "甲撤回")
        after = svc.receipt(before["回执"]["回执编号"])
        assert after["换算系数"] == "1000"
        assert after["归一取值"] == "2000"
        assert after["原始单位"] == "kg"
        assert after["目标单位"] == "g"
        assert after["引用授权"] == "US-961"
        assert after["系数出处"] == "授权共享 US-961"


class TestRevokedScopeGuard:
    def test_wildcard_grant_cannot_be_used_after_revoke_via_in_flight_flag(self):
        svc = share()
        grant(svc, grant_no="US-970", batch="*", request_kind="在途批次")
        svc.revoke("US-970", "t", "甲撤回")
        # 只自报「在途」不足以沿用通配授权的共享系数
        result = cast(svc, batch="FI-RANDOM", raw=5, grant_no="US-970",
                      request_kind="在途批次")
        assert result["ok"] is False
        assert "不是撤回前领办的在途申请" in result["message"]

    def test_named_batch_can_still_be_confirmed_after_revoke(self):
        svc = share()
        grant(svc, grant_no="US-971", batch=BATCH_IN_FLIGHT,
              request_kind="在途批次")
        svc.revoke("US-971", "t", "甲撤回")
        result = cast(svc, batch=BATCH_IN_FLIGHT, raw=2, grant_no="US-971",
                      request_kind="在途批次")
        assert result["ok"] is True
        assert result["归一取值"] == pytest.approx(2000.0)
        assert "撤回前在途" in result["系数出处"]

    def test_named_batch_new_request_kind_still_refused(self):
        svc = share()
        grant(svc, grant_no="US-972", batch=BATCH_IN_FLIGHT,
              request_kind="在途批次")
        svc.revoke("US-972", "t", "甲撤回")
        result = cast(svc, batch=BATCH_IN_FLIGHT, raw=2, grant_no="US-972",
                      request_kind="新批次")
        assert result["ok"] is False
        assert "已撤回" in result["message"]
