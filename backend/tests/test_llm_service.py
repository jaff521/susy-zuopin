"""LLM 法律合规研判服务与双轨离线重放单元测试 (LLM Compliance Diagnostic Service Tests)."""

import json
from unittest.mock import MagicMock, patch
import pytest
from pydantic import ValidationError

from app.schemas.compliance import (
    RiskLevel,
    ComplianceDefect,
    ComplianceScoreOverview,
    ComplianceReportSchema,
    ComplianceDiagnosticRequest,
)
from app.services.ocr_service import OCRResult, EURepInfo
from app.services.rag_service import RegulationMatch
from app.services.llm_service import LLMComplianceService, GB_T_45654_STAMP


@pytest.fixture
def mock_regulations():
    return [
        RegulationMatch(
            regulation_id="EU-GPSR-2023-988-ART9",
            title="欧盟通用产品安全法规 (GPSR) - 制造商与欧代基本义务",
            article="Regulation (EU) 2023/988, Article 9",
            category="general",
            content="Manufacturers shall indicate their EU Responsible Person postal address and email.",
            penalty_summary="海关扣押下架并处罚款",
            relevance_score=0.95
        ),
        RegulationMatch(
            regulation_id="EU-CE-TOY-2009-48-EC",
            title="欧盟玩具安全指令 - CE标志与警示语规范",
            article="Directive 2009/48/EC, Annex II",
            category="toys",
            content="Toys must bear CE marking and small parts choking warning for under 36 months.",
            penalty_summary="RAPEX预警全欧召回",
            relevance_score=0.92
        )
    ]


class TestComplianceSchemas:
    """数据契约完整性校验."""

    def test_schema_serialization_and_fields(self):
        defect = ComplianceDefect(
            id="DEF-001",
            defect_name="缺失欧代信息",
            risk_level=RiskLevel.HIGH,
            factual_finding="未见欧代地址",
            regulation_citation="GPSR Art 9",
            legal_consequence="查扣下架",
            rectification_before="无",
            rectification_after="印制欧代信息"
        )
        assert defect.risk_level == RiskLevel.HIGH
        assert defect.defect_name == "缺失欧代信息"
        assert defect.to_dict()["id"] == "DEF-001"

        overview = ComplianceScoreOverview(
            overall_score=50,
            risk_level=RiskLevel.HIGH,
            passed_checks=3,
            total_checks=5,
            high_risk_count=1,
            medium_risk_count=1,
            low_risk_count=0
        )
        assert overview.overall_score == 50

    def test_schema_score_boundary_validation(self):
        with pytest.raises(ValidationError):
            ComplianceScoreOverview(
                overall_score=105,
                risk_level=RiskLevel.HIGH,
            )

        with pytest.raises(ValidationError):
            ComplianceScoreOverview(
                overall_score=-1,
                risk_level=RiskLevel.HIGH,
            )


class TestLLMOfflineDiagnosticReplay:
    """双轨离线重放与路演防翻车特性验证."""

    def test_toy_defective_label_offline_diagnosis(self, mock_regulations):
        service = LLMComplianceService(api_key="sk-placeholder", model="qwen-max")
        ocr_result = OCRResult(
            raw_text="Plastic Toy Building Blocks. Made in China. Batch 202601",
            eu_rep_info=EURepInfo(found=False),
            ce_symbol_detected=False,
            warning_labels=[]
        )

        report = service.diagnose_compliance(
            task_id="TASK-TEST-001",
            product_name="儿童积木玩具",
            category="toys",
            ocr_result=ocr_result,
            regulations=mock_regulations,
            force_offline=True
        )

        assert isinstance(report, ComplianceReportSchema)
        assert report.score_overview.risk_level == RiskLevel.HIGH
        assert report.score_overview.overall_score < 60
        assert report.is_offline_replay is True
        assert report.processing_time_ms >= 0.0

        defect_ids = [d.id for d in report.defects]
        assert "DEF-GPSR-001" in defect_ids  # Missing EU REP
        assert "DEF-CE-002" in defect_ids    # Missing CE
        assert "DEF-TOY-003" in defect_ids   # Missing Choking Hazard

    def test_electronics_weee_offline_diagnosis(self, mock_regulations):
        service = LLMComplianceService(force_offline=True if hasattr(LLMComplianceService, "force_offline") else False)
        ocr_result = OCRResult(
            raw_text="USB Charging Cable 5V. CE. EU REP: Test GMBH, Berlin. info@test.eu",
            eu_rep_info=EURepInfo(found=True, name="Test GMBH", email="info@test.eu"),
            ce_symbol_detected=True,
            warning_labels=[]
        )

        report = service.diagnose_compliance(
            task_id="TASK-TEST-002",
            product_name="Type-C 充电线",
            category="electronics",
            ocr_result=ocr_result,
            regulations=mock_regulations,
            force_offline=True
        )

        assert report.score_overview.overall_score > 60
        defect_ids = [d.id for d in report.defects]
        assert "DEF-ELEC-004" in defect_ids  # Missing WEEE bin symbol

    def test_cosmetics_pao_offline_diagnosis(self, mock_regulations):
        service = LLMComplianceService()
        ocr_result = OCRResult(
            raw_text="Hydrating Face Cream 50ml. Ingredients: Aqua, Glycerin. CE. EU REP: EuroGmbH, Paris",
            eu_rep_info=EURepInfo(found=True, name="EuroGmbH"),
            ce_symbol_detected=True,
            warning_labels=[]
        )

        report = service.diagnose_compliance(
            task_id="TASK-TEST-003",
            product_name="玻尿酸面霜",
            category="cosmetics",
            ocr_result=ocr_result,
            regulations=mock_regulations,
            force_offline=True
        )

        defect_ids = [d.id for d in report.defects]
        assert "DEF-COSM-005" in defect_ids  # Missing PAO open jar symbol

    def test_toy_german_export_language_warning_medium_risk_75_score(self, mock_regulations):
        """Verifies the core competition demo scenario:
        Toy exported to Germany (DE) with English warnings only missing German warning.
        Must yield DEF-TOY-LANG-DE, risk_level MEDIUM, and score exactly 75!
        """
        service = LLMComplianceService()
        ocr_result = OCRResult(
            raw_text=(
                "SMART ROBOT TOY\n"
                "CE\n"
                "EU REP: Apex Compliance GmbH, Berlin, Germany\n"
                "WARNING: Not suitable for children under 3 years. Choking hazard - small parts.\n"
                "LOT: LOT-2026-X99"
            ),
            eu_rep_info=EURepInfo(found=True, name="Apex Compliance GmbH"),
            ce_symbol_detected=True,
            warning_labels=["Not suitable for children under 3 years", "Choking hazard - small parts"]
        )

        report = service.diagnose_compliance(
            product_name="智能早教益智玩具",
            category="toys",
            target_country="DE",
            ocr_result=ocr_result,
            regulations=mock_regulations,
            force_offline=True
        )

        assert report.score_overview.overall_score == 75
        assert report.score_overview.risk_level == RiskLevel.MEDIUM
        assert report.score_overview.medium_risk_count == 1
        assert report.score_overview.high_risk_count == 0
        defect_ids = [d.id for d in report.defects]
        assert "DEF-TOY-LANG-DE" in defect_ids
        de_defect = next(d for d in report.defects if d.id == "DEF-TOY-LANG-DE")
        assert "ACHTUNG" in de_defect.rectification_after.upper()

    def test_offline_mode_auto_fallback_with_string_ocr(self, mock_regulations):
        service = LLMComplianceService(api_key="")
        assert service.is_offline_available() is True

        report = service.diagnose_compliance(
            product_name="磁力拼装车",
            category="toys",
            ocr_text="Plastic Toy Car. Made in China.",
            regulations=mock_regulations,
        )

        assert report.is_offline_replay is True
        assert report.score_overview.risk_level == RiskLevel.HIGH
        assert len(report.defects) >= 2


class TestLLMOnlineAndCloudMock:
    """通义千问云端 API 调用与结构化解析测试."""

    def test_online_call_with_mocked_dashscope_json(self, mock_regulations):
        service = LLMComplianceService(api_key="sk-mocked-test-key-12345678", force_offline=False)

        mock_payload = {
            "score_overview": {
                "overall_score": 45,
                "risk_level": "HIGH",
                "passed_checks": 4,
                "total_checks": 10,
                "high_risk_count": 2,
                "medium_risk_count": 1,
                "low_risk_count": 0,
            },
            "defects": [
                {
                    "id": "DEF-001",
                    "defect_name": "缺少欧盟境内授权责任人(EU REP)联络信息",
                    "risk_level": "HIGH",
                    "factual_finding": "外包装仅印有中国制造商，未见欧代",
                    "regulation_citation": "GPSR Art 9",
                    "legal_consequence": "查扣下架",
                    "rectification_before": "Made in China",
                    "rectification_after": "增补欧代标签",
                }
            ],
            "cited_regulations": [
                {
                    "regulation_id": "EU-GPSR-2023-988-ART9",
                    "title": "GPSR Art 9",
                    "article": "Article 9",
                    "penalty_summary": "海关扣押",
                }
            ],
        }

        mock_response = f"```json\n{json.dumps(mock_payload, ensure_ascii=False)}\n```"

        with patch.object(service, "_call_dashscope_api", return_value=mock_response) as mock_api:
            report = service.diagnose_compliance(
                task_id="TASK-ONLINE-001",
                product_name="遥控玩具飞机",
                category="toys",
                ocr_text="RC Drone Toy, Made in China",
                regulations=mock_regulations,
            )

            mock_api.assert_called_once()
            assert report.is_offline_replay is False
            assert report.score_overview.overall_score == 45
            assert report.score_overview.risk_level == RiskLevel.HIGH
            assert len(report.defects) == 1
            assert report.task_id == "TASK-ONLINE-001"

    def test_online_exception_auto_fallback_to_offline(self, mock_regulations):
        service = LLMComplianceService(api_key="sk-mocked-key", force_offline=False)

        with patch.object(service, "_call_dashscope_api", side_effect=RuntimeError("DashScope timeout")):
            report = service.diagnose_compliance(
                task_id="TASK-ONLINE-FALLBACK",
                product_name="儿童积木",
                category="toys",
                ocr_text="Toy Blocks, Made in China",
                regulations=mock_regulations,
            )

            assert report.is_offline_replay is True
            assert report.product_name == "儿童积木"
            assert report.score_overview.risk_level == RiskLevel.HIGH


class TestLLMSafetyAndWatermark:
    """国家标准 AI 生成内容溯源标识与安全过滤验证."""

    def test_gbt_45654_watermark_present(self, mock_regulations):
        service = LLMComplianceService()
        ocr_result = OCRResult(raw_text="Product sample")
        report = service.diagnose_compliance(
            task_id="TASK-TEST-004",
            product_name="通用商品",
            category="general",
            ocr_result=ocr_result,
            regulations=mock_regulations,
            force_offline=True
        )
        assert "AI生成内容标识" in report.ai_attribution_stamp
        assert "出海易审" in report.ai_attribution_stamp
        assert report.ai_attribution_stamp == GB_T_45654_STAMP

    def test_api_key_leakage_redaction(self, mock_regulations):
        secret_key = "sk-dashscope-secret-sensitive-key-998877"
        service = LLMComplianceService(api_key=secret_key, force_offline=False)

        leaky_response = {
            "score_overview": {
                "overall_score": 60,
                "risk_level": "MEDIUM",
                "passed_checks": 5,
                "total_checks": 10,
                "high_risk_count": 0,
                "medium_risk_count": 1,
                "low_risk_count": 0,
            },
            "defects": [
                {
                    "id": "DEF-LEAK-01",
                    "defect_name": "诊断调试信息",
                    "risk_level": "MEDIUM",
                    "factual_finding": f"Diagnostics executed with key: {secret_key}",
                    "regulation_citation": "GPSR Art 9",
                    "legal_consequence": "Platform check",
                    "rectification_before": f"API KEY={secret_key}",
                    "rectification_after": "Clear",
                }
            ],
            "cited_regulations": [],
        }

        with patch.object(service, "_call_dashscope_api", return_value=json.dumps(leaky_response)):
            report = service.diagnose_compliance(
                product_name="保护隐私测试商品",
                category="general",
                ocr_text="Sample text",
            )

            dumped = report.to_json()
            assert secret_key not in dumped
            assert "[REDACTED_API_KEY]" in dumped

    def test_prompt_injection_defense_in_system_prompt(self):
        service = LLMComplianceService()
        sys_prompt = service._build_system_prompt()
        assert "Prompt Injection" in sys_prompt or "注入" in sys_prompt
        assert "API Key" in sys_prompt
        assert "JSON" in sys_prompt
