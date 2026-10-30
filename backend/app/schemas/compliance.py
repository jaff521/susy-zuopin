"""出海合规诊断核心数据契约 (Compliance Data Contracts & Schemas).

定义符合 Pydantic v2 规范的严格数据结构，包含综合评分概览、缺陷明细、
整改前后对比 (Before vs After)、法条溯源以及国标 GB/T 45654 水印溯源。
"""

from __future__ import annotations

import uuid
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class RiskLevel(str, Enum):
    """风险评级枚举 (红黄绿三色警戒)."""
    HIGH = "HIGH"       # 高危红牌: 海关直接扣押/全网强制下架/严重违法
    MEDIUM = "MEDIUM"   # 中危黄牌: 标签缺失关键信息/限期整改
    LOW = "LOW"         # 低危绿牌: 建议性优化/良好合规状态


class ComplianceDefect(BaseModel):
    """单项违规缺陷明细 (结构化契约)."""
    id: str = Field(
        default_factory=lambda: f"DEF-{uuid.uuid4().hex[:8].upper()}",
        description="缺陷唯一标识编号",
    )
    defect_name: str = Field(..., description="违规项名称，如'缺少欧盟境内授权责任人(EU REP)联络信息'")
    risk_level: RiskLevel = Field(..., description="该缺陷风险评级 (HIGH/MEDIUM/LOW)")
    factual_finding: str = Field(..., description="基于商品标签与说明书的事实依据提取")
    regulation_citation: str = Field(..., description="违反的具体法律条款")
    legal_consequence: str = Field(..., description="面临的官方执法与市场后果")
    rectification_before: str = Field(..., description="当前违规呈现形式 (Before)")
    rectification_after: str = Field(..., description="合规改进建议样式与内容 (After)")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ComplianceScoreOverview(BaseModel):
    """合规审查综合得分与分级仪表盘数据."""
    overall_score: int = Field(..., ge=0, le=100, description="综合合规得分 (0~100)")
    risk_level: RiskLevel = Field(..., description="商品整体最高风险等级")
    passed_checks: int = Field(default=0, ge=0, description="通过核验项数量")
    total_checks: int = Field(default=0, ge=0, description="总审查项数量")
    high_risk_count: int = Field(default=0, ge=0, description="高危项数量")
    medium_risk_count: int = Field(default=0, ge=0, description="中危项数量")
    low_risk_count: int = Field(default=0, ge=0, description="低危项数量")

    @field_validator("overall_score")
    @classmethod
    def validate_overall_score(cls, v: int) -> int:
        if v < 0 or v > 100:
            raise ValueError("overall_score must be between 0 and 100")
        return v


class ComplianceReportSchema(BaseModel):
    """出海商品 AI 合规审查与风险诊断完整报告契约."""
    report_id: str = Field(
        default_factory=lambda: f"REP-{uuid.uuid4().hex[:12].upper()}",
        description="报告唯一跟踪编号",
    )
    task_id: Optional[str] = Field(default=None, description="关联审查任务ID")
    product_name: str = Field(..., description="商品名称")
    category: str = Field(..., description="商品类目 (toys/electronics/cosmetics/general)")
    target_country: str = Field(default="EU", description="出海目标市场")
    score_overview: ComplianceScoreOverview = Field(..., description="合规评分概览")
    defects: List[ComplianceDefect] = Field(default_factory=list, description="检测到的缺陷列表")
    cited_regulations: List[Dict[str, Any]] = Field(default_factory=list, description="引用的权威法规清单")
    ai_attribution_stamp: str = Field(
        default="[AI生成内容标识: 由出海易审安全中台研判，依据欧盟法规知识库2026版]",
        description="GB/T 45654 生成式人工智能服务标识水印",
    )
    is_offline_replay: bool = Field(default=False, description="是否处于离线防翻车重放模式")
    processing_time_ms: float = Field(default=0.0, description="全流水线执行耗时(毫秒)")

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)


class ComplianceDiagnosticRequest(BaseModel):
    """诊断请求契约."""
    product_name: str = Field(..., description="商品名称")
    category: str = Field(..., description="商品类目")
    target_country: str = Field(default="EU", description="目标市场")
    ocr_text: str = Field(..., description="OCR提取文字")
    ocr_labels: Optional[List[str]] = Field(default=None, description="视觉检测标签")
    retrieved_regulations: Optional[List[Dict[str, Any]]] = Field(default=None, description="RAG检索法规")
    offline_mode: Optional[bool] = Field(default=None, description="是否强制离线重放")
    model: str = Field(default="qwen-plus", description="调用模型")


class ComplianceTaskCreate(BaseModel):
    """创建合规审查任务请求体."""
    product_name: str = Field(..., min_length=1, max_length=128)
    category: str = Field(default="toys")
    target_country: str = Field(default="EU")
    description: Optional[str] = Field(default="", max_length=2000)


class ComplianceTaskResponse(BaseModel):
    """创建合规审查任务响应体."""
    task_id: str
    status: str
    message: str
