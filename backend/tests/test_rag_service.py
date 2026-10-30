import pytest
from pathlib import Path
from typing import List

from app.services.rag_service import (
    RAGService,
    RegulationMatch,
    RAGRetrievalResult,
    OfflineDeterministicEmbeddingFunction,
)


@pytest.fixture
def rag_service(tmp_path):
    """Instantiate RAGService using an isolated temporary directory."""
    service = RAGService(persist_directory=str(tmp_path))
    service.seed_regulations(overwrite=True)
    return service


@pytest.fixture
def isolated_rag_service(rag_service):
    """Alias for backwards compatibility."""
    return rag_service


class TestOfflineEmbeddingFunction:
    """Offline embedding function property verification."""

    def test_embedding_dimension_and_norm(self):
        emb_fn = OfflineDeterministicEmbeddingFunction(dim=128)
        vec = emb_fn.embed_text("EU GPSR 2023/988 European Representative CE Mark")
        assert len(vec) == 128
        norm = sum(x * x for x in vec)
        assert abs(norm - 1.0) < 1e-4

    def test_embedding_determinism(self):
        emb_fn = OfflineDeterministicEmbeddingFunction(dim=128)
        text = "Article 9 Obligations of manufacturers"
        vec1 = emb_fn.embed_text(text)
        vec2 = emb_fn.embed_text(text)
        assert vec1 == vec2

    def test_empty_string_embedding(self):
        emb_fn = OfflineDeterministicEmbeddingFunction(dim=128)
        vec = emb_fn.embed_text("")
        assert len(vec) == 128
        assert all(x == 0.0 for x in vec)


class TestRAGServiceContractAndDataStructure:
    def test_regulation_match_contract(self):
        """Verify that RegulationMatch exposes all required fields and dictionary-style access."""
        match = RegulationMatch(
            regulation_id="EU-GPSR-2023-988-ART9",
            title="EU GPSR (通用产品安全法规) 第9条 制造商与欧代可追溯义务",
            article="Article 9",
            content="Manufacturers shall ensure that their products bear a type, batch or serial number...",
            penalty_summary="海关扣押、下架召回、处最高上年度全球营业额4%罚款",
            category="general",
            relevance_score=0.92,
            keywords=["GPSR", "追溯要求"],
        )

        assert match.regulation_id == "EU-GPSR-2023-988-ART9"
        assert "GPSR" in match.title
        assert match.article == "Article 9"
        assert "Manufacturers" in match.content
        assert "海关扣押" in match.penalty_summary
        assert match.category == "general"
        assert 0.0 <= match.relevance_score <= 1.0
        assert "GPSR" in match.keywords

        # Citation label
        label = match.citation_label()
        assert "[Article 9]" in label
        assert "GPSR" in label

        # Dict-like compatibility
        assert match["regulation_id"] == "EU-GPSR-2023-988-ART9"
        assert match.get("category") == "general"
        assert match.get("non_existing", "default") == "default"

        d = match.to_dict()
        assert isinstance(d, dict)
        assert d["regulation_id"] == "EU-GPSR-2023-988-ART9"

    def test_rag_retrieval_result_alias(self):
        """Verify RAGRetrievalResult is compatible with RegulationMatch."""
        assert RAGRetrievalResult is RegulationMatch or issubclass(RAGRetrievalResult, RegulationMatch)


class TestRAGKnowledgeRetrieval:
    def test_query_eu_rep_traceability(self, rag_service: RAGService):
        """Query: '欧盟责任人 追溯要求' -> should recall GPSR Art 9 / Art 19 with high relevance."""
        results = rag_service.search_regulations("欧盟责任人 追溯要求", top_k=3)

        assert len(results) > 0
        top_match = results[0]
        assert isinstance(top_match, RegulationMatch)

        # Verify GPSR traceability article is retrieved
        reg_ids = [r.regulation_id for r in results]
        assert any("GPSR" in rid and ("ART9" in rid or "ART19" in rid) for rid in reg_ids)

        # Verify content and penalty summary are populated
        assert top_match.content
        assert top_match.penalty_summary
        assert top_match.relevance_score > 0.0

    def test_query_eu_rep_missing_details(self, rag_service: RAGService):
        """Query: '商品外包装缺失欧代信息 EU REP 制造商地址与联系邮箱'."""
        results = rag_service.search_regulations("商品外包装缺失欧代信息 EU REP 制造商地址与联系邮箱", top_k=3)
        assert len(results) > 0
        top = results[0]
        assert "GPSR" in top.regulation_id or "GPSR" in top.title
        assert "罚" in top.penalty_summary or "下架" in top.penalty_summary or "扣押" in top.penalty_summary

    def test_query_toy_ce_warning(self, rag_service: RAGService):
        """Query: '儿童玩具 CE 警示 小零件' -> should recall EN 71 / Toy Safety Directive."""
        results = rag_service.search_regulations("儿童玩具 CE 警示 小零件", category="toys", top_k=3)

        assert len(results) > 0
        top_match = results[0]

        # Should match toy safety regulations
        assert top_match.category == "toys"
        matched_text = f"{top_match.title} {top_match.content}".lower()
        assert any(kw in matched_text for kw in ["toy", "玩具", "en 71", "en71", "choking", "2009/48/ec", "small parts", "零件"])

    def test_query_toy_choking_hazard(self, rag_service: RAGService):
        """Query: '儿童玩具 0-3岁窒息风险 小零件 warning not suitable for under 3 years'."""
        results = rag_service.search_regulations("儿童玩具 0-3岁窒息风险 小零件 warning not suitable for under 3 years", category="toys", top_k=2)
        assert len(results) > 0
        ids = [r.regulation_id for r in results]
        assert any("TOY" in rid or "EN71" in rid or "EN-71" in rid for rid in ids)
        assert results[0].category == "toys"

    def test_query_cosmetics_reach(self, rag_service: RAGService):
        """Query: '化妆品 禁用成分 REACH' -> should recall REACH Annex XVII or Cosmetics Regulation."""
        results = rag_service.search_regulations("化妆品 禁用成分 REACH", top_k=3)

        assert len(results) > 0
        reg_ids = [r.regulation_id for r in results]
        assert any("REACH" in rid or "COSMETICS" in rid or "1223" in rid for rid in reg_ids)

    def test_retrieve_electronics_rohs_lvd(self, rag_service: RAGService):
        """Query: '电子设备 铅汞重金属超标 低电压触电危险 RoHS LVD'."""
        results = rag_service.search_regulations("电子设备 铅汞重金属超标 低电压触电危险 RoHS LVD", category="electronics", top_k=2)
        assert len(results) > 0
        ids = [r.regulation_id for r in results]
        assert any("ROHS" in rid or "LVD" in rid for rid in ids)

    def test_category_filtering(self, rag_service: RAGService):
        """Filtering by category should strictly limit to that category."""
        toy_results = rag_service.search_regulations("安全警示 追溯", category="toys", top_k=5)
        for r in toy_results:
            assert r.category == "toys"


class TestRAGRobustnessAndDegradation:
    def test_empty_query_returns_empty_list(self, rag_service: RAGService):
        """Empty or whitespace-only query should gracefully return an empty list."""
        assert rag_service.search_regulations("") == []
        assert rag_service.search_regulations("   ") == []

    def test_obscure_gibberish_query_handling(self, rag_service: RAGService):
        """Gibberish or unmatched query should not raise exceptions."""
        results = rag_service.search_regulations("zzqxxkj19827391823 randomnonexistenttext")
        assert isinstance(results, list)
        if results:
            assert results[0].relevance_score <= 0.5

    def test_speed_and_offline_reliability(self, rag_service: RAGService):
        """Retrieval must complete in under 50ms offline for competitive demo."""
        import time
        start = time.perf_counter()
        results = rag_service.search_regulations("RoHS 铅 汞 限制")
        duration_ms = (time.perf_counter() - start) * 1000

        assert duration_ms < 50.0
        assert len(results) > 0

    def test_citation_label_formatting(self, rag_service: RAGService):
        results = rag_service.search_regulations("GPSR", top_k=1)
        assert len(results) > 0
        label = results[0].citation_label()
        assert "[" in label and "]" in label


class TestSeedDatabaseCompleteness:
    def test_minimum_15_regulations_seeded(self, rag_service: RAGService):
        """Ensure at least 15 authoritative EU regulations are present."""
        count = rag_service.count()
        assert count >= 15

    def test_all_seeded_records_have_complete_fields(self, rag_service: RAGService):
        """Verify each seeded item contains required fields with valid values."""
        records = rag_service.get_all_regulations()
        assert len(records) >= 15
        for reg in records:
            assert reg.regulation_id.startswith("EU-")
            assert len(reg.title) > 5
            assert len(reg.article) > 0
            assert len(reg.content) > 10
            assert len(reg.penalty_summary) > 5
            assert reg.category in ("toys", "electronics", "cosmetics", "general")


class TestDashScopeDenseEmbeddingFunction:
    """真实 DashScope text-embedding-v3 稠密向量检索与优雅降级测试."""

    def test_dashscope_embedding_offline_fallback(self):
        from app.services.rag_service import DashScopeEmbeddingFunction
        # Without API key or offline, gracefully falls back to deterministic 128-dim
        fn = DashScopeEmbeddingFunction(api_key="")
        vec = fn.embed_text("GPSR Article 9 EU REP")
        assert len(vec) == 128
        assert any(x != 0.0 for x in vec)

    def test_dashscope_cosine_similarity(self):
        from app.services.rag_service import DashScopeEmbeddingFunction
        v1 = [1.0, 0.0, 0.0]
        v2 = [1.0, 0.0, 0.0]
        v3 = [-1.0, 0.0, 0.0]
        assert DashScopeEmbeddingFunction.cosine_similarity(v1, v2) == 1.0
        assert DashScopeEmbeddingFunction.cosine_similarity(v1, v3) == 0.0
