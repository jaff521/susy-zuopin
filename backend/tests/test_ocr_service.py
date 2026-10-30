import io
import os
import tempfile
import pytest
from pathlib import Path

from app.services.ocr_service import OCRService, OCRResult, EURepInfo


@pytest.fixture
def ocr_service():
    """Instantiate OCRService instance."""
    return OCRService()


@pytest.fixture
def sample_compliant_toy_text():
    return """
    KIDS SMART BLOCKS - MODEL KB-2026
    CE
    EC REP: Apex Compliance Solutions GmbH
    Address: Friedrichstraße 45, 10117 Berlin, Germany
    Email: contact@apex-compliance.eu
    Tel: +49 30 1234567

    WARNING:
    Not suitable for children under 3 years.
    Choking Hazard - small parts.
    Keep away from fire.

    BATCH: LOT-2026-X99
    Made in China
    Materials: ABS Plastic, Silicone
    """


@pytest.fixture
def sample_cosmetics_text():
    return """
    GLOW ESSENCE HYDRATING CREAM 50ml
    CE
    EU Responsible Person: EuroBeauty Rep SAS, 12 Rue de Rivoli, 75001 Paris, France
    Email: rep@eurobeauty.fr
    LOT NO: B20260901-01
    Ingredients: Aqua, Glycerin, Niacinamide, Butylene Glycol, Phenoxyethanol, Ethylhexylglycerin.
    Avoid contact with eyes. Keep out of reach of children.
    """


class TestOCRServiceContractAndDataStructure:
    def test_ocr_result_structure_and_types(self):
        """Verify that OCRResult exposes all required fields with correct types."""
        result = OCRResult(
            raw_text="Sample text",
            eu_rep_info=EURepInfo(
                found=True,
                name="Test Rep Ltd",
                address="10 Test Way, London",
                email="info@testrep.eu",
                raw_block="EC REP: Test Rep Ltd...",
            ),
            warning_labels=["Choking Hazard"],
            ce_symbol_detected=True,
            ingredients=["Aqua", "Glycerin"],
            batch_or_serial="LOT-12345",
        )

        assert isinstance(result.raw_text, str)
        assert result.raw_text == "Sample text"
        assert result.ce_symbol_detected is True
        assert result.warning_labels == ["Choking Hazard"]
        assert result.ingredients == ["Aqua", "Glycerin"]
        assert result.batch_or_serial == "LOT-12345"

        # Check eu_rep_info attribute and dict-like access
        assert result.eu_rep_info.found is True
        assert result.eu_rep_info.name == "Test Rep Ltd"
        assert result.eu_rep_info.address == "10 Test Way, London"
        assert result.eu_rep_info.email == "info@testrep.eu"
        assert result.eu_rep_info["found"] is True
        assert result.eu_rep_info["name"] == "Test Rep Ltd"
        assert result.eu_rep_info["email"] == "info@testrep.eu"

    def test_default_empty_ocr_result(self):
        """Verify default initialization produces a safe empty state."""
        result = OCRResult()
        assert result.raw_text == ""
        assert result.ce_symbol_detected is False
        assert result.warning_labels == []
        assert result.ingredients == []
        assert result.batch_or_serial == ""
        assert result.eu_rep_info.found is False
        assert result.eu_rep_info.name == ""
        assert result.eu_rep_info.address == ""
        assert result.eu_rep_info.email == ""
        assert result.eu_rep_info.raw_block == ""


class TestOCRTextExtractionRules:
    def test_extract_compliant_toy_text(self, ocr_service, sample_compliant_toy_text):
        """Verify extraction of EU REP, CE, warnings, batch and materials."""
        result = ocr_service.extract_from_text(sample_compliant_toy_text)

        assert result.ce_symbol_detected is True
        assert result.eu_rep_info.found is True
        assert "Apex Compliance" in result.eu_rep_info.name
        assert "Berlin" in result.eu_rep_info.address
        assert result.eu_rep_info.email == "contact@apex-compliance.eu"

        # Check warnings
        warnings = " ".join(result.warning_labels).lower()
        assert "not suitable for children under 3 years" in warnings
        assert "choking hazard" in warnings

        # Check batch
        assert "LOT-2026-X99" in result.batch_or_serial

        # Check materials/ingredients
        assert any("ABS Plastic" in item for item in result.ingredients)
        assert any("Silicone" in item for item in result.ingredients)

    def test_extract_cosmetics_ingredients_and_rep(self, ocr_service, sample_cosmetics_text):
        """Verify ingredients list parsing and cosmetics EU REP extraction."""
        result = ocr_service.extract_from_text(sample_cosmetics_text)

        assert result.ce_symbol_detected is True
        assert result.eu_rep_info.found is True
        assert "EuroBeauty Rep" in result.eu_rep_info.name
        assert "Paris" in result.eu_rep_info.address
        assert result.eu_rep_info.email == "rep@eurobeauty.fr"

        assert len(result.ingredients) >= 4
        assert "Aqua" in result.ingredients
        assert "Glycerin" in result.ingredients
        assert "Niacinamide" in result.ingredients
        assert result.batch_or_serial == "B20260901-01"

    def test_missing_eu_rep_detection(self, ocr_service):
        """When text has no EU REP, found must be False."""
        text = "Cheap Toy Model 123. Made in China. Keep away from small children. LOT-001"
        result = ocr_service.extract_from_text(text)

        assert result.eu_rep_info.found is False
        assert result.eu_rep_info.name == ""
        assert result.eu_rep_info.address == ""
        assert result.eu_rep_info.email == ""
        assert result.batch_or_serial == "LOT-001"

    def test_multilingual_warnings(self, ocr_service):
        """Verify German, French and English safety warning detection."""
        multilingual_text = """
        Achtung! Nicht für Kinder unter 3 Jahren geeignet. Erstickungsgefahr wegen verschluckbarer Kleinteile.
        Attention! Ne convient pas aux enfants de moins de 36 mois. Risque d'étouffement.
        Warning! Not suitable for children under 3 years. Choking hazard.
        """
        result = ocr_service.extract_from_text(multilingual_text)
        assert len(result.warning_labels) >= 2
        joined_warnings = " ".join(result.warning_labels)
        assert "Nicht für Kinder" in joined_warnings or "Erstickungsgefahr" in joined_warnings
        assert "Choking hazard" in joined_warnings or "Not suitable" in joined_warnings


class TestImageExtractionAndDegradation:
    def test_extract_from_image_bytes(self, ocr_service):
        """Test extraction from raw bytes input."""
        # Minimal synthetic PNG bytes containing preset toy packaging signature
        header = b"\x89PNG\r\n\x1a\n"
        mock_payload = (
            header
            + b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4"
            + b"tEXtDescription\x00CE EC REP: FastRep EU GmbH contact@fastrep.eu Berlin LOT: B9901 Not suitable for children under 3 years"
        )

        result = ocr_service.extract_from_image(mock_payload, filename="sample_toy_package.png")
        assert isinstance(result, OCRResult)
        assert result.ce_symbol_detected is True
        assert result.eu_rep_info.found is True
        assert "FastRep" in result.eu_rep_info.name
        assert "contact@fastrep.eu" in result.eu_rep_info.email
        assert "B9901" in result.batch_or_serial

    def test_extract_from_file_path(self, ocr_service):
        """Test extraction given a temporary file path on disk."""
        with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as tmp:
            tmp.write(b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + b"EC REP: SafeGoods EU contact@safegoods.eu CE LOT-555")
            tmp_path = tmp.name

        try:
            result = ocr_service.extract_from_image(tmp_path)
            assert isinstance(result, OCRResult)
            assert result.ce_symbol_detected is True
            assert result.eu_rep_info.found is True
            assert "SafeGoods" in result.eu_rep_info.name
            assert result.batch_or_serial == "LOT-555"
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_corrupt_or_empty_image_graceful_degradation(self, ocr_service):
        """Verify that empty or corrupt inputs do not raise unhandled exceptions."""
        empty_result = ocr_service.extract_from_image(b"", filename="empty.jpg")
        assert isinstance(empty_result, OCRResult)
        assert empty_result.raw_text == ""
        assert empty_result.ce_symbol_detected is False
        assert empty_result.eu_rep_info.found is False

        corrupt_bytes = b"\x00\x01\x02\x03\xff\xfe\xaa\xbb" * 10
        corrupt_result = ocr_service.extract_from_image(corrupt_bytes, filename="blurry_noise.jpg")
        assert isinstance(corrupt_result, OCRResult)
        assert corrupt_result.eu_rep_info.found is False


class TestOfflineColdStartFallback:
    def test_offline_zero_dependency_preset_fallback(self, ocr_service):
        """
        Verify that in an offline host without Paddle/Tesseract,
        the built-in heuristic extractor can identify standard sample packages
        and return complete structured compliance data in milliseconds.
        """
        # Test preset demo samples by filename or sample cues
        sample_filename = "demo_children_toy_packaging.jpg"
        dummy_image = b"\xff\xd8\xff\xe0" + b"\x00" * 32

        result = ocr_service.extract_from_image(dummy_image, filename=sample_filename)

        assert isinstance(result, OCRResult)
        assert result.ce_symbol_detected is True
        assert result.eu_rep_info.found is True
        assert len(result.eu_rep_info.name) > 0
        assert len(result.eu_rep_info.email) > 0
        assert len(result.warning_labels) > 0
        assert len(result.batch_or_serial) > 0
        assert result.is_fallback is True

    def test_cloud_vision_ocr_graceful_fallback(self, ocr_service):
        """Verify _run_cloud_vision_ocr returns None and falls back when key is absent."""
        dummy_image = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
        res = ocr_service._run_cloud_vision_ocr(dummy_image)
        # Without network/in test environment, returns None gracefully
        assert res is None or isinstance(res, OCRResult)
