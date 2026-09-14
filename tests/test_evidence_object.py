import sys
import os
import tempfile

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if project_root not in sys.path:
    sys.path.append(project_root)

from core.evidence_object import (
    EvidenceObject,
    create_evidence_object,
    identify_source_type
)
from core.analysis_router import run_automated_analysis


def test_evidence_object_and_pipeline():
    print("==================================================")
    print("TESTING EVIDENCE OBJECT & SOURCE IDENTIFICATION")
    print("==================================================")

    test_dir = tempfile.mkdtemp()
    try:
        # 1. Forensic Image Candidate Test (.E01)
        e01_path = os.path.join(test_dir, "test_image.E01")
        with open(e01_path, "wb") as f:
            f.write(b"EVF\x09\x0d\x0a\xff\x00Dummy Forensic Image Content")

        # Test identify_source_type
        e01_source = identify_source_type(e01_path)
        assert e01_source == "forensic_image", f"Expected forensic_image, got {e01_source}"

        # Test create_evidence_object
        e01_obj = create_evidence_object(e01_path)
        assert isinstance(e01_obj, EvidenceObject)
        assert e01_obj.source_type == "forensic_image"
        assert e01_obj.sha256 is not None and len(e01_obj.sha256) == 64
        assert e01_obj.hash_algorithm == "SHA-256"

        print("Forensic Image Test Passed:")
        print(f"  - Source Type : {e01_obj.source_type}")
        print(f"  - Path        : {e01_obj.path}")
        print(f"  - SHA-256     : {e01_obj.sha256}")

        # Run pipeline with Forensic Image
        res_e01 = run_automated_analysis(e01_obj)
        assert res_e01["status"] == "SUCCESS"
        assert res_e01["source_type"] == "forensic_image"
        assert res_e01["evidence_context"]["source_type"] == "forensic_image"
        assert res_e01["evidence_context"]["sha256"] == e01_obj.sha256

        # 2. Individual Evidence File Test (.evtx)
        evtx_path = os.path.join(test_dir, "sample.evtx")
        with open(evtx_path, "wb") as f:
            f.write(b"ElfFile\x00Dummy Event Log Content")

        evtx_source = identify_source_type(evtx_path)
        assert evtx_source == "individual_file", f"Expected individual_file, got {evtx_source}"

        evtx_obj = create_evidence_object(evtx_path)
        assert isinstance(evtx_obj, EvidenceObject)
        assert evtx_obj.source_type == "individual_file"
        assert evtx_obj.sha256 is not None and len(evtx_obj.sha256) == 64

        print("\nIndividual Evidence File Test Passed:")
        print(f"  - Source Type : {evtx_obj.source_type}")
        print(f"  - Path        : {evtx_obj.path}")
        print(f"  - SHA-256     : {evtx_obj.sha256}")

        # Run pipeline with Individual Evidence File
        res_evtx = run_automated_analysis(evtx_obj)
        assert res_evtx["status"] == "SUCCESS"
        assert res_evtx["source_type"] == "individual_file"
        assert res_evtx["evidence_context"]["source_type"] == "individual_file"
        assert res_evtx["evidence_context"]["sha256"] == evtx_obj.sha256

        # 3. Confirm timestamp & hidden file checks execute
        assert res_e01["timestamp_result"] is not None
        assert res_e01["hidden_file_result"] is not None
        assert res_evtx["timestamp_result"] is not None
        assert res_evtx["hidden_file_result"] is not None

        # 4. Confirm evidence context is logically separate from findings
        assert "evidence_context" in res_e01
        assert "findings" in res_e01

        print("\n==================================================")
        print("ALL EVIDENCE OBJECT & SOURCE IDENTIFICATION TESTS PASSED!")
        print("==================================================")

    finally:
        import shutil
        shutil.rmtree(test_dir, ignore_errors=True)


if __name__ == "__main__":
    test_evidence_object_and_pipeline()
