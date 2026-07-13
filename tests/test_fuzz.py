"""Offline tests for the fuzz module: survey, spec parsing, and build assembly.

These never touch the network or the model. The end to end crash path is exercised
by hand against real targets (see docs), not here.
"""
from sabba.harness import fuzz


def test_parse_spec_plain_json():
    spec = fuzz._parse_spec(
        '{"entry":"e","sources":["a.c"],"includes":["inc"],"defines":["X"],'
        '"harness":"int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){return 0;}"}')
    assert spec.entry == "e"
    assert spec.sources == ["a.c"]
    assert spec.includes == ["inc"]
    assert spec.defines == ["X"]
    assert "LLVMFuzzerTestOneInput" in spec.harness


def test_parse_spec_fenced_and_prose():
    raw = ('sure, here:\n```json\n'
           '{"entry":"x","harness":"int LLVMFuzzerTestOneInput'
           '(const uint8_t*d,size_t s){return 0;}"}\n```\nhope that helps')
    spec = fuzz._parse_spec(raw)
    assert spec.entry == "x"
    assert spec.sources == [] and spec.includes == [] and spec.defines == []


def test_survey_skips_tests_and_finds_signatures(tmp_path):
    (tmp_path / "lib.c").write_text("int parse(const char *s, size_t n){return 0;}\n")
    (tmp_path / "lib.h").write_text("int parse(const char *s, size_t n);\n")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.c").write_text("int main(void){return 0;}\n")
    files, sigs, _docs = fuzz._survey(str(tmp_path))
    assert "lib.c" in files and "lib.h" in files
    assert all(not f.startswith("tests") for f in files)
    assert any("parse" in s for _f, s in sigs)


def test_build_cmd_shape(tmp_path):
    spec = fuzz.HarnessSpec(
        entry="e", sources=["a.c"], includes=["inc"], defines=["IMPL"],
        harness="int LLVMFuzzerTestOneInput(const uint8_t*d,size_t s){return 0;}")
    work = tmp_path / "w"
    work.mkdir()
    cmd = fuzz._build_cmd(str(tmp_path), spec, str(work))
    assert cmd[0] == "clang"
    assert "-fsanitize=address,fuzzer" in cmd
    assert "-DIMPL" in cmd
    assert str(work / "harness.c") in cmd
    assert (work / "harness.c").read_text().startswith("int LLVMFuzzerTestOneInput")
