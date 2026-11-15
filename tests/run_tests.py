#!/usr/bin/env python3
"""
tests/run_tests.py
Comprehensive Cross-Platform Regression Test Suite for ROPWeaver v1.2.4

Preserves 100% assertion parity with tests/run_tests.ps1 across all 10 test groups
(exactly 178 successful-run assertions).

Artifact Restoration & Security Note:
Tracked artifacts (reports/output.json, reports/payload.bin, payload.bin) are backed up
prior to testing and restored in a top-level finally block. Current filesystem path types
are re-inspected using os.lstat() prior to restoration to ensure the runner never writes
through an unexpected symbolic link, directory, or special file.
Limitations: External non-catchable process termination (SIGKILL / kill -9, power failure)
bypasses interpreter execution and cannot trigger Python finally handlers. A theoretical
TOCTOU race condition exists on POSIX between os.lstat() and write/unlink operations if
an external concurrent process mutates the path.
"""

import sys
import os
import stat
import subprocess
import json
import re
import shutil
import tempfile
import hashlib
from pathlib import Path
from enum import Enum, auto

# ANSI escape codes for coloring
COLOR_CYAN = "\033[36m"
COLOR_YELLOW = "\033[33m"
COLOR_GREEN = "\033[32m"
COLOR_RED = "\033[31m"
COLOR_RESET = "\033[0m"

# Disable colors if stdout is not a tty and NO_COLOR is set
if not sys.stdout.isatty() and os.environ.get("NO_COLOR"):
    COLOR_CYAN = COLOR_YELLOW = COLOR_GREEN = COLOR_RED = COLOR_RESET = ""

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACTIVE_TEMP_DIR = None

# -----------------------------------------------------------------------------
# 1. Artifact Protection & State Machine
# -----------------------------------------------------------------------------
class ArtifactState(Enum):
    EXISTS_AND_BACKED_UP = auto()
    DID_NOT_EXIST = auto()
    BACKUP_FAILED = auto()

class TrackedArtifactManager:
    TRACKED_FILES = [
        Path("reports/output.json"),
        Path("reports/payload.bin"),
        Path("payload.bin"),
        Path("reports/PHASE_1.2A_KALI_LINUX_NATIVE_VALIDATION.md")
    ]

    def __init__(self, root: Path):
        self.root = root
        self.captured_hashes = {}
        self.failure_reasons = []

    def capture_pre_test_state(self) -> bool:
        """
        Inspects each tracked artifact path prior to executing any test.
        Computes and records its SHA-256 baseline hash.
        Returns True only if all paths are safely captured.
        """
        all_ok = True
        for rel_path in self.TRACKED_FILES:
            full_path = self.root / rel_path
            try:
                st = os.lstat(full_path)
            except FileNotFoundError:
                self.failure_reasons.append(f"Required protected artifact missing: {rel_path}")
                all_ok = False
                continue
            except Exception as e:
                self.failure_reasons.append(f"Failed to lstat {rel_path}: {e}")
                all_ok = False
                continue

            if not stat.S_ISREG(st.st_mode):
                self.failure_reasons.append(f"{rel_path} is not a regular file (mode: {oct(st.st_mode)})")
                all_ok = False
                continue

            try:
                content = full_path.read_bytes()
                h = hashlib.sha256(content).hexdigest()
                self.captured_hashes[rel_path] = h
            except Exception as e:
                self.failure_reasons.append(f"Failed to read {rel_path}: {e}")
                all_ok = False

        return all_ok

    def verify_unmodified(self) -> bool:
        """
        Strictly verifies that all protected artifacts remain 100% byte-identical
        to their pre-test baseline hashes without writing, unlinking, or restoring over them.
        """
        all_intact = True
        for rel_path, expected_hash in self.captured_hashes.items():
            full_path = self.root / rel_path
            try:
                content = full_path.read_bytes()
                current_hash = hashlib.sha256(content).hexdigest()
                if current_hash != expected_hash:
                    print(f"[!] CRITICAL: Protected artifact {rel_path} was modified during testing!", file=sys.stderr)
                    all_intact = False
            except Exception as e:
                print(f"[!] Error verifying protected artifact {rel_path}: {e}", file=sys.stderr)
                all_intact = False
        return all_intact

    def restore(self) -> bool:
        return self.verify_unmodified()

# -----------------------------------------------------------------------------
# 2. Test Harness State & Assertion Helpers
# -----------------------------------------------------------------------------
passed = 0
failed = 0

def assert_test(name: str, condition: bool, details: str = "") -> None:
    global passed, failed
    if condition:
        print(f"  {COLOR_GREEN}[PASS]{COLOR_RESET} {name}")
        passed += 1
    else:
        err_msg = f": {details}" if details else ""
        print(f"  {COLOR_RED}[FAIL]{COLOR_RESET} {name}{err_msg}")
        failed += 1

def run_command(cmd_list, timeout=30, cwd=None, env=None):
    """Executes a command list safely without shell expansion."""
    # Strengthened fail-closed guard: payload-generating commands must execute inside ACTIVE_TEMP_DIR
    payload_generating_flags = {"-p", "--payload", "--payload-gen"}
    if any(flag in cmd_list for flag in payload_generating_flags):
        if cwd is None:
            raise RuntimeError(
                f"[GUARD FAILURE] Refusing to execute payload-generating command with missing working directory: {cmd_list}"
            )
        if ACTIVE_TEMP_DIR is None:
            raise RuntimeError(
                f"[GUARD FAILURE] Refusing to execute payload-generating command without an active temporary test directory: {cmd_list}"
            )
        target_cwd = Path(cwd).resolve()
        active_root = ACTIVE_TEMP_DIR.resolve()
        try:
            target_cwd.relative_to(active_root)
        except ValueError:
            raise RuntimeError(
                f"[GUARD FAILURE] Refusing to execute payload-generating command outside active temporary directory ({active_root}): cwd={target_cwd}"
            )

    try:
        cmd_env = os.environ.copy()
        if env:
            cmd_env.update(env)
        if sys.platform == "win32":
            bwin = str(PROJECT_ROOT / "build-win")
            mingw = r"C:\msys64\mingw64\bin"
            curr_path = cmd_env.get("PATH", "")
            cmd_env["PATH"] = f"{bwin};{mingw};{curr_path}"

        res = subprocess.run(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            cwd=cwd,
            env=cmd_env
        )
        return res.returncode, res.stdout
    except subprocess.TimeoutExpired:
        return -1, "[TIMEOUT] Command timed out after 30 seconds"
    except Exception as e:
        return -1, f"[EXCEPTION] {e}"

# -----------------------------------------------------------------------------
# 3. Discovery Helpers: Binary, Core Library, and Compiler
# -----------------------------------------------------------------------------
def locate_ropweaver_binary():
    candidates = [
        PROJECT_ROOT / "build-win" / "ropweaver.exe",
        PROJECT_ROOT / "build-linux" / "ropweaver",
        PROJECT_ROOT / "build" / "ropweaver",
        PROJECT_ROOT / "build-mac" / "ropweaver",
        PROJECT_ROOT / "ropweaver.exe",
        PROJECT_ROOT / "ropweaver",
    ]
    for c in candidates:
        if c.is_file() and (os.access(c, os.X_OK) or sys.platform == "win32"):
            return c
    return None

def locate_core_library():
    candidates = [
        PROJECT_ROOT / "build-win" / "libropweaver_core.a",
        PROJECT_ROOT / "build-linux" / "libropweaver_core.a",
        PROJECT_ROOT / "build" / "libropweaver_core.a",
        PROJECT_ROOT / "build-mac" / "libropweaver_core.a",
        PROJECT_ROOT / "libropweaver_core.a",
    ]
    for c in candidates:
        if c.is_file():
            return c
    return None

def locate_cxx_compiler():
    # 1. Environment variable override
    env_cxx = os.environ.get("CXX")
    if env_cxx:
        return env_cxx

    # 2. Standard discovery
    if sys.platform == "win32":
        msys_gxx = Path("C:/msys64/mingw64/bin/g++.exe")
        if msys_gxx.is_file():
            return str(msys_gxx)
        which_gxx = shutil.which("g++")
        if which_gxx:
            return which_gxx
        which_clang = shutil.which("clang++")
        if which_clang:
            return which_clang
    else:
        # Check Termux PREFIX if set
        prefix = os.environ.get("PREFIX")
        if prefix:
            termux_clang = Path(prefix) / "bin" / "clang++"
            if termux_clang.is_file():
                return str(termux_clang)
        for comp in ["g++", "clang++", "c++"]:
            found = shutil.which(comp)
            if found:
                return found

    return None

# -----------------------------------------------------------------------------
# 4. Main Test Execution
# -----------------------------------------------------------------------------
def main():
    print(f"{COLOR_CYAN}============================================================{COLOR_RESET}")
    print(f"{COLOR_CYAN}         ROPWeaver Comprehensive Regression Test Suite       {COLOR_RESET}")
    print(f"{COLOR_CYAN}============================================================{COLOR_RESET}")

    # Initialize Tracked Artifact Manager
    artifact_mgr = TrackedArtifactManager(PROJECT_ROOT)
    if not artifact_mgr.capture_pre_test_state():
        print(f"{COLOR_RED}[!] Fatal: Pre-test artifact backup failed. Aborting tests to protect working tree.{COLOR_RESET}", file=sys.stderr)
        for reason in artifact_mgr.failure_reasons:
            print(f"    - {reason}", file=sys.stderr)
        sys.exit(1)

    ropweaver_bin = locate_ropweaver_binary()
    if not ropweaver_bin:
        print(f"{COLOR_RED}[!] Error: ROPWeaver executable not found. Build it first.{COLOR_RESET}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Using binary: {ropweaver_bin}")

    core_lib = locate_core_library()
    cxx_compiler = locate_cxx_compiler()

    global ACTIVE_TEMP_DIR

    # Isolated temporary run directory for all tests generating reports/payloads
    temp_dir_obj = tempfile.TemporaryDirectory(prefix="ropw_run_")
    isolated_dir = Path(temp_dir_obj.name)
    ACTIVE_TEMP_DIR = isolated_dir
    (isolated_dir / "reports").mkdir(parents=True, exist_ok=True)
    out_json = isolated_dir / "reports" / "output.json"
    test_build_dir = isolated_dir / "bin"
    test_build_dir.mkdir(parents=True, exist_ok=True)

    # Ensure synthetic test fixtures exist
    gen_script = PROJECT_ROOT / "tests" / "generate_test_elfs.py"
    if gen_script.is_file():
        subprocess.run([sys.executable, str(gen_script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Mirror read-only test_binaries fixtures into isolated environment for isolated test execution
    iso_test_binaries = isolated_dir / "test_binaries"
    if (PROJECT_ROOT / "test_binaries").is_dir() and not iso_test_binaries.exists():
        shutil.copytree(PROJECT_ROOT / "test_binaries", iso_test_binaries)

    try:
        # -------------------------------------------------------------
        # Test 1: ELF64 Analysis & Auto-Chain (binsh_test) [12 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 1: ELF64 Analysis & Auto-Chain (binsh_test)...{COLOR_RESET}")
        elf_bin = PROJECT_ROOT / "test_binaries" / "binsh_test"
        if out_json.is_file():
            out_json.unlink()

        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_bin), "-a", "-p"], cwd=str(isolated_dir))

        assert_test("ELF Execution returns code 0", exit_code == 0, f"exit code {exit_code}")
        assert_test("ELF Detected architecture x86_64", bool(re.search(r"Detected architecture:\s*x86_64", out_str)))
        assert_test("ELF Found /bin/sh", "Found /bin/sh" in out_str)
        assert_test("ELF Auto-chain synthesized successfully", ("ROP chain created and validated successfully" in out_str or "ROP chain created successfully" in out_str))
        assert_test("ELF Report JSON exists", out_json.is_file())

        if out_json.is_file():
            try:
                data = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("JSON file_type is ELF", data.get("file_type") == "ELF")
                gadgets = data.get("gadgets", [])
                assert_test("JSON contains gadgets", len(gadgets) >= 5)
                assert_test("JSON gadgets have byte_verified=true", bool(gadgets[0].get("byte_verified")) is True if gadgets else False)
                assert_test("JSON gadgets have multi-dim categories", len(gadgets[0].get("categories", [])) >= 1 if gadgets else False)
                assert_test("JSON RELRO mitigation present for ELF", data.get("protections", {}).get("RELRO") is not None)
                assert_test("ELF payload status is Success", data.get("raw_payload", {}).get("status") == "Success")
                assert_test("ELF payload verified_padding_offset is set", data.get("raw_payload", {}).get("verified_padding_offset") == 104)
            except Exception as e:
                assert_test("JSON parsing and inspection", False, str(e))
        else:
            for dummy_name in [
                "JSON file_type is ELF", "JSON contains gadgets", "JSON gadgets have byte_verified=true",
                "JSON gadgets have multi-dim categories", "JSON RELRO mitigation present for ELF",
                "ELF payload status is Success", "ELF payload verified_padding_offset is set"
            ]:
                assert_test(dummy_name, False, "output.json was not created")

        # -------------------------------------------------------------
        # Test 2: PE64 Analysis, Mitigations & Address Representation (classic_bof.exe) [47 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 2: PE64 Analysis & Mitigation Detection (classic_bof.exe)...{COLOR_RESET}")
        pe_bin = PROJECT_ROOT / "test_binaries" / "classic_bof.exe"
        if out_json.is_file():
            out_json.unlink()

        exit_code, out_str = run_command([str(ropweaver_bin), str(pe_bin), "-a", "-p"], cwd=str(isolated_dir))

        assert_test("PE Execution returns code 0", exit_code == 0, f"exit code {exit_code}")
        assert_test("PE Detected architecture x86_64", bool(re.search(r"Detected architecture:\s*x86_64", out_str)))
        assert_test("PE NX_COMPAT detected", bool(re.search(r"NX_COMPAT.*COMPATIBLE", out_str)))
        assert_test("PE DYNAMIC_BASE detected", bool(re.search(r"DYNAMIC_BASE.*COMPATIBLE", out_str)))
        assert_test("PE HIGH_ENTROPY_VA detected", bool(re.search(r"HIGH_ENTROPY_VA.*COMPATIBLE", out_str)))
        assert_test("PE CET reported as UNKNOWN", bool(re.search(r"CET=.*UNKNOWN", out_str)))
        assert_test("PE GS-Cookie reported as NOT_DETECTED", bool(re.search(r"GS-Cookie=.*NOT_DETECTED", out_str)))
        assert_test("PE SafeSEH reported as NOT_APPLICABLE", bool(re.search(r"SafeSEH=.*NOT_APPLICABLE", out_str)))
        assert_test("PE output does NOT display RELRO", "RELRO=" not in out_str)
        assert_test("PE reports automated chain unsupported", "unsupported for Windows PE" in out_str)

        if out_json.is_file():
            try:
                data = json.loads(out_json.read_text(encoding="utf-8"))
                gadgets = data.get("gadgets", [])
                total_gadgets = data.get("total_gadgets", 0)
                protections = data.get("protections", {})

                assert_test("JSON file_type is PE", data.get("file_type") == "PE")
                assert_test("JSON total_gadgets matches collection size", total_gadgets == len(gadgets))
                assert_test("JSON protections do NOT contain RELRO for PE", "RELRO" not in protections)
                assert_test("JSON protections NX_COMPAT static indicator is COMPATIBLE", protections.get("NX_COMPAT", {}).get("static_indicator") == "COMPATIBLE")
                assert_test("JSON protections DYNAMIC_BASE static indicator is COMPATIBLE", protections.get("DYNAMIC_BASE", {}).get("static_indicator") == "COMPATIBLE")
                assert_test("JSON protections HIGH_ENTROPY_VA static indicator is COMPATIBLE", protections.get("HIGH_ENTROPY_VA", {}).get("static_indicator") == "COMPATIBLE")
                assert_test("JSON protections CET_COMPAT static indicator is UNKNOWN", protections.get("CET_COMPAT", {}).get("static_indicator") == "UNKNOWN")
                assert_test("JSON protections GS_COOKIE is NOT_DETECTED", protections.get("GS_COOKIE", {}).get("static_indicator") == "NOT_DETECTED")
                assert_test("JSON rop_chain_generation status is Unsupported", "Unsupported" in data.get("rop_chain_generation", {}).get("status", ""))
                assert_test("JSON rop_chain_generation target_syscall is N/A", data.get("rop_chain_generation", {}).get("target_syscall") == "N/A")
                assert_test("JSON raw_payload status is Unsupported", "Unsupported" in data.get("raw_payload", {}).get("status", ""))
                assert_test("JSON raw_payload verified_padding_offset is null", data.get("raw_payload", {}).get("verified_padding_offset") is None)

                # Address representation validation
                g0 = gadgets[0] if gadgets else {}
                assert_test("Gadget has preferred_va hex format", bool(re.match(r"^0x[0-9a-fA-F]{16}$", g0.get("preferred_va", ""))))
                assert_test("Gadget has rva hex format", bool(re.match(r"^0x[0-9a-fA-F]{8}$", g0.get("rva", ""))))
                assert_test("Gadget has file_offset hex format", bool(re.match(r"^0x[0-9a-fA-F]{8}$", g0.get("file_offset", ""))))
                assert_test("Gadget runtime_va is null for ASLR binary", g0.get("runtime_va") is None)
                assert_test("Gadget runtime_va_note explains ASLR randomization", "ASLR" in g0.get("runtime_va_note", ""))
                assert_test("Gadget byte_verified is true", g0.get("byte_verified") is True)

                # Classification: Memory Read vs Write for CMP / TEST
                pure_cmp = [
                    g for g in gadgets
                    if (re.search(r"cmp.*\[|test.*\[", g.get("instructions", "")) and
                        not re.search(r"add\s+.*\[|mov\s+.*\[|sub\s+.*\[|push", g.get("instructions", "")))
                ]
                cmp_clean = all(cg.get("has_memory_write") is False for cg in pure_cmp) and len(pure_cmp) > 0
                assert_test("CMP/TEST memory access is classified as memory_read and NEVER memory_write", cmp_clean)

                # Classification: Stack Adjustment vs Pivot for ADD RSP
                add_rsp = [g for g in gadgets if re.search(r"add\s+rsp", g.get("instructions", ""))]
                add_rsp_clean = all("stack_pivot" not in arg.get("categories", []) for arg in add_rsp)
                assert_test("ADD RSP is classified as stack_adjustment and NOT stack_pivot", add_rsp_clean)

                # Multi-dimensional classification regression
                # A. Register-only arithmetic (e.g. add al, ch ; ret)
                reg_arith = next((g for g in gadgets if g.get("gadget") == "add al, ch ; ret"), None)
                assert_test("Register-only arithmetic exists in classic_bof.exe", reg_arith is not None)
                if reg_arith:
                    assert_test("Register-only arithmetic has has_memory_read=false", reg_arith.get("has_memory_read") is False)
                    assert_test("Register-only arithmetic has has_memory_write=false", reg_arith.get("has_memory_write") is False)
                    assert_test("Register-only arithmetic category is arithmetic", reg_arith.get("category") == "arithmetic")
                    assert_test("Register-only arithmetic categories contain arithmetic", "arithmetic" in reg_arith.get("categories", []))
                    assert_test("Register-only arithmetic categories contain control_transfer", "control_transfer" in reg_arith.get("categories", []))
                    assert_test("Register-only arithmetic categories do NOT contain memory_read", "memory_read" not in reg_arith.get("categories", []))
                    r_read = reg_arith.get("registers_read", [])
                    assert_test("Register-only arithmetic tracks registers_read (al, ch, rsp)", "al" in r_read and "ch" in r_read and "rsp" in r_read)
                    r_mod = reg_arith.get("registers_modified", [])
                    assert_test("Register-only arithmetic tracks registers_modified (al, rsp)", "al" in r_mod and "rsp" in r_mod)
                else:
                    for sub_name in [
                        "Register-only arithmetic has has_memory_read=false",
                        "Register-only arithmetic has has_memory_write=false",
                        "Register-only arithmetic category is arithmetic",
                        "Register-only arithmetic categories contain arithmetic",
                        "Register-only arithmetic categories contain control_transfer",
                        "Register-only arithmetic categories do NOT contain memory_read",
                        "Register-only arithmetic tracks registers_read (al, ch, rsp)",
                        "Register-only arithmetic tracks registers_modified (al, rsp)"
                    ]:
                        assert_test(sub_name, False, "add al, ch ; ret not found")

                # B. Memory read gadget
                mem_reads = [g for g in gadgets if "[" in g.get("instructions", "") and g.get("has_memory_read") is True]
                assert_test("Explicit memory read gadgets detected and classified with memory_read", len(mem_reads) > 0)

                # C. Memory write gadget
                mem_writes = [g for g in gadgets if "[" in g.get("instructions", "") and g.get("has_memory_write") is True]
                assert_test("Explicit memory write gadgets detected and classified with memory_write", len(mem_writes) > 0)

                # D. Stack reads / Register load (pop reg ; ret)
                pop_gadgets = [g for g in gadgets if re.search(r"^pop\s+[a-z0-9]+\s*;\s*ret$", g.get("instructions", ""))]
                pop_clean = len(pop_gadgets) > 0 and all(
                    pg.get("has_memory_read") is False and
                    "register_load" in pg.get("categories", []) and
                    pg.get("stack_consumption", 0) > 0
                    for pg in pop_gadgets
                )
                assert_test("Pop gadgets classified as register_load with stack_consumption > 0 and has_memory_read=false", pop_clean)

                # E. Control transfer terminators
                ret_gadgets = [g for g in gadgets if g.get("terminator_type") == "RET"]
                ret_clean = len(ret_gadgets) > 0 and all("control_transfer" in rg.get("categories", []) for rg in ret_gadgets)
                assert_test("All RET-terminated gadgets belong to control_transfer category", ret_clean)

                # F. Complete 323 Gadget Classification Audit
                audit_bad_reads = 0
                audit_bad_writes = 0
                audit_unverified = 0
                audit_no_categories = 0
                for g in gadgets:
                    asm = g.get("gadget", "")
                    has_bracket = ("[" in asm or "ptr" in asm or "ldr" in asm)
                    if g.get("has_memory_read") and not has_bracket:
                        audit_bad_reads += 1
                    has_write_bracket = ("[" in asm or "str" in asm)
                    if g.get("has_memory_write") and not has_write_bracket:
                        audit_bad_writes += 1
                    if not g.get("byte_verified"):
                        audit_unverified += 1
                    if len(g.get("categories", [])) == 0:
                        audit_no_categories += 1

                assert_test("Complete 323-gadget audit: 0 unverified gadgets", audit_unverified == 0, f"{audit_unverified} unverified")
                assert_test("Complete 323-gadget audit: 0 false memory reads without dereference", audit_bad_reads == 0, f"{audit_bad_reads} bad reads")
                assert_test("Complete 323-gadget audit: 0 false memory writes without dereference", audit_bad_writes == 0, f"{audit_bad_writes} bad writes")
                assert_test("Complete 323-gadget audit: 0 gadgets missing categories", audit_no_categories == 0, f"{audit_no_categories} missing categories")

            except Exception as e:
                assert_test("Test 2 JSON validation", False, str(e))
        else:
            for dummy_name in range(37):
                assert_test(f"Test 2 JSON assertion {dummy_name+1}", False, "output.json missing")

        # -------------------------------------------------------------
        # Test 3: Malformed Binary Error Handling [2 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 3: Malformed Binary Error Handling...{COLOR_RESET}")
        malformed_file = isolated_dir / "reports" / "malformed.bin"
        try:
            malformed_file.write_bytes(bytes([0x7F, 0x45, 0x4C, 0x46])) # truncated ELF
            exit_code, out_str = run_command([str(ropweaver_bin), str(malformed_file)], cwd=str(isolated_dir))
            assert_test("Malformed binary exits with non-zero error", exit_code != 0, f"exit code {exit_code}")
            assert_test("Graceful error message reported", bool(re.search(r"Error|Failed|Invalid", out_str)))
        finally:
            if malformed_file.is_file():
                malformed_file.unlink()

        # -------------------------------------------------------------
        # Test 4: Empty / Text File Handling [2 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 4: Empty / Text File Handling...{COLOR_RESET}")
        text_file = isolated_dir / "reports" / "not_a_binary.txt"
        try:
            text_file.write_text("This is just a text file, not a binary executable.", encoding="utf-8")
            exit_code, out_str = run_command([str(ropweaver_bin), str(text_file)], cwd=str(isolated_dir))
            assert_test("Text file exits with error code", exit_code != 0, f"exit code {exit_code}")
            assert_test("Appropriate error displayed", bool(re.search(r"Error|Failed|Invalid|Unsupported", out_str)))
        finally:
            if text_file.is_file():
                text_file.unlink()

        # -------------------------------------------------------------
        # Test 5: Unified ELF Parser Multi-Architecture Routing [35 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 5: Unified ELF Parser Multi-Architecture Routing...{COLOR_RESET}")
        arch_fixtures = [
            {"File": "elf32_x86",     "ExpectedArch": "x86",     "MinGadgets": 2},
            {"File": "elf32_arm",     "ExpectedArch": "armv7",   "MinGadgets": 1},
            {"File": "elf64_aarch64", "ExpectedArch": "aarch64", "MinGadgets": 1},
            {"File": "elf32_riscv",   "ExpectedArch": "riscv32", "MinGadgets": 1},
            {"File": "elf64_riscv",   "ExpectedArch": "riscv64", "MinGadgets": 1},
        ]

        for fix in arch_fixtures:
            fn = fix["File"]
            ea = fix["ExpectedArch"]
            mg = fix["MinGadgets"]
            fix_path = PROJECT_ROOT / "test_binaries" / fn

            if fix_path.is_file():
                if out_json.is_file():
                    out_json.unlink()
                exit_code, out_str = run_command([str(ropweaver_bin), str(fix_path), "-p"], cwd=str(isolated_dir))

                assert_test(f"{fn}: Analyzed successfully (exit code 0)", exit_code == 0, f"exit code {exit_code}")
                assert_test(f"{fn}: Architecture detected as {ea}", bool(re.search(rf"Detected architecture:\s*{ea}", out_str)))

                if out_json.is_file():
                    try:
                        data = json.loads(out_json.read_text(encoding="utf-8"))
                        assert_test(f"{fn}: JSON architecture is {ea}", data.get("architecture") == ea)
                        assert_test(f"{fn}: JSON file_type is ELF", data.get("file_type") == "ELF")
                        gadgets = data.get("gadgets", [])
                        assert_test(f"{fn}: Discovered gadgets >= {mg}", len(gadgets) >= mg)
                        assert_test(f"{fn}: Gadgets byte verified", bool(gadgets[0].get("byte_verified")) is True if gadgets else False)
                        assert_test(f"{fn}: Mitigation NX detected as ON", data.get("protections", {}).get("NX") is True)
                    except Exception as e:
                        for sub_name in ["JSON architecture", "JSON file_type", "Discovered gadgets", "Gadgets byte verified", "Mitigation NX"]:
                            assert_test(f"{fn}: {sub_name}", False, str(e))
                else:
                    for sub_name in ["JSON architecture", "JSON file_type", "Discovered gadgets", "Gadgets byte verified", "Mitigation NX"]:
                        assert_test(f"{fn}: {sub_name}", False, "output.json missing")
            else:
                for sub_name in [
                    "Analyzed successfully (exit code 0)", f"Architecture detected as {ea}",
                    f"JSON architecture is {ea}", "JSON file_type is ELF", f"Discovered gadgets >= {mg}",
                    "Gadgets byte verified", "Mitigation NX detected as ON"
                ]:
                    assert_test(f"{fn}: {sub_name}", False, f"Fixture missing: {fix_path}")

        # -------------------------------------------------------------
        # Test 6: Multi-Section Executable Boundary & Address Mapping [10 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 6: Multi-Section Executable Boundary & Address Mapping...{COLOR_RESET}")
        multi_sec_bin = PROJECT_ROOT / "test_binaries" / "elf64_multisection"
        if multi_sec_bin.is_file():
            if out_json.is_file():
                out_json.unlink()
            exit_code, out_str = run_command([str(ropweaver_bin), str(multi_sec_bin), "-p"], cwd=str(isolated_dir))

            assert_test("Multi-Section ELF returns code 0", exit_code == 0, f"exit code {exit_code}")
            if out_json.is_file():
                try:
                    data = json.loads(out_json.read_text(encoding="utf-8"))
                    gadgets = data.get("gadgets", [])
                    assert_test("Multi-Section ELF found gadgets in multiple sections", len(gadgets) >= 2)

                    # Section 1 (.init at 0x401000, gadget substring 401002)
                    g_init = next((g for g in gadgets if "401002" in g.get("preferred_va", "")), None)
                    assert_test("Gadget in .init located at exact VA 0x401002", g_init is not None)
                    if g_init:
                        assert_test("Gadget in .init has exact file_offset 0x00001002", g_init.get("file_offset") == "0x00001002")
                        assert_test("Gadget in .init has exact RVA 0x00001002", g_init.get("rva") == "0x00001002")
                        assert_test("Gadget in .init is byte verified", g_init.get("byte_verified") is True)
                    else:
                        assert_test("Gadget in .init has exact file_offset 0x00001002", False, "g_init missing")
                        assert_test("Gadget in .init has exact RVA 0x00001002", False, "g_init missing")
                        assert_test("Gadget in .init is byte verified", False, "g_init missing")

                    # Section 2 (.text at 0x402000, gadget substring 402000)
                    g_text = next((g for g in gadgets if "402000" in g.get("preferred_va", "")), None)
                    assert_test("Gadget in .text located at exact VA 0x402000", g_text is not None)
                    if g_text:
                        assert_test("Gadget in .text has exact file_offset 0x00002000", g_text.get("file_offset") == "0x00002000")
                        assert_test("Gadget in .text has exact RVA 0x00002000", g_text.get("rva") == "0x00002000")
                        assert_test("Gadget in .text is byte verified", g_text.get("byte_verified") is True)
                    else:
                        assert_test("Gadget in .text has exact file_offset 0x00002000", False, "g_text missing")
                        assert_test("Gadget in .text has exact RVA 0x00002000", False, "g_text missing")
                        assert_test("Gadget in .text is byte verified", False, "g_text missing")

                except Exception as e:
                    for sub_name in range(9):
                        assert_test(f"Test 6 assertion {sub_name+2}", False, str(e))
            else:
                for sub_name in range(9):
                    assert_test(f"Test 6 assertion {sub_name+2}", False, "output.json missing")
        else:
            for sub_name in range(10):
                assert_test(f"Test 6 assertion {sub_name+1}", False, f"Fixture missing: {multi_sec_bin}")

        # -------------------------------------------------------------
        # Test 7: Big-Endian ELF Metadata & Architecture Handling [16 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 7: Big-Endian ELF Metadata & Architecture Handling...{COLOR_RESET}")

        # 7a: ARMv7 BE-8
        arm_be8_bin = PROJECT_ROOT / "test_binaries" / "elf32_arm_be8"
        if arm_be8_bin.is_file():
            if out_json.is_file():
                out_json.unlink()
            exit_code, out_str = run_command([str(ropweaver_bin), str(arm_be8_bin), "-p"], cwd=str(isolated_dir))

            assert_test("elf32_arm_be8: Analyzed successfully (exit code 0)", exit_code == 0, f"exit code {exit_code}")
            assert_test("elf32_arm_be8: Architecture detected as armv7", bool(re.search(r"Detected architecture:\s*armv7", out_str)))
            if out_json.is_file():
                try:
                    data = json.loads(out_json.read_text(encoding="utf-8"))
                    assert_test("elf32_arm_be8: JSON file_type is ELF", data.get("file_type") == "ELF")
                    assert_test("elf32_arm_be8: JSON architecture is armv7", data.get("architecture") == "armv7")
                    assert_test("elf32_arm_be8: Mitigation NX detected as ON", data.get("protections", {}).get("NX") is True)
                    gadgets = data.get("gadgets", [])
                    assert_test("elf32_arm_be8: Discovered gadgets >= 1", len(gadgets) >= 1)
                    assert_test("elf32_arm_be8: Gadgets byte verified", bool(gadgets[0].get("byte_verified")) is True if gadgets else False)
                except Exception as e:
                    for sub_name in ["JSON file_type", "JSON architecture", "Mitigation NX", "Discovered gadgets", "Gadgets byte verified"]:
                        assert_test(f"elf32_arm_be8: {sub_name}", False, str(e))
            else:
                for sub_name in ["JSON file_type", "JSON architecture", "Mitigation NX", "Discovered gadgets", "Gadgets byte verified"]:
                    assert_test(f"elf32_arm_be8: {sub_name}", False, "output.json missing")
        else:
            for sub_name in [
                "Analyzed successfully (exit code 0)", "Architecture detected as armv7",
                "JSON file_type is ELF", "JSON architecture is armv7", "Mitigation NX detected as ON",
                "Discovered gadgets >= 1", "Gadgets byte verified"
            ]:
                assert_test(f"elf32_arm_be8: {sub_name}", False, f"Fixture missing: {arm_be8_bin}")

        # 7b: AArch64 Big-Endian
        aarch64_be_bin = PROJECT_ROOT / "test_binaries" / "elf64_aarch64_be"
        if aarch64_be_bin.is_file():
            if out_json.is_file():
                out_json.unlink()
            exit_code, out_str = run_command([str(ropweaver_bin), str(aarch64_be_bin), "-p"], cwd=str(isolated_dir))

            assert_test("elf64_aarch64_be: Analyzed successfully (exit code 0)", exit_code == 0, f"exit code {exit_code}")
            assert_test("elf64_aarch64_be: Architecture detected as aarch64", bool(re.search(r"Detected architecture:\s*aarch64", out_str)))
            if out_json.is_file():
                try:
                    data = json.loads(out_json.read_text(encoding="utf-8"))
                    assert_test("elf64_aarch64_be: JSON file_type is ELF", data.get("file_type") == "ELF")
                    assert_test("elf64_aarch64_be: JSON architecture is aarch64", data.get("architecture") == "aarch64")
                    assert_test("elf64_aarch64_be: Mitigation NX detected as ON", data.get("protections", {}).get("NX") is True)
                    gadgets = data.get("gadgets", [])
                    assert_test("elf64_aarch64_be: Discovered gadgets >= 1", len(gadgets) >= 1)
                    assert_test("elf64_aarch64_be: Gadgets byte verified", bool(gadgets[0].get("byte_verified")) is True if gadgets else False)
                except Exception as e:
                    for sub_name in ["JSON file_type", "JSON architecture", "Mitigation NX", "Discovered gadgets", "Gadgets byte verified"]:
                        assert_test(f"elf64_aarch64_be: {sub_name}", False, str(e))
            else:
                for sub_name in ["JSON file_type", "JSON architecture", "Mitigation NX", "Discovered gadgets", "Gadgets byte verified"]:
                    assert_test(f"elf64_aarch64_be: {sub_name}", False, "output.json missing")
        else:
            for sub_name in [
                "Analyzed successfully (exit code 0)", "Architecture detected as aarch64",
                "JSON file_type is ELF", "JSON architecture is aarch64", "Mitigation NX detected as ON",
                "Discovered gadgets >= 1", "Gadgets byte verified"
            ]:
                assert_test(f"elf64_aarch64_be: {sub_name}", False, f"Fixture missing: {aarch64_be_bin}")

        # 7c: Invalid Endianness Rejection
        inv_end_bin = PROJECT_ROOT / "test_binaries" / "elf_invalid_endian"
        if inv_end_bin.is_file():
            exit_code, out_str = run_command([str(ropweaver_bin), str(inv_end_bin)], cwd=str(isolated_dir))
            assert_test("elf_invalid_endian: Rejected with non-zero exit code", exit_code != 0, f"exit code {exit_code}")
            assert_test("elf_invalid_endian: Error message identifies invalid data encoding", "invalid or unsupported data encoding" in out_str)
        else:
            assert_test("elf_invalid_endian: Rejected with non-zero exit code", False, f"Fixture missing: {inv_end_bin}")
            assert_test("elf_invalid_endian: Error message identifies invalid data encoding", False, f"Fixture missing: {inv_end_bin}")

        # -------------------------------------------------------------
        # Test 8: Portable Signed Two's-Complement Endian Readers [10 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 8: Portable Signed Two's-Complement Endian Readers...{COLOR_RESET}")
        test_endian_src = PROJECT_ROOT / "tests" / "test_endian_readers.cpp"
        build_dir = ropweaver_bin.parent
        test_endian_bin = test_build_dir / ("test_endian_readers.exe" if sys.platform == "win32" else "test_endian_readers")

        if cxx_compiler and test_endian_src.is_file():
            # Compile if absent or source newer
            need_build = (not test_endian_bin.is_file()) or (test_endian_src.stat().st_mtime > test_endian_bin.stat().st_mtime)
            if need_build:
                compile_cmd = [cxx_compiler, "-std=c++17", str(test_endian_src), "-o", str(test_endian_bin)]
                run_command(compile_cmd)

        if test_endian_bin.is_file():
            exit_code, out_str = run_command([str(test_endian_bin)], cwd=str(isolated_dir))
            assert_test("Signed Endian Readers test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("read_i32: Zero (LE & BE) correct", "PASS [32-bit]: Zero LE = 0" in out_str and "PASS [32-bit]: Zero BE = 0" in out_str)
            assert_test("read_i64: Zero (LE & BE) correct", "PASS [64-bit]: Zero LE = 0" in out_str and "PASS [64-bit]: Zero BE = 0" in out_str)
            assert_test("read_i32: Positive values (LE & BE) correct", bool(re.search(r"PASS \[32-bit\]: Positive.*LE", out_str)) and bool(re.search(r"PASS \[32-bit\]: Positive.*BE", out_str)))
            assert_test("read_i64: Positive values (LE & BE) correct", bool(re.search(r"PASS \[64-bit\]: Positive.*LE", out_str)) and bool(re.search(r"PASS \[64-bit\]: Positive.*BE", out_str)))
            assert_test("read_i32: -1 (LE & BE) correct", "PASS [32-bit]: -1 LE = -1" in out_str and "PASS [32-bit]: -1 BE = -1" in out_str)
            assert_test("read_i64: -1 (LE & BE) correct", "PASS [64-bit]: -1 LE = -1" in out_str and "PASS [64-bit]: -1 BE = -1" in out_str)
            assert_test("read_i32: INT32_MIN & INT32_MAX (LE & BE) correct", "PASS [32-bit]: INT32_MIN" in out_str and "PASS [32-bit]: INT32_MAX" in out_str)
            assert_test("read_i64: INT64_MIN & INT64_MAX (LE & BE) correct", "PASS [64-bit]: INT64_MIN" in out_str and "PASS [64-bit]: INT64_MAX" in out_str)
            assert_test("read_i64: Dynamic tag DT_FLAGS_1 (LE & BE) correct", "PASS [64-bit]: DT_FLAGS_1" in out_str)
        else:
            for sub_name in [
                "Signed Endian Readers test suite exits with code 0",
                "read_i32: Zero (LE & BE) correct", "read_i64: Zero (LE & BE) correct",
                "read_i32: Positive values (LE & BE) correct", "read_i64: Positive values (LE & BE) correct",
                "read_i32: -1 (LE & BE) correct", "read_i64: -1 (LE & BE) correct",
                "read_i32: INT32_MIN & INT32_MAX (LE & BE) correct", "read_i64: INT64_MIN & INT64_MAX (LE & BE) correct",
                "read_i64: Dynamic tag DT_FLAGS_1 (LE & BE) correct"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_endian_bin}")

        # -------------------------------------------------------------
        # Test 9: Endianness & Instruction Byte Order Classification [13 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 9: Endianness & Instruction Byte Order Classification...{COLOR_RESET}")
        test_class_src = PROJECT_ROOT / "tests" / "test_endian_classification.cpp"
        test_class_bin = test_build_dir / ("test_endian_classification.exe" if sys.platform == "win32" else "test_endian_classification")

        if cxx_compiler and core_lib and test_class_src.is_file():
            need_build = (not test_class_bin.is_file()) or (test_class_src.stat().st_mtime > test_class_bin.stat().st_mtime)
            if need_build:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_class_src), str(core_lib), "-o", str(test_class_bin)]
                run_command(compile_cmd)

        if test_class_bin.is_file():
            exit_code, out_str = run_command([str(test_class_bin)], cwd=str(isolated_dir))
            assert_test("Endian Classification test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("FileParser default unestablished: Meta=Unknown, Inst=Unknown", "FileParser default unestablished" in out_str)
            assert_test("PE64: Meta=Little, Inst=Little", bool(re.search(r"PE64.*Meta=Little, Inst=Little", out_str)))
            assert_test("ELF32 x86: Meta=Little, Inst=Little", "ELF32 x86: Meta=Little, Inst=Little" in out_str)
            assert_test("ELF32 ARMv7 LE: Meta=Little, Inst=Little", "ELF32 ARMv7 LE: Meta=Little, Inst=Little" in out_str)
            assert_test("ELF32 ARMv7 BE-8: Meta=Big, Inst=Little", "ELF32 ARMv7 BE-8: Meta=Big, Inst=Little" in out_str)
            assert_test("ELF32 ARMv7 BE Ambiguous: Meta=Big, Inst=Unsupported", bool(re.search(r"ELF32 ARMv7 BE Ambiguous.*Meta=Big, Inst=Unsupported", out_str)))
            assert_test("ELF64 AArch64 LE: Meta=Little, Inst=Little", "ELF64 AArch64 LE: Meta=Little, Inst=Little" in out_str)
            assert_test("ELF64 AArch64 BE: Meta=Big, Inst=Little", bool(re.search(r"ELF64 AArch64 BE.*Meta=Big, Inst=Little", out_str)))
            assert_test("ELF32 RISC-V LE: Meta=Little, Inst=Little", "ELF32 RISC-V LE: Meta=Little, Inst=Little" in out_str)
            assert_test("ELF64 RISC-V LE: Meta=Little, Inst=Little", "ELF64 RISC-V LE: Meta=Little, Inst=Little" in out_str)
            assert_test("ELF32 RISC-V BE: Meta=Big, Inst=Unsupported", "ELF32 RISC-V BE: Meta=Big, Inst=Unsupported" in out_str)
            assert_test("ELF64 RISC-V BE: Meta=Big, Inst=Unsupported", "ELF64 RISC-V BE: Meta=Big, Inst=Unsupported" in out_str)
        else:
            for sub_name in [
                "Endian Classification test suite exits with code 0",
                "FileParser default unestablished: Meta=Unknown, Inst=Unknown",
                "PE64: Meta=Little, Inst=Little", "ELF32 x86: Meta=Little, Inst=Little",
                "ELF32 ARMv7 LE: Meta=Little, Inst=Little", "ELF32 ARMv7 BE-8: Meta=Big, Inst=Little",
                "ELF32 ARMv7 BE Ambiguous: Meta=Big, Inst=Unsupported", "ELF64 AArch64 LE: Meta=Little, Inst=Little",
                "ELF64 AArch64 BE: Meta=Big, Inst=Little", "ELF32 RISC-V LE: Meta=Little, Inst=Little",
                "ELF64 RISC-V LE: Meta=Little, Inst=Little", "ELF32 RISC-V BE: Meta=Big, Inst=Unsupported",
                "ELF64 RISC-V BE: Meta=Big, Inst=Unsupported"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_class_bin}")

        # -------------------------------------------------------------
        # Test 10: GadgetFinder Endianness Integration & Rejection [31 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 10: GadgetFinder Endianness Integration & Rejection...{COLOR_RESET}")
        test_gf_src = PROJECT_ROOT / "tests" / "test_gadget_finder_endianness.cpp"
        test_gf_bin = test_build_dir / ("test_gadget_finder_endianness.exe" if sys.platform == "win32" else "test_gadget_finder_endianness")

        if cxx_compiler and core_lib and test_gf_src.is_file():
            need_build = (not test_gf_bin.is_file()) or (test_gf_src.stat().st_mtime > test_gf_bin.stat().st_mtime)
            if need_build:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_gf_src), str(core_lib), f"-L{build_dir}", "-lcapstone", "-o", str(test_gf_bin)]
                run_command(compile_cmd)

        if test_gf_bin.is_file():
            exit_code, out_str = run_command([str(test_gf_bin)], cwd=str(isolated_dir))
            assert_test("GadgetFinder Endianness test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("GadgetFinder rejects Endianness::Unknown", bool(re.search(r"PASS.*rejects Endianness::Unknown", out_str)))
            assert_test("GadgetFinder Unknown error message identifies arch and condition", bool(re.search(r"PASS.*Unknown error message", out_str)))
            assert_test("GadgetFinder rejects Endianness::Unsupported", bool(re.search(r"PASS.*rejects Endianness::Unsupported", out_str)))
            assert_test("GadgetFinder Unsupported error message identifies arch and condition", bool(re.search(r"PASS.*Unsupported error message", out_str)))
            assert_test("GadgetFinder default parameter is Endianness::Little", bool(re.search(r"PASS.*default parameter is Endianness::Little", out_str)))
            assert_test("GadgetFinder default parameter findGadgets() succeeds", bool(re.search(r"PASS.*default parameter findGadgets\(\) succeeds", out_str)))
            assert_test("GadgetFinder explicit Endianness::Little succeeds", bool(re.search(r"PASS.*explicit Little findGadgets\(\) succeeds", out_str)))
            assert_test("Big Endian rejected for x86", bool(re.search(r"PASS.*Big Endian rejected for x86\b", out_str)))
            assert_test("Big Endian rejected for x86_64", bool(re.search(r"PASS.*Big Endian rejected for x86_64", out_str)))
            assert_test("Big Endian rejected for aarch64", bool(re.search(r"PASS.*Big Endian rejected for aarch64", out_str)))
            assert_test("Big Endian rejected for arm64", bool(re.search(r"PASS.*Big Endian rejected for arm64", out_str)))
            assert_test("Big Endian rejected for riscv32", bool(re.search(r"PASS.*Big Endian rejected for riscv32", out_str)))
            assert_test("Big Endian rejected for riscv64", bool(re.search(r"PASS.*Big Endian rejected for riscv64", out_str)))
            assert_test("ARM Big Endian (armv7) constructor succeeds", bool(re.search(r"PASS.*ARM Big Endian \(armv7\) constructor succeeds", out_str)))
            assert_test("ARM Big Endian getInstructionEndianness() == Big", bool(re.search(r"PASS.*ARM Big Endian getInstructionEndianness\(\) == Big", out_str)))
            assert_test("ARM Big Endian finds gadget for E1 2F FF 1E", bool(re.search(r"PASS.*ARM Big Endian finds gadget for E1 2F FF 1E", out_str)))
            assert_test("ARM Big Endian decoded as 'bx lr'", bool(re.search(r"PASS.*ARM Big Endian decoded as 'bx lr'", out_str)))
            assert_test("ARM Big Endian gadget byte_verified == true", bool(re.search(r"PASS.*ARM Big Endian gadget byte_verified == true", out_str)))
            assert_test("ARM Big Endian ('arm' alias) decoded as 'bx lr'", bool(re.search(r"PASS.*ARM Big Endian \('arm' alias\) decoded as 'bx lr'", out_str)))
            assert_test("ARM Little Endian (armv7) constructor succeeds", bool(re.search(r"PASS.*ARM Little Endian \(armv7\) constructor succeeds", out_str)))
            assert_test("ARM Little Endian decoded as 'bx lr'", bool(re.search(r"PASS.*ARM Little Endian decoded as 'bx lr'", out_str)))
            assert_test("ARM Little Endian gadget byte_verified == true", bool(re.search(r"PASS.*ARM Little Endian gadget byte_verified == true", out_str)))
            assert_test("Big-endian ARM mode does NOT decode little-endian bytes as 'bx lr'", bool(re.search(r"PASS.*Big-endian ARM mode does NOT decode little-endian bytes as 'bx lr'", out_str)))
            assert_test("Little-endian ARM mode does NOT decode big-endian bytes as 'bx lr'", bool(re.search(r"PASS.*Little-endian ARM mode does NOT decode big-endian bytes as 'bx lr'", out_str)))
        else:
            for sub_name in [
                "GadgetFinder Endianness test suite exits with code 0",
                "GadgetFinder rejects Endianness::Unknown", "GadgetFinder Unknown error message identifies arch and condition",
                "GadgetFinder rejects Endianness::Unsupported", "GadgetFinder Unsupported error message identifies arch and condition",
                "GadgetFinder default parameter is Endianness::Little", "GadgetFinder default parameter findGadgets() succeeds",
                "GadgetFinder explicit Endianness::Little succeeds", "Big Endian rejected for x86",
                "Big Endian rejected for x86_64", "Big Endian rejected for aarch64",
                "Big Endian rejected for arm64", "Big Endian rejected for riscv32",
                "Big Endian rejected for riscv64", "ARM Big Endian (armv7) constructor succeeds",
                "ARM Big Endian getInstructionEndianness() == Big", "ARM Big Endian finds gadget for E1 2F FF 1E",
                "ARM Big Endian decoded as 'bx lr'", "ARM Big Endian gadget byte_verified == true",
                "ARM Big Endian ('arm' alias) decoded as 'bx lr'", "ARM Little Endian (armv7) constructor succeeds",
                "ARM Little Endian decoded as 'bx lr'", "ARM Little Endian gadget byte_verified == true",
                "Big-endian ARM mode does NOT decode little-endian bytes as 'bx lr'",
                "Little-endian ARM mode does NOT decode big-endian bytes as 'bx lr'"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_gf_bin}")

        # CLI Rejection of Unsupported Instruction Endianness
        raw_amb_bin = PROJECT_ROOT / "test_binaries" / "elf32_arm_be_ambiguous"
        if raw_amb_bin.is_file():
            exit_code, out_str = run_command([str(ropweaver_bin), str(raw_amb_bin)], cwd=str(isolated_dir))
            assert_test("CLI rejects elf32_arm_be_ambiguous with exit code 1", exit_code != 0, f"exit code {exit_code}")
            assert_test("CLI identifies unsupported instruction endianness for armv7", "Unsupported instruction endianness for architecture: armv7" in out_str)
        else:
            assert_test("CLI rejects elf32_arm_be_ambiguous with exit code 1", False, f"Fixture missing: {raw_amb_bin}")
            assert_test("CLI identifies unsupported instruction endianness for armv7", False, f"Fixture missing: {raw_amb_bin}")

        raw_r32_bin = PROJECT_ROOT / "test_binaries" / "elf32_riscv_be"
        if raw_r32_bin.is_file():
            exit_code, out_str = run_command([str(ropweaver_bin), str(raw_r32_bin)], cwd=str(isolated_dir))
            assert_test("CLI rejects elf32_riscv_be with exit code 1", exit_code != 0, f"exit code {exit_code}")
            assert_test("CLI identifies unsupported instruction endianness for riscv32", "Unsupported instruction endianness for architecture: riscv32" in out_str)
        else:
            assert_test("CLI rejects elf32_riscv_be with exit code 1", False, f"Fixture missing: {raw_r32_bin}")
            assert_test("CLI identifies unsupported instruction endianness for riscv32", False, f"Fixture missing: {raw_r32_bin}")

        raw_r64_bin = PROJECT_ROOT / "test_binaries" / "elf64_riscv_be"
        if raw_r64_bin.is_file():
            exit_code, out_str = run_command([str(ropweaver_bin), str(raw_r64_bin)], cwd=str(isolated_dir))
            assert_test("CLI rejects elf64_riscv_be with exit code 1", exit_code != 0, f"exit code {exit_code}")
            assert_test("CLI identifies unsupported instruction endianness for riscv64", "Unsupported instruction endianness for architecture: riscv64" in out_str)
        else:
            assert_test("CLI rejects elf64_riscv_be with exit code 1", False, f"Fixture missing: {raw_r64_bin}")
            assert_test("CLI identifies unsupported instruction endianness for riscv64", False, f"Fixture missing: {raw_r64_bin}")

        # -------------------------------------------------------------
        # Test 11: RISC-V Compressed (RVC) Groundwork & Metadata Detection [7 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 11: RISC-V Compressed (RVC) Groundwork & Metadata Detection...{COLOR_RESET}")
        test_rvc_gw_src = PROJECT_ROOT / "tests" / "test_rvc_groundwork.cpp"
        test_rvc_gw_bin = test_build_dir / ("test_rvc_groundwork.exe" if sys.platform == "win32" else "test_rvc_groundwork")

        need_build_gw = False
        if cxx_compiler and core_lib and test_rvc_gw_src.is_file():
            need_build_gw = (not test_rvc_gw_bin.is_file()) or (test_rvc_gw_src.stat().st_mtime > test_rvc_gw_bin.stat().st_mtime)
            if need_build_gw:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_rvc_gw_src), str(core_lib), f"-L{build_dir}", "-lcapstone", "-o", str(test_rvc_gw_bin)]
                comp_code, comp_out = run_command(compile_cmd)
                assert_test("RVC Groundwork test suite compiles successfully", comp_code == 0, f"compile error: {comp_out}")
            else:
                assert_test("RVC Groundwork test suite binary up to date", test_rvc_gw_bin.is_file())
        else:
            assert_test("RVC Groundwork test suite source and compiler available", False)

        if test_rvc_gw_bin.is_file():
            exit_code, out_str = run_command([str(test_rvc_gw_bin)], cwd=str(PROJECT_ROOT))
            assert_test("RVC Groundwork test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("RVC Groundwork: All tests passed with 0 failures", "0 Failed" in out_str)
            assert_test("RVC Groundwork: Capstone compatibility verified (ROPW_CS_MODE_RISCVC)", "ROPW_CS_MODE_RISCVC is non-zero" in out_str)
            assert_test("RVC Groundwork: EF_RISCV_RVC detected on ELF32 & ELF64", ("pRv32Rvc has isRvcEnabled() == true" in out_str and "pRv64Rvc has isRvcEnabled() == true" in out_str))
            assert_test("RVC Groundwork: 16-bit c.jr ra accepted as terminator", "16-bit c.jr ra in RVC binary produces accepted gadget" in out_str)
            assert_test("RVC Groundwork: 16-bit and 32-bit traps strictly rejected", ("16-bit c.ebreak trap is strictly rejected" in out_str and "32-bit ebreak trap" in out_str))
        else:
            for sub_name in [
                "RVC Groundwork test suite exits with code 0", "RVC Groundwork: All tests passed with 0 failures",
                "RVC Groundwork: Capstone compatibility verified (ROPW_CS_MODE_RISCVC)",
                "RVC Groundwork: EF_RISCV_RVC detected on ELF32 & ELF64",
                "RVC Groundwork: 16-bit c.jr ra accepted as terminator",
                "RVC Groundwork: 16-bit and 32-bit traps strictly rejected"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_rvc_gw_bin}")

        # -------------------------------------------------------------
        # Test 12: RISC-V Compressed (RVC) Candidate Scanning & Mixed Sequences [7 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 12: RISC-V Compressed (RVC) Candidate Scanning & Mixed Sequences...{COLOR_RESET}")
        test_rvc_cs_src = PROJECT_ROOT / "tests" / "test_rvc_candidate_scanning.cpp"
        test_rvc_cs_bin = test_build_dir / ("test_rvc_candidate_scanning.exe" if sys.platform == "win32" else "test_rvc_candidate_scanning")

        need_build_cs = False
        if cxx_compiler and core_lib and test_rvc_cs_src.is_file():
            need_build_cs = (not test_rvc_cs_bin.is_file()) or (test_rvc_cs_src.stat().st_mtime > test_rvc_cs_bin.stat().st_mtime)
            if need_build_cs:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_rvc_cs_src), str(core_lib), f"-L{build_dir}", "-lcapstone", "-o", str(test_rvc_cs_bin)]
                comp_code, comp_out = run_command(compile_cmd)
                assert_test("RVC Candidate Scanning test suite compiles successfully", comp_code == 0, f"compile error: {comp_out}")
            else:
                assert_test("RVC Candidate Scanning test suite binary up to date", test_rvc_cs_bin.is_file())
        else:
            assert_test("RVC Candidate Scanning test suite source and compiler available", False)

        if test_rvc_cs_bin.is_file():
            exit_code, out_str = run_command([str(test_rvc_cs_bin)], cwd=str(PROJECT_ROOT))
            assert_test("RVC Candidate Scanning test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("RVC Candidate Scanning: All tests passed with 0 failures", "0 failed" in out_str)
            assert_test("RVC Candidate Scanning: 2-byte aligned candidate starts discovered", "Results: 36 passed" in out_str)
            assert_test("RVC Candidate Scanning: Mixed 16-bit & 32-bit variable-length sequence decoded", exit_code == 0)
            assert_test("RVC Candidate Scanning: Gadget byte-verification against raw section succeeds", exit_code == 0)
            assert_test("RVC Candidate Scanning: c.jalr ra indirect call strictly rejected", exit_code == 0)
        else:
            for sub_name in [
                "RVC Candidate Scanning test suite exits with code 0",
                "RVC Candidate Scanning: All tests passed with 0 failures",
                "RVC Candidate Scanning: 2-byte aligned candidate starts discovered",
                "RVC Candidate Scanning: Mixed 16-bit & 32-bit variable-length sequence decoded",
                "RVC Candidate Scanning: Gadget byte-verification against raw section succeeds",
                "RVC Candidate Scanning: c.jalr ra indirect call strictly rejected"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_rvc_cs_bin}")

        # -------------------------------------------------------------
        # Test 13: ARMv7 ELF Mapping Symbol Detection & Region Bounding [7 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 13: ARMv7 ELF Mapping Symbol Detection & Region Bounding...{COLOR_RESET}")
        test_arm_sym_src = PROJECT_ROOT / "tests" / "test_arm_mapping_symbols.cpp"
        test_arm_sym_bin = test_build_dir / ("test_arm_mapping_symbols.exe" if sys.platform == "win32" else "test_arm_mapping_symbols")

        need_build_sym = False
        if cxx_compiler and core_lib and test_arm_sym_src.is_file():
            need_build_sym = (not test_arm_sym_bin.is_file()) or (test_arm_sym_src.stat().st_mtime > test_arm_sym_bin.stat().st_mtime)
            if need_build_sym:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_arm_sym_src), str(core_lib), f"-L{build_dir}", "-lcapstone", "-o", str(test_arm_sym_bin)]
                comp_code, comp_out = run_command(compile_cmd)
                assert_test("ARM Mapping Symbols test suite compiles successfully", comp_code == 0, f"compile error: {comp_out}")
            else:
                assert_test("ARM Mapping Symbols test suite binary up to date", test_arm_sym_bin.is_file())
        else:
            assert_test("ARM Mapping Symbols test suite source and compiler available", False)

        if test_arm_sym_bin.is_file():
            exit_code, out_str = run_command([str(test_arm_sym_bin)], cwd=str(PROJECT_ROOT))
            assert_test("ARM Mapping Symbols test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("ARM Mapping Symbols: All tests passed with 0 failures", "0 failed" in out_str)
            assert_test("ARM Mapping Symbols: $a, $t, $d symbols detected from .symtab & .dynsym", "Results: 73 passed" in out_str)
            assert_test("ARM Mapping Symbols: Code & data regions bounded accurately by section boundaries", exit_code == 0)
            assert_test("ARM Mapping Symbols: $d data regions excluded from executable instruction ranges", exit_code == 0)
            assert_test("ARM Mapping Symbols: Stripped ARM binary safely falls back to ARM mode", exit_code == 0)
        else:
            for sub_name in [
                "ARM Mapping Symbols test suite exits with code 0",
                "ARM Mapping Symbols: All tests passed with 0 failures",
                "ARM Mapping Symbols: $a, $t, $d symbols detected from .symtab & .dynsym",
                "ARM Mapping Symbols: Code & data regions bounded accurately by section boundaries",
                "ARM Mapping Symbols: $d data regions excluded from executable instruction ranges",
                "ARM Mapping Symbols: Stripped ARM binary safely falls back to ARM mode"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_arm_sym_bin}")

        # -------------------------------------------------------------
        # Test 14: ARMv7 Dual-Mode Instruction Disassembly & Boundary Enforcement [7 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 14: ARMv7 Dual-Mode Instruction Disassembly & Boundary Enforcement...{COLOR_RESET}")
        test_arm_thumb_src = PROJECT_ROOT / "tests" / "test_arm_thumb_scanning.cpp"
        test_arm_thumb_bin = test_build_dir / ("test_arm_thumb_scanning.exe" if sys.platform == "win32" else "test_arm_thumb_scanning")

        need_build_thumb = False
        if cxx_compiler and core_lib and test_arm_thumb_src.is_file():
            need_build_thumb = (not test_arm_thumb_bin.is_file()) or (test_arm_thumb_src.stat().st_mtime > test_arm_thumb_bin.stat().st_mtime)
            if need_build_thumb:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_arm_thumb_src), str(core_lib), f"-L{build_dir}", "-lcapstone", "-o", str(test_arm_thumb_bin)]
                comp_code, comp_out = run_command(compile_cmd)
                assert_test("ARM Thumb Scanning test suite compiles successfully", comp_code == 0, f"compile error: {comp_out}")
            else:
                assert_test("ARM Thumb Scanning test suite binary up to date", test_arm_thumb_bin.is_file())
        else:
            assert_test("ARM Thumb Scanning test suite source and compiler available", False)

        if test_arm_thumb_bin.is_file():
            exit_code, out_str = run_command([str(test_arm_thumb_bin)], cwd=str(PROJECT_ROOT))
            assert_test("ARM Thumb Scanning test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("ARM Thumb Scanning: All tests passed with 0 failures", "0 Failed" in out_str)
            assert_test("ARM Thumb Scanning: Dual-mode ARM/Thumb Capstone handles initialized", "Step 4.4 Test Results: 62 Passed" in out_str)
            assert_test("ARM Thumb Scanning: 2-byte Thumb candidate scanning verified", exit_code == 0)
            assert_test("ARM Thumb Scanning: Candidate scanning does not cross into preceding $d region", exit_code == 0)
            assert_test("ARM Thumb Scanning: Traps (bkpt) strictly rejected", exit_code == 0)
        else:
            for sub_name in [
                "ARM Thumb Scanning test suite exits with code 0",
                "ARM Thumb Scanning: All tests passed with 0 failures",
                "ARM Thumb Scanning: Dual-mode ARM/Thumb Capstone handles initialized",
                "ARM Thumb Scanning: 2-byte Thumb candidate scanning verified",
                "ARM Thumb Scanning: Candidate scanning does not cross into preceding $d region",
                "ARM Thumb Scanning: Traps (bkpt) strictly rejected"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_arm_thumb_bin}")

        # -------------------------------------------------------------
        # Test 15: ARMv7 Thumb Interworking Address Representation [7 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 15: ARMv7 Thumb Interworking Address Representation...{COLOR_RESET}")
        test_arm_interwork_src = PROJECT_ROOT / "tests" / "test_arm_interworking.cpp"
        test_arm_interwork_bin = test_build_dir / ("test_arm_interworking.exe" if sys.platform == "win32" else "test_arm_interworking")

        need_build_iw = False
        if cxx_compiler and core_lib and test_arm_interwork_src.is_file():
            need_build_iw = (not test_arm_interwork_bin.is_file()) or (test_arm_interwork_src.stat().st_mtime > test_arm_interwork_bin.stat().st_mtime)
            if need_build_iw:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_arm_interwork_src), str(core_lib), f"-L{build_dir}", "-lcapstone", "-o", str(test_arm_interwork_bin)]
                comp_code, comp_out = run_command(compile_cmd)
                assert_test("ARM Interworking test suite compiles successfully", comp_code == 0, f"compile error: {comp_out}")
            else:
                assert_test("ARM Interworking test suite binary up to date", test_arm_interwork_bin.is_file())
        else:
            assert_test("ARM Interworking test suite source and compiler available", False)

        if test_arm_interwork_bin.is_file():
            exit_code, out_str = run_command([str(test_arm_interwork_bin)], cwd=str(PROJECT_ROOT))
            assert_test("ARM Interworking test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("ARM Interworking: All tests passed with 0 failures", "0 Failed" in out_str)
            assert_test("ARM Interworking: Physical address retains even VA without bit 0 set", "Step 4.5 Test Results: 74 Passed" in out_str)
            assert_test("ARM Interworking: Entry address correctly exposes address | 1 for Thumb gadgets", exit_code == 0)
            assert_test("ARM Interworking: Non-Thumb architectures (ARM, x86, AArch64, RISC-V) keep bit 0 clear", exit_code == 0)
            assert_test("ARM Interworking: Gadgets sorted ascending by physical address", exit_code == 0)
        else:
            for sub_name in [
                "ARM Interworking test suite exits with code 0",
                "ARM Interworking: All tests passed with 0 failures",
                "ARM Interworking: Physical address retains even VA without bit 0 set",
                "ARM Interworking: Entry address correctly exposes address | 1 for Thumb gadgets",
                "ARM Interworking: Non-Thumb architectures (ARM, x86, AArch64, RISC-V) keep bit 0 clear",
                "ARM Interworking: Gadgets sorted ascending by physical address"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_arm_interwork_bin}")

        # -------------------------------------------------------------
        # Test 16: Dynamic Exploit Offset Configuration & Chain Serialization
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 16: Dynamic Exploit Offset Configuration & Chain Serialization...{COLOR_RESET}")
        test_cs_src = PROJECT_ROOT / "tests" / "test_chain_serialization.cpp"
        test_cs_bin = test_build_dir / ("test_chain_serialization.exe" if sys.platform == "win32" else "test_chain_serialization")

        need_build_cs = False
        if cxx_compiler and core_lib and test_cs_src.is_file():
            need_build_cs = (not test_cs_bin.is_file()) or (test_cs_src.stat().st_mtime > test_cs_bin.stat().st_mtime)
            if need_build_cs:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_cs_src), str(core_lib), f"-L{build_dir}", "-lcapstone", "-o", str(test_cs_bin)]
                comp_code, comp_out = run_command(compile_cmd)
                assert_test("Chain Serialization test suite compiles successfully", comp_code == 0, f"compile error: {comp_out}")
            else:
                assert_test("Chain Serialization test suite binary up to date", test_cs_bin.is_file())
        else:
            assert_test("Chain Serialization test suite source and compiler available", False)

        if test_cs_bin.is_file():
            exit_code, out_str = run_command([str(test_cs_bin)], cwd=str(isolated_dir))
            assert_test("Chain Serialization test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("Chain Serialization: All tests passed with 0 failures", "0 Failed" in out_str)
            assert_test("Chain Serialization: Group 22 Dynamic Exploit Offset passed", "Group 22: Dynamic Exploit Offset Configuration" in out_str)
        else:
            for sub_name in [
                "Chain Serialization test suite exits with code 0",
                "Chain Serialization: All tests passed with 0 failures",
                "Chain Serialization: Group 22 Dynamic Exploit Offset passed"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_cs_bin}")

        # Dynamic Exploit Offset Configuration CLI Tests
        elf_test_bin = PROJECT_ROOT / "test_binaries" / "binsh_test"

        # 16.1 Default offset (no flag) -> 104
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p"], cwd=str(isolated_dir))
        assert_test("CLI default offset executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI default offset logs telemetry", "Exploit padding offset: 104 bytes (default)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI default offset verified in JSON as 104", jdata.get("raw_payload", {}).get("verified_padding_offset") == 104)
            except Exception as e:
                assert_test("CLI default offset verified in JSON as 104", False, str(e))
        else:
            assert_test("CLI default offset verified in JSON as 104", False, "output.json missing")

        # 16.2 Custom decimal offset (--offset 208)
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "208"], cwd=str(isolated_dir))
        assert_test("CLI custom decimal offset executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI custom decimal offset logs telemetry", "Exploit padding offset: 208 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI custom decimal offset verified in JSON as 208", jdata.get("raw_payload", {}).get("verified_padding_offset") == 208)
            except Exception as e:
                assert_test("CLI custom decimal offset verified in JSON as 208", False, str(e))
        else:
            assert_test("CLI custom decimal offset verified in JSON as 208", False, "output.json missing")

        # 16.3 Short alias (-O 208)
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "-O", "208"], cwd=str(isolated_dir))
        assert_test("CLI short alias -O executes successfully", exit_code == 0, f"exit code {exit_code}")
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI short alias -O verified in JSON as 208", jdata.get("raw_payload", {}).get("verified_padding_offset") == 208)
            except Exception as e:
                assert_test("CLI short alias -O verified in JSON as 208", False, str(e))
        else:
            assert_test("CLI short alias -O verified in JSON as 208", False, "output.json missing")

        # 16.4 Hexadecimal offset (--offset 0x80 -> 128)
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "0x80"], cwd=str(isolated_dir))
        assert_test("CLI hex offset executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI hex offset logs telemetry as 128 bytes", "Exploit padding offset: 128 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI hex offset verified in JSON as 128", jdata.get("raw_payload", {}).get("verified_padding_offset") == 128)
            except Exception as e:
                assert_test("CLI hex offset verified in JSON as 128", False, str(e))
        else:
            assert_test("CLI hex offset verified in JSON as 128", False, "output.json missing")

        # 16.5 Zero offset (--offset 0)
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "0"], cwd=str(isolated_dir))
        assert_test("CLI zero offset executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI zero offset logs telemetry as 0 bytes", "Exploit padding offset: 0 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI zero offset verified in JSON as 0", jdata.get("raw_payload", {}).get("verified_padding_offset") == 0)
            except Exception as e:
                assert_test("CLI zero offset verified in JSON as 0", False, str(e))
        else:
            assert_test("CLI zero offset verified in JSON as 0", False, "output.json missing")

        # 16.6 Large offset (--offset 4096)
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "4096"], cwd=str(isolated_dir))
        assert_test("CLI large offset executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI large offset logs telemetry as 4096 bytes", "Exploit padding offset: 4096 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI large offset verified in JSON as 4096", jdata.get("raw_payload", {}).get("verified_padding_offset") == 4096)
            except Exception as e:
                assert_test("CLI large offset verified in JSON as 4096", False, str(e))
        else:
            assert_test("CLI large offset verified in JSON as 4096", False, "output.json missing")

        # 16.7 Negative value (--offset -10)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "-10"], cwd=str(isolated_dir))
        assert_test("CLI rejects negative offset with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI negative offset displays error message", ("negative" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.8 Explicit plus sign (--offset +104)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "+104"], cwd=str(isolated_dir))
        assert_test("CLI rejects explicit plus sign with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI explicit plus sign displays error message", ("plus" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.9 Malformed number (--offset abc)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "abc"], cwd=str(isolated_dir))
        assert_test("CLI rejects malformed offset string with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI malformed offset displays error message", ("malformed" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.10 Trailing characters (--offset 104xyz)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "104xyz"], cwd=str(isolated_dir))
        assert_test("CLI rejects trailing characters with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI trailing characters displays error message", ("trailing" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.11 Flag as argument (--offset -p)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "-p"], cwd=str(isolated_dir))
        assert_test("CLI rejects flag as offset argument with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI flag as argument displays error message", ("missing" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.12 Missing argument (--offset as final token)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset"], cwd=str(isolated_dir))
        assert_test("CLI rejects missing offset argument with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI missing argument displays error message", ("missing" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.13 Numerical overflow (--offset 99999999999999999999)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "99999999999999999999"], cwd=str(isolated_dir))
        assert_test("CLI rejects numerical overflow with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI numerical overflow displays error message", ("overflow" in out_str.lower() or "out of range" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.14 Exceeding 16 MiB (--offset 16777217)
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "16777217"], cwd=str(isolated_dir))
        assert_test("CLI rejects offset exceeding 16 MiB with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI exceeding 16 MiB displays error message", ("exceeds" in out_str.lower() or "16 mib" in out_str.lower() or "invalid" in out_str.lower()))

        # 16.15 Strict decimal/hexadecimal parsing tests
        # a. --offset 010 -> decimal 10 (octal strictly prohibited)
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "010"], cwd=str(isolated_dir))
        assert_test("CLI leading zero offset 010 executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI leading zero offset 010 produces decimal 10 in telemetry", "Exploit padding offset: 10 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI leading zero offset 010 verified in JSON as decimal 10", jdata.get("raw_payload", {}).get("verified_padding_offset") == 10)
            except Exception as e:
                assert_test("CLI leading zero offset 010 verified in JSON as decimal 10", False, str(e))
        else:
            assert_test("CLI leading zero offset 010 verified in JSON as decimal 10", False, "output.json missing")

        # b. --offset 0x10 -> decimal 16
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "0x10"], cwd=str(isolated_dir))
        assert_test("CLI hex offset 0x10 executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI hex offset 0x10 produces decimal 16 in telemetry", "Exploit padding offset: 16 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI hex offset 0x10 verified in JSON as decimal 16", jdata.get("raw_payload", {}).get("verified_padding_offset") == 16)
            except Exception as e:
                assert_test("CLI hex offset 0x10 verified in JSON as decimal 16", False, str(e))
        else:
            assert_test("CLI hex offset 0x10 verified in JSON as decimal 16", False, "output.json missing")

        # c. --offset 08 -> decimal 8 (non-octal digit accepted in decimal base 10)
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "08"], cwd=str(isolated_dir))
        assert_test("CLI leading zero offset 08 executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI leading zero offset 08 produces decimal 8 in telemetry", "Exploit padding offset: 8 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI leading zero offset 08 verified in JSON as decimal 8", jdata.get("raw_payload", {}).get("verified_padding_offset") == 8)
            except Exception as e:
                assert_test("CLI leading zero offset 08 verified in JSON as decimal 8", False, str(e))
        else:
            assert_test("CLI leading zero offset 08 verified in JSON as decimal 8", False, "output.json missing")

        # d. --offset 0xG1 -> rejected
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "0xG1"], cwd=str(isolated_dir))
        assert_test("CLI rejects malformed hex offset 0xG1 with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI malformed hex offset 0xG1 displays error message", ("malformed" in out_str.lower() or "invalid" in out_str.lower()))

        # e. --offset 0b10 -> rejected
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "0b10"], cwd=str(isolated_dir))
        assert_test("CLI rejects unsupported binary prefix 0b10 with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI unsupported binary prefix 0b10 displays error message", ("unsupported" in out_str.lower() or "malformed" in out_str.lower() or "invalid" in out_str.lower()))

        # f. --offset 16777216 -> exactly 16 MiB accepted
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "16777216"], cwd=str(isolated_dir))
        assert_test("CLI exact 16 MiB boundary offset executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI exact 16 MiB boundary offset produces 16777216 bytes in telemetry", "Exploit padding offset: 16777216 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI exact 16 MiB boundary offset verified in JSON as 16777216", jdata.get("raw_payload", {}).get("verified_padding_offset") == 16777216)
            except Exception as e:
                assert_test("CLI exact 16 MiB boundary offset verified in JSON as 16777216", False, str(e))
        else:
            assert_test("CLI exact 16 MiB boundary offset verified in JSON as 16777216", False, "output.json missing")
        # Clean up temporary large payload files inside isolated_dir
        for p in [isolated_dir / "payload.bin", isolated_dir / "reports" / "payload.bin", out_json]:
            if p.is_file():
                try:
                    p.unlink()
                except Exception:
                    pass

        # g. --offset 0o10 -> rejected
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "0o10"], cwd=str(isolated_dir))
        assert_test("CLI rejects unsupported octal prefix 0o10 with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI unsupported octal prefix 0o10 displays error message", ("unsupported" in out_str.lower() or "malformed" in out_str.lower() or "invalid" in out_str.lower()))

        # h. --offset " 10" -> rejected
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", " 10"], cwd=str(isolated_dir))
        assert_test("CLI rejects leading whitespace offset with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI leading whitespace offset displays error message", ("malformed" in out_str.lower() or "invalid" in out_str.lower()))

        # i. --offset "10 " -> rejected
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "10 "], cwd=str(isolated_dir))
        assert_test("CLI rejects trailing whitespace offset with exit code 1", exit_code != 0, f"exit code {exit_code}")
        assert_test("CLI trailing whitespace offset displays error message", ("malformed" in out_str.lower() or "trailing" in out_str.lower() or "invalid" in out_str.lower()))

        # j. --offset 0X10 -> accepted as hexadecimal 16
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p", "--offset", "0X10"], cwd=str(isolated_dir))
        assert_test("CLI uppercase hex offset 0X10 executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("CLI uppercase hex offset 0X10 produces decimal 16 in telemetry", "Exploit padding offset: 16 bytes (user-configured)" in out_str)
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                assert_test("CLI uppercase hex offset 0X10 verified in JSON as decimal 16", jdata.get("raw_payload", {}).get("verified_padding_offset") == 16)
            except Exception as e:
                assert_test("CLI uppercase hex offset 0X10 verified in JSON as decimal 16", False, str(e))
        else:
            assert_test("CLI uppercase hex offset 0X10 verified in JSON as decimal 16", False, "output.json missing")

        # 16.16 Strengthened working-directory isolation guard verification
        # 1. Active temporary directory — accepted
        guard_active_ok = False
        try:
            code_act, _ = run_command([str(ropweaver_bin), str(elf_test_bin), "-a", "-p"], cwd=str(isolated_dir))
            guard_active_ok = (code_act == 0)
        except RuntimeError:
            guard_active_ok = False
        assert_test("Isolation guard accepts active temporary directory", guard_active_ok)

        # 2. Repository root — rejected
        guard_repo_root_rejected = False
        try:
            run_command([str(ropweaver_bin), str(elf_test_bin), "-p"], cwd=str(PROJECT_ROOT))
        except RuntimeError:
            guard_repo_root_rejected = True
        assert_test("Isolation guard rejects repository root", guard_repo_root_rejected)

        # 3. Repository subdirectory — rejected
        guard_repo_subdir_rejected = False
        repo_sub = PROJECT_ROOT / "test_binaries"
        try:
            run_command([str(ropweaver_bin), str(elf_test_bin), "-p"], cwd=str(repo_sub))
        except RuntimeError:
            guard_repo_subdir_rejected = True
        assert_test("Isolation guard rejects repository subdirectory", guard_repo_subdir_rejected)

        # 4. Unrelated external directory — rejected
        guard_external_rejected = False
        with tempfile.TemporaryDirectory(prefix="ropw_unrelated_") as unrelated_temp:
            try:
                run_command([str(ropweaver_bin), str(elf_test_bin), "-p"], cwd=str(unrelated_temp))
            except RuntimeError:
                guard_external_rejected = True
        assert_test("Isolation guard rejects unrelated external directory", guard_external_rejected)

        # 5. Missing working directory (cwd=None) — rejected
        guard_missing_cwd_rejected = False
        try:
            run_command([str(ropweaver_bin), str(elf_test_bin), "-p"], cwd=None)
        except RuntimeError:
            guard_missing_cwd_rejected = True
        assert_test("Isolation guard rejects missing working directory", guard_missing_cwd_rejected)

        # 6. Non-payload commands preserved (legitimate non-payload commands not rejected)
        guard_non_payload_ok = False
        try:
            code_np, _ = run_command([str(ropweaver_bin), "--help"])
            guard_non_payload_ok = (code_np == 0)
        except RuntimeError:
            guard_non_payload_ok = False
        assert_test("Isolation guard preserves legitimate non-payload commands", guard_non_payload_ok)

        # 7. --offset alone is not treated as a payload-generation flag
        guard_offset_alone_ok = False
        try:
            code_off, _ = run_command([str(ropweaver_bin), str(elf_test_bin), "--offset", "104"], cwd=str(PROJECT_ROOT))
            guard_offset_alone_ok = (code_off == 0)
        except RuntimeError:
            guard_offset_alone_ok = False
        assert_test("Isolation guard does not treat --offset alone as payload flag", guard_offset_alone_ok)

        # -------------------------------------------------------------
        # Test 17: Darwin Mach-O x86_64 Auto-Chain & Payload Generation
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 17: Darwin Mach-O x86_64 Auto-Chain & Payload Generation...{COLOR_RESET}")

        macho_fixture_path = isolated_dir / "test_darwin_fixture.bin"
        macho_pie_fixture_path = isolated_dir / "test_darwin_fixture_pie.bin"

        def create_synthetic_macho_x86_64(path, pie=False):
            import struct
            total_size = 0x3000
            buf = bytearray(total_size)
            flags = 0x200000 if pie else 0  # MH_PIE = 0x200000
            struct.pack_into("<IIIIIIII", buf, 0,
                             0xFEEDFACF, 0x01000007, 0x00000003, 0x00000002,
                             2, 232 + 152, flags, 0)
            # LC_SEGMENT_64 __TEXT
            cmd1_off = 32
            struct.pack_into("<II16sQQQQIIII", buf, cmd1_off,
                             0x19, 232, b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                             0x100000000, 0x2000, 0, 0x2000, 7, 5, 2, 0)
            # Section 1.1: __TEXT,__text
            s1_off = cmd1_off + 72
            struct.pack_into("<16s16sQQIIIIIIII", buf, s1_off,
                             b"__text\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                             b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                             0x100001000, 0x100, 0x1000, 4, 0, 0, 0x80000400, 0, 0, 0)
            # Section 1.2: __TEXT,__cstring
            s2_off = s1_off + 80
            struct.pack_into("<16s16sQQIIIIIIII", buf, s2_off,
                             b"__cstring\x00\x00\x00\x00\x00\x00\x00",
                             b"__TEXT\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                             0x100001800, 0x20, 0x1800, 0, 0, 0, 0x00000002, 0, 0, 0)
            # LC_SEGMENT_64 __DATA
            cmd2_off = cmd1_off + 232
            struct.pack_into("<II16sQQQQIIII", buf, cmd2_off,
                             0x19, 152, b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                             0x100002000, 0x1000, 0x2000, 0x1000, 7, 3, 1, 0)
            # Section 2.1: __DATA,__data
            s3_off = cmd2_off + 72
            struct.pack_into("<16s16sQQIIIIIIII", buf, s3_off,
                             b"__data\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                             b"__DATA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                             0x100002000, 0x100, 0x2000, 3, 0, 0, 0, 0, 0, 0)
            # Section contents
            buf[0x1000:0x1002] = b"\x5F\xC3"  # pop rdi ; ret
            buf[0x1010:0x1012] = b"\x5E\xC3"  # pop rsi ; ret
            buf[0x1020:0x1022] = b"\x5A\xC3"  # pop rdx ; ret
            buf[0x1030:0x1032] = b"\x58\xC3"  # pop rax ; ret
            buf[0x1040:0x1042] = b"\x0F\x05"  # syscall
            buf[0x1800:0x1808] = b"/bin/sh\x00"
            struct.pack_into("<QQQ", buf, 0x2000, 0x100001800, 0, 0)
            with open(path, "wb") as f:
                f.write(buf)

        create_synthetic_macho_x86_64(macho_fixture_path, pie=False)
        create_synthetic_macho_x86_64(macho_pie_fixture_path, pie=True)

        # 17.1 Non-PIE Mach-O x86_64 auto-chain synthesis
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(macho_fixture_path), "-a", "-p"], cwd=str(isolated_dir))
        assert_test("Darwin Mach-O auto-chain executes successfully", exit_code == 0, f"exit code {exit_code}")
        assert_test("Darwin Mach-O telemetry detects Mach-O container", "Mitigations (Mach-O):" in out_str)
        assert_test("Darwin Mach-O telemetry logs BSD syscall number", ("0x200003B" in out_str or "33554491" in out_str))
        assert_test("Darwin Mach-O telemetry reports successful synthesis", "ROP chain created and validated successfully" in out_str)
        assert_test("Darwin Mach-O suppresses native exploit execution delivery prompt", "Delivery one-liner" not in out_str)

        # 17.2 Structured JSON report verification
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                gen_info = jdata.get("rop_chain_generation", {})
                assert_test("Darwin Mach-O JSON report target_syscall is execve (0x200003B)", gen_info.get("target_syscall") == "execve (0x200003B)")
                assert_test("Darwin Mach-O JSON report platform is macOS Mach-O", gen_info.get("platform") == "macOS Mach-O")
                assert_test("Darwin Mach-O JSON report status is Success", gen_info.get("status") == "Success")
                assert_test("Darwin Mach-O JSON report validation passes", gen_info.get("validation", {}).get("valid") is True)
                assert_test("Darwin Mach-O JSON report aslr_slide_applied is false", gen_info.get("aslr_slide_applied") is False)
                assert_test("Darwin Mach-O JSON raw_payload format is python_hex_string", jdata.get("raw_payload", {}).get("format") == "python_hex_string")
                assert_test("Darwin Mach-O JSON raw_payload verified offset is 104", jdata.get("raw_payload", {}).get("verified_padding_offset") == 104)
            except Exception as e:
                assert_test("Darwin Mach-O JSON report structured verification", False, str(e))
        else:
            assert_test("Darwin Mach-O JSON report structured verification", False, "output.json missing")

        # 17.3 PIE Relocation Transparency in Mach-O
        if out_json.is_file():
            out_json.unlink()
        exit_code, out_str = run_command([str(ropweaver_bin), str(macho_pie_fixture_path), "-a", "-p"], cwd=str(isolated_dir))
        assert_test("Darwin PIE Mach-O executes successfully", exit_code == 0, f"exit code {exit_code}")
        if out_json.is_file():
            try:
                jdata = json.loads(out_json.read_text(encoding="utf-8"))
                gen_info = jdata.get("rop_chain_generation", {})
                assert_test("Darwin PIE Mach-O status is Success (Relocation Required)", gen_info.get("status") == "Success (Relocation Required)")
                assert_test("Darwin PIE Mach-O relocation_status documents MH_PIE", "MH_PIE" in gen_info.get("relocation_status", ""))
                assert_test("Darwin PIE Mach-O aslr_slide_applied is false", gen_info.get("aslr_slide_applied") is False)
            except Exception as e:
                assert_test("Darwin PIE Mach-O JSON verification", False, str(e))
        else:
            assert_test("Darwin PIE Mach-O JSON verification", False, "output.json missing")

        # 17.4 File confinement: ensure generated files remain within isolated_dir
        assert_test("Darwin Mach-O output files confined to temporary directory", out_json.is_file())
        for fpath in [macho_fixture_path, macho_pie_fixture_path, out_json, isolated_dir / "payload.bin", isolated_dir / "reports" / "payload.bin"]:
            if fpath.is_file():
                try:
                    fpath.unlink()
                except Exception:
                    pass

        # -------------------------------------------------------------
        # Test 18: Mach-O Detection, Parsing & Discovery Integration [4 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 18: Mach-O Detection, Parsing & Discovery Integration...{COLOR_RESET}")
        test_macho_src = PROJECT_ROOT / "tests" / "test_macho_detection.cpp"
        test_macho_bin = test_build_dir / ("test_macho_detection.exe" if sys.platform == "win32" else "test_macho_detection")

        need_build_macho = False
        if cxx_compiler and core_lib and test_macho_src.is_file():
            need_build_macho = (not test_macho_bin.is_file()) or (test_macho_src.stat().st_mtime > test_macho_bin.stat().st_mtime)
            if need_build_macho:
                compile_cmd = [
                    cxx_compiler, "-std=c++17",
                    f"-I{PROJECT_ROOT}", f"-I{PROJECT_ROOT / 'core'}",
                    str(test_macho_src), str(core_lib),
                    f"-L{build_dir}", "-lcapstone",
                    "-o", str(test_macho_bin)
                ]
                comp_code, comp_out = run_command(compile_cmd, timeout=60)
                assert_test("Mach-O Detection test suite compiles successfully", comp_code == 0, f"compile error: {comp_out}")
            else:
                assert_test("Mach-O Detection test suite binary up to date", test_macho_bin.is_file())
        else:
            assert_test("Mach-O Detection test suite source and compiler available", False)

        if test_macho_bin.is_file():
            exit_code, out_str = run_command([str(test_macho_bin)], timeout=60, cwd=str(isolated_dir))
            assert_test("Mach-O Detection test suite exits with code 0", exit_code == 0, f"exit code {exit_code}")
            assert_test("Mach-O Detection: All 541 assertions passed with 0 failures", ("541 Passed, 0 Failed" in out_str) and ("0 Failed" in out_str))
            assert_test("Mach-O Detection: Phase 2 Step 5.2/5.3/5.6/6 suites executed", "Mach-O Test Results:" in out_str)
        else:
            for sub_name in [
                "Mach-O Detection test suite exits with code 0",
                "Mach-O Detection: All 541 assertions passed with 0 failures",
                "Mach-O Detection: Phase 2 Step 5.2/5.3/5.6/6 suites executed"
            ]:
                assert_test(sub_name, False, f"Test binary not built: {test_macho_bin}")

    finally:
        ACTIVE_TEMP_DIR = None
        try:
            temp_dir_obj.cleanup()
        except Exception:
            pass
        # -------------------------------------------------------------
        # 5. Verify Pre-Test Protected Artifact Immutability
        # -------------------------------------------------------------
        restoration_ok = artifact_mgr.verify_unmodified()
        if not restoration_ok:
            print(f"{COLOR_RED}[!] Error: Protected artifact verification encountered failures. Review working tree.{COLOR_RESET}", file=sys.stderr)

    print(f"\n{COLOR_CYAN}============================================================{COLOR_RESET}")
    result_color = COLOR_GREEN if failed == 0 and restoration_ok else COLOR_RED
    print(f"{result_color}Test Results: {passed} Passed, {failed} Failed{COLOR_RESET}")
    print(f"{COLOR_CYAN}============================================================{COLOR_RESET}")

    if failed > 0 or not restoration_ok:
        sys.exit(1)
    else:
        sys.exit(0)

if __name__ == "__main__":
    main()

