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
        Path("payload.bin")
    ]

    def __init__(self, root: Path):
        self.root = root
        self.states = {}
        self.failure_reasons = []

    def capture_pre_test_state(self) -> bool:
        """
        Inspects each tracked artifact path prior to executing any test.
        Returns True only if all paths are safely captured.
        Returns False if ANY path encounters a backup failure.
        """
        all_ok = True
        for rel_path in self.TRACKED_FILES:
            full_path = self.root / rel_path
            try:
                # Use lstat to inspect entry without following symbolic links
                st = os.lstat(full_path)
            except FileNotFoundError:
                self.states[rel_path] = (ArtifactState.DID_NOT_EXIST, None, None)
                continue
            except Exception as e:
                self.states[rel_path] = (ArtifactState.BACKUP_FAILED, None, None)
                self.failure_reasons.append(f"Failed to lstat {rel_path}: {e}")
                all_ok = False
                continue

            if stat.S_ISLNK(st.st_mode):
                self.states[rel_path] = (ArtifactState.BACKUP_FAILED, None, None)
                self.failure_reasons.append(f"{rel_path} is a symbolic link; refusing to treat as standard artifact.")
                all_ok = False
            elif stat.S_ISDIR(st.st_mode):
                self.states[rel_path] = (ArtifactState.BACKUP_FAILED, None, None)
                self.failure_reasons.append(f"{rel_path} is a directory; expected regular file or absent path.")
                all_ok = False
            elif stat.S_ISREG(st.st_mode):
                try:
                    content = full_path.read_bytes()
                    mode = stat.S_IMODE(st.st_mode)
                    self.states[rel_path] = (ArtifactState.EXISTS_AND_BACKED_UP, content, mode)
                except Exception as e:
                    self.states[rel_path] = (ArtifactState.BACKUP_FAILED, None, None)
                    self.failure_reasons.append(f"Failed to read {rel_path}: {e}")
                    all_ok = False
            else:
                self.states[rel_path] = (ArtifactState.BACKUP_FAILED, None, None)
                self.failure_reasons.append(f"{rel_path} is an unexpected special file (mode: {oct(st.st_mode)}).")
                all_ok = False

        return all_ok

    def restore(self) -> bool:
        """
        Restores tracked artifacts according to their exact captured state.
        Re-inspects current path types with os.lstat() to prevent writing through
        symbolic links or overwriting unexpected directories.
        Returns True if all restorations succeeded, False otherwise.
        """
        all_restored = True
        for rel_path, (state, original_bytes, original_mode) in self.states.items():
            full_path = self.root / rel_path

            current_st = None
            try:
                current_st = os.lstat(full_path)
            except FileNotFoundError:
                current_st = None
            except Exception as e:
                print(f"[!] Error during restoration: could not lstat {rel_path}: {e}", file=sys.stderr)
                all_restored = False
                continue

            # Case A: File originally existed and was backed up
            if state == ArtifactState.EXISTS_AND_BACKED_UP:
                if current_st is not None:
                    if stat.S_ISLNK(current_st.st_mode):
                        print(f"[!] Critical Error: Refusing to restore {rel_path} because it was replaced with a symbolic link.", file=sys.stderr)
                        all_restored = False
                        continue
                    if stat.S_ISDIR(current_st.st_mode):
                        print(f"[!] Critical Error: Refusing to restore {rel_path} because it was replaced with a directory.", file=sys.stderr)
                        all_restored = False
                        continue
                    if not stat.S_ISREG(current_st.st_mode):
                        print(f"[!] Critical Error: Refusing to restore {rel_path} because it is no longer a regular file (mode: {oct(current_st.st_mode)}).", file=sys.stderr)
                        all_restored = False
                        continue

                try:
                    full_path.parent.mkdir(parents=True, exist_ok=True)
                    full_path.write_bytes(original_bytes)
                    if original_mode is not None:
                        try:
                            os.chmod(full_path, original_mode)
                        except Exception:
                            pass
                except Exception as e:
                    print(f"[!] Error: Failed to restore regular file {rel_path}: {e}", file=sys.stderr)
                    all_restored = False

            # Case B: File originally did not exist
            elif state == ArtifactState.DID_NOT_EXIST:
                if current_st is not None:
                    if stat.S_ISLNK(current_st.st_mode):
                        print(f"[!] Critical Error: Refusing to remove {rel_path} because an unexpected symbolic link was created.", file=sys.stderr)
                        all_restored = False
                        continue
                    if stat.S_ISDIR(current_st.st_mode):
                        print(f"[!] Critical Error: Refusing to remove {rel_path} because an unexpected directory was created.", file=sys.stderr)
                        all_restored = False
                        continue
                    if not stat.S_ISREG(current_st.st_mode):
                        print(f"[!] Critical Error: Refusing to remove {rel_path} because an unexpected non-regular file exists.", file=sys.stderr)
                        all_restored = False
                        continue

                    try:
                        full_path.unlink()
                    except Exception as e:
                        print(f"[!] Error: Failed to remove test-created file {rel_path}: {e}", file=sys.stderr)
                        all_restored = False

            # Case C: Backup failed initially
            elif state == ArtifactState.BACKUP_FAILED:
                print(f"[!] Warning: Refusing to modify {rel_path} because initial backup failed.", file=sys.stderr)
                all_restored = False

        return all_restored

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

def run_command(cmd_list, timeout=30):
    """Executes a command list safely without shell expansion."""
    try:
        res = subprocess.run(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout)
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
        which_gxx = shutil.which("g++")
        if which_gxx:
            return which_gxx
        msys_gxx = Path("C:/msys64/mingw64/bin/g++.exe")
        if msys_gxx.is_file():
            return str(msys_gxx)
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

    out_json = PROJECT_ROOT / "reports" / "output.json"
    (PROJECT_ROOT / "reports").mkdir(parents=True, exist_ok=True)

    # Ensure synthetic test fixtures exist
    gen_script = PROJECT_ROOT / "tests" / "generate_test_elfs.py"
    if gen_script.is_file():
        subprocess.run([sys.executable, str(gen_script)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    try:
        # -------------------------------------------------------------
        # Test 1: ELF64 Analysis & Auto-Chain (binsh_test) [12 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 1: ELF64 Analysis & Auto-Chain (binsh_test)...{COLOR_RESET}")
        elf_bin = PROJECT_ROOT / "test_binaries" / "binsh_test"
        if out_json.is_file():
            out_json.unlink()

        exit_code, out_str = run_command([str(ropweaver_bin), str(elf_bin), "-a", "-p"])

        assert_test("ELF Execution returns code 0", exit_code == 0, f"exit code {exit_code}")
        assert_test("ELF Detected architecture x86_64", bool(re.search(r"Detected architecture:\s*x86_64", out_str)))
        assert_test("ELF Found /bin/sh", "Found /bin/sh" in out_str)
        assert_test("ELF Auto-chain synthesized successfully", "ROP chain created successfully" in out_str)
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

        exit_code, out_str = run_command([str(ropweaver_bin), str(pe_bin), "-a", "-p"])

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
        malformed_file = PROJECT_ROOT / "reports" / "malformed.bin"
        try:
            malformed_file.write_bytes(bytes([0x7F, 0x45, 0x4C, 0x46])) # truncated ELF
            exit_code, out_str = run_command([str(ropweaver_bin), str(malformed_file)])
            assert_test("Malformed binary exits with non-zero error", exit_code != 0, f"exit code {exit_code}")
            assert_test("Graceful error message reported", bool(re.search(r"Error|Failed|Invalid", out_str)))
        finally:
            if malformed_file.is_file():
                malformed_file.unlink()

        # -------------------------------------------------------------
        # Test 4: Empty / Text File Handling [2 assertions]
        # -------------------------------------------------------------
        print(f"\n{COLOR_YELLOW}[*] Test 4: Empty / Text File Handling...{COLOR_RESET}")
        text_file = PROJECT_ROOT / "reports" / "not_a_binary.txt"
        try:
            text_file.write_text("This is just a text file, not a binary executable.", encoding="utf-8")
            exit_code, out_str = run_command([str(ropweaver_bin), str(text_file)])
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
                exit_code, out_str = run_command([str(ropweaver_bin), str(fix_path), "-p"])

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
            exit_code, out_str = run_command([str(ropweaver_bin), str(multi_sec_bin), "-p"])

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
            exit_code, out_str = run_command([str(ropweaver_bin), str(arm_be8_bin), "-p"])

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
            exit_code, out_str = run_command([str(ropweaver_bin), str(aarch64_be_bin), "-p"])

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
            exit_code, out_str = run_command([str(ropweaver_bin), str(inv_end_bin)])
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
        test_endian_bin = build_dir / ("test_endian_readers.exe" if sys.platform == "win32" else "test_endian_readers")

        if cxx_compiler and test_endian_src.is_file():
            # Compile if absent or source newer
            need_build = (not test_endian_bin.is_file()) or (test_endian_src.stat().st_mtime > test_endian_bin.stat().st_mtime)
            if need_build:
                compile_cmd = [cxx_compiler, "-std=c++17", str(test_endian_src), "-o", str(test_endian_bin)]
                run_command(compile_cmd)

        if test_endian_bin.is_file():
            exit_code, out_str = run_command([str(test_endian_bin)])
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
        test_class_bin = build_dir / ("test_endian_classification.exe" if sys.platform == "win32" else "test_endian_classification")

        if cxx_compiler and core_lib and test_class_src.is_file():
            need_build = (not test_class_bin.is_file()) or (test_class_src.stat().st_mtime > test_class_bin.stat().st_mtime)
            if need_build:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_class_src), str(core_lib), "-o", str(test_class_bin)]
                run_command(compile_cmd)

        if test_class_bin.is_file():
            exit_code, out_str = run_command([str(test_class_bin)])
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
        test_gf_bin = build_dir / ("test_gadget_finder_endianness.exe" if sys.platform == "win32" else "test_gadget_finder_endianness")

        if cxx_compiler and core_lib and test_gf_src.is_file():
            need_build = (not test_gf_bin.is_file()) or (test_gf_src.stat().st_mtime > test_gf_bin.stat().st_mtime)
            if need_build:
                compile_cmd = [cxx_compiler, "-std=c++17", f"-I{PROJECT_ROOT}", str(test_gf_src), str(core_lib), "-lcapstone", "-o", str(test_gf_bin)]
                run_command(compile_cmd)

        if test_gf_bin.is_file():
            exit_code, out_str = run_command([str(test_gf_bin)])
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
            exit_code, out_str = run_command([str(ropweaver_bin), str(raw_amb_bin)])
            assert_test("CLI rejects elf32_arm_be_ambiguous with exit code 1", exit_code != 0, f"exit code {exit_code}")
            assert_test("CLI identifies unsupported instruction endianness for armv7", "Unsupported instruction endianness for architecture: armv7" in out_str)
        else:
            assert_test("CLI rejects elf32_arm_be_ambiguous with exit code 1", False, f"Fixture missing: {raw_amb_bin}")
            assert_test("CLI identifies unsupported instruction endianness for armv7", False, f"Fixture missing: {raw_amb_bin}")

        raw_r32_bin = PROJECT_ROOT / "test_binaries" / "elf32_riscv_be"
        if raw_r32_bin.is_file():
            exit_code, out_str = run_command([str(ropweaver_bin), str(raw_r32_bin)])
            assert_test("CLI rejects elf32_riscv_be with exit code 1", exit_code != 0, f"exit code {exit_code}")
            assert_test("CLI identifies unsupported instruction endianness for riscv32", "Unsupported instruction endianness for architecture: riscv32" in out_str)
        else:
            assert_test("CLI rejects elf32_riscv_be with exit code 1", False, f"Fixture missing: {raw_r32_bin}")
            assert_test("CLI identifies unsupported instruction endianness for riscv32", False, f"Fixture missing: {raw_r32_bin}")

        raw_r64_bin = PROJECT_ROOT / "test_binaries" / "elf64_riscv_be"
        if raw_r64_bin.is_file():
            exit_code, out_str = run_command([str(ropweaver_bin), str(raw_r64_bin)])
            assert_test("CLI rejects elf64_riscv_be with exit code 1", exit_code != 0, f"exit code {exit_code}")
            assert_test("CLI identifies unsupported instruction endianness for riscv64", "Unsupported instruction endianness for architecture: riscv64" in out_str)
        else:
            assert_test("CLI rejects elf64_riscv_be with exit code 1", False, f"Fixture missing: {raw_r64_bin}")
            assert_test("CLI identifies unsupported instruction endianness for riscv64", False, f"Fixture missing: {raw_r64_bin}")

    finally:
        # -------------------------------------------------------------
        # 5. Restore Pre-Test Tracked Artifacts
        # -------------------------------------------------------------
        restoration_ok = artifact_mgr.restore()
        if not restoration_ok:
            print(f"{COLOR_RED}[!] Error: Artifact restoration encountered failures. Review working tree.{COLOR_RESET}", file=sys.stderr)

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

