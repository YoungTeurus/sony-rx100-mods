"""Offline M7 1.00 FileControl recovery checks against the original ARM callbacks."""

import errno
import hashlib
import io
import json
import stat
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0


ROOT = Path(__file__).resolve().parents[1]
SENSER = ROOT / "extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libsencore.so"
SENSER_SHA256 = "d79365e3a168bffcad68bf8cce24bfa62be1de2e0d7ed062470632a0af9f1279"
sys.path.insert(0, str(ROOT / "scripts"))
import m7_stage7_phaseb_install as recovery


class RecoveryStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.image = SENSER.read_bytes()
        if hashlib.sha256(cls.image).hexdigest() != SENSER_SHA256:
            raise AssertionError("FileControl tests require the archived M7 1.00 library")

    def response(self, operation, lookup_error):
        # Start at the access(F_OK) call after the firmware has resolved the path.
        # Stop at the callback epilogue. For a successful read, stop before
        # constructing the transfer object. This model never opens a device.
        start, end = {"delete": (0x1305E, 0x130CE), "read": (0x136EC, 0x13762)}[operation]
        machine = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
        machine.mem_map(0xD000, 0x7000)
        machine.mem_write(0xD000, self.image[0xD000:0x14000])
        calls = []
        native_calls = {
            0xE850: ("access", -1 if lookup_error else 0),
            0xEB58: ("log", 0),
            0xE504: ("unlink", 0),
            0xE17C: ("log_file_exists", 0),
            0xDB74: ("sync", 0),
        }

        def trace(uc, address, _size, _data):
            if address in native_calls:
                name, result = native_calls[address]
                calls.append(name)
                uc.reg_write(UC_ARM_REG_R0, result & 0xFFFFFFFF)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            elif address == 0x13742 and operation == "read":
                uc.emu_stop()

        machine.hook_add(UC_HOOK_CODE, trace)
        machine.emu_start(start | 1, end, count=64)
        pc = machine.reg_read(UC_ARM_REG_PC)
        if pc == 0x13742 and operation == "read":
            return "begin_transfer", calls
        self.assertEqual(pc, end)
        return machine.reg_read(UC_ARM_REG_R0), calls

    def test_lookup_failure_hides_errno_from_host(self):
        # libc exposes -1 in r0 for all three faults. An attempt by the
        # callback to retrieve errno would leave the modeled PLT boundaries.
        for error in (errno.ENOENT, errno.EIO, errno.EACCES):
            with self.subTest(error=error):
                self.assertEqual(self.response("delete", error), (1, ["access"]))
                self.assertEqual(self.response("read", error), (0x82, ["access", "log"]))

    def test_accessible_path_reaches_delete_and_read_operations(self):
        self.assertEqual(
            self.response("delete", None), (1, ["access", "unlink", "log_file_exists", "sync"])
        )
        self.assertEqual(self.response("read", None), ("begin_transfer", ["access", "log_file_exists"]))


class MockService:
    """Byte-framed responses behind the real PMCA camera API. No USB import or device."""

    def __init__(self):
        self.files = dict.fromkeys(recovery.FILES, b"installed")
        self.files[recovery.PRELOAD] = recovery.HOOK.encode("ascii") + b"\n"
        self.files["/version.txt"] = recovery.BUILD.encode("ascii")
        self.calls = []
        self.failures = {}

    def sendSenserPacket(self, function, payload, output=None):
        if function != 0xFF01:
            raise AssertionError(f"Non-FileControl request {function:#x}")
        op, size = struct.unpack_from("<HH", payload)
        path = payload[4:4+size].rstrip(b"\0").decode("ascii")
        data = payload[4+size:]
        self.calls.append((op, path))
        result = self.failures.get((op, path))
        if isinstance(result, Exception):
            raise result
        if result is not None:
            return result, b""
        if op == 1:
            self.files[path] = data
        elif op == 3:
            self.files.pop(path, None)
        elif op == 2:
            if path not in self.files:
                return 0x82, b""
            output.write(self.files[path])
        else:
            raise AssertionError(f"Unknown file operation {op}")
        return 1, b""


class RecoveryCliTests(unittest.TestCase):
    def setUp(self):
        root = tempfile.TemporaryDirectory()
        self.addCleanup(root.cleanup)
        self.dest = Path(root.name).resolve() / "phaseb-install"
        self.service = MockService()
        self.stop_ok = True
        self.connected = False
        self.model = recovery.probe.MODEL
        self.authenticated = True
        self.secret = b"a private test key never suitable for receipts"
        self.service.files[recovery.FILES[-1]] = self.secret

    def connect(self, receipt, diagnostic, gate_factory):
        from pmca.usb.sony import SonySenserCamera
        self.connected = True
        receipt.update(model=self.model, service_authenticated=self.authenticated)
        try:
            diagnostic(SonySenserCamera(gate_factory(self.service)), receipt)
        finally:
            receipt["service_stop_requested"] = True
            receipt["service_stop_transport"].update(
                attempted=True, observed=True, transport_ok=self.stop_ok,
                error=None if self.stop_ok else "transport failed",
            )

    def run_cli(self):
        with patch.object(recovery, "RECEIPTS", self.dest), \
                patch.object(recovery.probe, "connect", self.connect), redirect_stdout(io.StringIO()):
            rc = recovery.main(["--mode", recovery.MODE, "--owner-authorized-flash"])
        output, = self.dest.glob("*.json")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o644)
        self.assertEqual(list(self.dest.glob("*.partial")), [])
        data = output.read_bytes()
        self.assertNotIn(self.secret, data)
        return rc, json.loads(data)

    def test_marker_first_then_each_delete_and_read(self):
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 0)
        expected = [(2, "/version.txt"), (1, recovery.MARKER), (2, recovery.MARKER), (2, recovery.PRELOAD)]
        for path in recovery.FILES:
            expected.extend([(3, path), (2, path)])
        self.assertEqual(self.service.calls, expected)
        self.assertEqual(self.service.files[recovery.MARKER], b"1\n")
        self.assertEqual(receipt["files"], [
            {"path": path, "delete_status": 1, "post_delete_read_status": 0x82} for path in recovery.FILES
        ])
        for key in ("disable_marker_written_and_readback", "data_capture_ok", "recovery_requests_ok",
                    "filecontrol_unreadable_after_delete", "service_stop_transport_ok"):
            self.assertTrue(receipt[key], key)
        self.assertFalse(receipt["absence_certified"])
        self.assertEqual(receipt["stock_state"], "INCONCLUSIVE")
        for word in ("0x82", "ENOENT", "EACCES", "EIO"):
            self.assertIn(word, receipt["note"])

    def test_unreadable_can_leave_all_targets_present(self):
        for path in recovery.FILES:
            self.service.failures[(3, path)] = 1
            self.service.failures[(2, path)] = 0x82
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 0)
        self.assertTrue(set(recovery.FILES) <= self.service.files.keys())
        self.assertTrue(receipt["filecontrol_unreadable_after_delete"])
        self.assertFalse(receipt["absence_certified"])

    def test_owner_flag_precedes_connection(self):
        with redirect_stderr(io.StringIO()), patch.object(recovery.probe, "connect") as connect:
            with self.assertRaises(SystemExit):
                recovery.main(["--mode", recovery.MODE])
            connect.assert_not_called()

    def test_wrong_build_precedes_writes(self):
        self.service.files["/version.txt"] = b"other"
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertEqual(self.service.calls, [(2, "/version.txt")])
        self.assertFalse(receipt["disable_marker_written_and_readback"])

    def test_failed_marker_readback_precedes_deletes(self):
        # A write acknowledgment cannot substitute for the marker's exact bytes.
        self.service.failures[(1, recovery.MARKER)] = 1
        self.service.files[recovery.MARKER] = b"old"
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["disable_read_status"], 1)
        self.assertFalse(receipt["disable_marker_written_and_readback"])
        self.assertFalse(any(op == 3 for op, _ in self.service.calls))

    def test_foreign_preload_entries_survive(self):
        self.service.files[recovery.PRELOAD] += b"/stock/library.so\n"
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertTrue(receipt["disable_marker_written_and_readback"])
        self.assertFalse(any(op == 3 for op, _ in self.service.calls))

    def test_readable_preload_stops_subsequent_deletes(self):
        self.service.failures[(3, recovery.PRELOAD)] = 1
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["files"], [
            {"path": recovery.PRELOAD, "delete_status": 1, "post_delete_read_status": 1}
        ])
        self.assertIn(recovery.HOOK, self.service.files)

    def test_readable_owner_key_does_not_enter_receipt(self):
        self.service.failures[(3, recovery.FILES[-1])] = 0x83
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 1)
        row = receipt["files"][-1]
        self.assertEqual((row["delete_status"], row["post_delete_read_status"]), (0x83, 1))
        self.assertTrue(receipt["data_capture_ok"])
        self.assertFalse(receipt["recovery_requests_ok"])

    def test_transport_loss_retains_last_confirmed_response(self):
        path = recovery.FILES[-1]
        self.service.failures[(2, path)] = OSError("disconnected")
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertEqual(receipt["files"][-1], {"path": path, "delete_status": 1, "post_delete_read_status": None})
        self.assertFalse(receipt["data_capture_ok"])
        self.assertTrue(receipt["service_stop_transport_ok"])

    def test_stop_transport_failure_is_separate(self):
        self.stop_ok = False
        rc, receipt = self.run_cli()
        self.assertEqual(rc, 1)
        self.assertTrue(receipt["recovery_requests_ok"])
        self.assertFalse(receipt["service_stop_transport_ok"])

    def test_gate_blocks_terminal_and_other_mutations_before_transport(self):
        gate = recovery.RecoveryGate(self.service)
        for function, payload in ((0x10, b"\0\0\xf1\0\1"),
                                  (0xFF01, recovery.packet(1, recovery.MARKER, b"other")),
                                  (0xFF01, recovery.packet(3, recovery.MARKER)),
                                  (0xFF01, recovery.packet(3, "/version.txt"))):
            with self.assertRaises(recovery.probe.ProbeError):
                gate.sendSenserPacket(function, payload)
        self.assertEqual(self.service.calls, [])
        self.assertFalse(hasattr(gate, "writeTerminal"))
        self.assertFalse(hasattr(gate, "readTerminal"))

    def test_existing_receipt_survives_collision(self):
        with recovery.custody(self.dest) as fd:
            (self.dest / "result.json").write_bytes(b"previous receipt")
            with self.assertRaises(FileExistsError):
                with recovery.public_receipt(fd, "result.json"):
                    self.fail("Recovery began despite an existing final receipt")
        self.assertEqual((self.dest / "result.json").read_bytes(), b"previous receipt")


class PhaseBHookAndSealTests(unittest.TestCase):
    """Verify sealed Phase B release, zero-/tmp_network isolation, and ARM Unicorn emulation of mlv2_sd_boot_hook.so."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT / "prototype-stage7-persist"))
        import build_stage7_phaseb_persist as phaseb_build
        cls.phaseb_build = phaseb_build
        cls.manifest = phaseb_build.verify_seal()
        cls.hook_bytes = (phaseb_build.OUT_PERSIST / "mlv2_sd_boot_hook.so").read_bytes()

    def _run_hook_in_unicorn(self, *, exe_path: bytes, uid: int = 0, disable_exists: bool = False,
                             worker_readable: bool = True, fork_results=(0, 0)):
        from elftools.elf.elffile import ELFFile
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_ARM, UC_HOOK_INTR
        from unicorn.arm_const import (
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R7, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
        )

        LOAD_BASE = 0x40010000
        STACK_TOP = 0x40200000
        RET_SENTINEL = 0x40300000

        elf = ELFFile(io.BytesIO(self.hook_bytes))
        uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
        uc.mem_map(LOAD_BASE, 0x100000)
        uc.mem_map(STACK_TOP - 0x10000, 0x10000)
        uc.mem_map(RET_SENTINEL, 0x1000)

        for seg in elf.iter_segments():
            if seg["p_type"] == "PT_LOAD":
                uc.mem_write(LOAD_BASE + seg["p_vaddr"], seg.data())

        # Apply R_ARM_RELATIVE relocations just like M7 glibc ld-2.11.2.so does
        for sec in elf.iter_sections():
            if sec["sh_type"] == "SHT_REL":
                for rel in sec.iter_relocations():
                    self.assertEqual(rel["r_info_type"], 23)  # R_ARM_RELATIVE
                    addr = LOAD_BASE + rel["r_offset"]
                    val = struct.unpack("<I", bytes(uc.mem_read(addr, 4)))[0]
                    uc.mem_write(addr, struct.pack("<I", (LOAD_BASE + val) & 0xFFFFFFFF))

        dyn = elf.get_section_by_name(".dynamic")
        tags = {t.entry.d_tag: t.entry.d_val for t in dyn.iter_tags()}
        init_arr_va = LOAD_BASE + tags["DT_INIT_ARRAY"]
        ctor_va = struct.unpack("<I", bytes(uc.mem_read(init_arr_va, 4)))[0]

        def read_cstr(va):
            out = bytearray()
            while len(out) < 256:
                b = bytes(uc.mem_read(va + len(out), 1))[0]
                if b == 0:
                    break
                out.append(b)
            return bytes(out)

        calls = []
        fork_iter = iter(fork_results)
        wait_eintr_sent = [False]
        next_fd = [0]

        def on_svc(emu, intno, _data):
            nr = emu.reg_read(UC_ARM_REG_R7)
            r0 = emu.reg_read(UC_ARM_REG_R0)
            r1 = emu.reg_read(UC_ARM_REG_R1)
            r2 = emu.reg_read(UC_ARM_REG_R2)
            r3 = emu.reg_read(UC_ARM_REG_R3)
            if nr == 85:  # readlink
                path = read_cstr(r0)
                calls.append(("readlink", path))
                to_write = exe_path[:r2]
                emu.mem_write(r1, to_write)
                emu.reg_write(UC_ARM_REG_R0, len(to_write))
            elif nr == 199:  # getuid32
                calls.append(("getuid32", uid))
                emu.reg_write(UC_ARM_REG_R0, uid)
            elif nr == 33:  # access
                path = read_cstr(r0)
                calls.append(("access", path, r1))
                if path == b"/setting/disable_sd_boot":
                    emu.reg_write(UC_ARM_REG_R0, 0 if disable_exists else (-2 & 0xFFFFFFFF))
                elif path == b"/setting/mlv2_sd_boot.sh":
                    emu.reg_write(UC_ARM_REG_R0, 0 if worker_readable else (-2 & 0xFFFFFFFF))
                else:
                    emu.reg_write(UC_ARM_REG_R0, -2 & 0xFFFFFFFF)
            elif nr == 2:  # fork
                res = next(fork_iter)
                calls.append(("fork", res))
                emu.reg_write(UC_ARM_REG_R0, res & 0xFFFFFFFF)
            elif nr == 114:  # wait4
                calls.append(("wait4", r0))
                if not wait_eintr_sent[0]:
                    wait_eintr_sent[0] = True
                    emu.reg_write(UC_ARM_REG_R0, -4 & 0xFFFFFFFF)  # -EINTR retry check
                else:
                    emu.reg_write(UC_ARM_REG_R0, r0)
            elif nr == 66:  # setsid
                calls.append(("setsid",))
                emu.reg_write(UC_ARM_REG_R0, 999)
            elif nr == 6:  # close
                if r0 in (0, 255):
                    calls.append(("close", r0))
                emu.reg_write(UC_ARM_REG_R0, 0)
            elif nr == 5:  # open
                path = read_cstr(r0)
                fd = next_fd[0]
                next_fd[0] += 1
                calls.append(("open", path, r1, fd))
                emu.reg_write(UC_ARM_REG_R0, fd)
            elif nr == 63:  # dup2
                calls.append(("dup2", r0, r1))
                emu.reg_write(UC_ARM_REG_R0, r1)
            elif nr == 11:  # execve
                path = read_cstr(r0)
                argv = []
                for idx in range(8):
                    p = struct.unpack("<I", bytes(emu.mem_read(r1 + idx * 4, 4)))[0]
                    if p == 0:
                        break
                    argv.append(read_cstr(p))
                envp = []
                for idx in range(8):
                    p = struct.unpack("<I", bytes(emu.mem_read(r2 + idx * 4, 4)))[0]
                    if p == 0:
                        break
                    envp.append(read_cstr(p))
                calls.append(("execve", path, argv, envp))
                emu.emu_stop()
            elif nr == 1:  # exit
                calls.append(("exit", r0))
                emu.emu_stop()
            else:
                raise AssertionError(f"Unexpected syscall {nr}")

        uc.hook_add(UC_HOOK_INTR, on_svc)
        uc.reg_write(UC_ARM_REG_SP, STACK_TOP - 16)
        uc.reg_write(UC_ARM_REG_LR, RET_SENTINEL)
        uc.emu_start(ctor_va, RET_SENTINEL, count=50000)
        return calls

    def test_seal_and_zero_tmp_network_in_phaseb_release(self):
        self.assertEqual(self.manifest["ram_root"], "/tmp_bt")
        for fname in ("mlv2_sd_boot_hook.so", "mlv2_card_read.elf", "mlv2_sd_boot.sh", "card.ustar"):
            blob = (self.phaseb_build.OUT_PERSIST / fname).read_bytes()
            self.assertNotIn(b"/tmp_network", blob, fname)

    def test_hook_returns_immediately_for_non_bsa_processes(self):
        for exe in (b"/bin/busybox", b"/usr/bin/im.elf", b"/usr/bin/sen.elf", b"/sbin/init"):
            with self.subTest(exe=exe):
                calls = self._run_hook_in_unicorn(exe_path=exe)
                self.assertEqual(calls, [("readlink", b"/proc/self/exe")])

    def test_hook_respects_killswitch_and_nonroot(self):
        calls = self._run_hook_in_unicorn(exe_path=b"/usr/bin/bsa_server", disable_exists=True)
        self.assertEqual([c[0] for c in calls], ["readlink", "getuid32", "access"])
        calls_uid = self._run_hook_in_unicorn(exe_path=b"/usr/bin/bsa_server", uid=1000)
        self.assertEqual([c[0] for c in calls_uid], ["readlink", "getuid32"])

    def test_hook_bsa_parent_waits_only_for_intermediate_child(self):
        calls = self._run_hook_in_unicorn(exe_path=b"/usr/bin/bsa_server", fork_results=(42,))
        self.assertIn(("fork", 42), calls)
        self.assertEqual(calls.count(("wait4", 42)), 2)  # retried -EINTR once then returned
        self.assertNotIn("execve", [c[0] for c in calls])

    def test_hook_bsa_intermediate_child_exits_zero(self):
        calls = self._run_hook_in_unicorn(exe_path=b"/usr/bin/bsa_server", fork_results=(0, 43))
        self.assertEqual(calls[-1], ("exit", 0))

    def test_hook_bsa_grandchild_execs_busybox_sh_worker(self):
        calls = self._run_hook_in_unicorn(exe_path=b"/usr/bin/bsa_server", fork_results=(0, 0))
        self.assertIn(("setsid",), calls)
        self.assertIn(("open", b"/dev/null", 0, 0), calls)
        self.assertIn(("open", b"/dev/null", 1, 1), calls)
        self.assertIn(("dup2", 1, 2), calls)
        self.assertEqual(
            calls[-1],
            (
                "execve",
                b"/bin/busybox",
                [b"busybox", b"sh", b"/setting/mlv2_sd_boot.sh"],
                [b"PATH=/usr/bin:/bin:/sbin:/usr/sbin"],
            ),
        )


class PhaseBBootScriptTests(unittest.TestCase):
    """Offline shell tests for Phase B mlv2_sd_boot.sh (/tmp_bt, kill-switch, S2R lock)."""

    def test_killswitch_and_s2r_live_lock_preserve_stock_bt_files(self):
        import os
        import subprocess
        script = ROOT / "prototype-stage7-persist/out-phaseb-persist/mlv2_sd_boot.sh"
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ram = root / "tmp_bt"
            ram.mkdir()
            bt_keys = ram / "ble_local_keys"
            bt_keys.write_bytes(b"STOCK_BT_KEYS")
            ver = root / "version.txt"
            ver.write_bytes(b"29110_03.2021050601")
            flag = root / "disable_sd_boot"
            flag.write_text("1\n")
            env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "MLV2_BB": "",
                "MLV2_DISABLE_FLAG": str(flag),
                "MLV2_RAM": str(ram),
                "MLV2_STAGE": str(ram / "mlv2"),
                "MLV2_MODS": str(ram / "mods"),
                "MLV2_DAEMON_DIR": str(ram / ".m7-s7-5d0000000001"),
                "MLV2_VERSION_FILE": str(ver),
                "MLV2_SKIP_MOUNT_CHECK": "1",
            }
            res = subprocess.run(["/bin/sh", str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertFalse((ram / "mlv2").exists())
            self.assertEqual(bt_keys.read_bytes(), b"STOCK_BT_KEYS")

            # Now test S2R live lock idempotency (remove disable flag, plant live PID lock)
            flag.unlink()
            proc = root / "proc"
            (proc / str(os.getpid())).mkdir(parents=True)
            (proc / str(os.getpid()) / "stat").write_text("1 (sh) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 100 0 0\n")
            lock = ram / "mlv2" / ".boot.lock"
            lock.mkdir(parents=True)
            (lock / "owner").write_text(f"worker {os.getpid()}\n")
            env["MLV2_PROC"] = str(proc)
            res2 = subprocess.run(["/bin/sh", str(script)], env=env, capture_output=True, text=True)
            self.assertEqual(res2.returncode, 0, res2.stderr)
            # Live lock was NOT removed or disturbed
            self.assertTrue(lock.is_dir())
            self.assertEqual(bt_keys.read_bytes(), b"STOCK_BT_KEYS")


class PhaseBInstallAndPrepTests(unittest.TestCase):
    """Offline tests for dry-run, prep-sd, supervised install (smoke-gate pass/fail), and normal uninstall."""

    def test_dry_run_succeeds_without_usb(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = recovery.main(["--mode", "dry-run"])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        self.assertEqual(data["status"], "DRY_RUN_OK")
        self.assertFalse(data["usb_contacted"])
        self.assertEqual(data["ram_root"], "/tmp_bt")

    def test_prep_sd_signs_and_preserves_dcim(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            sd = root / "SD"
            dcim = sd / "DCIM" / "100MSDCF"
            dcim.mkdir(parents=True)
            photo = dcim / "DSC00001.JPG"
            photo.write_bytes(b"STOCK_PHOTO")
            key_path = root / "owner.key"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = recovery.main([
                    "--mode", "prep-sd",
                    "--sd-root", str(sd),
                    "--owner-key", str(key_path),
                    "--create-owner-key",
                ])
            self.assertEqual(rc, 0)
            res = json.loads(buf.getvalue())
            self.assertEqual(res["status"], "SD_PREPARED_OK")
            self.assertTrue(res["owner_key_created"])
            self.assertEqual(len(key_path.read_bytes()), 32)
            self.assertEqual(stat.S_IMODE(key_path.stat().st_mode), 0o600)
            self.assertEqual(photo.read_bytes(), b"STOCK_PHOTO")
            tar_data = (sd / "MLV2.TAR").read_bytes()
            self.assertTrue(tar_data.startswith(b"M7SD1\x00\x00\x00"))
            self.assertEqual(hashlib.sha256(tar_data).hexdigest(), res["mlv2_tar_sha256"])

    def test_prep_sd_refuses_repo_root(self):
        with tempfile.TemporaryDirectory() as td:
            key = Path(td) / "k"
            key.write_bytes(b"K" * 32)
            with self.assertRaises(ValueError):
                recovery.run_prep_sd(ROOT, key)

    def _run_install_mock(self, *, smoke_reply="PRELOAD_SMOKE_OK", existing_preload=None):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td).resolve()
            dest = root / "phaseb-install"
            key_path = root / "owner.key"
            secret = b"S" * 32
            key_path.write_bytes(secret)

            files = {"/version.txt": recovery.BUILD.encode("ascii")}
            if existing_preload is not None:
                files[recovery.PRELOAD] = existing_preload
            term_cmds = []

            class MockInstallCam:
                def readFile(self, path, sink):
                    if path not in files:
                        raise recovery.FileControlError(0x82)
                    sink.write(files[path])

                def writeFile(self, path, data):
                    files[path] = bytes(data)

            class FakeTermSession:
                def __init__(self, cam, rec):
                    self.rec = rec

                def command(self, label, cmd, allowed=(0,), timeout=20):
                    # Enforce real Phase B wire-frame length (< 512 B) on every command!
                    wire, _, _ = recovery.frame(cmd, len(term_cmds), self.rec["nonce"])
                    if len(wire) >= 512:
                        raise AssertionError(f"Wire command {label} exceeded 512 B: {len(wire)}")
                    term_cmds.append((label, cmd))
                    if label == "read_mounts":
                        return (
                            "/dev/nflasha2 /setting vfat rw,noatime 0 0\n"
                            "/dev/nflasha10 /etc vfat rw,noatime 0 0\n",
                            0,
                        )
                    if label in ("chmod_staged", "backup_preload", "write_preload_new"):
                        if label == "write_preload_new":
                            lines = []
                            if recovery.PRELOAD in files:
                                lines = [
                                    ln.decode("ascii") for ln in files[recovery.PRELOAD].splitlines()
                                    if ln.strip() and ln.decode("ascii").strip() != recovery.HOOK
                                ]
                            lines.append(recovery.HOOK)
                            files[recovery.PRELOAD + ".new"] = ("\n".join(lines) + "\n").encode("ascii")
                        return "", 0
                    if label == "move_staged":
                        for p in (recovery.HOOK, recovery.BOOT_SH, recovery.READER, recovery.OWNER_KEY):
                            files[p] = files.pop(p + ".new")
                        return "", 0
                    if label == "clear_disable":
                        files.pop(recovery.MARKER, None)
                        return "STAGE_MOVED_OK\n", 0
                    if label == "live_ld_preload_smoke_test":
                        return smoke_reply + "\n", 0
                    if label == "activate_preload":
                        files[recovery.PRELOAD] = files.pop(recovery.PRELOAD + ".new")
                        return files[recovery.PRELOAD].decode("ascii"), 0
                    if label == "post_preload_sanity":
                        return "POST_PRELOAD_OK\n", 0
                    if label == "clean_preload":
                        if recovery.PRELOAD in files:
                            kept = [
                                ln for ln in files[recovery.PRELOAD].splitlines()
                                if ln.strip() and ln.decode("ascii").strip() != recovery.HOOK
                            ]
                            if kept:
                                files[recovery.PRELOAD] = b"\n".join(kept) + b"\n"
                            else:
                                files.pop(recovery.PRELOAD, None)
                        return "", 0
                    if label == "rm_phaseb_files":
                        for p in (recovery.HOOK, recovery.BOOT_SH, recovery.READER, recovery.OWNER_KEY,
                                  recovery.MARKER, recovery.PRECAP_CFG):
                            files.pop(p, None)
                        return "", 0
                    if label == "verify_uninstall_absence":
                        absent = all(p not in files for p in (recovery.HOOK, recovery.BOOT_SH, recovery.READER, recovery.OWNER_KEY))
                        return f"ABSENCE_OK={1 if absent else 0}\n", 0
                    if label == "verify_preload_absent":
                        clean = (
                            recovery.PRELOAD not in files
                            or recovery.HOOK.encode("ascii") not in files[recovery.PRELOAD].splitlines()
                        )
                        return ("PRELOAD_CLEAN\n" if clean else "PRELOAD_STILL_SET\n"), 0
                    raise AssertionError(f"Unexpected cmd label: {label}")

            @recovery.contextlib.contextmanager
            def fake_open_terminal(cam, rec):
                try:
                    yield FakeTermSession(cam, rec)
                finally:
                    rec["terminal_disable_verified"] = True

            def fake_connect(receipt, diagnostic, gate_factory):
                receipt.update(model=recovery.probe.MODEL, service_authenticated=True)
                try:
                    diagnostic(MockInstallCam(), receipt)
                finally:
                    receipt["service_stop_requested"] = True
                    receipt["service_stop_transport"].update(
                        attempted=True, observed=True, transport_ok=True, error=None
                    )

            with patch.object(recovery, "RECEIPTS", dest), \
                    patch.object(recovery.probe, "connect", fake_connect), \
                    patch.object(recovery, "open_terminal", fake_open_terminal), \
                    redirect_stdout(io.StringIO()):
                rc = recovery.main([
                    "--mode", "install",
                    "--owner-authorized-flash",
                    "--owner-key", str(key_path),
                ])
                inst_json, = dest.glob("*-install.json")
                inst_raw = inst_json.read_bytes()
                self.assertNotIn(secret, inst_raw)
                inst_receipt = json.loads(inst_raw)

                # Also exercise uninstall if install succeeded
                uninst_rc, uninst_receipt = None, None
                if rc == 0:
                    uninst_rc = recovery.main(["--mode", "uninstall", "--owner-authorized-flash"])
                    uninst_json, = dest.glob("*-uninstall.json")
                    uninst_receipt = json.loads(uninst_json.read_bytes())

            return rc, inst_receipt, files, term_cmds, uninst_rc, uninst_receipt

    def test_install_happy_path_and_clean_uninstall(self):
        rc, rec, files, cmds, urc, urec = self._run_install_mock()
        self.assertEqual(rc, 0)
        self.assertTrue(rec["install_ok"])
        self.assertTrue(rec["live_preload_smoke_passed"])
        labels = [lbl for lbl, _ in cmds]
        self.assertLess(labels.index("live_ld_preload_smoke_test"), labels.index("activate_preload"))
        self.assertEqual(urc, 0)
        self.assertTrue(urec["uninstall_ok"])
        self.assertNotIn(recovery.PRELOAD, files)
        self.assertNotIn(recovery.HOOK, files)

    def test_install_aborts_before_preload_on_smoke_failure(self):
        rc, rec, files, cmds, _, _ = self._run_install_mock(smoke_reply="SEGFAULT")
        self.assertEqual(rc, 1)
        self.assertFalse(rec["install_ok"])
        self.assertFalse(rec["live_preload_smoke_passed"])
        self.assertNotIn(recovery.PRELOAD, files)
        self.assertNotIn("activate_preload", [lbl for lbl, _ in cmds])

    def test_install_gate_forwards_real_senser_terminal_and_blocks_disallowed(self):
        from pmca.usb.sony import SonySenserCamera
        seen = []

        class RawDev:
            def sendSenserPacket(self, fn, payload, output=None):
                seen.append((fn, payload))
                return (0 if fn == 0x40 else 1), b""

        rec = {"terminal_toggles": []}
        gate = recovery.InstallGate(RawDev(), allow_writes=True, receipt=rec)
        cam = SonySenserCamera(gate)
        cam.writeFile(recovery.HOOK + ".new", b"ELF")
        cam.setTerminalEnable(True)
        # FileControl must be blocked while terminal is open!
        with self.assertRaises(recovery.probe.ProbeError):
            cam.writeFile(recovery.HOOK + ".new", b"ELF")
        cam.setTerminalEnable(False)
        self.assertTrue(gate.terminal_disable_verified)
        cam.readFile(recovery.PRELOAD)
        with self.assertRaises(recovery.probe.ProbeError):
            cam.writeFile("/etc/other", b"X")

    def test_uninstall_preserves_unrelated_preload_entries(self):
        rc, _, files, _, urc, urec = self._run_install_mock(existing_preload=b"/usr/lib/stock.so\n")
        self.assertEqual(rc, 0)
        self.assertEqual(urc, 0)
        self.assertTrue(urec["uninstall_ok"])
        self.assertEqual(files.get(recovery.PRELOAD), b"/usr/lib/stock.so\n")


if __name__ == "__main__":
    unittest.main()
