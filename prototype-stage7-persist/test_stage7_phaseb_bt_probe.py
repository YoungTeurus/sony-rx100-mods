"""Offline tests using the framed, in-memory Senser device from the Phase B suite."""
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import re
import sys
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE.parent / "scripts"), str(HERE)]
import m7_stage7_phaseb_bt_probe as bt
from test_stage7_phaseb_collect import InMemoryCameraDevice, STOCK_MOUNTS, m7_stat_line

pb = bt.pb
DOT = "  77 drwxr-xr-x 2 0 0 80 Jan  1 00:01 .\n"


def processes():
    raw = bytearray()
    for pid in (*pb.TRACKED, 999):
        stat = m7_stat_line(pid, "test", 200)
        raw.extend(f"R|/proc/{pid}|0|0|/sbin/init\nS|".encode() + stat + b"\nC|\n\n")
        raw.extend(b"T|0|" + (stat if pid != 999 else b"") + f"\nE|/proc/{pid}\n".encode())
    return bytes(raw)


BUSYBOX = HERE.parent / "extracted/m7-stage7-phaseb-1.00-20261127T184903Z/bin/busybox"


def audit_frame(cmd):
    """Reject any wire command outside the reviewed M7 command grammar."""
    # Pin inherited command text independently of its imported definitions.
    # Generated marker commands vary only by inode, digest and token.
    normalized = re.sub(r"\.m7-pb-bt-ret\.[0-9a-f]{12}\.[0-9a-f]{32}\.[A-Za-z0-9]{6}", "MARKER", cmd)
    normalized = re.sub(r"(?<=p=/proc/)[1-9][0-9]{0,9}(?=;)", "PID", normalized)
    normalized = normalized.replace(".m7-pb-bt-ret.txt", "MARKER")
    normalized = re.sub(r"\b[0-9a-f]{32}\b", "DIGEST", normalized)
    normalized = re.sub(r'(?<= )[0-9a-f]{24}(?=")', 'TAG', normalized)
    normalized = re.sub(r"(?<=M7BT )[0-9a-f]{12} ", "NONCE ", normalized)
    normalized = re.sub(r'\[ "\$1" = "[0-9]+" \]', '[ "$1" = "INODE" ]', normalized)
    if normalized not in AUDITED_FRAMES:
        raise AssertionError(f"Command outside exact-build audit: {cmd}")


AUDITED_FRAMES = {
    'HISTFILE=/dev/null; export HISTFILE; ulimit -c 0 && umask 077',
    '/bin/busybox cat /proc/mounts',
    'rc=0; for d in /tmp_network; do if [ -L "$d" ] || [ ! -d "$d" ]; then echo "ANC BAD $d"; rc=1; else echo "ANC OK $d"; fi; done; if [ -L /version.txt ] || [ ! -f /version.txt ]; then echo "ANC BAD /version.txt"; rc=1; else echo "ANC OK /version.txt"; fi; [ "$rc" -eq 0 ]',
    '/bin/busybox cat /version.txt',
    '/bin/busybox cat /proc/sys/kernel/random/boot_id',
    '/bin/busybox cat /proc/uptime',
    '/bin/busybox cat /proc/cmdline',
    'if [ -e /proc/self/mountinfo ]; then /bin/busybox cat /proc/self/mountinfo; fi',
    'if [ -L /tmp_bt ]; then (exit 1); elif [ -d /tmp_bt ]; then /bin/busybox ls -lai /tmp_bt; elif [ ! -e /tmp_bt ]; then echo ABSENT; else (exit 1); fi',
    'if [ -L /tmp_network ]; then (exit 1); elif [ -d /tmp_network ]; then /bin/busybox ls -lai /tmp_network; elif [ ! -e /tmp_network ]; then echo ABSENT; else (exit 1); fi',
    'b=/bin/busybox;for p in /proc/[1-9]*;do [ -e "$p/stat" ]||continue;s=$($b cat "$p/stat" 2>/dev/null)||continue;e=$($b readlink "$p/exe" 2>/dev/null);o=$($b wc -c "$p/cmdline" 2>/dev/null);w=$?;set -- $o;n=${1:-0};echo "R|$p|$w|$n|$e";echo "S|$s";echo "C|";$b cat "$p/cmdline" 2>/dev/null;c=$?;echo;t=$($b cat "$p/stat" 2>/dev/null);echo "T|$c|$t";echo "E|$p";done',
    '/bin/busybox dmesg',
    'bt_guard() { [ ! -L /tmp_bt ] && set -- $(/bin/busybox md5sum /proc/self/mountinfo /proc/mounts) && [ "$#" = 4 ] && [ "$1" = "DIGEST" ] && [ "$3" = "DIGEST" ] && [ . -ef /tmp_bt ]; }',
    '(cd -P /tmp_bt && bt_guard && { f=./MARKER; if [ -L "$f" ]; then echo UNSAFE; elif [ -f "$f" ]; then echo REGULAR; elif [ -e "$f" ]; then echo UNSAFE; else echo ABSENT; fi; })',
    '(cd -P /tmp_bt && bt_guard && { [ -r . ] && [ -x . ] || exit 1; set -- ./.m7-pb-bt-ret.*; for f; do if [ -e "$f" ] || [ -L "$f" ]; then echo "$f"; fi; done; })',
    '[ ! -L /proc/self/fd/7 ] && [ ! -L /proc/self/fd/8 ] && [ ! -L /proc/self/fd/9 ]',
    r"""eval "$(/bin/busybox echo -e 'exec 8<<"M7EOF"\nM7EOF\n ')" && [ -p /proc/self/fd/8 ] && exec 9>/proc/self/fd/8""",
    '(cd -P /tmp_bt && bt_guard && { /bin/busybox cpio -i <&8 8<&- 9>&- 3>&- >/dev/null 2>&1 & echo $!; })',
    r"/bin/busybox echo -ne '07070100000001000081800000000000000000000000017fffffff00000001000000000000000000000000000000000000004300000000MARKER\000\000\000\000' >&9",
    'bt_p=/proc/PID; bt_c=$bt_p/fd/3; bt_target=/tmp_bt/MARKER',
    'bt_owned() { [ "$bt_p/exe" -ef /bin/busybox ] && [ "$bt_p/fd/0" -ef /proc/self/fd/8 ] && [ -f "$bt_c" ] && [ "$(/bin/busybox readlink "$bt_c")" = "$bt_target" ]; }',
    'for i in 1 2 3 4 5; do bt_owned && break; /bin/busybox usleep 20000; done; bt_owned && exec 7<>"$bt_c" && bt_owned && [ /proc/self/fd/7 -ef "$bt_c" ] && /bin/busybox ls -Li /proc/self/fd/7',
    '(/bin/busybox sleep 10 0>&9 8<&- 9>&- >/dev/null 2>&1 &) && exec 9>&-', 'exec 9>&- 8<&- 7>&-',
    '(cd -P /tmp_bt && bt_guard && { f=./MARKER; d=/proc/self/fd/7; [ ! -L "$f" ] && [ -f "$d" ] && [ "$f" -ef "$d" ]; })',
    '(cd -P /tmp_bt && bt_guard && { f=./MARKER; d=/proc/self/fd/7; [ ! -L "$f" ] && [ -f "$d" ] && [ "$f" -ef "$d" ] && echo "M7BT NONCE TAG" >&7; })',
    '(cd -P /tmp_bt && bt_guard && { f=./MARKER; d=/proc/self/fd/7; [ ! -L "$f" ] && [ -f "$d" ] && [ "$f" -ef "$d" ] && /bin/busybox dd if="$d" bs=1 count=44 2>/dev/null; })',
    '(cd -P /tmp_bt && bt_guard && { /bin/busybox ls -li ./MARKER; })',
    '(cd -P /tmp_bt && bt_guard && { /bin/busybox dd if=./MARKER bs=1 count=44 2>/dev/null; })',
    '(cd -P /tmp_bt && bt_guard && { f=./MARKER; d=/proc/self/fd/7; [ ! -L "$f" ] && [ -f "$f" ] && exec 7<"$f" && set -- $(/bin/busybox ls -Li "$d") && [ "$1" = "INODE" ] && set -- $(/bin/busybox md5sum "$d") && [ "$1" = "DIGEST" ] && bt_guard && [ ! -L "$f" ] && [ "$f" -ef "$d" ] && /bin/busybox rm "$f"; })',
}


class FirmwareAudit(unittest.TestCase):
    def test_exact_image_tables_and_compiled_flags(self):
        image = BUSYBOX.read_bytes()
        self.assertEqual(hashlib.sha256(image).hexdigest(),
                         "e6ebb87e6de8814f994c18ed194a22bfb463fe55cb8f66aef94b22fb6103905f")
        names = image[0x28802:0x28a1c].split(b"\0")[:-1]
        applets = dict(zip(names, struct.unpack_from("<90I", image, 0x27560)))
        required = {b"[": 0x255f1, b"cat": 0x21a71, b"ls": 0x23745, b"wc": 0x258f9,
                    b"readlink": 0x23f31, b"dd": 0x2242d, b"dmesg": 0x18cb5,
                    b"md5sum": 0x23a95, b"rm": 0x23f5d, b"echo": 0x2278d, b"cpio": 0x1de75, b"usleep": 0x2eacd, b"sleep": 0x24079}
        for name, entry in required.items():
            self.assertEqual(applets[name], entry)
        # The regular member goes to O_EXCL|O_CREAT|O_WRONLY. Short copy
        # branches to the fatal path before close and pathname metadata updates.
        self.assertEqual(image[0x1fc70-0x8000:0x1fc78-0x8000], bytes.fromhex("c1213068ecf784fe"))
        self.assertEqual(image[0x1fbca-0x8000:0x1fbce-0x8000], bytes.fromhex("9a420cdc"))
        self.assertEqual(image[0xcd4e-0x8000:0xcd54-0x8000], bytes.fromhex("54ea050309d0"))
        self.assertIn(b"short read\0", image)
        for absent in (b"command", b"stat", b"df"):
            self.assertNotIn(absent, applets)
        builtins = {}
        for off in range(0x27b48, 0x27c68, 8):
            ptr, entry = struct.unpack_from("<II", image, off)
            name = image[ptr - 0x8000 + 1:].split(b"\0", 1)[0]
            builtins[name] = entry
        for name, entry in {b"export": 0x13ce9, b"ulimit": 0x146f5, b"umask": 0x145d5,
                            b"set": 0x14331, b"echo": 0x2278d, b"exit": 0x13da9,
                            b"eval": 0x174f1, b"break": 0x14581, b"exec": 0x14ca9, b"cd": 0x149bd, b"continue": 0x14581}.items():
            self.assertEqual(builtins[name], entry)
        self.assertNotIn(b"command", builtins)
        operators = {image[i:i+4].split(b"\0", 1)[0] for i in range(0x34579, 0x34669, 6)}
        self.assertTrue(set(b"-p -L -e -d -f -ef -eq -r -x ! =".split()) <= operators)
        for literal in (b"LP\0", b"HSatfdscmlpnvw\0", b"Cnoclobber\0",
                        b"Cadil1gnsxAkcetuSXrvFpLRhT:w:\0", b"lwcL\0", b"cs:n:\0",
                        b"bs\0count\0seek\0skip\0if\0of\0", b"ituvF:dm\0",
                        b"%s  %s\n\0", b"PS1=\\w \\$ \0"):
            self.assertIn(literal, image, literal)


    def test_exact_arm_member_allocation_and_short_eof(self):
        # Execute the original extract callback, intercepting libc boundaries.
        # No firmware process or filesystem is involved in the ARM model.
        from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_THUMB
        from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_SP
        image = BUSYBOX.read_bytes()
        for existing_mtime, collision in ((None, False), (None, True), (-2147483648, False),
                                          (0, False), (2147483647, False)):
            with self.subTest(mtime=existing_mtime, collision=collision):
                arm = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
                arm.mem_map(0x8000, 0x68000)
                arm.mem_write(0x8000, image)
                archive, member, path = 0x60000, 0x60100, 0x60200
                def word(address, value):
                    arm.mem_write(address, struct.pack("<I", value & 0xffffffff))
                word(archive + 0x10, member)
                word(archive + 0x30, 0x10)  # cpio -i default flags, VA 0x1de90
                word(member, path)
                word(member + 8, 1)
                word(member + 0x18, 0o100600)
                word(member + 0x1c, 0x7fffffff)
                word(0x53b04, 0x60300)
                word(0x60300, 2)
                arm.reg_write(UC_ARM_REG_SP, 0x6e000)
                arm.reg_write(UC_ARM_REG_R0, archive)
                events = []
                def hook(uc, pc, size, user):
                    def return_to_caller(value):
                        uc.reg_write(UC_ARM_REG_R0, value & 0xffffffff)
                        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                    if pc == 0x2d3e4:  # lstat64
                        if existing_mtime is not None:
                            word(uc.reg_read(UC_ARM_REG_R1) + 0x50, existing_mtime)
                        return_to_caller(-1 if existing_mtime is None else 0)
                    elif pc == 0xb7ec:  # open64@plt
                        events.append(("open", uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)))
                        return_to_caller(-1 if collision else 3)
                    elif pc == 0x2d5ae:  # copy reads EOF from the private pipe
                        events.append(("copy", uc.reg_read(UC_ARM_REG_R1), uc.reg_read(UC_ARM_REG_R2)))
                        uc.reg_write(UC_ARM_REG_R1, 0)
                        return_to_caller(0)
                    elif pc == 0x2d5d0:  # skip diagnostic
                        return_to_caller(0)
                    elif pc in (0x2e18a, 0xcdac, 0x2d438, 0xb6d4, 0x1fd0a):
                        events.append(pc)
                        uc.emu_stop()
                arm.hook_add(UC_HOOK_CODE, hook)
                arm.emu_start(0x1fb49, 0x6f000, count=500)
                if existing_mtime is not None:
                    self.assertEqual(events, [0x2e18a])  # skip, no unlink
                elif collision:
                    self.assertEqual(events, [("open", 0xc1, 0o100600), 0xcdac])
                else:
                    self.assertEqual(events, [("open", 0xc1, 0o100600), ("copy", 3, 1), 0x2d438])


class Camera:
    def __init__(self):
        self.mount = "none /tmp_bt tmpfs rw 0 0\n"
        self.raw = None
        self.name = bt.MARK
        self.guard = None
        self.changed_at_write = False
        self.fail_after_plant = False
        self.interrupt_at_byte = None
        self.build = pb.BUILD
        self.extra_mounts = ""
        self.proc = processes()
        self.inode = 81
        self.mountinfo = "14 12 0:29 / /tmp_bt rw - tmpfs none rw\n"

    def respond(self, cmd):
        audit_frame(cmd)
        if cmd.startswith("bt_guard()"):
            self.guard = cmd
            return "", 0
        if cmd.startswith("(cd -P /tmp_bt && bt_guard && { "):
            if not cmd.endswith("; })"):
                raise AssertionError("Unbalanced cwd scope")
            cmd = cmd[len("(cd -P /tmp_bt && bt_guard && { "):-len("; })")]
            if self.guard != bt.mount_guard(STOCK_MOUNTS + self.mount, self.mountinfo):
                return "", 1
        if cmd == pb.SETUP_CMD:
            return "", 0
        if cmd == pb.TRANSITION_ANCESTOR_CHECK_CMD:
            return "ANC OK /tmp_network\nANC OK /version.txt\n", 0
        if cmd == pb.MOUNTS_CMD:
            return STOCK_MOUNTS + self.mount + self.extra_mounts, 0
        if cmd == pb.VERSION_CMD:
            return self.build, 0
        if cmd == pb.BOOT_ID_CMD:
            return "8e236270-88fd-4439-9b75-66387d5fb5c0", 0
        if cmd == pb.UPTIME_CMD:
            return "150.10 10.00", 0
        if cmd == pb.CMDLINE_CMD:
            return "warm.mode=2", 0
        if "/proc/self/mountinfo" in cmd:
            return self.mountinfo, 0
        if "ls -lai" in cmd:
            return ("ABSENT" if "/tmp_bt" in cmd and not self.mount else DOT), 0
        if cmd == pb.PROC_SNAPSHOT_CMD:
            return self.proc, 0
        if cmd == pb.DMESG_CMD:
            return b"resume\xff\x00\n", 0
        if cmd == bt.DISCOVER:
            return ("" if self.raw is None else "./" + self.name + "\n"), 0
        if cmd == bt.state_command(self.name):
            return ("ABSENT" if self.raw is None else "REGULAR"), 0
        if cmd in (bt.FD_FREE, bt.PIPE_OPEN, bt.PIPE_CLOSE, bt.PIPE_DEADLINE):
            return "", 0
        if cmd.startswith("/bin/busybox echo -ne "):
            self.requested_name = re.search(r"\.m7-pb-bt-ret\.[0-9a-f]{12}\.[0-9a-f]{32}\.[0-9a-f]{6}", cmd)[0]
            return "", 0
        if cmd == bt.CREATOR:
            if self.changed_at_write:
                return "", 1
            self.name = self.requested_name
            self.raw = b""
            self.creator_inode = self.inode
            return "1250", 0
        if cmd.startswith(("bt_p=/proc/1250;", "bt_owned()")):
            return "", 0
        if cmd.startswith("for i in 1 2 3 4 5;"):
            if self.creator_inode != self.inode:
                return "", 1
            return f"{self.creator_inode} /proc/self/fd/7", 0
        if 'd=/proc/self/fd/7' in cmd and 'exec 7<' not in cmd and self.creator_inode != self.inode:
            return "", 1
        if 'dd if="$d"' in cmd:
            return self.raw, 0
        if cmd.endswith('[ "$f" -ef "$d" ]'):
            return "", 0
        if 'echo "M7BT ' in cmd:
            self.raw = (re.search(r'echo "(M7BT [^"]+)"', cmd)[1] + "\n").encode("ascii")
            if self.interrupt_at_byte is not None:
                self.raw = self.raw[:self.interrupt_at_byte]
                self.interrupt_at_byte = None
                return "", 1
            if self.fail_after_plant:
                self.fail_after_plant = False
                return "", 1
            return "", 0
        if cmd == f"/bin/busybox ls -li ./{self.name}":
            return f"{self.inode} -rw------- 1 0 0 {len(self.raw)} May  6  2021 ./{self.name}\n", 0
        if cmd == f"/bin/busybox dd if=./{self.name} bs=1 count=44 2>/dev/null":
            return self.raw, 0
        if '/bin/busybox rm "$f"' in cmd:
            assert hashlib.md5(self.raw).hexdigest() in cmd
            self.raw = None
            return "", 0
        raise AssertionError(cmd)


class PromptDevice(InMemoryCameraDevice):
    def _handle_wire(self, wire):
        super()._handle_wire(wire)
        cmd = self.commands_received[-1]
        if re.search(r"\bcd\s", cmd) and not (cmd.startswith("(cd ") and cmd.endswith("; })")):
            prompt = pb.terminal.SHELL_PROMPT
            if self.rx.endswith(prompt):
                self.rx[-len(prompt):] = b"/tmp_bt # "


class ProbeTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name).resolve() / "phaseb-probes"
        self.camera = Camera()
        patcher = patch.object(bt, "OUT", self.directory)
        patcher.start()
        self.addCleanup(patcher.stop)

    def invoke(self, mode, label="capture", *, fail_stop=False, fail_disable=False, expect_receipt=True):
        dev = PromptDevice(self.camera.respond, fail_stop=fail_stop, fail_final_disable=fail_disable)
        from pmca.usb.sony import SonySenserAuthDevice, SonySenserCamera

        def connect(receipt, diagnostic, gate_factory):
            receipt["model"] = pb.MODEL
            try:
                diagnostic(SonySenserCamera(gate_factory(dev)), receipt)
            finally:
                pb.probe.finish_service(SonySenserAuthDevice(dev.driver), receipt)

        output = io.StringIO()
        with patch.object(pb.probe, "connect", connect), patch("time.sleep"), contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
            rc = bt.main(["--transition-probe", "--label", label, "--ram-marker", mode])
        if not expect_receipt:
            self.assertNotIn("RESULT=", output.getvalue())
            return rc, None, dev.commands_received, output.getvalue()
        path = Path(re.search(r"^RESULT=(.*)$", output.getvalue(), re.M)[1])
        rec = json.loads(path.read_bytes())
        self.assertEqual(rec["stock_side_effect_disclosure"], bt.DISCLOSURE)
        self.assertTrue(any("/setting/.etools" in line for line in rec["stock_side_effect_disclosure"]))
        self.assertIsNone(rec["stock_flash_writes_observed"])
        self.assertNotIn("tool_flash_writes_performed", rec)
        self.assertFalse(dev.pulls)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        return rc, rec, dev.commands_received, output.getvalue()

    def test_plant_check_remove(self):
        rc, plant, _, _ = self.invoke("plant")
        self.assertEqual(rc, 0, plant)
        expected = plant["marker"]["after"]
        self.assertEqual(expected["bytes"], 43)
        self.assertEqual(expected["md5"], hashlib.md5(self.camera.raw).hexdigest())
        self.assertEqual(len(plant["df_k"]), 5)
        rc, check, cmds, _ = self.invoke("check", "s2r")
        self.assertEqual(rc, 0, check)
        self.assertEqual(check["marker"]["after"], expected)
        self.assertEqual(check["directories"]["/tmp_bt"]["inode"], plant["directories"]["/tmp_bt"]["inode"])
        self.assertFalse(any("busybox cpio" in cmd or 'rm "$f"' in cmd for cmd in cmds))
        self.assertEqual(check["raced_pids"][0]["pid"], 999)
        self.assertEqual(check["processes"][0]["comm"], "test")
        self.assertEqual(base64.b64decode(check["dmesg_b64"]), b"resume\xff\x00\n")
        rc, removed, _, _ = self.invoke("check-and-remove")
        self.assertEqual(rc, 0, removed)
        self.assertEqual(removed["marker"]["status"], "removed")
        self.assertIsNone(self.camera.raw)

    def test_marker_absent_after_transition(self):
        self.assertEqual(self.invoke("plant")[0], 0)
        self.camera.raw = None
        rc, rec, _, _ = self.invoke("check", "wbi")
        self.assertEqual(rc, 0, rec)
        self.assertEqual(rec["marker"]["status"], "absent")
        self.assertEqual(rec["df_k"]["/etc"]["status"], "df_unavailable")

    def test_mutation_commands_in_host_scratch_directory(self):
        root = self.directory.parent
        _, _, cmds, _ = self.invoke("plant")
        write = next(cmd for cmd in cmds if 'echo "M7BT' in cmd)
        target = root / self.camera.name
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        creator = os.open(target, flags, 0o600)
        self.addCleanup(os.close, creator)
        inode = os.fstat(creator).st_ino
        nonce, seed = bt.NEW_NAME.fullmatch(target.name).groups()
        token = bt.inode_token(nonce, seed, inode).strip()
        write = re.sub(r'M7BT [0-9a-f]{12} [0-9a-f]{24}', token, write)

        def shell(cmd, before_command=""):
            cmd = cmd.replace("cd -P /tmp_bt", "cd -P .").replace("/bin/busybox ", "")
            if sys.platform == "darwin":
                cmd = cmd.replace('/proc/self/fd/7', '/dev/fd/7')
                cmd = cmd.replace('[ "$f" -ef "$d" ]',
                                  '[ ! -L "$f" ] && set -- $(ls -i "$f") && i=$1 && '
                                  'set -- $(ls -Li "$d") && [ "$1" = "$i" ]')
            setup = f"exec 7<&{creator}; bt_guard() {{ true; }}; "
            return subprocess.run(["/bin/sh", "-c", setup + before_command + cmd], pass_fds=(creator,),
                                  cwd=root, capture_output=True, timeout=3, env={"PATH": os.environ.get("PATH", os.defpath), "LC_ALL": "C"})

        saved = root / "saved"
        target.rename(saved)
        for kind in ("empty", "fifo", "link"):
            if kind == "empty":
                target.touch()
            elif kind == "fifo":
                os.mkfifo(target)
            else:
                target.symlink_to(saved)
            with self.subTest(kind=kind):
                self.assertNotEqual(shell(write).returncode, 0)
                if kind == "empty":
                    self.assertEqual(target.read_bytes(), b"")
            target.unlink()
        self.assertEqual(saved.read_bytes(), b"")
        saved.rename(target)
        unrelated = root / "other"
        unrelated.write_bytes(b"untouched")
        with patch.dict(os.environ, {"d": "external-sentinel", "f": str(unrelated)}):
            self.assertEqual(shell(write).returncode, 0)
        self.assertEqual(unrelated.read_bytes(), b"untouched")
        self.assertEqual(target.read_bytes(), (token + "\n").encode())
        # Swap after the name/fd predicate and after the echo redirection was
        # applied. Only the original fd can receive bytes during that interval.
        os.ftruncate(creator, 0)
        os.lseek(creator, 0, os.SEEK_SET)
        swap_at_echo = 'echo() { mv "$f" saved && touch "$f" && command echo "$@"; }; '
        self.assertEqual(shell(write, swap_at_echo).returncode, 0)
        self.assertEqual(target.read_bytes(), b"")
        self.assertEqual(saved.read_bytes(), (token + "\n").encode())
        target.unlink()
        saved.rename(target)
        self.camera.raw = target.read_bytes()
        self.camera.name = target.name
        self.camera.inode = inode
        binding = next(self.directory.glob("*.inode"))
        binding.write_text(json.dumps(dict(name=target.name, inode=inode)))
        _, _, cmds, _ = self.invoke("check-and-remove")
        remove = next(cmd for cmd in cmds if 'rm "$f"' in cmd)
        target.write_bytes(b"x" * 43)
        self.assertNotEqual(shell(remove).returncode, 0)
        target.write_bytes((token + "\n").encode())
        self.assertEqual(shell(remove).returncode, 0)
        self.assertFalse(target.exists())

    def test_replacement_at_create_ack_or_after_write(self):
        original = self.camera.respond
        for boundary in ("busybox cpio -i", 'echo "M7BT'):
            self.camera.raw = None
            def replace_after_ack(cmd):
                reply = original(cmd)
                if boundary in cmd:
                    self.camera.inode += 1
                    self.camera.raw = b"" if boundary == "busybox cpio -i" else self.camera.raw
                return reply
            self.camera.respond = replace_after_ack
            rc, rec, cmds, _ = self.invoke("plant")
            self.assertEqual(rc, 1)
            self.assertFalse(rec["marker_baseline_established"])
            self.assertNotEqual(rec.get("marker", {}).get("status"), "planted")
            if boundary == "busybox cpio -i":
                self.assertEqual(self.camera.raw, b"")
                self.assertFalse(any('echo "M7BT' in cmd for cmd in cmds))

    def test_skip_absent_flash_readonly_and_stack(self):
        for rows in ("", "/dev/d /tmp_bt vfat rw 0 0\n", "none /tmp_bt tmpfs ro 0 0\n", self.camera.mount * 2):
            self.camera.mount = rows
            for mode in bt.ACTIONS:
                with self.subTest(mount=rows, mode=mode):
                    rc, rec, cmds, _ = self.invoke(mode)
                    self.assertEqual(rc, int(mode != "check"), rec)
                    self.assertEqual(rec["data_capture_ok"], mode != "check-and-remove")
                    self.assertEqual(rec["marker"]["status"], "skipped_not_tmpfs")
                    self.assertFalse(any(bt.PREFIX in cmd or "bt_guard" in cmd for cmd in cmds))

    def test_pinned_cwd_must_be_tmpfs(self):
        for self.camera.mountinfo in ("", "14 12 0:9 / /tmp_bt ro - tmpfs none ro\n"):
            rc, rec, cmds, _ = self.invoke("plant")
            self.assertEqual(rc, 1)
            self.assertTrue(rec["terminal_disable_verified"])
            self.assertFalse(any("busybox cpio" in cmd for cmd in cmds))
        self.camera.mountinfo = "14 12 0:29 / /tmp_bt rw - tmpfs none rw\n"
        self.camera.changed_at_write = True
        self.assertEqual(self.invoke("plant")[0], 1)
        self.assertIsNone(self.camera.raw)

    def test_untrusted_marker_or_changed_inode(self):
        self.camera.raw = b"M7_PB_MARKER 111111111111 20261127T160000Z\n"
        self.assertEqual(self.invoke("check-and-remove")[0], 1)
        self.camera.raw = None
        self.assertEqual(self.invoke("plant")[0], 0)
        self.camera.inode += 1
        rc, rec, _, _ = self.invoke("check-and-remove")
        self.assertEqual(rc, 1)
        self.assertIn("inode or content mismatch", rec["error"])
        self.assertIsNotNone(self.camera.raw)

    def test_custody_survives_disable_and_final_receipt_loss(self):
        rc, plant, _, _ = self.invoke("plant", fail_disable=True)
        self.assertEqual(rc, 1)
        self.assertFalse(plant["terminal_disable_verified"])
        self.assertFalse(plant["data_capture_ok"])
        next(self.directory.glob("*.json")).write_bytes(b"")
        self.assertEqual(self.invoke("check")[0], 0)
        self.assertEqual(self.invoke("check-and-remove")[0], 0)
        self.assertIsNone(self.camera.raw)

    def test_custody_with_only_old_failed_teardown_receipt(self):
        self.assertEqual(self.invoke("plant", fail_disable=True)[0], 1)
        name = next(self.directory.glob("*.json"))
        record = json.loads(name.read_bytes())
        self.camera.name = bt.MARK
        record["marker"].pop("name")
        self.camera.raw = f"M7_PB_MARKER {record['nonce']} {record['utc']}\n".encode()
        record["marker"]["after"].update(content=self.camera.raw.decode(), md5=hashlib.md5(self.camera.raw).hexdigest())
        name.write_text(json.dumps(record))
        next(self.directory.glob("*.intent")).unlink()
        self.assertEqual(self.invoke("check-and-remove")[0], 0)

    def test_created_marker_without_readback(self):
        self.camera.fail_after_plant = True
        self.assertEqual(self.invoke("plant")[0], 1)
        self.assertTrue(self.camera.raw)
        self.assertEqual(self.invoke("check-and-remove")[0], 0)
        self.assertIsNone(self.camera.raw)
        self.camera.fail_after_plant = True
        self.assertEqual(self.invoke("plant")[0], 1)
        self.camera.inode += 1
        self.assertEqual(self.invoke("check-and-remove")[0], 1)
        self.assertTrue(self.camera.raw)

    def test_alternate_directory_and_permission_preflight(self):
        self.directory.mkdir(mode=0o500)
        self.addCleanup(os.chmod, self.directory, 0o700)
        alt = self.directory.with_name("phaseb-probes-local")
        with patch.object(pb.probe, "connect") as connect, contextlib.redirect_stderr(io.StringIO()) as errors:
            args = ["--transition-probe", "--label", "case", "--ram-marker", "check"]
            if os.getuid() != 0:
                self.assertEqual(bt.main(args), 1)
                self.assertIn("--receipt-dir", errors.getvalue())
                connect.assert_not_called()
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bt.main(args + ["--receipt-dir", str(alt)]), 1)
            connect.assert_called_once()
        self.assertTrue(list(alt.glob("*.json")))

    def test_partial_plant_recovers_only_matching_inode_and_prefix(self):
        for length in (0, 9, 42):
            self.camera.interrupt_at_byte = length
            self.assertEqual(self.invoke("plant")[0], 1)
            self.assertEqual(len(self.camera.raw), length)
            rc, rec, _, _ = self.invoke("check")
            self.assertEqual((rc, rec["marker"]["status"]), (1, "incomplete"))
            self.assertEqual(self.invoke("plant")[0], 1)
            self.camera.inode += 1
            self.assertEqual(self.invoke("check-and-remove")[0], 1)
            self.camera.inode -= 1
            self.assertEqual(self.invoke("check-and-remove")[0], 0)
            self.assertIsNone(self.camera.raw)
        self.assertEqual(self.invoke("plant")[0], 0)
        self.camera.raw = b"unrelated"
        self.assertEqual(self.invoke("check-and-remove")[0], 1)
        self.assertEqual(self.camera.raw, b"unrelated")

    def test_legacy_r2_partial_recovery(self):
        rc, prior, _, _ = self.invoke("plant")
        self.assertEqual(rc, 0)
        nonce = prior["nonce"]
        seed = bt.NEW_NAME.fullmatch(self.camera.name)[2]
        self.camera.name = bt.MARK
        prior["marker"].pop("name")
        final = next(self.directory.glob("*.json"))
        final.write_text(json.dumps(prior))
        intent = next(self.directory.glob("*.intent"))
        intent.write_text(json.dumps(dict(path="/tmp_bt/" + bt.MARK, seed=seed, nonce=nonce)))
        for length in (0, 9):
            self.camera.raw = prior["marker"]["after"]["content"].encode()[:length]
            self.assertEqual(self.invoke("check-and-remove")[0], 0)
        final.unlink()
        self.camera.raw = b""
        rc, rec, cmds, _ = self.invoke("check-and-remove")
        self.assertEqual(rc, 1)
        self.assertIn(bt.RECOVERY, rec["error"])
        self.assertFalse(any('rm "$f"' in cmd for cmd in cmds))

    def test_pre_binding_interruption_gives_owner_recovery(self):
        checkpoint = bt.checkpoint
        def interrupted(directory, name, payload):
            if name.endswith(".inode"):
                raise KeyboardInterrupt
            return checkpoint(directory, name, payload)
        with patch.object(bt, "checkpoint", interrupted):
            self.assertEqual(self.invoke("plant")[0], 1)
        self.assertEqual(self.camera.raw, b"")
        rc, rec, cmds, _ = self.invoke("check-and-remove")
        self.assertEqual(rc, 1)
        self.assertIn(bt.RECOVERY, rec["error"])
        self.assertFalse(any('rm "$f"' in cmd for cmd in cmds))
        self.camera.raw = None
        self.assertEqual(self.invoke("check-and-remove")[0], 0)
        self.assertEqual(self.invoke("plant")[0], 0)

    def test_readonly_cleanup_with_retained_marker(self):
        self.assertEqual(self.invoke("plant")[0], 0)
        raw = self.camera.raw
        self.camera.mount = self.camera.mount.replace(" rw ", " ro ")
        self.camera.mountinfo = self.camera.mountinfo.replace(" rw", " ro")
        rc, rec, cmds, output = self.invoke("check-and-remove")
        self.assertEqual(rc, 1)
        self.assertFalse(rec["marker_cleanup_verified"])
        self.assertTrue(rec["capture_complete"])
        self.assertTrue(rec["telemetry_capture_ok"])
        self.assertIn("DATA_CAPTURE_OK=False", output)
        self.assertEqual(self.camera.raw, raw)
        self.assertFalse(any('rm "$f"' in cmd for cmd in cmds))

    def test_primary_capture_and_final_disable_errors(self):
        self.camera.build = "other"
        rc, rec, _, _ = self.invoke("check", fail_disable=True)
        self.assertEqual(rc, 1)
        self.assertIn("Unexpected camera build", rec["error"])
        self.assertNotEqual(rec["terminal_disable_error"], rec["error"])
        self.assertFalse(rec["terminal_disable_verified"])

    def test_receipt_publication_failures(self):
        def fail_dump(receipt, output, **kwargs):
            output.write('{"label":')
            self.assertFalse(list(self.directory.glob("*.json")))
            raise OSError("ENOSPC during JSON write")
        for method, failure in ((bt.json, ("dump", fail_dump)), (bt.os, ("fsync", OSError("fsync"))),
                                (bt.os, ("link", OSError("link")))):
            with self.subTest(method=failure[0]), patch.object(method, failure[0], side_effect=failure[1]), patch.object(pb.probe, "connect"):
                with self.assertRaises(OSError):
                    bt.run("fault", "check")
                self.assertEqual(list(self.directory.iterdir()), [])

    def test_atomic_receipt_preserves_existing_receipt(self):
        self.directory.mkdir()
        previous = self.directory / "same.json"
        previous.write_bytes(b'{"old": true}\n')
        with bt.custody(self.directory) as directory:
            with self.assertRaises(FileExistsError), bt.receipt_output(directory, previous.name):
                self.fail("Existing receipt was reserved")
        self.assertEqual(list(self.directory.iterdir()), [previous])
        self.assertEqual(json.loads(previous.read_bytes()), {"old": True})

    def test_receipt_collision_after_preflight(self):
        existing = b'{"earlier_receipt":true}\n'
        final = self.directory / "20261127T200000Z-012345abcdef-bt-collision.json"
        def competing_writer(*args, **kwargs):
            with final.open("xb") as output:
                output.write(existing)
        with patch.object(pb.probe, "connect", competing_writer), patch.object(bt.time, "strftime", return_value="20261127T200000Z"), patch.object(bt.secrets, "token_hex", return_value="012345abcdef"):
            with self.assertRaises(FileExistsError):
                bt.run("collision", "check")
        self.assertEqual(final.read_bytes(), existing)
        self.assertEqual(list(self.directory.iterdir()), [final])

    def test_r4_temporary_receipt_exchange_during_capture(self):
        self.directory.mkdir()
        self.directory.chmod(0o777)
        capture = bt.capture
        def swap_during_capture(*args):
            temporary, = self.directory.glob(".*.partial")
            actor = (
                "from pathlib import Path\nimport sys\n"
                "p = Path(sys.argv[1])\n"
                "p.rename(p.with_name('displaced'))\n"
                """p.write_bytes(b'{"partial":')"""
            )
            subprocess.run([sys.executable, "-B", "-c", actor, str(temporary)], check=True)
            return capture(*args)

        with patch.object(bt, "capture", swap_during_capture):
            rc, _, _, _ = self.invoke("check", expect_receipt=False)
        self.assertEqual(rc, 1)
        self.assertEqual(list(self.directory.glob("*.json")), [])
        self.assertTrue(json.loads((self.directory / "displaced").read_bytes())["bt_probe_ok"])
        foreign, = self.directory.glob(".*.partial")
        self.assertEqual(foreign.read_bytes(), b'{"partial":')

    def test_temporary_exchange_at_link_publishes_pinned_inode(self):
        link = os.link
        displaced = self.directory / "displaced"
        def swap_then_link(*args, **kwargs):
            temporary, = self.directory.glob(".*.partial")
            temporary.rename(displaced)
            temporary.write_bytes(b'{"partial":')
            return link(*args, **kwargs)

        with patch.object(bt.os, "link", swap_then_link):
            rc, receipt, _, _ = self.invoke("check")
        self.assertEqual(rc, 0)
        self.assertTrue(receipt["bt_probe_ok"])
        final, = self.directory.glob("*.json")
        self.assertTrue(final.samefile(displaced))
        foreign, = self.directory.glob(".*.partial")
        self.assertEqual(foreign.read_bytes(), b'{"partial":')

    def test_published_bytes_are_verified_before_success(self):
        link = os.link
        def corrupt_then_return(source, name, **kwargs):
            link(source, name, **kwargs)
            final = self.directory / name
            with final.open("r+b") as result:
                result.write(b"!")  # Same inode and length.
        with patch.object(bt.os, "link", corrupt_then_return):
            rc, _, _, _ = self.invoke("check", expect_receipt=False)
        self.assertEqual(rc, 1)
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_invalid_cli_paths_refused_without_connection(self):
        self.directory.symlink_to(self.directory.parent, target_is_directory=True)
        with patch.object(pb.probe, "connect") as connect:
            for dest in (self.directory, self.directory.with_name("bad-name")):
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    rc = bt.main(["--transition-probe", "--label", "case", "--ram-marker", "check",
                                  "--receipt-dir", str(dest)])
                self.assertEqual(rc, 1)
                self.assertIn("Receipt failed", errors.getvalue())
                self.assertNotIn("Traceback", errors.getvalue())
            connect.assert_not_called()

    def test_audit_rejects_unsupported_applets_options_and_cwd(self):
        for cmd in ("command -v df", "/bin/busybox cpio -o -H newc", "stat -f -c %t .",
                    "cd -P /tmp_bt", "/bin/busybox ls -Z /tmp_bt", "echo YES; cd /tmp_bt"):
            with self.subTest(cmd=cmd), self.assertRaises(AssertionError):
                audit_frame(cmd)

    def test_unscoped_cd_breaks_real_frame_matcher(self):
        dev = PromptDevice(lambda _: ("", 0))
        from pmca.usb.sony import SonySenserCamera
        receipt = {"commands": [], "steps": [], "nonce": "123456abcdef"}
        gate = pb.PhaseBCollectGate(dev, frozenset(), receipt=receipt)
        session = pb.PhaseBTerminalSession(SonySenserCamera(gate), receipt)
        with self.assertRaisesRegex(pb.probe.ProbeError, "unexpected trailing bytes"):
            session.command("legacy_pin", "cd -P /tmp_bt")
        self.assertTrue(gate.poisoned)

    def test_stop_and_terminal_results(self):
        rc, rec, _, text = self.invoke("check", fail_stop=True)
        self.assertEqual(rc, 1)
        self.assertTrue(rec["terminal_disable_verified"])
        self.assertIn("GenericUsbException", rec["service_stop_transport"]["error"])
        self.assertIn("DATA_CAPTURE_OK=True\nSERVICE_STOP_TRANSPORT_OK=False", text)
        self.assertFalse(rec["bt_probe_ok"])
        rc, rec, _, _ = self.invoke("check", fail_disable=True)
        self.assertEqual(rc, 1)
        self.assertFalse(rec["terminal_disable_verified"])
        self.assertFalse(rec["data_capture_ok"])

    def test_build_or_bad_process_refuses_before_marker(self):
        self.camera.build = "other"
        self.assertEqual(self.invoke("plant")[0], 1)
        self.camera.build = pb.BUILD
        self.camera.proc = b""
        self.assertEqual(self.invoke("plant")[0], 1)
        self.assertIsNone(self.camera.raw)

    def test_overmounted_version_is_never_read(self):
        self.camera.extra_mounts = "none /version.txt tmpfs rw 0 0\n"
        rc, rec, cmds, _ = self.invoke("plant")
        self.assertEqual(rc, 1)
        self.assertTrue(rec["terminal_disable_verified"])
        self.assertNotIn(pb.VERSION_CMD, cmds)

    def test_real_shell_mount_guard_and_subshell_cwd(self):
        root = self.directory.parent
        bt_dir = root / "tmp_bt"
        bt_dir.mkdir()
        mounts = root / "mounts"
        info = root / "mountinfo"
        mounts.write_text(STOCK_MOUNTS + self.camera.mount)
        info.write_text(self.camera.mountinfo)
        guard = bt.mount_guard(mounts.read_text(), info.read_text())
        # Map only kernel inputs and applet path to the host scratch fixture.
        command = (guard + "; " + bt.scoped("echo OK") + '; rc=$?; pwd; exit "$rc"')
        command = command.replace("/proc/self/mountinfo", str(info)).replace("/proc/mounts", str(mounts))
        command = command.replace("/tmp_bt", str(bt_dir)).replace("/bin/busybox ", "")
        def check():
            return subprocess.run(["/bin/sh", "-c", command], cwd=root, text=True, capture_output=True)
        result = check()
        self.assertEqual(result.stdout.splitlines(), ["OK", str(root)])
        self.assertEqual(result.returncode, 0)
        info.write_text(info.read_text().replace("14 12", "15 12"))
        self.assertNotEqual(check().returncode, 0)
        info.write_text(self.camera.mountinfo)
        mounts.write_text(STOCK_MOUNTS)
        self.assertNotEqual(check().returncode, 0)

    def test_custody_and_label_guards_before_connection(self):
        self.directory.symlink_to(self.directory.parent, target_is_directory=True)
        with patch.object(pb.probe, "connect") as connect:
            with self.assertRaises(ValueError):
                bt.run("case", "check")
            for name in ("EviDEnce", "SoUrCeS"):
                with patch.object(bt, "OUT", pb.ROOT / name), self.assertRaises(ValueError):
                    bt.run("case", "check")
            with self.assertRaises(ValueError):
                bt.run("../outside", "check")
            connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
