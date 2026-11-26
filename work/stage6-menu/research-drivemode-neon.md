# Stage 6 Research (Track A) — Drive Mode & Continuous-Only Gate (RX100M7 1.00)

- **Author / Role:** Gemini 4 Neon (read-only research)
- **Date:** 2026-11-21
- **Scope:** Stage 6 Research Question 1 (`plans/06-autonomy.md`) — Drive Mode storage, exact enum values, zero-ptrace read-only access, mid-hold drive-mode changes, and read-only Still Image Format / Size / Aspect / Quality gating.
- **Hardware / Production edits:** None. Offline static analysis only. No camera/USB access, no `evidence/**` edits, no production code edits.

## Evidence Identity & Labels

All primary proofs come from original Sony DSC-RX100M7 firmware `1.00` (`build 29110_03.2021050601`) binaries:

| Binary | Path | SHA-256 |
|---|---|---|
| `libObj.so` (M7 1.00) | `extracted/m7-1.00-29110_03.2021050601-20261104T212913Z/usr/lib/libObj.so` | `38cba88dab492ed8529ae1ec80636bce64d649229ed790023f3579144860a092` |
| `libMWF.so` (M7 1.00) | `extracted/m7-mwf-20261105T130923Z-63c22574a4f9/usr/lib/libMWF.so` | `49e3199ca9dbcfbca612f6c2e4b2fae430ef510f33ce1300470a215c6ad9e4ba` |
| `libmprctrl.so` (M7 1.00) | `extracted/m7-mprctrl-20261105T104604Z-4ef9ad61f354/usr/lib/libmprctrl.so` | `fa688648fbe2873b34a2c1ce9efbd2d612bf6260688284a8a469c64c7a0b8126` |

One M7A 1.01 UI binary (`extracted/m7a-1.01-fw/.../lib/viewUnified2.so`) is cited **only** as secondary UI corroboration and is explicitly marked as such wherever referenced. All `libObj.so` addresses are ELF VAs (runtime address = `m7_config.bias + VA`); code is Thumb unless noted.

Labels: **PROVEN** = verified directly in M7 1.00 disassembly/tables with ≥2 independent confirmations; **HYPOTHESIS** = consistent with evidence but not yet witnessed live on M7 1.00 hardware; **GAP** = open item requiring hardware observation.

---

## 0. Executive Verdict Table

| Claim | Status | Proof Summary |
|---|---|---|
| `CamSetParams` singleton lives in `libObj.so` `.bss` at `bias + 0x145f3f0` (guard `bias + 0x145f3ec`) | **PROVEN** | `CamSetParams::GetInstance` (`0xa6e384`) GOT `0x13a24cc` → `0x145f3f0` (`R_ARM_RELATIVE`), guard GOT `0x13a62dc` → `0x145f3ec`; independently confirmed by `CamStateMgr::Init` (`0xb5ee02..0xb5ee0a`) storing it into `CamStateMgr + 0x1a88` (`0x145f3e8`). |
| `CamSetParams` maps `paramId ∈ [0x9500, 0xa231]` linearly to `bias + 0x145f3f0 + (paramId - 0x9500) * 4` | **PROVEN** | `ParamId2Idx` (`0xa83454`) computes `paramId - 0x9500`; used identically by `GetParamPtr` (`0xa834d0`), `GetParam` (`0xa837d8`), and `SetParam` (`0xa83daa`). |
| `PARAMID_DRIVE_MODE_ACT` (`0x9541`) slot is `bias + 0x145f4f4`, pointing to an 8-byte `MWF::ParamStd_Template<int, 7>` (`+0 = int value`, `+4 = funcTable*` where `funcTable[0] == 7`) | **PROVEN** | `Base→ACT` table `0x10d9ee8` (`0xa7d520`: `0x9539 → 0x9541`); `libMWF.so` `GetValue` (`0x258b8`), `SetValue` (`0x25876`), `GetType` (`0x20ab0`), `funcTable` (`0x42cec = {7,0,0}`); `libObj.so` `GetParam` (`0xa837ec` 8-byte `ldm/stm`). |
| Scalar `CamSetParams` entries are updated **in-place** (single 32-bit `str`, no free/realloc) during shooting | **PROVEN** | `SetParam` (`0xa83db6..0xa83dc6`) calls `CopyParam` (`0xd3e2f4`) → `operator=` (`libObj` PLT `0x108bb4` → `libMWF` `0x258c0`) → `str r1, [r0]`. `ClearAll` (`0xa9598c`) is called only at ctor (`0xa959f2`) and `CamStateMgr::Finalize` (`0xb61db4`, teardown only). |
| Complete Drive Mode enum values (`0x005e` Single, `0x005f` Burst, `0x05bc` BOL Burst, `0x0c89` Single/Spot Burst, `0x0060` Bracket, `0x0064..0x0564` Self-timer, etc.) | **PROVEN** | 4 independent M7 1.00 confirmations: `VALUEID` table (`0x1346eec`), Model `App2Obj`/`Obj2App` (`0x72ea6c`/`0x72f91a`), `CamMsgConv` Liro & Capture encoders (`0xb18714`/`0xb1d700`), and `GetDriveModeForUPM` (`0xb644cc`). |
| Whether RX100M7 1.00 menu "Continuous Shooting Hi/Mid/Lo" writes `0x005f` (`BURST`) only, or also `0x05bc` (`BOL_BURST`) | **HYPOTHESIS / GAP** | Both `0x005f` and `0x05bc` are wired as unlimited continuous shooting (`count=0`) in M7 1.00 `libObj.so`. Secondary M7A `viewUnified2.so` maps Continuous Hi/Mid/Lo to `0x005f` (`BURST`). Accepting `{0x005f, 0x05bc}` safely covers both; 1 hardware read will confirm which M7 1.00 writes. |
| Still File Format / Size / Aspect / Quality live in the same `CamSetParams` `.bss` array (`bias + 0x145f5f0..0x145f5fc`) | **PROVEN** | Confirmed by `Base→ACT` table (`0x10d9ee8`), `StillSizeInfoMgr` (`0xa964fe..0xa96a50`), `Model` (`0x73df84..0x73e04c`), and `CamSetParams_InitDefaults` (`0xa84170`). `JPEG-only` = `0x00bd`, `Size L` = `0x00b3`, `Aspect 3:2` = `0x00b9`. |
| Zero-ptrace read-only access via `/proc/<pid>/mem` (`pread64`) | **PROVEN** | Pure `.bss` + private RW heap reads; zero `ptrace`, zero Sony function calls, zero mutexes taken; single aligned 32-bit `str` cannot tear. |
| Mid-hold Drive Mode change is possible via `0x7520` (`CamMgr` handles it while `m_IsCapRunning != 0`; e.g., Recall Custom Hold / remote) | **PROVEN (mechanism)** | `CamMgr` `0xaaabf6 → 0xaaac76` handles `MSGID_SET_DRIVE_MODE_CMD` (`0x7520`) while `m_IsCapRunning` (`+0x100`) is non-zero; normal menu is inhibited by `InhMgr` `0x5ea`/`0x672` on `NID_STILL_LOCK_COMP` (`0xaae556`). |

---

## 1. Where Drive Mode & Shooting Settings Live (PROVEN)

### 1.1 `CamSetParams` Singleton in `libObj.so` `.bss`

Unlike heap-only model objects, Sony's central camera-parameter store `CamSetParams` is a **static `.bss` singleton** inside `libObj.so`, located directly after `CamStateMgr` (`0x145d960`):

1. **Confirmation 1 — `CamSetParams::GetInstance()` (`libObj.so` `0xa6e384`, Thumb):**
   ```asm
   00a6e388  ldr  r4, [pc, #0x40]    ; lit[0xa6e3cc] = 0x92edc8
   00a6e38a  ldr  r3, [pc, #0x44]    ; lit[0xa6e3d0] = 0x9184
   00a6e38c  add  r4, pc             ; r4 = 0x139d158 (GOT base)
   00a6e38e  ldr  r6, [r4, r3]       ; GOT[0x13a62dc] -> 0x145f3ec (R_ARM_RELATIVE, init guard)
   00a6e390  ldr  r3, [r6]
   00a6e392  tst.w r3, #1
   00a6e396  ldr  r3, [pc, #0x3c]    ; lit[0xa6e3d4] = 0x5374
   00a6e398  ldr  r5, [r4, r3]       ; GOT[0x13a24cc] -> 0x145f3f0 (R_ARM_RELATIVE, CamSetParams object)
   00a6e39a  bne  #0xa6e3be
   ...
   00a6e3a6  bl   #0xa959d2          ; CamSetParams::CamSetParams(0x145f3f0)
   ```
   `.bss` spans `0x14247f8..0x1463900` (size `0x3f108`). Both `0x145f3ec` and `0x145f3f0` lie inside `.bss` and carry `R_ARM_RELATIVE` (type 23) relocations in `.rel.dyn`.

2. **Confirmation 2 — `CamStateMgr::Init()` (`libObj.so` `0xb5edf8`):**
   ```asm
   00b5edfe  bl    #0xb5d904         ; reset CamStateMgr fields
   00b5ee02  bl    #0xa6e384         ; r0 = CamSetParams::GetInstance() == bias + 0x145f3f0
   00b5ee06  add.w r3, r4, #0x1a80   ; r4 = CamStateMgr (bias + 0x145d960)
   00b5ee0a  str   r0, [r3, #8]      ; *(bias + 0x145f3e8) = bias + 0x145f3f0
   ```
   Every `CamMgr` / `StillSizeInfoMgr` / `CamStateMgr` reader loads `CamSetParams*` from `[CamStateMgr + 0x1a88]` (`bias + 0x145f3e8`), e.g. `0xaae5b8..0xaae5bc`, `0xa964fa..0xa96504`, `0xb644e6..0xb644f2`.

3. **Constructor & size (`libObj.so` `0xa959d2`):**
   - `0xa959d4..0xa959e0`: initializes mutex wrapper at `this + 0x3d24`.
   - `0xa959e4..0xa959ec`: `memset(this, 0, 0x3d24)` — `0x3d24 / 4 = 0xf49` (3913) `MWF::Param*` pointer slots (matching the dump loop limit `movw r3, #0xf49` at `0xa83752` and `ClearAll` loop limit `0xa959c0`).

### 1.2 Linear Slot Addressing (`ParamId2Idx`, `libObj.so` `0xa83454`)

```asm
00a83454  sub.w r0, r1, #0x9500      ; r0 = paramId - 0x9500
00a83458  movw  r2, #0xd31
00a8345c  cmp   r0, r2               ; 0x9500 <= paramId <= 0xa231 ?
00a83462  bls   #0xa83482            ; yes -> return (paramId - 0x9500)
00a83464  sub.w r0, r1, #0xc000      ; 0xc000 <= paramId <= 0xc216 ?
00a83468  movw  r2, #0x216
00a8346c  cmp   r0, r2
00a8346e  bhi   #0xa83478
00a83470  sub.w r0, r1, #0xb200
00a83474  subs  r0, #0xce            ; -> paramId - 0xb2ce (slots 0xd32..0xf48)
00a83476  pop   {r7, pc}
```

Both `CamSetParams::GetParam` (`0xa837b8`, at `0xa837d8: ldr.w r5, [r5, r0, lsl #2]`) and `CamSetParams::SetParam` (`0xa83d80`, at `0xa83daa: ldr.w r8, [r4, r0, lsl #2]`) index directly into `CamSetParams[index]`:

$$\text{slot\_va}(\text{paramId}) = \text{bias} + \texttt{0x145f3f0} + (\text{paramId} - \texttt{0x9500}) \times 4 \qquad (\text{for } \texttt{0x9500} \le \text{paramId} \le \texttt{0xa231})$$

### 1.3 `MWF::ParamStd_Template<int, Type=7>` Layout & In-Place Update Proof

Verified in `libMWF.so` (M7 1.00):
- `_ZN3MWF17ParamStd_TemplateIiLNS_5Param4TypeE7EE13virtual_CloneEPKS1_` (`0x25914`): `movs r0, #8; blx operator new` → **8-byte object**.
- `_ZNK3MWF17ParamStd_TemplateIiLNS_5Param4TypeE7EE8GetValueEv` (`0x258b8`):
  ```asm
  000258bc  ldr r0, [r0]             ; int32_t value at offset +0
  ```
- `_ZN3MWF17ParamStd_TemplateIiLNS_5Param4TypeE7EE8SetValueEi` (`0x25876`):
  ```asm
  0002587a  str r1, [r0]             ; single aligned 32-bit write to +0
  ```
- `_ZNK3MWF5Param7GetTypeEv` (`0x20ab0`):
  ```asm
  00020ab0  ldr r3, [r0, #4]         ; offset +4 = funcTable*
  00020ab6  ldr r0, [r3]             ; funcTable[0] == Type (7)
  ```
- `_ZN3MWF17ParamStd_TemplateIiLNS_5Param4TypeE7EE9funcTableE` (`libMWF.so` `0x42cec`, 12 bytes): `{ 0x00000007, 0x00000000, 0x00000000 }`.
- Independently confirmed in `libObj.so` `CamSetParams::GetParam` (`0xa837e0..0xa837f0`): for `GetType() ∈ 1..8`, it copies the 8 bytes verbatim via `ldm.w r5, {r0, r1}; stm.w r6, {r0, r1}`.

**In-place update proof (no heap free/realloc during normal operation):**
1. In `CamSetParams::SetParam` (`0xa83d80`):
   ```asm
   00a83daa  ldr.w r8, [r4, r0, lsl #2]  ; r8 = existing MWF::Param*
   00a83db0  cmp.w r8, #0
   00a83db4  beq   #0xa83dd8             ; only allocates if slot was NULL
   00a83db6  mov   r0, r8
   00a83db8  bl    #0x1225f8             ; GetType()
   00a83dbc  subs  r0, #1
   00a83dbe  cmp   r0, #7
   00a83dc0  bhi   #0xa83dcc             ; only deletes+reallocs if non-scalar (array/struct)
   00a83dc2  mov   r0, r6                ; src
   00a83dc4  mov   r1, r8                ; dst (existing 8-byte ParamStd<int,7>*)
   00a83dc6  bl    #0xd3e2f4             ; CopyParam -> operator= -> SetValue (str r1, [r0])
   ```
   `CopyParam` (`0xd3e2f4`) dispatches on `type - 1` via `tbb` (`0xd3e328`); for `type = 7` (case 6), it tail-branches to PLT `0x108bb4` (`GOT 0x139d59c` = `_ZN3MWF17ParamStd_TemplateIiLNS_5Param4TypeE7EEaSERKS3_`), which in `libMWF.so` (`0x258c0..0x258d8`) calls `GetValue(src)` then `SetValue(dst, val)` (`str r1, [r0]`).
2. `CamSetParams::ClearAll` (`0xa9598c`, the only code that deletes/NULLs scalar slots) has **exactly 2 callers** in `libObj.so`:
   - `0xa959f2` inside `CamSetParams::CamSetParams` (startup, slots already 0),
   - `0xb61db4` inside `CamStateMgr::Finalize` (`0xb61da8`), whose only 2 callers are `ObjCamera` teardown (`0xaea4c4`) and `CamStateMgr::~CamStateMgr` (`0xb61eea`).

### 1.4 Exact `.bss` Slot Addresses for Drive Mode & Still Image Format

All `PARAMID` names are verified from `libObj.so`'s ID-indexed pointer table anchored at `0x9953 → 0x1338620`, and all `Base → _ACT` mappings are verified from `libObj.so` `0xa7d520` (static table at `0x10d9ee8`, indexed by `paramId - 0x9507`):

| Setting | Base `PARAMID` | `_ACT` `PARAMID` | `_ACT` Name | `.bss` Slot VA (`bias + VA`) | Default in `0xa84170` |
|---|---|---|---|---|---|
| **Drive Mode (active)** | `0x9539` | **`0x9541`** | `PARAMID_DRIVE_MODE_ACT` | **`0x145f4f4`** | `0x005e` (`SINGLE`) |
| Drive Mode (user set) | `0x9539` | `0x953d` | `PARAMID_DRIVE_MODE_SET` | `0x145f4e4` | `0x005e` (`SINGLE`) |
| Burst Max (active) | `0x953a` | `0x9542` | `PARAMID_BURST_MAX_ACT` | `0x145f4f8` | `0` (`uint32`) |
| **Burst Speed (active)** | `0x953b` | **`0x9543`** | `PARAMID_BURST_SPEED_ACT` | **`0x145f4fc`** | `0x0068` (`M`) |
| **BOL Burst Speed (active)** | `0x9b37` | **`0x9b39`** | `PARAMID_BOL_BURST_SPEED_ACT` | **`0x1460cd4`** | `0x05bd` (`L`) |
| Spot Burst Speed (active) | `0xa01f` | `0xa021` | `PARAMID_SPOT_BURST_SPEED_ACT` | `0x1462074` | `0x0c8b` (`M`) |
| **Still Size (active)** | `0x9578` | **`0x9580`** | `PARAMID_STILL_SIZE_ACT` | **`0x145f5f0`** | `0x00b3` (`L`) |
| **Still Aspect (active)** | `0x9579` | **`0x9581`** | `PARAMID_STILL_ASPECT_ACT` | **`0x145f5f4`** | `0x00b8` (`4:3`) |
| **JPEG Quality (active)** | `0x957a` | **`0x9582`** | `PARAMID_JPEG_QUALITY_ACT` | **`0x145f5f8`** | `0x00ba` (`STD`) |
| **Still File Format (active)** | `0x957b` | **`0x9583`** | `PARAMID_STILL_FILE_FORMAT_ACT` | **`0x145f5fc`** | `0x00bd` (`JPEG`) |

Note on `_ACT` vs `_SET`: always gate on **`_ACT`** (`0x9541`, `0x9580..0x9583`). `_SET` reflects the user's menu preference even when an exposure/scene mode exclusion overrides it, whereas `_ACT` is the actual effective camera mode updated by `SequenceSetDriveMode` (`0xa5e344 → 0xa83e1c → 0xa83dee → 0xb7302c → 0xa83d80`) and read by every downstream capture/recorder/UPM consumer.

Note on `CamStateMgr + 0xb2c` (`bias + 0x145e48c`, `m_StillFileFormat` in `DebugDump` `0xb5f340`): it is populated from `PARAMID_STILL_FILE_FORMAT_ACT` at `0xb6393e..0xb63952`, but its enclosing function `0xb63868` has 0 direct `bl` callers (indirect/init path only). `CamSetParams` (`bias + 0x145f5fc`) is the canonical live store read directly by `StillSizeInfoMgr` (`0xa96a08`), so prefer `CamSetParams`.

---

## 2. Exact Drive Mode & Burst Speed Enum Values (PROVEN)

### 2.1 Four Independent Confirmations in M7 1.00 `libObj.so`

Every `VALUEID_*` below is verified across four independent sites in M7 1.00 `libObj.so`:
1. **`VALUEID` name pointer table** (`0x1346eec`, anchored at `0x4b = VALUEID_AF_LOCK_CLEAR`).
2. **UI / Model writer & reader**:
   - Writer `App2Obj` (`0x72ea6c`, called by `0x722356` and `0x7244de` to build `ObjMsg(0x3100, 0x7520)` = `MSGID_SET_DRIVE_MODE_CMD` with `PARAMID_DRIVE_MODE` `0x9539`).
   - Reader `Obj2App` (`0x72f91a`, called by `0x73cf2e` on `MSGID_NOTIFY_DRIVE_MODE_EVT` `0x8515` reading `PARAMID_DRIVE_MODE_ACT` `0x9541`).
3. **`CamMsgConv` RTOS packet builders**:
   - `SetDriveModeForLiro` (`0xb18714`, building RTOS command `0x400e` from `MSGID_SET_DRIVE_MODE_CMD` `0x7520`, called by `SequenceSetDriveMode` `0xa5e26c`).
   - Capture command builder (`0xb1d700`, reading `PARAMID_DRIVE_MODE_ACT` `0x9541` from `CamSetParams` at `0xb1d720`).
4. **`GetDriveModeForUPM`** (`0xb644cc`, reading `PARAMID_DRIVE_MODE_ACT` `0x9541` at `0xb644ea`, `PARAMID_BOL_BURST_SPEED_ACT` `0x9b39` at `0xb64598`, `PARAMID_SPOT_BURST_SPEED_ACT` `0xa021` at `0xb645d6`, and `PARAMID_BURST_SPEED_ACT` `0x9543` at `0xb64628`).

### 2.2 Complete `PARAMID_DRIVE_MODE_ACT` (`0x9541`) Enum Table

| Hex Value | `VALUEID` Name (`0x1346eec`) | Model App (`0x72f91a`) | Liro `0x400e` byte+8 / count (`0xb18714`) | Capture byte+8 / count (`0xb1d700`) | UPM byte+9 (`0xb644cc`) | Meaning | Pre-Capture Gate |
|---|---|---|---|---|---|---|---|
| **`0x005e`** | `VALUEID_DRIVE_MODE_SINGLE` | `0` | `0` / `1` | `0` / `1` | `0` | Single Shooting | **REFUSE** |
| **`0x005f`** | `VALUEID_DRIVE_MODE_BURST` | `1` | `1` / `0` (unlimited) | `1` / `0` (unlimited) | `3` | **Continuous Shooting** (speed in `0x9543`) | **ARM** |
| **`0x05bc`** | `VALUEID_DRIVE_MODE_BOL_BURST` | `0xf` | `8` / `0` (unlimited) | `0x21` / `0` (unlimited) | `6` | **Blackout-Less Continuous Shooting** (speed in `0x9b39`) | **ARM** |
| `0x0062` | `VALUEID_DRIVE_MODE_SPEED_PRIOR_BURST` | `4` | `5` / `0` | `0x13` / `0` | `5` | Speed-Priority Continuous Burst (legacy/other bodies) | **REFUSE** (or optional; see §2.4) |
| **`0x0c89`** | `VALUEID_DRIVE_MODE_SPOT_BURST` | `0x10` | `9` / `7` | `1` / `7` | `7` | **Single Burst Shooting** (fixed 7-shot 90/60/30 fps; `StillSizeInfoMgr` sets `+0x18=7` at `0xa96bc4`) | **REFUSE** |
| `0x0063` | `VALUEID_DRIVE_MODE_RAW_BURST` | `5` | `4` / `burst_max` | `5` / `burst_max` | `4` | RAW Burst (fixed count) | **REFUSE** |
| `0x0060` | `VALUEID_DRIVE_MODE_BRACKET` | `2` | bracket (`0x954d`) | bracket (`0x954d`) | `2` | Exposure / WB / DRO Bracket | **REFUSE** |
| `0x0061` | `VALUEID_DRIVE_MODE_REMOTE` | `3` | `3` / `1` | `0` / `1` | `1` | Remote Commander | **REFUSE** |
| `0x0064` | `VALUEID_DRIVE_MODE_SINGLE_SELF_10S` | `7` | `6` / `1` | `0` / `1` | `0` | Self-timer Single 10 s | **REFUSE** |
| `0x0562` | `VALUEID_DRIVE_MODE_SINGLE_SELF_5S` | `0xc` | `6` / `1` | `0` / `1` | `0` | Self-timer Single 5 s | **REFUSE** |
| `0x0065` | `VALUEID_DRIVE_MODE_SINGLE_SELF_2S` | `8` | `6` / `1` | `0` / `1` | `0` | Self-timer Single 2 s | **REFUSE** |
| `0x0066` | `VALUEID_DRIVE_MODE_BURST_SELF_10S` | `9` | `7` / `burst_max` | `1` / `burst_max` | `3` | Self-timer Cont. 10 s (3/5 shots) | **REFUSE** |
| `0x0564` | `VALUEID_DRIVE_MODE_BURST_SELF_5S` | `0xe` | `7` / `burst_max` | `1` / `burst_max` | `3` | Self-timer Cont. 5 s (3/5 shots) | **REFUSE** |
| `0x0563` | `VALUEID_DRIVE_MODE_BURST_SELF_2S` | `0xd` | `7` / `burst_max` | `1` / `burst_max` | `3` | Self-timer Cont. 2 s (3/5 shots) | **REFUSE** |
| `0x0580` | `VALUEID_DRIVE_MODE_RAW_BURST_SELF_2S` | `5` | `4` / `burst_max` | `5` / `burst_max` | `4` | Self-timer RAW Burst 2 s | **REFUSE** |
| `0x0581` | `VALUEID_DRIVE_MODE_RAW_BURST_SELF_5S` | `5` | `4` / `burst_max` | `5` / `burst_max` | `4` | Self-timer RAW Burst 5 s | **REFUSE** |
| `0x0582` | `VALUEID_DRIVE_MODE_RAW_BURST_SELF_10S` | `5` | `4` / `burst_max` | `5` / `burst_max` | `4` | Self-timer RAW Burst 10 s | **REFUSE** |

### 2.3 Burst Speed Sub-Enums (PROVEN)

All three speed parameters are independently confirmed in `VALUEID` table (`0x1346eec`), Model `App2Obj`/`Obj2App` (`0x72ea0e`/`0x72fa12`, `0x72ea3e`/`0x72fa40`), `CamMsgConv` (`0xb1dc28..0xb1dd24`), and `GetDriveModeForUPM` (`0xb6458c..0xb64668`):

| Speed Parameter | `.bss` Slot VA | Lo | Mid | Hi | Hi+ |
|---|---|---|---|---|---|
| `PARAMID_BURST_SPEED_ACT` (`0x9543`) | `bias + 0x145f4fc` | `0x0067` (`BURST_SPEED_L`) | `0x0068` (`BURST_SPEED_M`) | `0x0069` (`BURST_SPEED_H`) | `0x0594` (`BURST_SPEED_H_PLUS`) |
| `PARAMID_BOL_BURST_SPEED_ACT` (`0x9b39`) | `bias + 0x1460cd4` | `0x05bd` (`BOL_BURST_SPEED_L`) | `0x05be` (`BOL_BURST_SPEED_M`) | `0x05bf` (`BOL_BURST_SPEED_H`) | — |
| `PARAMID_SPOT_BURST_SPEED_ACT` (`0xa021`) | `bias + 0x1462074` | `0x0c8a` (`SPOT_BURST_SPEED_L`) | `0x0c8b` (`SPOT_BURST_SPEED_M`) | `0x0c8c` (`SPOT_BURST_SPEED_H`) | — |

### 2.4 `BURST` (`0x005f`) vs `BOL_BURST` (`0x05bc`) Nuance on RX100M7 (HYPOTHESIS / GAP)

- In M7 1.00 `libObj.so`, **both** `0x005f` (`VALUEID_DRIVE_MODE_BURST`) and `0x05bc` (`VALUEID_DRIVE_MODE_BOL_BURST`, blackout-less continuous shooting) are live unlimited continuous-shooting modes (`count = 0`), and `libObj.so` contains RX100M7-era exclusion strings referencing `BOL_BURST` (`0x1136cd5 PARAMID_EXC_CONF_BOL_BURST_POSSIBILITY`, `0x1153e48 ...DRIVE_MODE_BURST_SHUTTER_TYPE_AUTO_EE_TYPE_STILL_BOL_BURST`, `0x1154575 ...SHUTTER_TYPE_ELEC_EE_TYPE_STILL_BOL_BURST`).
- In secondary M7A 1.01 UI (`viewUnified2.so`, `CmnViewModelWrpStlRecDriveMode::getDriveModeValue` `0x40fdd2..0x40fe12` and `WrapperDriveMode::getDriveMode` `0x4e6dce..0x4e6e34`), the Drive Mode menu's Continuous Shooting Lo/Mid/Hi items map to App mode `1` = **`0x005f` (`VALUEID_DRIVE_MODE_BURST`)** with `PARAMID_BURST_SPEED_ACT` (`0x0067`/`0x0068`/`0x0069`); `0x0f` (`BOL_BURST`) is not handled in `getDriveModeValue`.
- **HYPOTHESIS:** RX100M7 1.00 Continuous Shooting Hi/Mid/Lo writes `0x005f` (`VALUEID_DRIVE_MODE_BURST`) into `PARAMID_DRIVE_MODE_ACT` (with blackout-less shooting controlled internally by shutter type / `BOL_BURST_POSSIBILITY`), or writes `0x05bc` under certain shutter/electronic configurations.
- **GAP:** Neither `0x005f` nor `0x05bc` has yet been sampled from live M7 1.00 RAM (prior receipts did not read `0x145f3f0+`). Accepting **`drive_mode_act == 0x005f || drive_mode_act == 0x05bc`** (and logging both `drive_mode_act`, `burst_speed_act`, and `bol_burst_speed_act` in the Stage 6 journal) safely handles both possibilities while rejecting Single (`0x005e`), Single Burst (`0x0c89`), Self-timer, and Bracket.

---

## 3. Image Format, Size, Aspect & Quality Gate (PROVEN)

Stage 5 currently hard-checks `width == 5472 && height == 3648` (`prototype-producer-probe/ram_precapture_ring.c:533`) and JPEG-only flags `(flags & 0xffffff) != 0x000101` (`prototype-producer-probe/ram_capture.c:252`), which causes non-JPEG or non-20M settings to fail late (or trigger `retain_unresolved`).

All four Still Image parameters sit **contiguously** in `CamSetParams` at `bias + 0x145f5f0..0x145f5ff` (one 16-byte `pread64` gets all four `MWF::Param*` pointers). Each enum is verified across three independent M7 1.00 confirmations: `VALUEID` table (`0x1346eec`), `StillSizeInfoMgr` (`0xa965f8..0xa96a50`), and Model `Obj2App` (`0x73df84..0x73e04c` → `0x72f5d4..0x72f660` + LUTs at `0xfc9c8c`, `0xfc9df8`, `0xfc9e0c`):

| Parameter (`_ACT`) | `.bss` Slot VA | Hex Value | `VALUEID` Name | `StillSizeInfoMgr` int | Model int | Stage 6 Gate |
|---|---|---|---|---|---|---|
| `PARAMID_STILL_FILE_FORMAT_ACT` (`0x9583`) | `bias + 0x145f5fc` | **`0x00bd`** | `VALUEID_STILL_FILE_FORMAT_JPEG` | `0` (`0xa96a2c`) | `0` | **ALLOW** |
| | | `0x00be` | `VALUEID_STILL_FILE_FORMAT_RAW` | `2` (`0xa96a30`) | `1` | **REFUSE** (clean) |
| | | `0x00bf` | `VALUEID_STILL_FILE_FORMAT_RAW_JPEG` | `1` (`0xa96a36`) | `2` | **REFUSE** (clean) |
| | | `0x00c2` | `VALUEID_STILL_FILE_FORMAT_NONE` | error | `-1` | **REFUSE** |
| `PARAMID_STILL_SIZE_ACT` (`0x9580`) | `bias + 0x145f5f0` | **`0x00b3`** | `VALUEID_STILL_SIZE_L` (20M) | `0` (`0xa9662a`) | `0` | **ALLOW** |
| | | `0x00b4` | `VALUEID_STILL_SIZE_M` (10M) | `1` (`0xa9662e`) | `1` | **REFUSE** (clean) |
| | | `0x00b5` | `VALUEID_STILL_SIZE_S` (5M) | `2` (`0xa96632`) | `2` | **REFUSE** (clean) |
| | | `0x00b6` | `VALUEID_STILL_SIZE_VGA` | `3` (`0xa96636`) | `3` | **REFUSE** (clean) |
| `PARAMID_STILL_ASPECT_ACT` (`0x9581`) | `bias + 0x145f5f4` | **`0x00b9`** | `VALUEID_STILL_ASP_3_2` (3:2) | `0` (`0xa966a2`) | `1` | **ALLOW** |
| | | `0x00b8` | `VALUEID_STILL_ASP_4_3` (4:3) | `1` (`0xa9669c`) | `0` | **REFUSE** (clean) |
| | | `0x00b7` | `VALUEID_STILL_ASP_16_9` (16:9) | `2` (`0xa96698`) | `2` | **REFUSE** (clean) |
| | | `0x03e3` | `VALUEID_STILL_ASP_1_1` (1:1) | `3` (`0xa966a6`) | `3` | **REFUSE** (clean) |
| `PARAMID_JPEG_QUALITY_ACT` (`0x9582`) | `bias + 0x145f5f8` | `0x00ba` | `VALUEID_JPEG_STD` | `0` | `0` | **ALLOW** (log) |
| | | `0x00bb` | `VALUEID_JPEG_FINE` | `1` | `1` | **ALLOW** (log) |
| | | `0x00bc` | `VALUEID_JPEG_EXFINE` | `2` | `2` | **ALLOW** (log) |

**Note on `5472x3648`:** `libmprctrl.so` (`MprCtrlStillMgr::GetBackupStillSize`, `0x1bc01`) loads the pixel-dimension lookup table from Backup EEPROM rather than hardcoding `5472`/`3648` literals in `libObj.so` or `libmprctrl.so`. On RX100M7 (20.1 MP 3:2 sensor), `L` (`0x00b3`) + `3:2` (`0x00b9`) + `JPEG` (`0x00bd`) is the unique combination matching Stage 5's `5472x3648` JPEG-only requirement (already confirmed by Stage 5 hardware receipts).

---

## 4. Zero-Ptrace Read-Only Access Recipe (PROVEN)

The helper reads `im.elf` memory purely via `pread64` (`syscall 180`) on `/proc/<pid>/mem` — **zero `ptrace`, zero Sony function calls, zero mutexes taken**:

1. **Runtime identity & init guard (1 `pread64` of 8 bytes at `bias + 0x145f3e8`):**
   - `u32[0]` (`CamStateMgr + 0x1a88`) **must equal** `bias + 0x145f3f0`.
   - `(u32[1] & 1)` (`CamSetParams` C++11 static init guard at `bias + 0x145f3ec`) **must equal** `1`.
   - If either fails → fail closed (do not arm).
2. **Slot pointer reads (3 `pread64` calls total, or 2 if skipping `bol_burst_speed`):**
   - 12 bytes at `bias + 0x145f4f4` → `{ p_drive_mode_act, p_burst_max_act, p_burst_speed_act }`.
   - 4 bytes at `bias + 0x1460cd4` → `p_bol_burst_speed_act` (optional diagnostic / speed witness).
   - 16 bytes at `bias + 0x145f5f0` → `{ p_still_size_act, p_still_aspect_act, p_jpeg_quality_act, p_still_file_format_act }`.
3. **Pointer validation & scalar dereference (per required slot):**
   - Verify `p` is 4-byte aligned, non-zero, and `[p, p + 8)` lies inside a private RW anonymous/heap VMA (`private_range(o, p, 8)`).
   - Read 8 bytes `{ val, func_table }` from `p`.
   - **Type witness:** verify `func_table` is 4-byte aligned and non-zero, and read 4 bytes `type_id = u32(func_table)` → **must equal `7`** (`MWF::Param::Type` for `int32_t`). (Note: `func_table` lies in `libMWF.so` `.data.rel.ro`/`.rodata`, which is a mapped file segment rather than a private RW heap VMA, so do not require `private_range` on `func_table`; or validate it once against `libMWF.so` bias + `0x42cec`.)
   - Because `SetValue` executes a single aligned 32-bit `str r1, [r0]` on an object never freed during camera operation, the passive 32-bit `pread64` is atomic and cannot tear.
4. **Total syscall cost:**
   - Pre-arm check (once on S1 rise): ~10–12 tiny `pread64` calls (< 100 bytes total).
   - Mid-hold poll (per tick): 1 `pread64` of 4 bytes at `bias + 0x145f4f4` + 1 `pread64` of 8 bytes at `p_drive_mode_act` (2 syscalls/tick).

---

## 5. Mid-Hold Drive Mode Change & Recommended Gate Behavior

### 5.1 Can Drive Mode Change While S1 Is Held? (PROVEN)

- **Normal menu UI:** inhibited once AF/AE lock completes — `CamMgr` case `0x202c` (`NID_STILL_LOCK_COMP`, `0xaae556..0xaae592`) calls `InhMgr::ChangeInhFactorStatus(0x5ea, true)` and `ChangeInhFactorStatus(0x672, true)` followed by `UpdateInhFactor()`.
- **Non-menu paths (Recall Custom Hold / external commands):** `ObjCamera` / `CamMgr` does **not** unconditionally reject `MSGID_SET_DRIVE_MODE_CMD` (`0x7520`) while S1 or capture is active. Specifically, `CamMgr` (`0xaaabf6 → 0xaaac76..0xaaac8c`) explicitly checks `CamStateMgr::GetIsCapRunning()` (`+0x100`, `0xb5fcd4`) and `GetIsLiroEEStartEnable()` (`+0xd54`, `0xb62d40`) when `0x7520` arrives, issuing RTOS command `0x40d6` (`0xaaab50`) if a capture is active. In addition, `libObj.so` implements Recall Custom Hold (`PARAMID_PUSH_MR_{1,2,3}_DRIVE_MODE_*`), which allows a custom button held during shooting to temporarily override Drive Mode.

### 5.2 Recommended Gate State Machine for Stage 6

1. **Off / Refused state (zero interference):**
   - On physical S1 rising edge (idle → arm check): read `drive_mode_act`, `still_file_format_act`, `still_size_act`, `still_aspect_act`, `jpeg_quality_act`.
   - Arm **if and only if**:
     - helper toggle is ON (`enabled == 1`), AND
     - `(drive_mode_act == 0x005f || drive_mode_act == 0x05bc)`, AND
     - `still_file_format_act == 0x00bd` (JPEG only), AND
     - `still_size_act == 0x00b3` (L / 20M), AND
     - `still_aspect_act == 0x00b9` (3:2), AND
     - `jpeg_quality_act ∈ {0x00ba, 0x00bb, 0x00bc}`.
   - Otherwise: **stay completely idle** — no `ptrace` attach, no software S1/S2 injection, no frame retain, no `retain_unresolved`. Log a single non-fatal gate-refusal record with the exact hex values read (so diagnostics immediately show e.g. `SINGLE`, `SPOT_BURST`, `RAW+JPEG`, or `16:9`).
2. **Mid-hold change (while armed in `PRECAP_ROLL`, before full-press trigger):**
   - Re-read `drive_mode_act` (and `still_file_format_act` / `still_size_act` / `still_aspect_act` if desired — cheap at 2–5 `pread64`s) on each polling tick.
   - If the predicate stops holding (e.g. Recall Custom Hold switches to Single, or read fails): **immediately cancel and tear down cleanly** (same path as half-press release: stop software S2, discard/release all retained RAM ring frames, release software S1, detach `ptrace`), and **latch a refusal until physical S1 is released** (no mid-hold thrashing; require a fresh S1 press in Continuous to re-arm).
3. **Post-trigger (`PRECAP_POST` / `PRECAP_DRAIN` saving):**
   - Once physical full-press has already triggered save of frames already in RAM, finish saving the already-admitted valid `5472x3648` JPEG frames cleanly, then enforce the gate before any subsequent arm.

---

## 6. Open Gaps (Honest Accounting)

1. **Live M7 1.00 hardware value for Continuous Shooting Hi/Mid/Lo (`0x005f` vs `0x05bc`):** Static M7 1.00 code supports both `0x005f` (`BURST`) and `0x05bc` (`BOL_BURST`); M7A UI points to `0x005f`. Not yet read from live M7 1.00 RAM. Accepting `{0x005f, 0x05bc}` and logging the exact read value closes this on the first hardware run.
2. **Exact `CamSetParams_InitDefaults` (`0xa84170`) caller:** No direct `bl` caller of `0xa84170` was found (possibly unused/dead or invoked indirectly), whereas runtime population of `CamSetParams` via `0xa83e1c` (`SetParams`, 289 callers including `SequenceSetDriveMode` `0xa5e344`) is proven. Because the gate checks for non-NULL pointers and `type_id == 7` before reading, an unpopulated slot fails closed safely.
3. **Offline hardware receipt cross-check:** Checked `evidence/` and `work/stage5-no-card-writes/`; no prior M7 1.00 receipt captured `0x145f3f0..0x145f600` (`CamSetParams`), so live RAM readback awaits Stage 6 hardware testing.
4. **RAW / RAW+JPEG and non-3:2 / non-L support:** This gate cleanly refuses unsupported formats without hanging in `retain_unresolved`; adding native RAW+JPEG or arbitrary-size pre-capture remains out of Stage 6 scope.

---

## 7. Reproducibility Commands (Offline)

All checks ran read-only with `.venv-analysis/bin/python` and `work/stage4-no-card-writes/opus/odis.py`:

```sh
# CamSetParams singleton & slot mapper
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xa6e384 0x48
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xa83454 0x40
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xa837b8 0x60
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xa83d80 0x70
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xd3e2f4 0xb0

# Drive mode writers/readers & consumers
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0x72ea6c 0x9c
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0x72f91a 0xa4
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xa5e224 0x160
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xb18714 0x120
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xb1d700 0x120
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xb644cc 0x1b0

# Still size / aspect / quality / file format consumers
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xa965f8 0xe0
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0xa96970 0xd0
.venv-analysis/bin/python work/stage4-no-card-writes/opus/odis.py at 0x72f5d4 0x9c
```
