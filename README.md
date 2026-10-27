# ex7loader

Loads the Windows 7 x64 `explorer.exe` on Windows 10 x64 without replacing the
real one. The process is still created from `C:\Windows\explorer.exe`, so its
image path is genuine everywhere (PEB, Task Manager, WMI, taskbar pinning);
only the in-memory image gets swapped.

It's a single native DLL (`explorer7.dll`) registered as an Application
Verifier provider through Image File Execution Options. Verifier providers get
`DLL_PROCESS_VERIFIER` before ntdll snaps the main image's imports, which is the
one point early enough to replace the image and let the loader snap the Win7
imports normally.

The repo has two parts:

| folder | what | license |
| ------ | ---- | ------- |
| repo root | `explorer7.dll`, the image-swap loader | MIT |
| [`wrapper/`](wrapper) | `wrp64.dll`, our fork of the [Explorer7-10to7](https://github.com/Win10to7/Explorer7-10to7) wrapper | GPLv3 |

Use the wrapper from this repo. The loader is built and tested against this
fork, and stock Explorer7 wrappers are missing the fixes listed below.

You still need your own copy of the Windows 7 `explorer.exe` and its `.mui`;
those aren't in this repo.

## What it does

At `DLL_PROCESS_VERIFIER`, for the shell instance only (explorer started with no
arguments, so folder windows stay stock Win10 explorer):

1. Reads `<Explorer7Path>\explorer.exe` and validates its PE headers.
2. Refuses to swap if the Win7 image is bigger than the reserved Win10 image.
3. Maps the Win7 sections over the live image, applies base relocations,
   drops the stale bound-import directory, and fixes the loader's cached entry
   point and image size.
4. Plants a jump at the Win10 entry RVA so the main thread lands on the Win7
   entry point.
5. Restores per-section protections and marks the Win7 code as valid CFG
   call targets.
6. Hooks `ntdll!NtOpenFile` to redirect `%windir%\<lang>\explorer.exe.mui` and
   `%windir%\theme\` opens to `Explorer7Path`. A `.mui` is checksum-bound to its
   binary, so the Win10 one doesn't work against the Win7 image.

At `DLL_PROCESS_ATTACH` it clears `FLG_APPLICATION_VERIFIER` from the PEB so
`verifier.dll` doesn't thunk every module's imports afterwards. Without that,
every Explorer window costs an extra 146-190 ms.

If anything fails before the swap starts, it logs (debug builds) and leaves
stock explorer running.

## Wrapper fork

`wrapper/` is Win10to7/Explorer7-10to7 at commit `553f50c`, imported with its
history, plus one commit of changes on top:

- **Classic theme taskbar stayed composited.** The tray accent helpers handed
  `SetWindowCompositionAttribute` a pointer to their own dead local, so DWM got
  stack garbage as the accent state. After a live Aero to Classic switch the
  taskbar kept a glass accent until explorer restarted.
- **Tray icons vanished after app updates.** Win7's tray rejects a `NIF_GUID`
  icon whose exe path no longer matches the remembered one, and never forgets
  the old path. Apps that update into a new versioned folder (Discord's
  `app-1.0.xxxx`) lost their icon for good. Same file name in a new folder is
  now accepted.
- **Per-theme taskbar style.** With no `Theme` override, a
  `Theme\<active style name>.msstyles` is used when it exists, so a Windows 10
  port of a style can get its Windows 7 original on the taskbar and start menu.
  See `wrapper/README.md`.
- **UWP icon leak.** `GetUWPIcon` deleted the bitmap and released the shell
  item factory twice, and didn't check `ImageList_Create`.

Upstream commits after `553f50c` aren't merged.

## Requirements

- Windows 10 x64. Not tested on Windows 11 or ARM64.
- MSVC (Build Tools for Visual Studio with the C++ workload, v143 toolset) and
  the Windows SDK.
- Windows 7 x64 `explorer.exe` and `en-US\explorer.exe.mui`.
- The Explorer7 data files (`Import Me.reg`, the `theme` folder, orbs). The
  wrapper README covers them.

## Build

Loader:

```bat
build.bat
```

It finds MSVC through `vswhere` if `cl.exe` isn't already on `PATH` and writes
`explorer7.dll` next to the script. It links only against `ntdll.lib`, no CRT.

Wrapper, from a Developer Command Prompt (or with `MSBuild.exe` by full path):

```bat
msbuild wrapper\explorerwrapper\explorerwrapper.vcxproj /p:Configuration=Release /p:Platform=x64
```

Output is `wrapper\explorerwrapper\Release\wrp64.dll`. MinHook ships as
`libMinHook.x64.lib` in the same folder.

## Install

As Administrator:

1. Copy `explorer7.dll` to `%windir%\System32`.
2. Put the Win7 `explorer.exe` at `C:\explorer7\explorer.exe` and its MUI at
   `C:\explorer7\en-US\explorer.exe.mui`. To use another folder, change
   `Explorer7Path` in `explorer7_install.reg`.
3. Put the `wrp64.dll` you built from `wrapper/` in `%windir%`.
4. Import `explorer7_install.reg`.
5. Sign out, or restart `explorer.exe`.

`explorer7_install.reg` documents each value it sets. Two matter:

- `VerifierFlags` must be nonzero. Leaving it out makes ntdll fall back to a
  default that enables page heap, which costs about a quarter of explorer's CPU.
- `MitigationOptions` turns CFG off for explorer.exe. The process is created
  from the CFG-enabled Win10 binary, and the Win7 code fast-fails without it.

## Uninstall

Import `explorer7_uninstall.reg` as Administrator, then restart `explorer.exe`.
It removes every value the install file added.

If the shell won't start, use Task Manager's Run new task with `regedit`, delete
those values under
`HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\explorer.exe`,
then run `explorer.exe`.

## Limitations

- Debug logging (`DbgPrint`) only exists in `_DEBUG` builds.
- The image tail past the Win7 `SizeOfImage` is made read-only rather than
  unmapped. Unmapping it would break the unwind data the loader cached from the
  Win10 image.
- Only en-US MUI redirection has been tested.

## License

The loader (repo root) is MIT, see [LICENSE](LICENSE). The wrapper in
`wrapper/` is GPLv3, see [wrapper/LICENSE](wrapper/LICENSE). The Windows 7
files are Microsoft's and aren't included.
