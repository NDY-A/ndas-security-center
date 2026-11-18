"""Apply NDAS compatibility patches to the pinned speakeasy-emulator install.

Run after `pip install speakeasy-emulator==1.5.11` during sandbox preparation.
Idempotent: each replacement is skipped when its NDAS marker is present.

Patches (all discovered via live emulation of real samples):
1. winemu: map the fault page after SEH dispatch so unicorn's instruction
   retry lands on the SEH handler instead of faulting again (Delphi and
   malware SEH probes killed the whole run).
2. winemu.get_proc: return NULL for exports that have neither an
   implementation nor a hook, matching real GetProcAddress semantics
   (fake pointers were called by runtime-probing samples and aborted).
3. kernel32: VerSetConditionMask/VerifyVersionInfo are stdcall and their
   64-bit parameters occupy two stack slots (argc=4); the stock cdecl+
   argc=3 definitions desynchronized the guest stack after the version
   checks nearly every modern installer performs.
"""

import sys
from pathlib import Path

MARKER = "NDAS patch"

REPLACEMENTS = [
    (
        "windows/winemu.py",
        """        # Are there any SEH handlers registered?
        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_fetch', address)""",
        """        # Are there any SEH handlers registered?
        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                # NDAS patch: unicorn retries the faulting access after a memory
                # hook returns True; map the fault page so the retry proceeds
                # from the redirected SEH handler instead of faulting again.
                fault_page = address & 0xFFFFFFFFFFFFF000
                try:
                    self.mem_map(self.page_size, base=fault_page)
                    self.tmp_maps.append((fault_page, self.page_size))
                except Exception:
                    pass
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_fetch', address)""",
    ),
    (
        "windows/winemu.py",
        """        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True
        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_read', address)""",
        """        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                # NDAS patch: see _handle_invalid_fetch.
                fault_page = address & 0xFFFFFFFFFFFFF000
                try:
                    self.mem_map(self.page_size, base=fault_page)
                    self.tmp_maps.append((fault_page, self.page_size))
                except Exception:
                    pass
                return True
        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_read', address)""",
    ),
    (
        "windows/winemu.py",
        """        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_write', address)""",
        """        if self.dispatch_handlers:
            rv = self.dispatch_seh(ddk.STATUS_ACCESS_VIOLATION, address)
            if rv:
                # NDAS patch: see _handle_invalid_fetch.
                fault_page = address & 0xFFFFFFFFFFFFF000
                try:
                    self.mem_map(self.page_size, base=fault_page)
                    self.tmp_maps.append((fault_page, self.page_size))
                except Exception:
                    pass
                return True

        fakeout = address & 0xFFFFFFFFFFFFF000
        self.mem_map(self.page_size, base=fakeout)

        error = self.get_error_info('invalid_write', address)""",
    ),
    (
        "windows/winemu.py",
        """        for addr, mod, fn in self.dyn_imps:
            if mod_name == mod and func_name == fn:
                return addr

        if not self.dyn_imps:
            curr_idx = winemu.DYM_IMP_RESERVE""",
        """        for addr, mod, fn in self.dyn_imps:
            if mod_name == mod and func_name == fn:
                return addr

        # NDAS patch: return NULL for exports that have neither an
        # implementation nor a registered API hook, matching real
        # GetProcAddress semantics. Fake pointers make runtime-probing
        # samples call into decoys and abort.
        if not self.get_api_hooks(mod_name, func_name):
            _, attrs = self.api.get_export_func_handler(mod_name, func_name)
            if not attrs:
                return 0

        if not self.dyn_imps:
            curr_idx = winemu.DYM_IMP_RESERVE""",
    ),
    (
        "winenv/api/usermode/kernel32.py",
        """    @apihook('VerSetConditionMask', argc=3, conv=e_arch.CALL_CONV_CDECL)""",
        """    # NDAS patch: VerSetConditionMask/VerifyVersionInfo are WINAPI (stdcall);
    # marking them cdecl unbalances the guest stack and corrupts return
    # addresses after the version checks that Delphi/installers perform.
    # The 64-bit parameters occupy two 32-bit stack slots, so argc is 4.
    @apihook('VerSetConditionMask', argc=4)""",
    ),
    (
        "winenv/api/usermode/kernel32.py",
        """    @apihook('VerifyVersionInfo', argc=3, conv=e_arch.CALL_CONV_CDECL)""",
        """    @apihook('VerifyVersionInfo', argc=4)""",
    ),
    (
        "winenv/api/usermode/kernel32.py",
        """        con_mask, type_mask, cond = argv

        return 0""",
        """        con_low, con_high, type_mask, cond = argv

        return 0""",
    ),
    (
        "winenv/api/usermode/kernel32.py",
        """        vinfo, type_mask, con_mask = argv

        return True""",
        """        vinfo, type_mask, con_low, con_high = argv

        return True""",
    ),
]


def main():
    if len(sys.argv) < 2:
        print("usage: patch-speakeasy.py <site-packages-dir>")
        return 2
    root = Path(sys.argv[1]) / "speakeasy"
    if not root.is_dir():
        print(f"speakeasy package not found under {root}")
        return 2

    applied = 0
    skipped = 0
    failed = []
    for relative, old, new in REPLACEMENTS:
        path = root / relative
        text = path.read_text(encoding="utf-8")
        if new in text:
            skipped += 1
            continue
        if old not in text:
            failed.append(relative)
            continue
        path.write_text(text.replace(old, new, 1), encoding="utf-8")
        applied += 1

    print(f"speakeasy patches: applied={applied} skipped={skipped} unmatched={len(failed)}")
    for item in sorted(set(failed)):
        print(f"  unmatched replacement in {item} (upstream changed?)")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
