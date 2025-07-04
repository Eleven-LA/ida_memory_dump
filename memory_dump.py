
import ida_kernwin
import ida_idaapi
import ida_bytes
import idc
from pathlib import Path

PLUGIN_VERSION = "1.0"

# -----------------------------
# Utility helpers
# -----------------------------

def _ask_hex(prompt: str, default: str = "0x0") -> int | None:
    text = ida_kernwin.ask_str(default, 0, prompt)  # 将 ida_kernwin.HIST_INPUT 改为 0
    if text is None:
        return None
    try:
        return int(text, 16)
    except ValueError:
        ida_kernwin.warning(f"Invalid hexadecimal value: {text}")
        return None



def _save_file_dialog(default_name: str) -> str | None:
    """Ask the user where to save the dump."""
    return ida_kernwin.ask_file(True, default_name, "Save dump as")


# -----------------------------
# Plugin class
# -----------------------------

class memory_dump_plugin_t(ida_idaapi.plugin_t):
    flags = ida_idaapi.PLUGIN_UNL  # Unload the plugin when IDA exits
    comment = "Dump an arbitrary memory range to a binary file"
    help = comment
    wanted_name = "Memory Dump…"
    wanted_hotkey = "Alt-Shift-D"

    # --------------------------------------------------
    # IDA plugin lifecycle hooks
    # --------------------------------------------------
    def init(self):
        ida_kernwin.msg("[memdump] Memory Dump Plugin v%s initialised\n" % PLUGIN_VERSION)
        return ida_idaapi.PLUGIN_OK

    def term(self):
        # Nothing to clean up — plugin is stateless
        pass

    # --------------------------------------------------
    # Main entry point when the user activates the plugin
    # --------------------------------------------------
    def run(self, _arg):
        # 1) Ask for the start address
        start = _ask_hex("Start address (hex)", default="0x%X" % ida_kernwin.get_screen_ea())
        if start is None:
            return

        # 2) Decide how to specify the length
        choice = ida_kernwin.ask_buttons("By &Size", "By &End address", "Cancel", 1,
                                          "Specify dump length by size in bytes \n"
                                          "or by end address (inclusive)")
        if choice == 2 or choice == -1:  # Cancel pressed or dialog closed
            return

        size: int | None = None
        if choice == 1:  # Size mode
            size_val = _ask_hex("Size in bytes (hex)", default="0x100")
            if size_val is None or size_val <= 0:
                ida_kernwin.warning("Size must be a positive, non‑zero value.")
                return
            size = size_val
        elif choice == 0:  # End address mode
            end = _ask_hex("End address (hex, inclusive)", default="0x%X" % (start + 0xFF))
            if end is None or end < start:
                ida_kernwin.warning("End address must be greater than or equal to start address.")
                return
            size = end - start + 1

        # 3) Read bytes from the database / debugger memory
        data = ida_bytes.get_bytes(start, size)
        if data is None:
            ida_kernwin.warning("Failed to read %d bytes at 0x%X. Ensure the range is mapped and loaded." % (size, start))
            return

        # 4) Ask user where to save the dump
        default_fname = "%X_%X.bin" % (start, size)
        fp = _save_file_dialog(default_fname)
        if not fp:
            return  # User cancelled

        # 5) Write the dump
        try:
            Path(fp).write_bytes(data)
            ida_kernwin.msg("[memdump] Wrote %d bytes to %s\n" % (size, fp))
        except OSError as exc:
            ida_kernwin.warning(f"Could not write file: {exc}")


# --------------------------------------------------
# Plugin entry point
# --------------------------------------------------

def PLUGIN_ENTRY():
    return memory_dump_plugin_t()
