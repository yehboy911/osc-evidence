"""
interactive_menu.py
===================
Curses-based multi-select checkbox menu for osc-evidence enhanced scan options.

Falls back to simple text input when curses is unavailable (e.g. CI, pipe).
"""

from __future__ import annotations

from typing import List, Optional


class MenuOption:
    """One selectable option in the checkbox menu."""

    def __init__(self, key: str, label: str, selected: bool = True) -> None:
        self.key = key
        self.label = label
        self.selected = selected


def show_menu(options: List[MenuOption]) -> List[MenuOption]:
    """Display a checkbox menu and return options with updated selections.

    Uses curses when available; falls back to plain text input.
    """
    try:
        import curses
        return _curses_menu(options, curses)
    except Exception:
        return _fallback_menu(options)


def _curses_menu(options: List[MenuOption], curses) -> List[MenuOption]:
    result = list(options)

    def _draw(stdscr) -> None:
        curses.curs_set(0)
        try:
            curses.init_pair(1, curses.COLOR_BLACK, curses.COLOR_WHITE)
        except Exception:
            pass
        current = 0

        while True:
            stdscr.clear()
            h, _ = stdscr.getmaxyx()

            header = "Enhanced scan options  [Space=toggle  Enter=confirm  q=skip]"
            stdscr.addstr(0, 0, header)

            for i, opt in enumerate(result):
                check = "[x]" if opt.selected else "[ ]"
                marker = "> " if i == current else "  "
                line = f"  {marker}{check} {opt.label}"
                row = i + 2
                if row < h:
                    if i == current:
                        try:
                            stdscr.addstr(row, 0, line, curses.color_pair(1))
                        except Exception:
                            stdscr.addstr(row, 0, line)
                    else:
                        stdscr.addstr(row, 0, line)

            stdscr.refresh()
            key = stdscr.getch()

            if key == curses.KEY_UP and current > 0:
                current -= 1
            elif key == curses.KEY_DOWN and current < len(result) - 1:
                current += 1
            elif key == ord(" "):
                result[current].selected = not result[current].selected
            elif key in (ord("\n"), ord("\r"), curses.KEY_ENTER):
                break
            elif key in (ord("q"), ord("Q"), 27):  # ESC or q
                for opt in result:
                    opt.selected = False
                break

    curses.wrapper(_draw)
    return result


def _fallback_menu(options: List[MenuOption]) -> List[MenuOption]:
    """Simple text-based fallback when curses is unavailable."""
    print("\nEnhanced scan options:")
    for i, opt in enumerate(options):
        status = "x" if opt.selected else " "
        print(f"  {i + 1}. [{status}] {opt.label}")
    print(
        "  Enter numbers to toggle (comma-separated), or press Enter to accept defaults:"
    )
    try:
        raw = input("  > ").strip()
    except (EOFError, KeyboardInterrupt):
        return options

    if raw:
        for token in raw.split(","):
            token = token.strip()
            if token.isdigit():
                idx = int(token) - 1
                if 0 <= idx < len(options):
                    options[idx].selected = not options[idx].selected

    return options


def prompt_config_h() -> Optional[str]:
    """Prompt the user for a path to FFmpeg's config.h file."""
    print("  Path to FFmpeg config.h (or press Enter to skip): ", end="", flush=True)
    try:
        path = input().strip()
    except (EOFError, KeyboardInterrupt):
        return None
    return path if path else None


def prompt_sbom_csv() -> List[str]:
    """Prompt the user for one or more SBOM CSV file paths.

    Accepts comma-separated paths or one per line.
    Enter an empty line to finish.
    """
    print("  SBOM CSV path(s) — enter one per line, empty line to finish:")
    paths: List[str] = []
    while True:
        try:
            print("    > ", end="", flush=True)
            raw = input().strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not raw:
            break
        # Support comma-separated on one line
        for p in raw.split(","):
            p = p.strip().strip("'\"")
            if p:
                paths.append(p)
    return paths
