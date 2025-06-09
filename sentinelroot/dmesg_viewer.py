import curses
import subprocess
import time
from typing import List, Dict

LOG_TAG = "sentinelroot"


def read_dmesg_lines() -> List[str]:
    """Return dmesg lines related to SentinelRoot."""
    try:
        out = subprocess.check_output(
            ["dmesg", "-x", "-T", "--color=never"],
            text=True,
        )
        return [line for line in out.splitlines() if LOG_TAG in line]
    except Exception:
        return []


LEVEL_PAIRS: Dict[str, int] = {}


def init_colors() -> None:
    curses.start_color()
    curses.use_default_colors()
    pairs = {
        "emerg": curses.COLOR_RED,
        "alert": curses.COLOR_RED,
        "crit": curses.COLOR_MAGENTA,
        "err": curses.COLOR_RED,
        "warn": curses.COLOR_YELLOW,
        "notice": curses.COLOR_CYAN,
        "info": curses.COLOR_WHITE,
        "debug": curses.COLOR_GREEN,
    }
    for idx, (level, color) in enumerate(pairs.items(), start=1):
        curses.init_pair(idx, color, -1)
        LEVEL_PAIRS[level] = idx


def parse_level(line: str) -> str:
    parts = line.split(":", 2)
    if len(parts) >= 2:
        return parts[1].strip()
    return "info"


def draw_lines(stdscr, lines: List[str], scroll: int) -> None:
    height, width = stdscr.getmaxyx()
    visible = lines[scroll : scroll + height]
    for idx, line in enumerate(visible):
        level = parse_level(line)
        pair = curses.color_pair(LEVEL_PAIRS.get(level, LEVEL_PAIRS["info"]))
        stdscr.addnstr(idx, 0, line, width - 1, pair)

    # scrollbar
    total = len(lines)
    if total > height:
        bar_height = max(1, height * height // total)
        bar_pos = scroll * (height - bar_height) // (total - height)
        for i in range(height):
            attr = curses.A_REVERSE if bar_pos <= i < bar_pos + bar_height else curses.A_DIM
            stdscr.addch(i, width - 1, " ", attr)


def main(stdscr) -> None:
    curses.curs_set(0)
    stdscr.nodelay(True)
    init_colors()
    lines = read_dmesg_lines()
    scroll = max(0, len(lines) - curses.LINES)
    last_refresh = time.time()
    while True:
        now = time.time()
        if now - last_refresh >= 1:
            prev_len = len(lines)
            lines = read_dmesg_lines()
            if len(lines) > prev_len and scroll >= prev_len - curses.LINES:
                scroll = max(0, len(lines) - curses.LINES)
            elif scroll > len(lines) - curses.LINES:
                scroll = max(0, len(lines) - curses.LINES)
            last_refresh = now

        stdscr.erase()
        draw_lines(stdscr, lines, scroll)
        stdscr.refresh()

        ch = stdscr.getch()
        if ch == ord("q"):
            break
        elif ch == curses.KEY_UP:
            scroll = max(0, scroll - 1)
        elif ch == curses.KEY_DOWN:
            scroll = min(max(len(lines) - curses.LINES, 0), scroll + 1)
        elif ch == curses.KEY_NPAGE:
            scroll = min(max(len(lines) - curses.LINES, 0), scroll + curses.LINES)
        elif ch == curses.KEY_PPAGE:
            scroll = max(0, scroll - curses.LINES)
        time.sleep(0.05)


if __name__ == "__main__":
    curses.wrapper(main)
