import curses
import time
from .sentinel import run_heuristics

HEADER = "SentinelRoot Heuristic Report (press 'q' to quit)"
INTERVAL = 60  # seconds between heuristic runs


def draw_lines(stdscr, lines, scroll):
    height, width = stdscr.getmaxyx()
    visible = lines[scroll: scroll + height]
    for idx, line in enumerate(visible):
        stdscr.addnstr(idx, 0, line, width - 1)
    total = len(lines)
    if total > height:
        bar_height = max(1, height * height // total)
        bar_pos = scroll * (height - bar_height) // (total - height)
        for i in range(height):
            attr = curses.A_REVERSE if bar_pos <= i < bar_pos + bar_height else curses.A_DIM
            stdscr.addch(i, width - 1, ' ', attr)


def append_report(lines):
    report = run_heuristics()
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    summary = report.summary() or "No issues detected"
    lines.append(f"--- {ts} ---")
    lines.extend(summary.splitlines())
    lines.append("")


def main(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(True)
    lines = [HEADER, ""]
    append_report(lines)
    height, _ = stdscr.getmaxyx()
    scroll = max(0, len(lines) - height)
    last_run = time.time()

    while True:
        now = time.time()
        if now - last_run >= INTERVAL:
            prev_len = len(lines)
            append_report(lines)
            height, _ = stdscr.getmaxyx()
            if scroll >= prev_len - height:
                scroll = max(0, len(lines) - height)
            last_run = now

        stdscr.erase()
        draw_lines(stdscr, lines, scroll)
        stdscr.refresh()

        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q')):
            break
        elif ch == curses.KEY_UP:
            scroll = max(0, scroll - 1)
        elif ch == curses.KEY_DOWN:
            height, _ = stdscr.getmaxyx()
            scroll = min(max(len(lines) - height, 0), scroll + 1)
        elif ch == curses.KEY_NPAGE:
            height, _ = stdscr.getmaxyx()
            scroll = min(max(len(lines) - height, 0), scroll + height)
        elif ch == curses.KEY_PPAGE:
            height, _ = stdscr.getmaxyx()
            scroll = max(0, scroll - height)
        time.sleep(0.05)


if __name__ == "__main__":
    curses.wrapper(main)
