import curses
from .sentinel import run_heuristics


def draw_report(stdscr, report_str):
    stdscr.clear()
    stdscr.addstr(0, 0, "SentinelRoot Heuristic Report (press 'q' to quit)")
    lines = report_str.split('\n')
    for idx, line in enumerate(lines, start=2):
        if idx >= curses.LINES:
            break
        stdscr.addstr(idx, 0, line)
    stdscr.refresh()


def main(stdscr):
    report = run_heuristics()
    report_str = report.summary() or "No issues detected"
    draw_report(stdscr, report_str)
    while True:
        ch = stdscr.getch()
        if ch in (ord('q'), ord('Q')):
            break


if __name__ == "__main__":
    curses.wrapper(main)
