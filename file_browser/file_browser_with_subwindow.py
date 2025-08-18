import os
import curses

def list_files(path):
    """Returns a list of files and directories in the given path."""
    try:
        entries = os.listdir(path)
        entries.sort(key=lambda x: (not os.path.isdir(os.path.join(path, x)), x.lower()))
        return [".."] + entries  # add option to go up
    except PermissionError:
        return [".."]
    except FileNotFoundError:
        return [".."]

def file_browser(stdscr, path):
    """File browser window embedded inside the main application."""
    curses.curs_set(0)  # Hide cursor

    current_selection = 0
    scroll_offset = 0

    while True:
        # Get terminal size
        term_h, term_w = stdscr.getmaxyx()

        # Subwindow: ~60% width, ~60% height, centered
        win_h = max(12, term_h * 6 // 10)
        win_w = max(50, term_w * 6 // 10)
        start_y = max(1, (term_h - win_h) // 2)
        start_x = max(2, (term_w - win_w) // 2)

        # Background (main app still visible)
        stdscr.refresh()

        # Subwindow
        file_win = curses.newwin(win_h, win_w, start_y, start_x)
        file_win.keypad(True)
        file_win.box()

        # Header (path)
        truncated_path = (path[:win_w - 12] + "…") if len(path) > win_w - 12 else path
        file_win.addstr(0, 2, f"Browsing: {truncated_path}")

        # Footer (help text)
        footer = " ↑↓ Navigate | Enter Open | Esc Quit "
        file_win.addstr(win_h - 1, (win_w - len(footer)) // 2, footer, curses.A_DIM)

        # Files
        files = list_files(path)
        max_height = win_h - 3  # space between header/footer

        for i, file in enumerate(files[scroll_offset:scroll_offset + max_height]):
            full_path = os.path.join(path, file) if file != ".." else os.path.dirname(path)
            display = f"[DIR] {file}" if os.path.isdir(full_path) else f"     {file}"

            truncated_display = display[:win_w - 6]
            if i + scroll_offset == current_selection:
                file_win.addstr(i + 1, 2, f"> {truncated_display}", curses.A_REVERSE)
            else:
                file_win.addstr(i + 1, 2, f"  {truncated_display}")

        file_win.refresh()
        key = file_win.getch()

        # Navigation
        if key == curses.KEY_UP and current_selection > 0:
            current_selection -= 1
            if current_selection < scroll_offset:
                scroll_offset -= 1
        elif key == curses.KEY_DOWN and current_selection < len(files) - 1:
            current_selection += 1
            if current_selection >= scroll_offset + max_height:
                scroll_offset += 1
        elif key == 10:  # Enter
            selected_file = files[current_selection]
            new_path = os.path.join(path, selected_file) if selected_file != ".." else os.path.dirname(path)

            if os.path.isdir(new_path):
                path = os.path.abspath(new_path)
                current_selection = 0
                scroll_offset = 0
            else:
                file_win.clear()
                file_win.box()
                msg = f"Opening file: {selected_file}"
                file_win.addstr(win_h // 2, (win_w - len(msg)) // 2, msg)
                file_win.refresh()
                file_win.getch()
        elif key == 27:  # ESC quits
            break

def main_app(stdscr):
    """Main application loop."""
    curses.curs_set(0)
    stdscr.keypad(True)

    while True:
        stdscr.clear()
        stdscr.addstr(0, 0, "File Browser Application Menu", curses.A_BOLD)
        stdscr.addstr(2, 0, "1. Browse Files")
        stdscr.addstr(3, 0, "2. Exit")
        stdscr.refresh()

        key = stdscr.getch()

        if key == ord('1'):
            file_browser(stdscr, os.getcwd())
        elif key == ord('2'):
            break

if __name__ == "__main__":
    curses.wrapper(main_app)
