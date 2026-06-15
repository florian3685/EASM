#!/usr/bin/env python3
"""
EASM Scanner — Hacker TUI (Terminal User Interface)
Interactive module selector with arrow keys, space toggle, enter confirm.
"""

import curses
import sys
import os

# ── Module definitions ──
MODULES = [
    (1,  "Attack Surface",      "hosts, ports, CVEs, logins",       True),
    (2,  "Infrastructure",      "TLS, headers, CDN/WAF",            True),
    (3,  "DNS Config",          "DNSSEC, SPF, DMARC, typosquat",    True),
    (4,  "Mail Config",         "SMTP TLS, open relay, blacklists", True),
    (5,  "Privacy & Rep",       "trackers, cookies, safebrowsing",  True),
    (6,  "Darknet / OSINT",     "breaches, LeakIX, GH dorking",     True),
    (7,  "Advanced Recon",      "wayback, JS secrets, takeover",    True),
    (8,  "Param Fuzzing",       "arjun hidden param discovery",     True),
    (9,  "GitHub Recon",        "source leaks, token hunting",      True),
    (10, "Cloud Assets",        "S3/Azure/GCP bucket fuzzing",      True),
    (11, "EXPLOITATION",        "sqli, xss, lfi, db dump, cves",    False),
    (12, "Subdomain Takeover",  "dangling CNAMEs to S3/GH/Heroku",  True),
    (13, "JS Secrets Scanner",  "AWS/Stripe/JWT keys in JS files",  True),
    (14, "Web Asset Intel",     "fast API/admin/artifact mapping",   True),
]

ATTACK_PROFILES = [
    ("Full Recon",       "passive recon, no active attacks",     [1,2,3,4,5,6,7,8,9,10,12,13,14]),
    ("Full Assault",     "everything + exploitation",            [1,2,3,4,5,6,7,8,9,10,11,12,13,14]),
    ("Data Extractor",   "subdoms > params > dump db & users",   [1,7,8,11]),
    ("DB Hunter",        "find and crack open databases",        [1,8,11]),
    ("Web Pwn",          "xss lfi rfi ssti ssrf on all urls",    [1,7,8,11,13,14]),
    ("Mail & DNS",       "mail server exploits + dns misconfig", [1,3,4,11]),
    ("OSINT Only",       "passive intel, zero noise",            [5,6,9]),
    ("Cloud & Source",   "github leaks + bucket hunting",        [9,10,12,13,14]),
    ("Quick Wins",       "subdomain takeover + secrets only",    [1,12,13,14]),
    ("Custom",           "pick your own modules below",          []),
]

BANNER = [
    "╔══════════════════════════════════════════════════════════════════╗",
    "║  ███████╗ █████╗ ███████╗███╗   ███╗  ███████╗██╗  ██╗        ║",
    "║  ██╔════╝██╔══██╗██╔════╝████╗ ████║  ██╔════╝╚██╗██╔╝        ║",
    "║  █████╗  ███████║███████╗██╔████╔██║  █████╗   ╚███╔╝         ║",
    "║  ██╔══╝  ██╔══██║╚════██║██║╚██╔╝██║  ██╔══╝   ██╔██╗         ║",
    "║  ███████╗██║  ██║███████║██║ ╚═╝ ██║  ███████╗██╔╝ ██╗        ║",
    "║  ╚══════╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝  ╚══════╝╚═╝  ╚═╝        ║",
    "║                                                                ║",
    "║   external attack surface management + exploitation engine     ║",
    "║   v2.0  ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░     ║",
    "╚══════════════════════════════════════════════════════════════════╝",
]


def _put(win, y, x, text, attr=0):
    max_y, max_x = win.getmaxyx()
    if y < 0 or y >= max_y or x >= max_x:
        return
    win.addnstr(y, x, text, max_x - x - 1, attr)


def run_tui():
    return curses.wrapper(_main)


def _main(stdscr):
    curses.curs_set(0)
    stdscr.nodelay(False)
    stdscr.keypad(True)

    curses.start_color()
    curses.use_default_colors()
    curses.init_pair(1, curses.COLOR_GREEN, -1)
    curses.init_pair(2, curses.COLOR_RED, -1)
    curses.init_pair(3, curses.COLOR_CYAN, -1)
    curses.init_pair(4, curses.COLOR_YELLOW, -1)
    curses.init_pair(5, curses.COLOR_MAGENTA, -1)
    curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_GREEN)
    curses.init_pair(7, curses.COLOR_WHITE, curses.COLOR_RED)
    curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_CYAN)

    G = curses.color_pair(1)
    R = curses.color_pair(2)
    C = curses.color_pair(3)
    Y = curses.color_pair(4)
    M = curses.color_pair(5)
    SB = curses.color_pair(6) | curses.A_BOLD
    DB = curses.color_pair(7) | curses.A_BOLD
    IB = curses.color_pair(8) | curses.A_BOLD

    mod_on = [m[3] for m in MODULES]
    stealth = True
    exploit = False
    section = "domain"
    domain = ""
    cur = 0
    pcur = 0
    ocur = 0
    prof = -1

    while True:
        stdscr.erase()
        h, w = stdscr.getmaxyx()

        for i, line in enumerate(BANNER):
            if i < h:
                col = R if i < 7 else (C if i < 9 else G)
                _put(stdscr, i, 2, line, col | curses.A_BOLD)

        y = len(BANNER) + 1

        # status bar
        st = f" target: {domain if domain else '---'}  |  stealth: {'on' if stealth else 'off'}  |  exploit: {'ARMED' if exploit else 'safe'} "
        if y < h:
            _put(stdscr, y, 2, st, Y | curses.A_BOLD)
        y += 2

        # ── DOMAIN ──
        act = section == "domain"
        mk = ">" if act else " "
        at = (G | curses.A_BOLD) if act else C
        if y < h:
            _put(stdscr, y, 2, f"{mk} -- target --", at)
        y += 1
        if y < h:
            cur_ch = "_" if act else ""
            _put(stdscr, y, 5, f"domain: {domain}{cur_ch}", G | curses.A_BOLD if act else G)
        y += 2

        # ── PROFILES ──
        act = section == "profile"
        mk = ">" if act else " "
        at = (G | curses.A_BOLD) if act else C
        if y < h:
            _put(stdscr, y, 2, f"{mk} -- attack profile --", at)
        y += 1

        for i, (name, desc, _) in enumerate(ATTACK_PROFILES):
            if y >= h - 1:
                break
            sel = (i == prof)
            is_c = (act and i == pcur)

            if is_c:
                la = DB if i == 1 else SB
            elif sel:
                la = G | curses.A_BOLD
            else:
                la = curses.A_NORMAL

            dot = "*" if sel else "o"
            ptr = " > " if is_c else "   "
            line = f"   {ptr}{dot} {name:16s} {desc}"
            _put(stdscr, y, 2, line, la)
            y += 1
        y += 1

        # ── MODULES ──
        act = section == "modules"
        mk = ">" if act else " "
        at = (G | curses.A_BOLD) if act else C
        if y < h:
            _put(stdscr, y, 2, f"{mk} -- modules -- [space] toggle", at)
        y += 1

        for i, (num, name, desc, _) in enumerate(MODULES):
            if y >= h - 1:
                break
            is_c = (act and i == cur)
            on = mod_on[i]

            if is_c:
                la = DB if num == 11 else SB
            elif num == 11 and on:
                la = R | curses.A_BOLD
            elif on:
                la = G
            else:
                la = curses.A_DIM

            box = "[x]" if on else "[ ]"
            ptr = " > " if is_c else "   "
            line = f"   {ptr}{box} {num:2d}. {name:20s} {desc}"
            _put(stdscr, y, 2, line, la)
            y += 1
        y += 1

        # ── OPTIONS ──
        act = section == "options"
        mk = ">" if act else " "
        at = (G | curses.A_BOLD) if act else C
        if y < h:
            _put(stdscr, y, 2, f"{mk} -- options --", at)
        y += 1

        opts = [
            ("stealth mode", "tls spoofing + request jitter", stealth),
            ("exploit mode", "active weaponized exploitation", exploit),
        ]
        for i, (oname, odesc, oval) in enumerate(opts):
            if y >= h - 1:
                break
            is_c = (act and i == ocur)
            if is_c:
                la = DB if i == 1 else SB
            elif oval:
                la = (R | curses.A_BOLD) if i == 1 else (G | curses.A_BOLD)
            else:
                la = curses.A_DIM

            tog = "on " if oval else "off"
            ptr = " > " if is_c else "   "
            line = f"   {ptr}[{tog}] {oname:18s} {odesc}"
            _put(stdscr, y, 2, line, la)
            y += 1
        y += 1

        # ── LAUNCH ──
        act = section == "launch"
        if y < h:
            if act:
                _put(stdscr, y, 5, ">>> ENTER TO LAUNCH <<<", DB)
            else:
                _put(stdscr, y, 5, "    launch scan", curses.A_DIM)
        y += 2

        # help
        if y < h:
            _put(stdscr, y, 2, " tab=section  arrows=move  space=toggle  enter=select  q=quit", Y)

        stdscr.refresh()

        # ── INPUT ──
        key = stdscr.getch()
        secs = ["domain", "profile", "modules", "options", "launch"]

        if key == ord('q') or key == ord('Q'):
            return None

        elif key == 9:  # tab
            ix = secs.index(section)
            section = secs[(ix + 1) % len(secs)]

        elif key == 353:  # shift-tab
            ix = secs.index(section)
            section = secs[(ix - 1) % len(secs)]

        elif section == "domain":
            if key in (curses.KEY_BACKSPACE, 127, 8):
                domain = domain[:-1]
            elif key in (10, 13):
                if domain:
                    section = "profile"
            elif 32 <= key <= 126:
                domain += chr(key)

        elif section == "profile":
            if key == curses.KEY_UP:
                pcur = max(0, pcur - 1)
            elif key == curses.KEY_DOWN:
                pcur = min(len(ATTACK_PROFILES) - 1, pcur + 1)
            elif key in (10, 13, ord(' ')):
                prof = pcur
                _, _, mods = ATTACK_PROFILES[prof]
                if prof == len(ATTACK_PROFILES) - 1:
                    section = "modules"
                else:
                    for i, (num, *_) in enumerate(MODULES):
                        mod_on[i] = num in mods
                    exploit = 11 in mods

        elif section == "modules":
            if key == curses.KEY_UP:
                cur = max(0, cur - 1)
            elif key == curses.KEY_DOWN:
                cur = min(len(MODULES) - 1, cur + 1)
            elif key == ord(' '):
                mod_on[cur] = not mod_on[cur]
                if MODULES[cur][0] == 11:
                    exploit = mod_on[cur]
                prof = len(ATTACK_PROFILES) - 1
            elif key in (10, 13):
                section = "launch"

        elif section == "options":
            if key == curses.KEY_UP:
                ocur = max(0, ocur - 1)
            elif key == curses.KEY_DOWN:
                ocur = min(1, ocur + 1)
            elif key in (ord(' '), 10, 13):
                if ocur == 0:
                    stealth = not stealth
                else:
                    exploit = not exploit
                    for i, (num, *_) in enumerate(MODULES):
                        if num == 11:
                            mod_on[i] = exploit

        elif section == "launch":
            if key in (10, 13):
                if not domain:
                    section = "domain"
                    continue
                selected = [num for i, (num, *_) in enumerate(MODULES) if mod_on[i]]
                d = domain.strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
                if "/" in d:
                    d = d.split("/")[0]
                return {
                    "domain": d,
                    "modules": sorted(selected),
                    "stealth": stealth,
                    "exploit": exploit,
                }
