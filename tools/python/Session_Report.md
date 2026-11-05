# Session_Report.py

> Linux-only terminal session recorder that produces a Bugterium walkthrough
> draft in the canonical walkthrough format. Records in a clean `bash` subshell by
> default, so the transcript is readable regardless of your own shell config.

---

## Purpose

Record a live terminal session (Hack The Box, OSCP lab, or local practice)
and turn it into a structured walkthrough draft. The draft is written to a
per-session directory together with the raw transcript and a metadata file.

Use case: during a pentest or CTF session, run the recorder once at the
start, work normally in the subshell, exit when done. The result is a
`walkthrough-draft.md` with the canonical walkthrough standard skeleton, ready to be
finished by hand (or by an AI assistant) into a full writeup.

---

## Quick start (standalone)

If you only want the tool and not the whole repository:

```bash
mkdir -p ~/tools && cd ~/tools
curl -fsSL -o Session_Report.py \
  https://raw.githubusercontent.com/N3xu666/Bugterium/main/tools/python/Session_Report.py
python3 Session_Report.py --version
```

The script is self-contained (standard library only). No `git clone`, no
`pip install`, no dependencies required.

To also fetch the documentation:

```bash
curl -fsSL -o Session_Report.md \
  https://raw.githubusercontent.com/N3xu666/Bugterium/main/tools/python/Session_Report.md
```

### Install as a Python package (optional)

The tool is also published as `methodman-session-report` and installs the
`session-report` command. This requires `pip` and (recommended on
Debian/Ubuntu/Kali where PEP 668 blocks system-wide installs) a virtual
environment.

```bash
python3 -m venv ~/.venvs/bugterium
source ~/.venvs/bugterium/bin/activate
pip install "git+https://github.com/N3xu666/Bugterium.git#subdirectory=tools/python"
session-report --version
```

Once installed, use the `session-report` command in place of
`python3 Session_Report.py`:

```bash
session-report start --machine Layover --target 10.10.11.10
```

This is entirely optional - the `curl` method above works without any
installation.

---

## Requirements

- **Linux only.** The recorder relies on `script(1)` from `util-linux`.
  macOS and Windows are not supported (macOS `script(1)` has different flags
  and no `-f`; Windows has no equivalent).
- **Python 3.9+** (uses `list[str]` in annotations, `datetime.timezone.utc`,
  `tempfile.mkstemp`, all available since 3.9).
- **`util-linux`** installed (`script` binary in `$PATH`).
  - Debian / Ubuntu: `sudo apt install util-linux`
  - Fedora / RHEL: `sudo dnf install util-linux`
  - Arch: `sudo pacman -S util-linux`
- **`/bin/bash`** for the default clean-shell mode (present on virtually
  every Linux distribution). If missing, the tool falls back to `/bin/sh`.
- Standard library only. No pip dependencies.

---

## How recording works

The tool starts `script(1)` with an explicit child command:

- **Default (`clean` mode):** `bash --noprofile --norc --rcfile <temp>` where
  `<temp>` is a minimal rc that sets a short `PS1` and disables PTY echo on
  the first prompt. Your own `.bashrc`, `.zshrc`, oh-my-zsh, powerlevel10k,
  and syntax highlighting are **not** loaded. The transcript contains only
  commands and their output, with no prompt redraw noise.
- **`--raw-shell` mode:** your `$SHELL` with its own configs. Prompt redraws
  and color escapes end up in the transcript. The heuristic cleaner will
  strip the ANSI escapes, but zsh/fish/oh-my-zsh may leave residue. Use
  `--raw-shell` only if you specifically need your own environment (aliases,
  tab completion, custom prompt).

The chosen mode is recorded in `metadata.json` (field `shell`).

---

## Usage

### Record a session

```
python Session_Report.py start --machine <name> [--target <ip>]
                               [--language en|ru|az] [--output <dir>]
                               [--raw-shell]
```

### Rebuild a draft from an existing session

```
python Session_Report.py reclean <session_dir>
```

Use `reclean` after upgrading the tool to regenerate `walkthrough-draft.md`
from the saved `raw.txt` without re-recording the session.

### Arguments (start)

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--machine` | yes | - | Machine name (e.g. `Layover`). Used for the session directory name. |
| `--target` | no | empty | Target IP or hostname. Stored in metadata and in the draft. |
| `--language` | no | `en` | Walkthrough language. One of `en`, `ru`, `az`. |
| `--output` | no | `sessions` | Output root directory. Created if missing. |
| `--raw-shell` | no | off | Record in your own `$SHELL` with its user configs. |

### Example (default, clean shell)

```
$ python Session_Report.py start --machine Layover --target 10.10.11.10 --language en
[Session_Report] Session directory: /home/op/Bugterium/sessions/Layover-20261012T143012Z
[Session_Report] Metadata:          /home/op/Bugterium/sessions/Layover-20261012T143012Z/metadata.json
[Session_Report] Draft:             /home/op/Bugterium/sessions/Layover-20261012T143012Z/walkthrough-draft.md
[Session_Report] Shell:             /bin/bash --noprofile --norc (clean, no user configs)
[Session_Report] Cleaner:           heuristic
[Session_Report] Starting script(1). Type 'exit' to stop recording.

$ nmap -p- --min-rate 5000 10.10.11.10
...
$ exit

[Session_Report] Transcript cleaned: 8432 -> 6211 bytes.
[Session_Report] Final draft: /home/op/Bugterium/sessions/Layover-20261012T143012Z/walkthrough-draft.md
```

---

## Output layout

```
sessions/
+-- <machine>-<UTC timestamp>/
    +-- metadata.json          # machine, target, started, host, operator, language, shell
    +-- raw.txt                # raw script(1) output
    +-- walkthrough-draft.md   # cleaned draft in the canonical walkthrough format
```

`raw.txt` is kept for reference. The `.md` draft is the cleaned version with
the AI prompt block, the walkthrough skeleton, and the raw transcript
appended under `## Raw Transcript`.

**Note:** `sessions/` is listed in `.gitignore`. Drafts are local-only until
you decide to publish them (after masking sensitive values).

---

## Transcript cleanup

Cleanup runs on the raw `script(1)` output before appending to the `.md`.
The cleaner is stdlib-only and tailored for the clean-shell mode.

Steps:

1. **ANSI escape sequences** stripped (CSI, OSC, two-character escapes).
   Removes color codes, bracketed-paste toggles (`ESC[?2004h/l`),
   reverse-video echo (`ESC[7m`, `ESC[27m`), cursor moves
   (`ESC[A`, `ESC[B`, `ESC[C`, `ESC[D`), and erase-to-end (`ESC[K`).
2. **`script(1)` banner** lines removed.
3. **Line endings** normalized: `\r\n` and lone `\r` -> `\n`.
4. **Whitespace-only lines** converted to empty lines, trailing
   whitespace stripped.
5. **Immediate prompt echo dropped.** Bash echoes the command before
   executing, so a command may appear twice in a row after ANSI stripping:
   once as `bash-5.3$ cmd` and once as plain `cmd`. The cleaner drops the
   plain echo line only when it is the IMMEDIATE next line after its own
   prompt. Real output that happens to equal an earlier command is kept
   (this was a bug before v0.6.0: a session-wide dedupe dropped any line
   matching an earlier command, including legitimate file contents).
6. **Blank runs collapsed**: 3+ consecutive newlines -> 2.

Result: a readable transcript with commands and their real output, no
shell prompt noise.

### Rebuild an existing draft

```
python Session_Report.py reclean sessions/Layover-20261012T143012Z
```

Reads `metadata.json` and `raw.txt` from the session directory, regenerates
`walkthrough-draft.md` from the header down. The existing `.md` is
overwritten.

---

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Session recorded / recleaned successfully. |
| 1 | Runtime failure (e.g. `script(1)` failed to launch, `raw.txt` missing). |
| 2 | Platform check failed: not Linux, or `script(1)` not found in `$PATH`. |

---

## Safety

- **No keylogger.** The tool does not read `/dev/input/event*`, does not hook
  the kernel, does not intercept syscalls. It only invokes `script(1)` in a
  child process, exactly as a user would run it manually.
- **No network.** The recorder is fully offline.
- **No telemetry.** The tool does not phone home, does not write outside the
  chosen output directory.

See `../../SECURITY.md` for the project-wide policy on authorized use.

---

## Limitations

- **Linux only.** See Requirements.
- **Single terminal.** One invocation = one recording session. Multiple
  parallel terminals are not merged.
- **Default mode has no shell conveniences.** No aliases, no tab completion,
  no `~/.bashrc`. This is intentional: the walkthrough should show the raw
  commands. If you need your usual environment, use `--raw-shell`.
- **`--raw-shell` may leave residue.** zsh/fish/oh-my-zsh emit cursor-move
  and redraw sequences that a regex cleaner cannot fully resolve. The
  transcript will be readable but may contain extra blank lines or repeated
  prompt fragments.
- **No masking.** Real secrets (flags, passwords, hashes) are captured as-is.
  Mask them manually before publishing, per the canonical walkthrough standard.

---

## Recording multi-window sessions

### The problem

`Session_Report.py` records **one terminal**. `script(1)` captures a single
pty and cannot see what happens in another window. In a typical HTB or
OSCP session you almost always need a second window (a `nc` listener, a
`python -m http.server`, Metasploit, a reverse-shell catcher). Only the
window where `session-report start` was launched ends up in `raw.txt`.

There is no perfect solution: every approach either changes your habits,
is invasive, or captures only part of the work. Pick the option that fits
your workflow.

### Option A - tmux (recommended)

Work inside a single `tmux` session. All windows and panes share one pty,
so `script(1)` sees everything.

```bash
tmux new -s htb
# inside tmux, in the first pane:
session-report start --machine Foo --target 10.10.11.10

# create more windows / panes:
#   Ctrl+b c   new window
#   Ctrl+b %   split vertically
#   Ctrl+b "   split horizontally
#   Ctrl+b n   next window
#   Ctrl+b p   previous window
#   Ctrl+b d   detach (session keeps running)

# when done: exit each shell; the tmux session ends and the draft is ready
```

Pros:

- One recording covers every window and pane.
- Nothing is added to `~/.bashrc` or `~/.zshrc`.
- Explicit start and end.
- Works with `nc`, Metasploit, `ssh`, reverse shells - everything.

Cons:

- You must work inside `tmux` (`Ctrl+b` prefix).
- Mouse support is off by default; enable with `set -g mouse on` in
  `~/.tmux.conf` if you want scrolling and copy-paste to work as usual.

### Option B - one session per window, merge manually

Start a separate recorder in each window that matters:

```bash
# window 1 (the main work)
session-report start --machine Foo --target 10.10.11.10

# window 2 (the listener)
session-report start --machine Foo-listener
```

At the end you have two independent session directories. Open both drafts
and copy the relevant lines from the listener draft into the main draft
under `## Foothold` or `## Privilege Escalation`.

Pros:

- No `tmux` required.
- Everything is captured - just in separate files.

Cons:

- You must remember to run `session-report start` in every new window.
- Manual merge at the end.

### Option C - shell hook that auto-starts script (not recommended)

A hook in `~/.bashrc` / `~/.zshrc` can start `script` automatically in
every new interactive shell while a flag file exists. This gives the
closest experience to "work as usual and forget about recording".
However, it is **not implemented** in the current version of
`Session_Report.py` and is documented here only so you understand the
trade-offs before asking for it.

Pros:

- The closest thing to "no change in habits".

Cons:

- Invasive: it modifies `~/.bashrc` / `~/.zshrc`.
- Invisible recording: you do not see that it is running; a mistyped
  password or token ends up in a log file.
- Breaks in subtle ways with nested pty: `ssh`, `docker exec`,
  `sudo su -`, `screen`, `tmux`.
- `session-report stop` cannot reliably flush sessions that are still
  open; either the user closes every window manually or the tool kills
  them, losing buffered output.
- Logs are not masked. Every command typed in every shell is recorded.

### Recommendation

Use **Option A (tmux)** for any session where a second window is likely.
It is the cleanest available approach. If you have never used `tmux`,
treat it as a 10-minute investment. The four keys you need are
`Ctrl+b c` (new window), `Ctrl+b %` (vertical split),
`Ctrl+b n` / `Ctrl+b p` (switch windows), and `Ctrl+b d` (detach).

If you cannot use `tmux`, use **Option B** and accept the manual merge.

**Do not use Option C** unless you fully understand the trade-offs;
it is not implemented in the current version.
---

## Tests

CI runs two jobs for this tool:

- `tools-syntax` (ubuntu-latest): `python -m py_compile` on every `.py`
  file under `tools/` to catch syntax errors.
- `tools-tests` (ubuntu-latest): the pytest suite in
  `tools/python/tests/` (three files: `test_cleaner.py`
  for the transcript cleaner, `test_script_cmd.py` for shell-quoting and
  command construction, `test_integration.py` for `cmd_start` (with
  `subprocess.run` mocked) and `cmd_reclean` end-to-end), plus a
  pip-install smoke test of the
  `methodman-session-report` package (`pip install ./tools/python` +
  `session-report --version`).

To run a smoke test locally on Linux:

```
$ python Session_Report.py --version
Session_Report.py 0.6.0

$ python Session_Report.py start --machine Test --target 127.0.0.1
# ... type a few commands, then 'exit'
$ ls sessions/Test-*/
metadata.json  raw.txt  walkthrough-draft.md
```

---

## License

MIT. Applies to `Session_Report.py`, this document, and the rest of the `methodman-session-report` pip package.

Documentation elsewhere in the repository is licensed under CC BY-NC 4.0 - see [../../LICENSE](../../LICENSE).

## See also

- the canonical walkthrough standard - walkthrough standard the draft follows.
- the placeholder scheme section of the walkthrough standard - placeholder scheme for masking.
- `../../SECURITY.md` - authorized use policy.
- `../../methodology/OSCP-Reporting.md` - OSCP report evidence rules.