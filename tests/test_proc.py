"""sprat.proc: cancellable subprocess runner, live output tailing, progress/cancel helpers.

Real child processes are started with `sys.executable -c ...` (Python is always available).
"""
import os
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
from types import SimpleNamespace

import pytest

from sprat import proc
from sprat.config import Config
from sprat.proc import Cancelled, Result, Tail, check, progress, run_cmd

PY = sys.executable


def py(code: str, *args: str) -> list[str]:
    return [PY, "-c", textwrap.dedent(code), *args]


@pytest.fixture(autouse=True)
def private_tmp(tmp_path, monkeypatch):
    """run_cmd's scratch dirs go under tmp_path, so leaks can be checked and nothing touches the real temp."""
    d = tmp_path / "proc-tmp"
    d.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(d))
    return d


# ---------- check / progress ----------

def test_check_without_cancel_attribute_or_event_does_nothing():
    check(object())
    check(None)
    check(Config())
    check(SimpleNamespace(cancel=threading.Event()))


def test_check_raises_when_cancel_is_set():
    ev = threading.Event()
    ev.set()
    with pytest.raises(Cancelled):
        check(SimpleNamespace(cancel=ev))


def test_progress_without_listener_is_a_noop():
    progress(Config(), "lint", "hello")
    progress(object(), "lint", "hello")


def test_progress_sends_full_event_with_defaults():
    got = []
    progress(Config(on_progress=got.append), "zap", "msg")
    progress(Config(on_progress=got.append), "zap", "half", op="GET /a", done=5, total=10, level="warn")
    assert got == [{"stage": "zap", "msg": "msg", "op": "", "done": None, "total": None, "level": "info"},
                   {"stage": "zap", "msg": "half", "op": "GET /a", "done": 5, "total": 10, "level": "warn"}]


# ---------- Tail ----------

def test_tail_missing_file_gives_no_lines(tmp_path):
    assert Tail(tmp_path / "nope").lines() == []


def test_tail_returns_only_new_complete_lines(tmp_path):
    f = tmp_path / "log"
    f.write_bytes(b"one\ntwo\npart")
    t = Tail(f)
    assert t.lines() == ["one", "two"]
    assert t.lines() == []  # nothing new, partial line still held back
    with open(f, "ab") as h:
        h.write(b"ial\nthree\n")
    assert t.lines() == ["partial", "three"]
    assert t.lines() == []


def test_tail_strips_crlf_keeps_blank_lines_and_replaces_bad_utf8(tmp_path):
    f = tmp_path / "log"
    f.write_bytes(b"a\r\n\r\n\xff\xfe x\n" + "café –\n".encode())
    assert Tail(f).lines() == ["a", "", "�� x", "café –"]


def test_tail_handles_multibyte_char_split_across_reads(tmp_path):
    f = tmp_path / "log"
    data = "– done\n".encode()
    f.write_bytes(data[:1])
    t = Tail(f)
    assert t.lines() == []
    with open(f, "ab") as h:
        h.write(data[1:])
    assert t.lines() == ["– done"]


def test_tail_file_appearing_later(tmp_path):
    f = tmp_path / "later"
    t = Tail(f)
    assert t.lines() == []
    f.write_text("x\n")
    assert t.lines() == ["x"]


# ---------- run_cmd: basics ----------

def test_result_is_a_plain_dataclass():
    assert Result(1, "o", "e") == Result(1, "o", "e")


def test_captures_stdout_stderr_and_returncode():
    r = run_cmd(py("""
        import sys
        print("out line")
        print("err line", file=sys.stderr)
        sys.exit(3)
    """))
    assert r.returncode == 3
    assert r.stdout.splitlines() == ["out line"]
    assert r.stderr.splitlines() == ["err line"]


@pytest.mark.parametrize("code", [0, 1, 2, 7, 255])
def test_nonzero_exit_is_returned_not_raised(code):
    assert run_cmd(py(f"import sys; sys.exit({code})")).returncode == code


def test_no_output_gives_empty_strings():
    r = run_cmd(py("pass"))
    assert (r.returncode, r.stdout, r.stderr) == (0, "", "")


def test_output_is_decoded_as_utf8_with_replacement():
    r = run_cmd(py(r"""
        import sys
        sys.stdout.buffer.write("café – ok\n".encode() + b"\xff\n")
    """))
    assert r.stdout.splitlines() == ["café – ok", "�"]


def test_env_is_passed_to_the_child():
    env = {**os.environ, "SPRAT_PROC_MARKER": "hello-42"}
    r = run_cmd(py("import os; print(os.environ.get('SPRAT_PROC_MARKER'))"), env=env)
    assert r.stdout.strip() == "hello-42"


def test_env_none_inherits_the_parent_environment(monkeypatch):
    monkeypatch.setenv("SPRAT_PROC_INHERIT", "yes")
    assert run_cmd(py("import os; print(os.environ['SPRAT_PROC_INHERIT'])")).stdout.strip() == "yes"


def test_stdin_is_closed_so_prompts_cannot_hang():
    r = run_cmd(py("import sys; print(repr(sys.stdin.read()))"), timeout=20)
    assert r.stdout.strip() == "''"


def test_arguments_with_spaces_and_quotes_arrive_intact():
    args = ["two words", 'say "hi"', "back\\slash\\", "", "a&b|c"]
    r = run_cmd(py("import sys, json; print(json.dumps(sys.argv[1:]))", *args))
    import json
    assert json.loads(r.stdout) == args


def test_large_output_does_not_deadlock():
    r = run_cmd(py("""
        import sys
        chunk = "x" * 1023 + "\\n"
        for _ in range(4096):
            sys.stdout.write(chunk)
            sys.stderr.write(chunk)
    """), timeout=60)
    assert r.returncode == 0
    assert len(r.stdout.splitlines()) == 4096 and len(r.stderr.splitlines()) == 4096


def test_missing_executable_raises_and_cleans_up(private_tmp):
    with pytest.raises(FileNotFoundError):
        run_cmd(["definitely-not-a-real-tool-sprat"])
    assert list(private_tmp.iterdir()) == []


def test_scratch_dir_is_removed_after_success(private_tmp):
    run_cmd(py("print('x')"))
    assert list(private_tmp.iterdir()) == []


# ---------- run_cmd: timeout / cancel ----------

def test_timeout_kills_the_process_and_raises(private_tmp):
    t = time.time()
    with pytest.raises(subprocess.TimeoutExpired) as ei:
        run_cmd(py("import time; time.sleep(30)"), timeout=0.5)
    assert time.time() - t < 15
    assert ei.value.timeout == 0.5
    assert list(private_tmp.iterdir()) == []


def test_cancel_already_set_stops_immediately_and_calls_on_cancel(private_tmp):
    ev, called = threading.Event(), []
    ev.set()
    t = time.time()
    with pytest.raises(Cancelled):
        run_cmd(py("import time; time.sleep(30)"), cancel=ev, on_cancel=lambda: called.append(1))
    assert called == [1]
    assert time.time() - t < 15
    assert list(private_tmp.iterdir()) == []


def test_cancel_mid_run_without_on_cancel():
    ev = threading.Event()
    threading.Timer(0.4, ev.set).start()
    with pytest.raises(Cancelled):
        run_cmd(py("import time; time.sleep(30)"), cancel=ev)


def test_unset_cancel_event_lets_the_command_finish():
    assert run_cmd(py("print('fine')"), cancel=threading.Event()).stdout.strip() == "fine"


def test_on_cancel_not_called_on_normal_exit_or_timeout():
    called = []
    run_cmd(py("pass"), cancel=threading.Event(), on_cancel=lambda: called.append(1))
    with pytest.raises(subprocess.TimeoutExpired):
        run_cmd(py("import time; time.sleep(30)"), timeout=0.3, on_cancel=lambda: called.append(1))
    assert called == []


@pytest.mark.slow
def test_cancel_kills_the_whole_process_tree(tmp_path):
    """A grandchild (like node under npx, or a schemathesis worker) must die too."""
    hb = tmp_path / "heartbeat"
    grandchild = (f"import time\nfor _ in range(300):\n    open({str(hb)!r}, 'a').write('.')\n"
                  "    time.sleep(0.05)\n")
    parent = py(f"""
        import subprocess, sys, time
        subprocess.Popen([sys.executable, "-c", {grandchild!r}])
        time.sleep(60)
    """)
    ev = threading.Event()

    def tick(_lines):
        if hb.exists() and hb.stat().st_size > 3:
            ev.set()

    with pytest.raises(Cancelled):
        run_cmd(parent, cancel=ev, on_tick=tick, timeout=30)
    time.sleep(0.5)  # let a final write land
    size = hb.stat().st_size
    time.sleep(1.0)
    assert hb.stat().st_size == size, "grandchild still running after cancel"


# ---------- run_cmd: live output ----------

def test_on_tick_sees_output_while_the_process_runs(tmp_path):
    sentinel = tmp_path / "go"
    ticks = []

    def tick(lines):
        ticks.append(lines)
        if "first" in lines:
            sentinel.write_text("x")  # the child waits for this, so "first" was seen before it exited

    r = run_cmd(py(f"""
        import os, time
        print("first", flush=True)
        for _ in range(200):
            if os.path.exists({str(sentinel)!r}):
                break
            time.sleep(0.05)
        print("second" if os.path.exists({str(sentinel)!r}) else "never saw tick")
    """), on_tick=tick, timeout=30)
    assert r.stdout.splitlines() == ["first", "second"]
    seen = [l for t in ticks for l in t]
    assert seen == ["first", "second"]  # each line exactly once, in order


def test_on_tick_includes_stderr_lines():
    seen = []
    run_cmd(py("""
        import sys
        print("to out")
        print("to err", file=sys.stderr)
    """), on_tick=lambda lines: seen.extend(lines))
    assert sorted(seen) == ["to err", "to out"]


def test_on_tick_gets_lines_written_just_before_exit():
    seen = []
    run_cmd(py("print('\\n'.join(f'line {i}' for i in range(50)))"), on_tick=lambda lines: seen.extend(lines))
    assert seen == [f"line {i}" for i in range(50)]


def test_on_tick_gets_a_final_line_without_newline():
    seen = []
    run_cmd(py("import sys; sys.stdout.write('a\\nTotal of 39 URLs')"), on_tick=lambda lines: seen.extend(lines))
    assert seen == ["a", "Total of 39 URLs"]


# ---------- Windows quirks ----------

@pytest.mark.skipif(sys.platform != "win32", reason="Windows batch files")
def test_runs_a_cmd_file_by_full_path(tmp_path):
    bat = tmp_path / "hello tool.cmd"
    bat.write_text("@echo off\r\necho hi %1\r\nexit /b 4\r\n")
    r = run_cmd([str(bat), "there"])
    assert r.stdout.strip() == "hi there" and r.returncode == 4


@pytest.mark.skipif(sys.platform != "win32", reason="Windows PATHEXT resolution")
def test_shutil_which_resolves_cmd_shims_that_run_cmd_can_start(tmp_path, monkeypatch):
    """lint resolves npx with shutil.which (npx is npx.cmd on Windows); run_cmd itself doesn't use PATHEXT."""
    import shutil
    (tmp_path / "fakenpx.cmd").write_text("@echo off\r\necho shim ok\r\n")
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ.get("PATH", ""))
    exe = shutil.which("fakenpx")
    assert exe and exe.lower().endswith(".cmd")
    assert run_cmd([exe]).stdout.strip() == "shim ok"


# ---------- _kill_tree and platform branches (faked) ----------

class FakePopen:
    def __init__(self, poll=None, wait_raises=False):
        self.pid, self._poll, self.wait_raises, self.killed, self.waited = 4242, poll, wait_raises, False, None

    def poll(self):
        return self._poll

    def wait(self, timeout=None):
        self.waited = timeout
        if self.wait_raises:
            raise subprocess.TimeoutExpired("x", timeout)
        return 0

    def kill(self):
        self.killed = True


@pytest.fixture
def fake_run(monkeypatch):
    calls = []
    monkeypatch.setattr(proc.subprocess, "run", lambda *a, **k: calls.append((a, k)))
    return calls


def test_kill_tree_ignores_finished_process(fake_run):
    p = FakePopen(poll=0)
    proc._kill_tree(p)
    assert fake_run == [] and p.waited is None


def test_kill_tree_windows_uses_taskkill_tree(fake_run, monkeypatch):
    monkeypatch.setattr(proc.sys, "platform", "win32")
    p = FakePopen()
    proc._kill_tree(p)
    assert fake_run[0][0][0] == ["taskkill", "/PID", "4242", "/T", "/F"]
    assert p.waited == 10 and not p.killed


def test_kill_tree_falls_back_to_kill_when_wait_times_out(fake_run, monkeypatch):
    monkeypatch.setattr(proc.sys, "platform", "win32")
    p = FakePopen(wait_raises=True)
    proc._kill_tree(p)
    assert p.killed


def test_kill_tree_posix_kills_the_process_group(fake_run, monkeypatch):
    monkeypatch.setattr(proc.sys, "platform", "linux")
    monkeypatch.setattr(proc.signal, "SIGKILL", 9, raising=False)
    killed = []
    monkeypatch.setattr(proc.os, "killpg", lambda pid, sig: killed.append((pid, sig)), raising=False)
    p = FakePopen()
    proc._kill_tree(p)
    assert killed == [(4242, 9)] and fake_run == [] and p.waited == 10


def test_kill_tree_posix_tolerates_already_gone_group(fake_run, monkeypatch):
    monkeypatch.setattr(proc.sys, "platform", "linux")
    monkeypatch.setattr(proc.signal, "SIGKILL", 9, raising=False)

    def gone(pid, sig):
        raise ProcessLookupError

    monkeypatch.setattr(proc.os, "killpg", gone, raising=False)
    proc._kill_tree(FakePopen())


@pytest.mark.parametrize("platform, expect", [("linux", {"start_new_session": True}), ("win32", {})])
def test_popen_gets_new_session_only_on_posix(monkeypatch, platform, expect):
    seen = {}

    class P:
        returncode = 0

        def __init__(self, cmd, **kw):
            seen.update(kw)

        def poll(self):
            return 0

    monkeypatch.setattr(proc.sys, "platform", platform)
    monkeypatch.setattr(proc.subprocess, "Popen", P)
    assert run_cmd(["x"]) == Result(0, "", "")
    assert {k: v for k, v in seen.items() if k == "start_new_session"} == expect
    assert seen["stdin"] is subprocess.DEVNULL
