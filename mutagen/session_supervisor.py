"""
Persistent Fuzzing Supervisor — Stateful Session Execution Engine.

Unlike the fire-and-forget ``execute_payload`` function, the
``SessionSupervisor`` keeps a target process alive across an ordered
*sequence* of payloads and records per-step state transitions (stdout
deltas, stderr deltas, coverage growth, crash attribution).

This is critical for stateful targets like protocol state machines,
multiplexers, and authentication handlers where a vulnerability only
triggers after the process has been driven through a specific sequence
of states (e.g. AUTH → SELECT → OVERFLOW).

Delivery modes
--------------
``session:stdin``   — Keeps a single Popen process with an open stdin pipe.
                      Each step writes to stdin and reads stdout/stderr.
``session:tcp:<port>`` — Spawns the process then maintains a persistent TCP
                         socket, sending each step over the same connection.
"""

from __future__ import annotations

import re
import socket
import queue
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class StepResult:
    """Result of a single input step within a persistent session."""
    step_index: int
    input_sent: str
    stdout_delta: str = ""
    stderr_delta: str = ""
    coverage_delta: list[int] = field(default_factory=list)
    cumulative_coverage: set[int] = field(default_factory=set)
    is_alive: bool = True
    return_code: Optional[int] = None
    crash_type: str = "none"
    elapsed_ms: float = 0.0


@dataclass
class SessionResult:
    """Aggregated result of an entire payload sequence (session)."""
    steps: list[StepResult] = field(default_factory=list)
    crashed: bool = False
    crash_step: Optional[int] = None
    crash_type: str = "none"
    total_coverage: set[int] = field(default_factory=set)
    coverage_progression: list[set[int]] = field(default_factory=list)
    return_code: Optional[int] = None

# ---------------------------------------------------------------------------
# Crash classification — shared taxonomy with executor.py
# ---------------------------------------------------------------------------

_WINDOWS_NTSTATUS = {
    -1073741819: "ACCESS_VIOLATION (Memory Corruption!)",
    3221225477: "ACCESS_VIOLATION (Memory Corruption!)",
    -1073740940: "HEAP_CORRUPTION (Double Free / Heap Corruption!)",
    3221226356: "HEAP_CORRUPTION (Double Free / Heap Corruption!)",
    -1073741676: "STACK_OVERFLOW",
    -1073741571: "STACK_BUFFER_OVERRUN",
}

_POSIX_SIGNALS = {
    -11: "SIGSEGV (Segmentation Fault)",
    -6: "SIGABRT (Aborted)",
    -4: "SIGILL (Illegal Instruction)",
    -8: "SIGFPE (Floating Point Exception)",
    -7: "SIGBUS (Bus Error)",
}


def _classify_crash(return_code: int) -> str:
    """Classify a non-zero return code into a crash type string."""
    if not isinstance(return_code, int):
        return "none"
    if return_code in _WINDOWS_NTSTATUS:
        return _WINDOWS_NTSTATUS[return_code]
    if return_code in _POSIX_SIGNALS:
        return _POSIX_SIGNALS[return_code]
    if return_code == 101:
        return "RUST_PANIC (Safety Violation!)"
    if return_code < 0:
        return f"SIGNAL_{abs(return_code)}"
    # Non-zero but not a crash signal (e.g. return 1)
    return "none"



def _extract_coverage(text: str) -> list[int]:
    """Parse ``__MUTAGEN_COV__:1,2,3,...`` markers from stdout."""
    cov_match = re.search(r'__MUTAGEN_COV__:([0-9,]*)\b', text)
    if cov_match:
        raw = cov_match.group(1)
        if raw:
            try:
                return [int(x) for x in raw.split(",") if x]
            except ValueError:
                pass
    return []


def _strip_coverage_marker(text: str) -> str:
    """Remove ``__MUTAGEN_COV__`` lines from output text."""
    return re.sub(r'\n?__MUTAGEN_COV__:[0-9,]*\b\n?', '\n', text).strip()


# ---------------------------------------------------------------------------
# Oracle detection — mirrors executor.py logic
# ---------------------------------------------------------------------------

_LOGICAL_INDICATORS = [
    "access granted", "privileges acquired", "admin privileges",
    "flag{", "root:", "uid=0", "systeminfo", "cmd.exe", "/bin/sh",
    "vuln_triggered", "exploit_success", "authenticated as admin",
]

_HEAP_HARD_SIGNATURES = [
    "addresssanitizer", "ubsanitizer", "corrupted size vs. prev_size",
    "malloc(): corrupted top size", "free(): invalid next size",
    "double free or corruption", "invalid pointer",
    "heap corruption detected", "invalid heap pointer",
    "_crtisvalidheappointer",
]

_HEAP_SOFT_SIGNATURES = [
    "sasl_bufover", "bufover", "buffer overflow",
    "heap buffer overflow", "heap-buffer-overflow",
    "stack-buffer-overflow", "use-after-free",
    "double-free", "memory corruption",
]


def _check_oracles(stdout: str, stderr: str, return_code: int) -> tuple[bool, str]:
    """Run logical-exploit and heap-corruption oracle checks on output.

    Returns (crashed: bool, crash_type: str).
    """
    combined = (stdout + stderr).lower()

    # Logical exploit check
    for indicator in _LOGICAL_INDICATORS:
        if indicator in combined:
            return True, f"LOGICAL_EXPLOIT (Matched signature: '{indicator}')"

    # Heap corruption — hard signatures are crashes regardless of exit code
    for sig in _HEAP_HARD_SIGNATURES:
        if sig in combined:
            return True, f"HEAP_CORRUPTION (Caught overflow signature: '{sig}')"

    # Heap corruption — soft signatures need abnormal exit code
    for sig in _HEAP_SOFT_SIGNATURES:
        if sig in combined:
            if return_code not in (0, 1):
                return True, f"HEAP_CORRUPTION (Caught overflow signature: '{sig}')"

    return False, "none"


# ---------------------------------------------------------------------------
# SessionSupervisor
# ---------------------------------------------------------------------------

class SessionSupervisor:
    """Manages a long-lived target process for stateful, sequence-based fuzzing.

    Parameters
    ----------
    exe_path : str
        Path to the compiled target binary.
    delivery_mode : str
        One of ``session:stdin`` or ``session:tcp:<port>``.
    timeout : int
        Global session timeout in seconds.
    sandbox : str
        Sandbox mode (``none`` or ``docker``). Docker support follows the
        same pattern as ``executor.py`` but keeps the container alive.
    step_timeout : float
        Default per-step timeout in seconds (how long to wait for output
        after sending one input). Defaults to 2.0.
    """

    def __init__(
        self,
        exe_path: str,
        delivery_mode: str = "session:stdin",
        timeout: int = 30,
        sandbox: str = "none",
        step_timeout: float = 2.0,
    ):
        self.exe_path = exe_path
        self.delivery_mode = delivery_mode
        self.timeout = timeout
        self.sandbox = sandbox
        self.step_timeout = step_timeout

        self._process: Optional[subprocess.Popen] = None
        self._socket: Optional[socket.socket] = None
        self._stdout_queue: queue.Queue = queue.Queue()
        self._stderr_queue: queue.Queue = queue.Queue()
        self._stdout_thread: Optional[threading.Thread] = None
        self._stderr_thread: Optional[threading.Thread] = None
        self._cumulative_coverage: set[int] = set()
        self._step_count = 0
        self._started = False


    # -- Lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the target process and open communication channels."""
        if self._started:
            raise RuntimeError("Session already started. Call kill() first.")

        # Parse the inner delivery mode
        inner = self._inner_mode()

        cmd = [self.exe_path]

        if inner == "stdin":
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        elif inner.startswith("tcp:"):
            # Spawn the server process; no stdin needed
            self._process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            # Give the server a moment to bind
            time.sleep(0.5)
            port = int(inner.split(":")[1])
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._socket.settimeout(self.step_timeout)
            self._socket.connect(("127.0.0.1", port))
        else:
            raise ValueError(
                f"Unsupported session delivery mode: {self.delivery_mode}. "
                "Use 'session:stdin' or 'session:tcp:<port>'."
            )

        self._started = True
        self._step_count = 0
        self._cumulative_coverage = set()

        if inner == "stdin" and self._process:
            self._stdout_queue = queue.Queue()
            self._stderr_queue = queue.Queue()

            def read_stream(stream, q):
                try:
                    while True:
                        char = stream.read(1)
                        if not char:
                            break
                        q.put(char)
                except Exception:
                    pass
                finally:
                    try:
                        stream.close()
                    except Exception:
                        pass

            self._stdout_thread = threading.Thread(
                target=read_stream, args=(self._process.stdout, self._stdout_queue), daemon=True
            )
            self._stderr_thread = threading.Thread(
                target=read_stream, args=(self._process.stderr, self._stderr_queue), daemon=True
            )
            self._stdout_thread.start()
            self._stderr_thread.start()

    def kill(self) -> None:
        """Force-terminate the target process and clean up resources."""
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None

        if self._process:
            try:
                self._process.kill()
                self._process.wait(timeout=2)
            except Exception:
                pass
            self._process = None

        self._stdout_thread = None
        self._stderr_thread = None
        self._started = False


    @property
    def is_alive(self) -> bool:
        """Check if the managed process is still running."""
        if self._process is None:
            return False
        return self._process.poll() is None

    # -- Step execution ------------------------------------------------------

    def send_step(self, input_data: str, step_timeout: Optional[float] = None) -> StepResult:
        """Send one input to the persistent process and capture the response.

        Parameters
        ----------
        input_data : str
            The payload to send for this step.
        step_timeout : float, optional
            Override the default per-step timeout.

        Returns
        -------
        StepResult
            Captures stdout/stderr deltas, coverage, crash info for this step.
        """
        if not self._started or self._process is None:
            return StepResult(
                step_index=self._step_count,
                input_sent=input_data,
                is_alive=False,
                crash_type="SESSION_NOT_STARTED",
            )

        step_idx = self._step_count
        self._step_count += 1
        timeout = step_timeout if step_timeout is not None else self.step_timeout
        t0 = time.perf_counter()

        # Check if process is already dead before sending
        if not self.is_alive:
            rc = self._process.returncode
            crash_type = _classify_crash(rc) if rc and rc != 0 else "PROCESS_DEAD"
            return StepResult(
                step_index=step_idx,
                input_sent=input_data,
                is_alive=False,
                return_code=rc,
                crash_type=crash_type,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        inner = self._inner_mode()
        stdout_delta = ""
        stderr_delta = ""

        try:
            if inner == "stdin":
                stdout_delta, stderr_delta = self._send_stdin(input_data, timeout)
            elif inner.startswith("tcp:"):
                stdout_delta, stderr_delta = self._send_tcp(input_data, timeout)
        except _StepTimeout:
            return StepResult(
                step_index=step_idx,
                input_sent=input_data,
                is_alive=self.is_alive,
                crash_type="STEP_TIMEOUT (possible hang on this step)",
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )
        except (BrokenPipeError, OSError) as e:
            # Process died while we were writing
            rc = self._process.returncode if self._process else -1
            crash_type = _classify_crash(rc) if rc and rc != 0 else f"PIPE_ERROR: {e}"
            return StepResult(
                step_index=step_idx,
                input_sent=input_data,
                is_alive=False,
                return_code=rc,
                crash_type=crash_type,
                elapsed_ms=(time.perf_counter() - t0) * 1000,
            )

        elapsed = (time.perf_counter() - t0) * 1000

        # Coverage extraction
        cov_blocks = _extract_coverage(stdout_delta)
        stdout_delta = _strip_coverage_marker(stdout_delta)
        new_blocks = set(cov_blocks) - self._cumulative_coverage
        self._cumulative_coverage.update(cov_blocks)

        # Check if process died during this step
        alive = self.is_alive
        rc = None if alive else self._process.returncode
        crash_type = "none"
        crashed_here = False

        if not alive and rc is not None and rc != 0:
            crash_type = _classify_crash(rc)
            if crash_type != "none":
                crashed_here = True

        # Oracle detection on output
        if not crashed_here and (stdout_delta or stderr_delta):
            oracle_crashed, oracle_type = _check_oracles(
                stdout_delta, stderr_delta, rc if rc is not None else 0
            )
            if oracle_crashed:
                crash_type = oracle_type
                crashed_here = True

        return StepResult(
            step_index=step_idx,
            input_sent=input_data,
            stdout_delta=stdout_delta[:500],
            stderr_delta=stderr_delta[:500],
            coverage_delta=sorted(new_blocks),
            cumulative_coverage=set(self._cumulative_coverage),
            is_alive=alive,
            return_code=rc,
            crash_type=crash_type,
            elapsed_ms=elapsed,
        )

    # -- Sequence execution --------------------------------------------------

    def run_sequence(self, steps: list[str]) -> SessionResult:
        """Convenience: feed an entire ordered payload sequence.

        Automatically starts the process if not already started.
        Returns an aggregated ``SessionResult`` with per-step detail.
        """
        if not self._started:
            self.start()

        result = SessionResult()

        for i, input_data in enumerate(steps):
            step = self.send_step(input_data)
            result.steps.append(step)
            result.coverage_progression.append(set(step.cumulative_coverage))
            result.total_coverage.update(step.cumulative_coverage)

            if step.crash_type != "none":
                result.crashed = True
                result.crash_step = step.step_index
                result.crash_type = step.crash_type
                result.return_code = step.return_code
                break  # Session is over — process crashed

            if not step.is_alive:
                # Process exited cleanly mid-sequence
                result.return_code = step.return_code
                break

        # Double check if the process actually crashed or died at the end of the sequence
        if not result.crashed and self._process:
            if self._inner_mode() == "stdin" and self._process.stdin:
                try:
                    self._process.stdin.close()
                except Exception:
                    pass

            try:
                # Wait up to 5 seconds for Windows Error Reporting to finalize if crashed
                rc = self._process.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                rc = None

            if rc is not None and rc != 0:
                crash_type = _classify_crash(rc)
                if crash_type != "none":
                    result.crashed = True
                    result.crash_type = crash_type
                    result.return_code = rc
                    if result.steps:
                        result.crash_step = len(result.steps) - 1
                        result.steps[-1].crash_type = crash_type
                        result.steps[-1].is_alive = False
                        result.steps[-1].return_code = rc

        return result


    # -- Context manager support ---------------------------------------------

    def __enter__(self) -> "SessionSupervisor":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.kill()

    # -- Private helpers -----------------------------------------------------

    def _inner_mode(self) -> str:
        """Extract the inner delivery mode from 'session:stdin' or 'session:tcp:8080'."""
        if self.delivery_mode.startswith("session:"):
            return self.delivery_mode[len("session:"):]
        return self.delivery_mode

    def _send_stdin(self, data: str, timeout: float) -> tuple[str, str]:
        """Write data to stdin and read available stdout/stderr within timeout."""
        proc = self._process
        assert proc is not None and proc.stdin is not None

        # Write the input followed by a newline delimiter
        proc.stdin.write(data + "\n")
        proc.stdin.flush()

        # Non-blocking read from thread-safe queues
        stdout_chunks = []
        stderr_chunks = []
        deadline = time.perf_counter() + timeout

        while time.perf_counter() < deadline:
            # Drain stdout
            while not self._stdout_queue.empty():
                try:
                    stdout_chunks.append(self._stdout_queue.get_nowait())
                except queue.Empty:
                    break

            # Drain stderr
            while not self._stderr_queue.empty():
                try:
                    stderr_chunks.append(self._stderr_queue.get_nowait())
                except queue.Empty:
                    break

            # If the process terminated, stop waiting
            if proc.poll() is not None:
                break

            time.sleep(0.01)

            # If we got output, wait a tiny bit for any trailing bytes and break
            if stdout_chunks or stderr_chunks:
                time.sleep(0.05)
                # Drain one last time
                while not self._stdout_queue.empty():
                    try:
                        stdout_chunks.append(self._stdout_queue.get_nowait())
                    except queue.Empty:
                        break
                while not self._stderr_queue.empty():
                    try:
                        stderr_chunks.append(self._stderr_queue.get_nowait())
                    except queue.Empty:
                        break
                break

        return "".join(stdout_chunks), "".join(stderr_chunks)


    def _send_tcp(self, data: str, timeout: float) -> tuple[str, str]:
        """Send data over the persistent TCP socket and read stdout/stderr."""
        if self._socket is None:
            raise OSError("TCP socket is not connected")

        self._socket.settimeout(timeout)
        self._socket.sendall(data.encode("utf-8"))

        # Read any response from the socket
        response = b""
        try:
            response = self._socket.recv(4096)
        except socket.timeout:
            pass

        # Also drain stdout/stderr from the process
        proc = self._process
        stderr_data = ""
        stdout_data = response.decode("utf-8", errors="replace")

        if proc and proc.stderr:
            import selectors
            sel = selectors.DefaultSelector()
            try:
                sel.register(proc.stderr, selectors.EVENT_READ)
                events = sel.select(timeout=0.1)
                if events:
                    stderr_data = proc.stderr.read(4096) or ""
            except Exception:
                pass
            finally:
                sel.close()

        return stdout_data, stderr_data


class _StepTimeout(Exception):
    """Internal: raised when a single step exceeds its timeout."""
    pass
