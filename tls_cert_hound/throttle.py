import time

from .logging_utils import log_message


class ThrottleController:
    def __init__(self, delay: float, auto: bool, verbose: bool):
        self.delay = max(delay, 0.0)
        self.auto = auto
        self.verbose = verbose
        self.success_streak = 0
        self.next_allowed_time = None

    def wait(self, force: bool = False):
        if self.delay <= 0:
            return
        now = time.time()
        if self.next_allowed_time is None:
            self.next_allowed_time = now
        remaining = self.next_allowed_time - now
        if remaining > 0:
            log_message(
                f"[*] Throttling: sleeping {remaining:.2f}s before next request.",
                self.verbose,
                force=force,
            )
            time.sleep(remaining)
        self.next_allowed_time = time.time() + self.delay

    def record_success(self):
        if not self.auto:
            return
        self.success_streak += 1
        if self.success_streak >= 5 and self.delay > 0:
            self.delay = max(self.delay / 2.0, 0.1)
            self.success_streak = 0
            log_message(
                f"[*] Auto-throttle: 5 successful requests, delay now {self.delay:.2f}s.",
                self.verbose,
                force=True,
            )
            if self.next_allowed_time is not None:
                self.next_allowed_time = time.time() + self.delay

    def record_5XX(self, code: int):
        if not self.auto:
            return
        factor = 10.0 if self.delay < 0.5 else 3.0
        self.delay = max(self.delay * factor, 0.1)
        self.success_streak = 0
        log_message(
            f"[!] Auto-throttle: HTTP {code} received, delay now {self.delay:.2f}s.",
            self.verbose,
            force=True,
        )
        self.next_allowed_time = time.time() + self.delay

    def snapshot(self):
        return {
            "delay": self.delay,
            "success_streak": self.success_streak,
        }

    def restore(self, state):
        self.delay = float(state.get("delay", self.delay))
        self.success_streak = int(state.get("success_streak", 0))
