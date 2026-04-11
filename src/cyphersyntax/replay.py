from __future__ import annotations

from dataclasses import dataclass, field

from .errors import ReplayDetectedError


@dataclass(slots=True)
class ReplayWindow:
    window_size: int = 1024
    highest_seen: int = -1
    seen: set[int] = field(default_factory=set)

    def observe(self, sequence: int) -> None:
        if sequence in self.seen:
            raise ReplayDetectedError(f"replayed sequence number: {sequence}")
        if sequence <= self.highest_seen - self.window_size:
            raise ReplayDetectedError(f"stale sequence number outside replay window: {sequence}")
        self.seen.add(sequence)
        if sequence > self.highest_seen:
            self.highest_seen = sequence
        floor = self.highest_seen - self.window_size
        self.seen = {n for n in self.seen if n > floor}
