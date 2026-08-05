from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from threading import RLock
from types import TracebackType
from typing import Protocol, TypeVar

from .errors import ReplayDetectedError
from .protocol import validate_message_sequence


_Result = TypeVar("_Result")


class _ContextLock(Protocol):
    def __enter__(self) -> object: ...

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None: ...


@dataclass(slots=True)
class ReplayWindow:
    window_size: int = 1024
    highest_seen: int = field(default=-1, init=False)
    seen: set[int] = field(default_factory=set, init=False)
    _lock: _ContextLock = field(
        default_factory=RLock,
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if isinstance(self.window_size, bool) or not isinstance(self.window_size, int):
            raise TypeError("replay window size must be an integer")
        if self.window_size <= 0:
            raise ValueError("replay window size must be positive")

    def _check_unlocked(self, sequence: int) -> None:
        validate_message_sequence(sequence)
        if sequence in self.seen:
            raise ReplayDetectedError(f"replayed sequence number: {sequence}")
        if sequence <= self.highest_seen - self.window_size:
            raise ReplayDetectedError(
                f"stale sequence number outside replay window: {sequence}"
            )

    def _record_unlocked(self, sequence: int) -> None:
        self.seen.add(sequence)
        if sequence > self.highest_seen:
            self.highest_seen = sequence
        floor = self.highest_seen - self.window_size
        self.seen = {number for number in self.seen if number > floor}

    def observe(self, sequence: int) -> None:
        with self._lock:
            self._check_unlocked(sequence)
            self._record_unlocked(sequence)

    def authenticate_and_record(
        self,
        sequence: int,
        operation: Callable[[], _Result],
    ) -> _Result:
        with self._lock:
            self._check_unlocked(sequence)
            result = operation()
            self._record_unlocked(sequence)
            return result
