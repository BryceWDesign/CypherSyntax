from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from cyphersyntax.errors import ReplayDetectedError
from cyphersyntax.protocol import MAX_MESSAGE_SEQUENCE
from cyphersyntax.replay import ReplayWindow


def test_replay_window_accepts_out_of_order_messages_within_window():
    replay_window = ReplayWindow(window_size=4)

    replay_window.observe(3)
    replay_window.observe(1)
    replay_window.observe(2)

    assert replay_window.highest_seen == 3
    assert replay_window.seen == {1, 2, 3}


def test_replay_window_rejects_duplicate_and_stale_messages():
    replay_window = ReplayWindow(window_size=4)

    replay_window.observe(4)
    with pytest.raises(ReplayDetectedError, match="replayed sequence number"):
        replay_window.observe(4)
    with pytest.raises(ReplayDetectedError, match="stale sequence number"):
        replay_window.observe(0)


def test_failed_authentication_does_not_change_replay_state():
    replay_window = ReplayWindow()

    def reject() -> bytes:
        raise RuntimeError("authentication failed")

    with pytest.raises(RuntimeError, match="authentication failed"):
        replay_window.authenticate_and_record(7, reject)

    assert replay_window.highest_seen == -1
    assert replay_window.seen == set()
    assert replay_window.authenticate_and_record(7, lambda: b"accepted") == b"accepted"


def test_concurrent_duplicate_delivery_records_only_once():
    replay_window = ReplayWindow()
    start = Barrier(2)

    def deliver() -> bytes:
        start.wait()
        try:
            return replay_window.authenticate_and_record(9, lambda: b"accepted")
        except ReplayDetectedError:
            return b"replayed"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: deliver(), range(2)))

    assert sorted(results) == [b"accepted", b"replayed"]
    assert replay_window.highest_seen == 9
    assert replay_window.seen == {9}


@pytest.mark.parametrize("window_size", [0, -1])
def test_replay_window_requires_positive_size(window_size):
    with pytest.raises(ValueError, match="must be positive"):
        ReplayWindow(window_size=window_size)


@pytest.mark.parametrize("window_size", [True, 1.5, "1024"])
def test_replay_window_requires_integer_size(window_size):
    with pytest.raises(TypeError, match="must be an integer"):
        ReplayWindow(window_size=window_size)


@pytest.mark.parametrize("sequence", [-1, MAX_MESSAGE_SEQUENCE + 1])
def test_replay_window_rejects_out_of_range_sequences(sequence):
    replay_window = ReplayWindow()

    with pytest.raises(ValueError, match="unsigned 64-bit integer"):
        replay_window.observe(sequence)


@pytest.mark.parametrize("sequence", [True, 1.5, "1"])
def test_replay_window_rejects_non_integer_sequences(sequence):
    replay_window = ReplayWindow()

    with pytest.raises(TypeError, match="must be an integer"):
        replay_window.observe(sequence)
