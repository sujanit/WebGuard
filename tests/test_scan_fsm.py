
import pytest

from webguard.scan_fsm import ScanStateMachine


def test_initial_state():
    fsm = ScanStateMachine()

    assert fsm.state == "INITIALIZED"
    assert fsm.get_history() == ["INITIALIZED"]


def test_valid_scan_workflow():
    fsm = ScanStateMachine()

    workflow = [
        "VALIDATING",
        "SCANNING",
        "ANALYZING",
        "REPORTING",
        "COMPLETED"
    ]

    for state in workflow:
        fsm.transition(state)

    assert fsm.state == "COMPLETED"

    assert fsm.get_history() == [
        "INITIALIZED",
        "VALIDATING",
        "SCANNING",
        "ANALYZING",
        "REPORTING",
        "COMPLETED"
    ]


def test_invalid_transition():
    fsm = ScanStateMachine()

    with pytest.raises(ValueError):
        fsm.transition("COMPLETED")


def test_failed_scan_transition():
    fsm = ScanStateMachine()

    fsm.transition("VALIDATING")
    fsm.transition("FAILED")

    assert fsm.state == "FAILED"


def test_terminal_state_rejects_transition():
    fsm = ScanStateMachine()

    fsm.transition("VALIDATING")
    fsm.transition("FAILED")

    with pytest.raises(ValueError):
        fsm.transition("SCANNING")


def test_history_returns_copy():
    fsm = ScanStateMachine()

    history = fsm.get_history()
    history.append("FAKE_STATE")

    assert "FAKE_STATE" not in fsm.get_history()
