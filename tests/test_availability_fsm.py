from webguard.availability_fsm import AvailabilityStateMachine


def test_healthy_slow_and_unavailable_states():
    fsm = AvailabilityStateMachine()

    assert fsm.observe(True, 250, 1000)["state"] == "Healthy"
    assert fsm.observe(True, 1200, 1000)["state"] == "Slow"
    assert fsm.observe(False, 30, 1000)["state"] == "Unavailable"


def test_recovery_requires_two_successful_checks():
    fsm = AvailabilityStateMachine("Unavailable")

    first_success = fsm.observe(True, 200, 1000)
    assert first_success["state"] == "Recovering"
    assert first_success["recovery_attempts"] == 1

    second_success = fsm.observe(True, 200, 1000)
    assert second_success["state"] == "Restored"
    assert second_success["recovery_attempts"] == 2

    stable_success = fsm.observe(True, 200, 1000)
    assert stable_success["state"] == "Healthy"
    assert stable_success["recovery_attempts"] == 0


def test_failed_recovery_resets_consecutive_successes():
    fsm = AvailabilityStateMachine("Unavailable")
    fsm.observe(True, 200, 1000)

    failed_recovery = fsm.observe(False, 30, 1000)
    assert failed_recovery["state"] == "Unavailable"
    assert failed_recovery["recovery_attempts"] == 0
