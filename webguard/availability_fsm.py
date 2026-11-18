class AvailabilityStateMachine:
    RECOVERY_SUCCESS_THRESHOLD = 2

    def __init__(self, state="Unknown", recovery_attempts=0):
        self.state = state
        self.recovery_attempts = recovery_attempts

    def observe(self, successful, response_time_ms, slow_threshold_ms):
        previous_state = self.state

        if not successful:
            self.state = "Unavailable"
            self.recovery_attempts = 0
        elif previous_state == "Unavailable":
            self.state = "Recovering"
            self.recovery_attempts = 1
        elif previous_state == "Recovering":
            self.recovery_attempts += 1
            self.state = (
                "Restored"
                if self.recovery_attempts >= self.RECOVERY_SUCCESS_THRESHOLD
                else "Recovering"
            )
        else:
            self.recovery_attempts = 0
            self.state = (
                "Slow"
                if response_time_ms > slow_threshold_ms
                else "Healthy"
            )

        return {
            "previous_state": previous_state,
            "state": self.state,
            "changed": self.state != previous_state,
            "recovery_attempts": self.recovery_attempts
        }
