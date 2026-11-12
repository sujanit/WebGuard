
"""
WebGuard FLAT Engine - Scan Finite State Machine

Controls the sequence of a WebGuard security scan.
"""


class ScanStateMachine:

    def __init__(self):
        self.state = "INITIALIZED"
        self.history = [self.state]

        self.transitions = {
            "INITIALIZED": ["VALIDATING", "FAILED"],
            "VALIDATING": ["SCANNING", "FAILED"],
            "SCANNING": ["ANALYZING", "FAILED"],
            "ANALYZING": ["REPORTING", "FAILED"],
            "REPORTING": ["COMPLETED", "FAILED"],
            "COMPLETED": [],
            "FAILED": []
        }

    def transition(self, new_state):

        allowed_states = self.transitions.get(self.state, [])

        if new_state not in allowed_states:
            raise ValueError(
                f"Invalid transition: {self.state} -> {new_state}"
            )

        self.state = new_state
        self.history.append(new_state)

        return self.state

    def get_history(self):
        return self.history.copy()


if __name__ == "__main__":

    fsm = ScanStateMachine()

    workflow = [
        "VALIDATING",
        "SCANNING",
        "ANALYZING",
        "REPORTING",
        "COMPLETED"
    ]

    print("WebGuard Scan FSM")
    print("-" * 35)

    for next_state in workflow:
        fsm.transition(next_state)
        print(f"Current State: {fsm.state}")

    print("\nWorkflow History:")
    print(" -> ".join(fsm.get_history()))
