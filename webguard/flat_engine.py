
"""
WebGuard FLAT Engine

Implements:
1. Regular Expression validation
2. Deterministic Finite Automaton (DFA)
"""

import re


class FlatEngine:

    def __init__(self):
        self.engine_name = "WebGuard FLAT Engine"
        self.version = "1.1.0"

    # ---------------------------------
    # Regular Expression Validation
    # ---------------------------------

    def validate_url_pattern(self, url):
        pattern = (
            r"^https?://[A-Za-z0-9.\-\[\]:]+"
            r"(?::\d{1,5})?(?:/.*)?$"
        )

        return bool(re.fullmatch(pattern, url))

    def validate_header_name(self, header_name):
        pattern = r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$"

        return bool(re.fullmatch(pattern, header_name))

    # ---------------------------------
    # DFA URL Scheme Validation
    # ---------------------------------

    def validate_url_scheme_dfa(self, url):

        transitions = {
            "q0": {"h": "q1"},
            "q1": {"t": "q2"},
            "q2": {"t": "q3"},
            "q3": {"p": "q4"},
            "q4": {":": "q5", "s": "q4s"},
            "q4s": {":": "q5s"},
            "q5": {"/": "q6"},
            "q6": {"/": "HTTP_ACCEPT"},
            "q5s": {"/": "q6s"},
            "q6s": {"/": "HTTPS_ACCEPT"},
        }

        state = "q0"

        for character in url:

            # Once a valid scheme is recognized,
            # remaining characters are permitted.
            if state in ("HTTP_ACCEPT", "HTTPS_ACCEPT"):
                return True

            if character not in transitions.get(state, {}):
                return False

            state = transitions[state][character]

        return state in ("HTTP_ACCEPT", "HTTPS_ACCEPT")


if __name__ == "__main__":

    engine = FlatEngine()

    test_urls = [
        "http://127.0.0.1:3000",
        "https://localhost",
        "ftp://localhost",
        "invalid-url"
    ]

    print("=" * 45)
    print(engine.engine_name)
    print("DFA URL Scheme Validation")
    print("=" * 45)

    for url in test_urls:
        result = engine.validate_url_scheme_dfa(url)

        print(f"{url} --> {'ACCEPTED' if result else 'REJECTED'}")
