"""Rule-based phishing signals.

Each rule looks at one email and, if it fires, returns a reason:
{"id": ..., "severity": "low" | "medium" | "high", "message": ...}.
The messages are shown to the user in the Gmail banner, so they must be plain and specific.
"""
