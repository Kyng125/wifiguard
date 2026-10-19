"""Evaluation tooling for Chapter 4: repeated, seeded trials of the five scenarios in Table 3.5.

    traffic.py   varied normal traffic and attack scenarios built from synthetic frames
    harness.py   runs each trial in an isolated database and computes the Section 3.13 measures
    export.py    CSV, metrics table and an auto-filled methodology note for the report

These are simulated trials: they verify the detection logic and its inherent delay. They are not over-the-air results.
See docs/evaluation.md.
"""
