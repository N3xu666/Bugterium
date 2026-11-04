# OSCP Reporting Notes

> **Disclaimer:** This document does NOT replace the official OffSec Exam Guide.
> Requirements, scoring, and report structure may change at any time.
> Always check the current OffSec documentation before the exam:
> https://help.offsec.com/hc/en-us/articles/360046458572-OSCP-Exam-Guide

This is a personal summary of what I track while preparing for OSCP,
and how it maps to the walkthroughs in this repository.

---

## Table of Contents

- [1. Official Sources](#1-official-sources)
- [2. What Goes Into the Report](#2-what-goes-into-the-report)
- [3. Screenshot Rules](#3-screenshot-rules)
- [4. Report Structure](#4-report-structure)
- [5. Common Mistakes](#5-common-mistakes)
- [6. How This Maps to Bugterium Walkthroughs](#6-how-this-maps-to-bugterium-walkthroughs)

---

## 1. Official Sources

- **OffSec Exam Guide** - authoritative, changes without notice.
- **OffSec FAQ** - scoring, retakes, report template.
- **OffSec Report Template** - use the official one, do not invent your own layout.

Links are intentionally not hardcoded here - search the OffSec Help Center for the current URLs.

---

## 2. What Goes Into the Report

The report proves you obtained the required flags, not that you "tried hard".
Every claimed objective needs evidence:

- A screenshot of the command and its output.
- A screenshot of the flag value (user / root / SYSTEM / Administrator).
- A short narrative explaining what the step achieved and why it worked.

Minimum evidence per machine:

| Objective | Evidence |
|-----------|----------|
| Foothold | Command that gives initial access + shell proof |
| User flag | `whoami` + `type` / `cat` of user flag file |
| Privilege escalation vector | Misconfiguration / vulnerability found + command |
| Root flag | `whoami` (root) + flag file content |

---

## 3. Screenshot Rules

A screenshot must be self-sufficient. A reviewer who was not in the exam
should be able to read it and understand what happened.

Rules:

- Full terminal window, not a cropped fragment.
- Command visible, output visible, prompt visible.
- Hostname / target IP visible in the prompt or in the command.
- No blur, no resize artifacts, no mobile photo.
- One screenshot per logical step - do not stack unrelated output.

If the output is long, take two screenshots (top and bottom) rather than one illegible one.

---

## 4. Report Structure

Follow the official template. A common structure:

1. **Executive Summary** - non-technical, 1 page. What was tested, what was found, risk rating.
2. **Methodology** - how the assessment was performed (recon, exploitation, post-exploitation).
3. **Findings** - one section per machine / vulnerability. Evidence, impact, remediation.
4. **Appendix** - full command logs, tool output, flag screenshots.

Do NOT pad the report. Quality beats volume.

---

## 5. Common Mistakes

- Missing screenshots for a claimed flag.
- Screenshots without command output (only the command).
- Flags typed as text instead of a screenshot of the flag file.
- Using the wrong template or renaming it.
- Submitting before the report is proofread.
- Claiming points for steps that were not actually completed.

---

## 6. How This Maps to Bugterium Walkthroughs

Walkthroughs in `WRITEUPS/01 Hack The Box/02 OSCP/` carry an OSCP reporting note:

    > [!IMPORTANT]
    > OSCP report: take a screenshot of this step (command + output + timestamp).

These notes are REMINDERS, not requirements. They mark the steps that
typically need a screenshot in the exam report. See the OSCP reporting notes section in the canonical walkthrough standard.
for the exact rule.

The walkthroughs are NOT exam reports. They are study material. The exam report
must follow the official OffSec template and include the evidence listed in §2 above.

---

*This document is a personal summary. It is not affiliated with OffSec.*

