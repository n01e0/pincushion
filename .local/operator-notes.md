# pincushion operator notes

Local-only notes for the operator. Keep this file in `.local/` and do not copy its planning/detail-heavy content into the public README.

## README boundary
- `README.md` stays public-facing and high-level.
- Design details, phased plans, tasklists, and dry-run scratch notes stay under `.local/`.
- If a note includes local workflow decisions or operator judgement, prefer `.local/` unless it is necessary for outside contributors.

## Current rule of thumb
- Public README: what pincushion is, how to run the main command, how to verify locally.
- `.local/`: planning context, operator reminders, rollout notes, package choices, and anything still in flux.

## Before editing public docs
- Remove local-only planning language.
- Avoid copying tasklist/design prose verbatim.
- Keep examples minimal and stable.

## Local dry-run memo
- Sample watchlist: `.local/sample-watchlist.yaml`
- Dry-run checklist: `.local/dry-run.md`
- If the public README starts growing operator-only setup steps, move that detail back under `.local/`.
