<!-- Do not hard-wrap this body. GitHub renders a single newline as a line
     break, so the 75-column rule is for commit messages and stops here. -->

## Objective

<!-- The problem or goal, as a short bullet list. The reasoning the issue does
     not carry: why this is worth doing, not only what it is. -->

## Solution

<!-- What was done, as a short bullet list. For a bug fix include the root
     cause; for a feature include what was added.

     Then two lines this project asks for:
     - Safety: can anything here reach a target outside the declared scope, or
       let traffic leave the lab? If no, which gate holds (isolation, the scope
       resolver, the intensity ladder)? If it touches a verdict, which CLAUDE.md
       row does its worst failure land on?
     - What was rejected and why, and what was deliberately left undone (with
       the follow-up issue or milestone that picks it up). -->

## Verification

<!-- What was run and what it printed, not what would happen. The gate at
     minimum (bash .claude/scripts/gate.sh), plus any test whose name is the
     guard and the mutation that makes it fail.

     End with the recommended review tier and why, per .claude/skills/review:
     it turns on what the change can cause (a verdict, an exit code, a
     diagnostic, an escape from scope), not on how large it is. The reviewer
     decides whether to spend it. -->

<!-- Issue link at the bottom (not under a heading). Use the keyword that fits:
     Closes #N   — feature implementation or task completion
     Fixes #N    — bug fix
     Resolves #N — general resolution (discussion, refactor, etc.) -->
