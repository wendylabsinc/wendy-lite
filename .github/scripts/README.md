# Pull-request review automation

These scripts are maintained in wendy-lite. They were ported from WendyOS
commit `ff6098ee34985749f4d9caf0459b3832549c4a6a` and adapted for Lite's firmware
review guidance and generated Go/nanopb binding paths. Changes here are reviewed
and shipped in this repository; CI does not download executable review scripts
from another repository.

`review_diff.py` divides the complete handwritten diff into bounded batches.
`security_review.py` validates the reviewed revision and coverage, calls the
model, and prepares the review comment. Generated bindings are excluded using
the fixed paths in that script; their `.proto` and `.options` inputs remain
reviewable. Lite retains its existing model and comment-only finding policy.
Incomplete review coverage still fails the workflow.

The workflow loads scripts from its immutable base commit. While introducing
these files to a base that does not have them, it uses the explicitly pinned
local bootstrap commit recorded in the workflow. It extracts only the
reviewer scripts, tests and locked dependencies and does not execute the pull request's application code. Once
the files exist on the base branch, that branch owns subsequent reviewer updates.

Run the deterministic tests without model credentials or network calls:

```sh
python3 .github/scripts/review_diff_test.py
python3 .github/scripts/security_review_test.py
```

The SDK and its transitive dependencies are pinned with artifact hashes in
`security-review-requirements.txt`. Regenerate the lock for the CI environment
when updating `security-review-requirements.in`:

```sh
uv pip compile .github/scripts/security-review-requirements.in --generate-hashes \
  --python-version 3.12 --python-platform x86_64-unknown-linux-gnu \
  --no-header --no-annotate \
  --output-file .github/scripts/security-review-requirements.txt
```

If rebasing the introducing branch changes the pinned bootstrap commit, update
the workflow pin to the new commit that contains all reviewer files and the lock.
