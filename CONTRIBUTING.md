# Contributing to SPRAT

Thanks for helping. Bug reports, fixes, new checks and better docs are all welcome.

## Set up

```
git clone https://github.com/rigsutra/sprat.git
cd sprat
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[test]"
```

Node.js and Docker are optional. Without them the `lint` and `zap` stages, and the
tests that need the real tools, are skipped.

## Run the tests

```
pytest                    # everything that can run on this machine
pytest -m "not slow"      # quick loop: skips the end-to-end runs
pytest -m external        # only the tests that drive real Spectral / ZAP
```

The `e2e` tests start `examples/demo_api.py` and run SPRAT against it end to end.
If you add a check, add a planted flaw to the demo API that the check should catch.

## Making a change

- Open an issue first for anything bigger than a bug fix, so we can agree on the
  approach before you spend time on it.
- Keep a pull request to one change. Add or update tests for it.
- Match the style of the code around your change. There is no formatter config;
  lines run to about 120 characters.
- Findings should tell the user what was sent, what came back, what a correct API
  would do, and how to fix it. A finding nobody can act on is noise.
- Never weaken a check to make a test pass. If a check is wrong, fix it and say why
  in the pull request.

## Reporting bugs

Open an issue with the SPRAT version, OS, the command or UI steps, and what you
expected. If a finding is wrong, attach the test-log entry for it (Test log tab, or
`test-log.ndjson`). Remove tokens and private URLs first. SPRAT masks headers it
knows about, but check anyway.

Security problems in SPRAT itself go through [SECURITY.md](SECURITY.md), not a
public issue.

## License

By contributing you agree that your contribution is licensed under the
[Apache License 2.0](LICENSE), the same as the rest of the project.
