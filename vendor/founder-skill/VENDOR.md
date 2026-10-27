# Vendored: founder-skill

| | |
| --- | --- |
| Upstream | https://github.com/Jakeschincariol/founder-skill |
| Browser | https://github.com/Jakeschincariol/founder-skill |
| Imported revision | `fd9385b0cfe1b96bebce3898fbd506d73eff5a9d` |
| Import date | 2026-10-27 |
| License | MIT - see [LICENSE](LICENSE), Copyright (c) 2026 Jake Schincariol |
| Method | `git clone --depth 50` then `rsync -a --exclude '.git'` |

## What is imported

The complete upstream tree (30 files): all eleven skills with their
`SKILL.md` instruction files, the four standard-library Python tools
(`unit_economics.py`, `panel.py`, `van_westendorp.py`, `compile.py`), their
example inputs, the upstream `tests/` suite, and the MIT `LICENSE`.

Selective inclusion was considered; the upstream tools import each other
(`compile.py` loads `unit_economics.py` by relative path) and the tests load
skills by folder name, so the tree is imported whole rather than trimmed.

## Local adaptations

**None.** No upstream file was modified. Everything Zero-Trust Sentinel adds
lives outside this directory:

- `business_intel.py` - the integration module (registry, tool runner, LLM
  skill runner, research gate)
- `api.py` - `/business/*` routes
- `db.py` - `business_projects` / `business_outputs`
- `static/assets/js/business.js` + the `#business` section in
  `static/index.html` - cockpit UI
- `test_business_intel.py` - integration tests

The vendored tools are executed as fixed-argv subprocesses from
`business_intel._run_tool`; they are never imported into the API process and
never receive model-authored commands.

## Provenance check

```
$ git -C vendor/founder-skill ...   # (no .git: provenance recorded above)
$ head -3 LICENSE
MIT License

Copyright (c) 2026 Jake Schincariol
$ cd vendor/founder-skill && python3 -m unittest discover -s tests
Ran 29 tests in 0.226s
OK
```

Credit: made by Jake Schincariol, https://opusjake.ai.
