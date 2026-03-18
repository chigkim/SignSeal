First check `git ls-files *.py` and only review/edit with those files unless instructed.
When implementing or revising a feature, use a simple, cohesive design that prioritizes security, readability, consistency, efficiency, maintainability, and modularity.
- Make sure changes are applied consistently across the core, API, CLI, and GUI.
- Avoid unnecessary wrappers, translation layers, redundant code paths, or multiple entry points that serve the same purpose.
- Use clear abstractions without adding unnecessary complexity.
- Eliminate duplication and dead code.
- Do not implement fallbacks, backward compatibility layers, legacy support, migration paths, or any version specific handling, including accommodations for outdated files, commands, or parameters.
- All components must conform strictly to the latest implementation, with a single, unified format, schema, structure, naming style.
The format is locked — do not add migration paths, backward compatibility layers, or version-specific branching. If a change would break `test_absolute`, the change is wrong.
Do not modify `FORMAT_VERSION` in `SignSeal/config.py` or any version-bearing constant. All versioning is derived from that single constant.
If necessary edit/create relevant unit tests inside @tests/.
**CRITICAL**: `tests/test_absolute.py` must NEVER be modified under any circumstance. This file is the ground truth for format compatibility. If `test_absolute` fails, the implementation is wrong — fix the implementation to pass the test, not the other way around.
**CRITICAL**: If a unit test targets GUI functionality, it must be fully automated and run non-interactively. It must not require any user input or manual interaction, as this will cause the test to hang.
Run the unit tests with `pytest tests -x --sw -v --tb long`.
When it needs to start testing from the beginning, add `--sw-reset`.
If you create a new code file that are necessary, make sure to git add.
When you finish, alert the user by running: `powershell -c "[console]::beep(500,500)"`.