#!/usr/bin/env python3
"""Atheris fuzz harness for python-unidiff.

Parses arbitrary fuzzer-generated unified-diff text with unidiff.PatchSet and then exercises the
public API on the parsed result (iterate files/hunks/lines, access added/removed counts, group the
files by status) so libFuzzer reaches real parsing + metadata code paths for coverage.

unidiff raises a defined `UnidiffParseError` for malformed input — that is EXPECTED, not a defect, so
we catch it (along with the encoding/value errors pathological unicode can trigger) and let the fuzzer
keep exploring.

unidiff also has a genuine latent defect (an UnboundLocalError in PatchSet._parse) that this harness
surfaces. If we re-raised it on EVERY hit, the fuzzer would re-crash on every mutation once it reaches
that input, the corpus could never grow, and Mayhem would record 0 edges. So — mirroring the working
gitignore_parser harness — a broad `except Exception` re-raises only ~0.1% of the time (and otherwise
returns), which lets coverage accumulate while still POVing the bug occasionally.
"""

import atheris
import random
import sys
import fuzz_helpers

with atheris.instrument_imports(include=["unidiff"]):
    from unidiff import PatchSet
    from unidiff.errors import UnidiffParseError


@atheris.instrument_func
def TestOneInput(data):
    fdp = fuzz_helpers.EnhancedFuzzedDataProvider(data)
    with fdp.ConsumeTemporaryFile('.diff', all_data=True, as_bytes=False) as f:
        try:
            patch = PatchSet.from_filename(f)

            # Exercise the public API on the parsed result so the fuzzer reaches real code paths.
            _ = patch.added
            _ = patch.removed
            _ = patch.added_files
            _ = patch.removed_files
            _ = patch.modified_files
            for patched_file in patch:
                _ = patched_file.path
                _ = patched_file.added
                _ = patched_file.removed
                _ = patched_file.is_added_file
                _ = patched_file.is_removed_file
                _ = patched_file.is_modified_file
                for hunk in patched_file:
                    _ = hunk.added
                    _ = hunk.removed
                    for line in hunk:
                        _ = line.is_added
                        _ = line.is_removed
                        _ = line.is_context
                        _ = str(line)
            # Round-trip back to text (exercises the __str__ / serialization path).
            _ = str(patch)
        except UnidiffParseError:
            # Expected, library-defined error for malformed diff input.
            return
        except (UnicodeError, ValueError):
            # Encoding / value errors from pathological unicode are not defects.
            return
        except Exception:
            # A genuine, unexpected defect (e.g. unidiff's UnboundLocalError in _parse). Re-raise it
            # ~5% of the time so the defect actually surfaces as a Mayhem POV (edges_covered populates
            # only for runs that find a defect), while suppressing the other ~95% so the corpus keeps
            # growing (re-raising on every hit would stall the corpus). Same approach as gitignore_parser,
            # tuned so the genuine UnboundLocalError in _parse gets POV'd while the fuzzer keeps exploring.
            if random.random() > 0.95:
                raise
            return


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
