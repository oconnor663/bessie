#! /usr/bin/env python3

import os
import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent


def run(cwd, args, env={}):
    result = subprocess.run(args, cwd=(HERE / cwd), env=(os.environ | env))
    if result.returncode != 0:
        print("TEST FAILED!!!")
        sys.exit(result.returncode)


run("rust/lib", ["cargo", "test"])
run("rust/lib", ["cargo", "test", "--no-default-features"])
# RUSTC_BOOTSTRAP allows us to test benchmarks on the stable Rust toolchain.
# It's not appropriate for normal development, and we only use it here.
run("rust/lib", ["cargo", "test", "--all-targets"], env={"RUSTC_BOOTSTRAP": "1"})
run("rust/bin", ["cargo", "test"])

print("All tests passed.")
