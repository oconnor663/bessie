#! /usr/bin/env python3

import pathlib
import subprocess
import sys

HERE = pathlib.Path(__file__).parent


def run(cwd, args):
    result = subprocess.run(args, cwd=(HERE / cwd))
    if result.returncode != 0:
        print("TEST FAILED!!!")
        sys.exit(result.returncode)


run("rust/lib", ["cargo", "test"])
run("rust/bin", ["cargo", "test"])

print("All tests passed.")
