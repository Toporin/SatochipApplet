#!/usr/bin/env python3
"""Compile the applet and run its nonce-counter regression in jCardSim only."""
import argparse
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jcardsim', required=True, type=Path)
    parser.add_argument('--java-home', required=True, type=Path)
    parser.add_argument('--applet', type=Path, default=root,
                        help='source checkout to test (default: this checkout)')
    args = parser.parse_args()
    jar = args.jcardsim.resolve()
    expected = 'f6c3b6b8140401a47cf39d7b9dbfc052e381474c6c3b22018051024be1fca97c'
    if hashlib.sha256(jar.read_bytes()).hexdigest() != expected:
        parser.error('expected com.klinec:jcardsim:3.0.5.11 (see tests/README.md)')
    sources = sorted((args.applet / 'src/org/satochip/applet').glob('*.java'))
    if not sources:
        parser.error('no applet sources found')
    with tempfile.TemporaryDirectory(prefix='satochip-counter-') as directory:
        subprocess.run([str(args.java_home / 'bin/javac'), '-cp', str(jar),
                        '-d', directory, *map(str, sources),
                        str(root / 'tests/Musig2NonceCounterTest.java')], check=True)
        subprocess.run([str(args.java_home / 'bin/java'),
                        '-Dcom.licel.jcardsim.randomdata.secure=1', '-cp',
                        directory + os.pathsep + str(jar),
                        'Musig2NonceCounterTest'], check=True)


if __name__ == '__main__':
    main()
