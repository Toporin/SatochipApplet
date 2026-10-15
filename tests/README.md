# MuSig2 nonce-counter regression

This test compiles the actual applet sources and invokes their nonce-generation
and invalid-token handlers in jCardSim. It uses a disposable private key of 1 and
reflection to set up the simulator and move the counter near its boundaries.
It does not connect to a reader or modify a physical card. It bypasses APDU
transport and PIN setup to isolate nonce bookkeeping; it is not a hardware,
secure-channel, or complete signing test.

Requirements: Python 3, JDK 17, and `com.klinec:jcardsim:3.0.5.11`:

```sh
curl --fail --location --output /tmp/jcardsim-3.0.5.11.jar \
  https://repo.maven.apache.org/maven2/com/klinec/jcardsim/3.0.5.11/jcardsim-3.0.5.11.jar
python3 tests/run-nonce-counter.py \
  --java-home /path/to/jdk-17 \
  --jcardsim /tmp/jcardsim-3.0.5.11.jar
```

The runner checks the jar's SHA-256 before compiling. All compiled classes are
temporary. No additional Python packages, Java Card SDK, or wallet app is needed.
The test only generates nonces and checks rejection before signature arithmetic,
so it does not need the simulator RSA-exponent workaround used by full signing
tests.

To reproduce the original failure without modifying either checkout, pass an
unmodified `musig2-support` / `v0.15-0.1` checkout:

```sh
git worktree add --detach /tmp/satochip-counter-stock \
  3aa97fdc32c3fe3afade3cd5eb7cd9d0d4bd197c
python3 tests/run-nonce-counter.py \
  --java-home /path/to/jdk-17 \
  --jcardsim /tmp/jcardsim-3.0.5.11.jar \
  --applet /tmp/satochip-counter-stock
```

The original source succeeds for IDs 32767 and 32768, then throws
`ArrayIndexOutOfBoundsException` at ID 32769: the signed short is -32767,
whose remainder modulo 16 is -15. The counter increment is never reached.

With the fix, all three boundary IDs succeed. Seventeen outstanding nonces
across that boundary evict the oldest ID (`9c47`). ID 65535 succeeds; the next
request takes the existing overflow path (`9c46`), clears valid IDs, rotates
the MAC key (the previous encrypted nonce is rejected with `9c44`), and restarts
at ID 1. These assertions use the applet's actual state and handlers, rather
than reimplementing the indexing expression in the test.
