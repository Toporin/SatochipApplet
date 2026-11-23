package org.satochip.applet;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Checks Secp256k1.reduceModP() against BigInteger. It is a pure function on byte arrays, so it is
 * called directly rather than through an APDU: on the simulator, isOnCurve() never reaches it
 * (JCardEngine has no RSA squaring, see SatochipBenchmark), and on a card only the yes/no answer of
 * isOnCurve() is visible.
 */
@DisplayName("Secp256k1 fast reduction modulo p")
public class Secp256k1ReduceTest {

  private static final BigInteger P = new BigInteger(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
  private static final BigInteger TWO_512 = BigInteger.ONE.shiftLeft(512);

  /** Reduces x (< 2^512) with reduceModP, at a non-zero offset, and checks it against x mod p. */
  private static void check(BigInteger x) {
    final int offset = 7;
    byte[] buffer = new byte[offset + 64 + 5];
    Arrays.fill(buffer, (byte) 0xA5); // the bytes around the operand must be left untouched
    System.arraycopy(fixed(x, 64), 0, buffer, offset, 64);

    Secp256k1.reduceModP(buffer, (short) offset);

    byte[] expected = new byte[offset + 64 + 5];
    Arrays.fill(expected, (byte) 0xA5);
    Arrays.fill(expected, offset, offset + 32, (byte) 0);
    System.arraycopy(fixed(x.mod(P), 32), 0, expected, offset + 32, 32);
    assertArrayEquals(expected, buffer, "reduceModP(" + x.toString(16) + ")");
  }

  /** Big-endian, unsigned, left-padded to size bytes. */
  private static byte[] fixed(BigInteger x, int size) {
    byte[] raw = x.toByteArray();
    byte[] out = new byte[size];
    int n = Math.min(raw.length, size);
    System.arraycopy(raw, raw.length - n, out, size - n, n);
    return out;
  }

  @Test
  @DisplayName("Edge values around 0, p, 2^256, p^2 and 2^512")
  void edgeValues() {
    BigInteger two256 = BigInteger.ONE.shiftLeft(256);
    BigInteger[] values = {
        BigInteger.ZERO, BigInteger.ONE, BigInteger.valueOf(7),
        P.subtract(BigInteger.ONE), P, P.add(BigInteger.ONE),
        two256.subtract(BigInteger.ONE), two256, two256.add(BigInteger.ONE),
        P.shiftLeft(1), P.shiftLeft(1).subtract(BigInteger.ONE),
        P.multiply(P), P.subtract(BigInteger.ONE).pow(2), P.multiply(P).subtract(BigInteger.ONE),
        // needs the third fold: H*c + L = 2^257 - 1, then c + 2^256 - 1 >= 2^256 again
        thirdFoldValue(),
        two256.subtract(BigInteger.ONE).multiply(two256.subtract(BigInteger.ONE)),
        TWO_512.subtract(BigInteger.ONE),
    };
    for (BigInteger v : values) {
      check(v.mod(TWO_512));
    }
  }

  /** x = H*2^256 + L with H*c + L = 2^257 - 1 (c = 2^256 - p), L < c. */
  private static BigInteger thirdFoldValue() {
    BigInteger two256 = BigInteger.ONE.shiftLeft(256);
    BigInteger c = two256.subtract(P);
    BigInteger target = BigInteger.ONE.shiftLeft(257).subtract(BigInteger.ONE);
    BigInteger h = target.divide(c);
    BigInteger l = target.subtract(h.multiply(c));
    return h.shiftLeft(256).add(l);
  }

  @Test
  @DisplayName("Products of field elements, as isOnCurve() computes them")
  void randomProducts() {
    Random rng = new Random(0x5A70C819L);
    for (int i = 0; i < 20000; i++) {
      BigInteger a = new BigInteger(256, rng).mod(P);
      BigInteger b = new BigInteger(256, rng).mod(P);
      check(a.multiply(b));
    }
  }

  @Test
  @DisplayName("Arbitrary 512-bit values, including those with many 0xFF bytes")
  void randomWideValues() {
    Random rng = new Random(0x0DDBA11L);
    for (int i = 0; i < 20000; i++) {
      check(new BigInteger(512, rng));
    }
    // dense values maximize every column of the fold, hence the carries
    for (int i = 0; i < 2000; i++) {
      byte[] x = new byte[64];
      for (int j = 0; j < 64; j++) {
        x[j] = rng.nextInt(4) == 0 ? (byte) rng.nextInt(256) : (byte) 0xFF;
      }
      check(new BigInteger(1, x));
    }
  }

  @Test
  @DisplayName("Valid and invalid points are classified as by the curve equation")
  void curveEquationMatchesBigInteger() {
    // isOnCurve() itself needs the RSA engine; check here that the reduced terms it compares,
    // y^2 and x^3 + 7 mod p, are what reduceModP() produces from the same products
    Random rng = new Random(42);
    for (int i = 0; i < 2000; i++) {
      BigInteger x = new BigInteger(256, rng).mod(P);
      BigInteger y = new BigInteger(256, rng).mod(P);
      byte[] y2 = fixed(y.multiply(y), 64);
      Secp256k1.reduceModP(y2, (short) 0);
      byte[] x2 = fixed(x.multiply(x), 64);
      Secp256k1.reduceModP(x2, (short) 0);
      byte[] x3 = fixed(new BigInteger(1, Arrays.copyOfRange(x2, 32, 64)).multiply(x), 64);
      Secp256k1.reduceModP(x3, (short) 0);
      assertEquals(y.multiply(y).mod(P), new BigInteger(1, Arrays.copyOfRange(y2, 32, 64)));
      assertEquals(x.pow(3).mod(P), new BigInteger(1, Arrays.copyOfRange(x3, 32, 64)));
    }
  }
}
