package org.satochip.applet;

import org.bouncycastle.util.encoders.Hex;

/**
 * Pinned test vectors.
 *
 * <p>These are deliberately duplicated here rather than shared with pysatochip: the point of an
 * independent vector set is that a mistake in one repository's copy does not silently propagate to
 * the other. Keep them in sync by hand when the upstream specifications change.
 */
public final class Vectors {
  private Vectors() {}

  // ---------------------------------------------------------------------------------------------
  // BIP32 -- test vector 1 from the specification
  // https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#test-vector-1
  // ---------------------------------------------------------------------------------------------

  public static final byte[] BIP32_SEED = Hex.decode("000102030405060708090a0b0c0d0e0f");

  /** Chain m -- serialized public key, compressed. */
  public static final byte[] BIP32_M_PUBKEY =
      Hex.decode("0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2");

  /** Chain m/0' -- serialized public key, compressed. */
  public static final byte[] BIP32_M_0H_PUBKEY =
      Hex.decode("035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56");

  /** Chain m/0'/1 -- serialized public key, compressed. */
  public static final byte[] BIP32_M_0H_1_PUBKEY =
      Hex.decode("03501e454bf00751f24b1b489aa925215d66af2234e3891c3b21a52bedb3cd711c");

  /** Chain m/0'/1/2' -- serialized public key, compressed. */
  public static final byte[] BIP32_M_0H_1_2H_PUBKEY =
      Hex.decode("0357bfe1e341d01c69fe5654309956cbea516822fba8a601743a012a7896ee8dc2");

  /** Chain m/0'/1/2'/2 -- serialized public key, compressed. */
  public static final byte[] BIP32_M_0H_1_2H_2_PUBKEY =
      Hex.decode("02e8445082a72f29b75ca48748a914df60622a609cacfce8ed0e35804560741d29");

  /** Chain m/0'/1/2'/2/1000000000 -- serialized public key, compressed. */
  public static final byte[] BIP32_M_0H_1_2H_2_1000000000_PUBKEY =
      Hex.decode("022a471424da5e657499d1ff51cb43c47481a03b1e77f951fe64cec9f5a48f7011");

  // ---------------------------------------------------------------------------------------------
  // secp256k1 domain parameters, for the in-test BIP340 verifier
  // ---------------------------------------------------------------------------------------------

  public static final java.math.BigInteger SECP256K1_P = new java.math.BigInteger(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
  public static final java.math.BigInteger SECP256K1_N = new java.math.BigInteger(
      "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
}
