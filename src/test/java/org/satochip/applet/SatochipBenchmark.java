package org.satochip.applet;

import javacard.framework.AID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.satochip.desktop.PCSCCardChannel;
import org.satochip.io.APDUResponse;
import pro.javacard.engine.JavaCardEngine;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.satochip.applet.SatochipTest.*;

/**
 * Times the Schnorr and MuSig2 signing commands, plus two control commands, on the applet that is
 * currently installed on the card. Nothing is installed first, so that CAPs built from different
 * commits can be compared (see scripts/benchmark-commits.sh). Run with {@code ./gradlew benchmarkCard}.
 *
 * <p>Each APDU is timed individually with {@link System#nanoTime()} around the secure channel
 * round trip, after untimed warm-up rounds. The control commands (ECDSA signing, GET RANDOM) do
 * not use the code under test: if they differ between two runs, the measurement setup is drifting.
 *
 * <p>Results go to {@code <out>/<label>.csv} ({@code label,operation,iteration,micros}) and a
 * summary is printed. On the simulator target, this only checks that the harness works.
 */
@Tag("benchmark")
@DisplayName("Benchmark the Satochip applet")
public class SatochipBenchmark {

  private final String label = System.getProperty("org.satochip.bench.label", "current");
  private final int iterations = Integer.getInteger("org.satochip.bench.iterations", 50);
  private final int warmup = Integer.getInteger("org.satochip.bench.warmup", 5);
  private final File outDir = new File(System.getProperty("org.satochip.bench.out", "build/benchmark"));
  private final boolean simulator =
      "simulator".equals(System.getProperty("org.satochip.test.target", "card"));

  /** operation -> samples in microseconds, in insertion order */
  private final Map<String, List<Long>> samples = new LinkedHashMap<>();

  private TestSatochipCommandSet cmdSet;

  @Test
  @DisplayName("Time Schnorr, MuSig2 and control commands")
  void benchmark() throws Exception {
    Security.addProvider(new BouncyCastleProvider());
    cmdSet = new TestSatochipCommandSet(openChannel());
    cmdSet.setLoggerLevel(java.util.logging.Level.SEVERE);
    cmdSet.cardSelect().checkOK();
    prepare();

    // Schnorr: the tweaked key is staged once, as a wallet does to sign several inputs
    byte[] tweak = ok(cmdSet.sendRawSecure(INS_TAPROOT_TWEAK_PRIVKEY, 0xFF, 0x00, new byte[]{0x00}), "taproot tweak");
    byte[] tweakedPubkey = Arrays.copyOfRange(tweak, 2, 2 + 65);
    byte[] hash = sha256("satochip benchmark".getBytes());
    byte[] sig = ok(cmdSet.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00, hash), "Schnorr signature");
    assertTrue(verifyBip340(tweakedPubkey, hash, sig), "the Schnorr signature does not verify");
    for (int i = -warmup; i < iterations; i++) {
      time("schnorr_sign", i, () -> cmdSet.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00, hash));
    }

    // MuSig2: nonce generation then partial signature, as in musig2PartialSignatureTest
    BigInteger n = Vectors.SECP256K1_N;
    byte[] b = bytes32(new BigInteger(1, sha256("musig2 b".getBytes())).mod(n));
    byte[] ea = bytes32(new BigInteger(1, sha256("musig2 ea".getBytes())).mod(n));
    byte[] finalizeData = concat(b, ea, new byte[]{0x00, 0x01});
    for (int i = -warmup; i < iterations; i++) {
      time("musig2_nonce_init", i, () -> cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_INIT,
          new byte[]{0x00, (byte) 0xFF, 0x00}));
      byte[] secnonce = time("musig2_nonce_final", i,
          () -> cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_FINALIZE, new byte[0]));
      time("musig2_sign_init", i, () -> cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_INIT, secnonce));
      byte[] psig = time("musig2_sign_final", i,
          () -> cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_FINALIZE, finalizeData));
      assertEquals(32, psig.length, "a MuSig2 partial signature is 32 bytes");
    }

    // controls: not affected by the blinded Schnorr/MuSig2 arithmetic
    for (int i = -warmup; i < iterations; i++) {
      time("ecdsa_sign (control)", i, () -> cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00, hash));
    }
    for (int i = -warmup; i < iterations; i++) {
      time("get_random (control)", i, () -> cmdSet.sendRawSecure(INS_GET_RANDOM, 32, 0x00, new byte[0]));
    }

    report();
  }

  /** Brings the card to a set-up, seeded, authenticated state, with a derived BIP32 key. */
  private void prepare() {
    if (!isSetupDone(cmdSet)) {
      setupCard(cmdSet);
    }
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw(),
        "VERIFY PIN failed: the card must use the test PIN " + new String(PIN));
    if (!isSeeded(cmdSet)) {
      assertEquals(SW_OK, cmdSet.cardBip32ImportSeed(Vectors.BIP32_SEED).getSw(), "could not seed the card");
    }
    cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/0");
  }

  private interface Apdu {
    APDUResponse send();
  }

  /** Sends one APDU, records its duration unless it is a warm-up round (i < 0), checks 0x9000. */
  private byte[] time(String operation, int i, Apdu apdu) {
    long start = System.nanoTime();
    APDUResponse response = apdu.send();
    long micros = (System.nanoTime() - start) / 1000;
    byte[] data = ok(response, operation);
    if (i >= 0) {
      samples.computeIfAbsent(operation, k -> new ArrayList<>()).add(micros);
    }
    return data;
  }

  private static byte[] ok(APDUResponse response, String what) {
    assertEquals(SW_OK, response.getSw(),
        what + " failed with SW " + Integer.toHexString(response.getSw()));
    return response.getData();
  }

  private void report() throws IOException {
    outDir.mkdirs();
    File csv = new File(outDir, label + ".csv");
    try (PrintWriter w = new PrintWriter(new FileWriter(csv))) {
      w.println("label,operation,iteration,micros");
      for (Map.Entry<String, List<Long>> e : samples.entrySet()) {
        List<Long> s = e.getValue();
        for (int i = 0; i < s.size(); i++) {
          w.println(label + "," + e.getKey() + "," + i + "," + s.get(i));
        }
      }
    }

    System.out.println();
    System.out.println("Benchmark '" + label + "' (" + iterations + " iterations, " + warmup + " warm-up)"
        + (simulator ? " -- SIMULATOR: timings are meaningless, harness check only" : ""));
    System.out.println(String.format(Locale.ROOT, "%-22s %5s %9s %9s %9s %9s %9s",
        "operation (ms)", "n", "min", "median", "mean", "p90", "stddev"));
    for (Map.Entry<String, List<Long>> e : samples.entrySet()) {
      List<Long> s = new ArrayList<>(e.getValue());
      Collections.sort(s);
      double mean = s.stream().mapToLong(Long::longValue).average().orElse(0);
      double var = s.stream().mapToDouble(v -> (v - mean) * (v - mean)).sum() / Math.max(1, s.size() - 1);
      System.out.println(String.format(Locale.ROOT, "%-22s %5d %9.2f %9.2f %9.2f %9.2f %9.2f",
          e.getKey(), s.size(), s.get(0) / 1000.0, percentile(s, 50) / 1000.0, mean / 1000.0,
          percentile(s, 90) / 1000.0, Math.sqrt(var) / 1000.0));
    }
    System.out.println("Samples written to " + csv.getAbsolutePath());
  }

  /** Nearest-rank percentile of sorted samples. */
  private static double percentile(List<Long> sorted, int p) {
    int rank = (int) Math.ceil(p / 100.0 * sorted.size());
    return sorted.get(Math.max(0, rank - 1));
  }

  private org.satochip.io.CardChannel openChannel() throws Exception {
    TerminalFactory tf;
    if (simulator) {
      JavaCardEngine engine = JavaCardEngine.create();
      engine.installApplet(aid(SATOCHIP_INSTANCE_AID), Satochip.class);
      tf = engine.toTerminalFactory();
    } else {
      tf = TerminalFactory.getDefault();
    }
    CardTerminal terminal = null;
    for (CardTerminal t : tf.terminals().list()) {
      if (t.isCardPresent()) {
        terminal = t;
        break;
      }
    }
    assertNotNull(terminal, "No card found in any reader");
    Card card = terminal.connect("*");
    System.out.println("Benchmarking on " + terminal.getName()
        + ", ATR " + Hex.toHexString(card.getATR().getBytes()));
    return new PCSCCardChannel(card.getBasicChannel());
  }

  private static AID aid(byte[] bytes) {
    return new AID(bytes, (short) 0, (byte) bytes.length);
  }
}
