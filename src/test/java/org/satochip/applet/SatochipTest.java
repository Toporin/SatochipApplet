package org.satochip.applet;

import javacard.framework.AID;
import org.bitcoinj.crypto.ChildNumber;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.*;
import org.satochip.desktop.PCSCCardChannel;
import org.satochip.io.APDUCommand;
import org.satochip.io.APDUResponse;
import pro.javacard.engine.JavaCardEngine;

import javax.smartcardio.Card;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;
import java.security.MessageDigest;
import java.security.Security;
import java.security.Signature;
import java.util.Arrays;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

/**
 * APDU-level test suite for the Satochip applet.
 *
 * <p>The applet has no test hooks: everything here goes over the APDU interface exactly as a real
 * client would, which is what lets the same suite run against the JCardEngine simulator or a
 * physical card. Pick the target with {@code -Porg.satochip.test.target=simulator|card}; the
 * default is {@code card}, and CI uses {@code simulator}.
 *
 * <p><b>Shared-card model.</b> Like Keycard's suite, the card is set up once and reused: a factory
 * reset on applet versions before v0.16 required physically removing and reinserting the card, so
 * per-test reinstallation is not an option on hardware. Every test must therefore leave the card
 * in the agreed baseline state (set up, PIN = {@link #PIN}, all feature policies enabled) and
 * {@link #tearDown()} re-verifies the PIN so the next test starts authenticated.
 *
 * <p>For the same reason nothing here ever sets a policy to BLOCKED or blocks the PUK: those are
 * irreversible without a factory reset and would poison the rest of the run.
 */
@DisplayName("Test the Satochip Applet")
@TestMethodOrder(MethodOrderer.MethodName.class)
public class SatochipTest {

  // --- applet constants, mirrored from Satochip.java -------------------------------------------
  static final byte INS_GET_RANDOM = (byte) 0x30;
  static final byte INS_SETUP = (byte) 0x2A;
  static final byte INS_GET_STATUS = (byte) 0x3C;
  static final byte INS_CARD_LABEL = (byte) 0x3D;
  static final byte INS_SET_NDEF = (byte) 0x3F;
  static final byte INS_SET_FEATURE_POLICY = (byte) 0x3A;
  static final byte INS_VERIFY_PIN = (byte) 0x42;
  static final byte INS_CHANGE_PIN = (byte) 0x44;
  static final byte INS_UNBLOCK_PIN = (byte) 0x46;
  static final byte INS_LOGOUT_ALL = (byte) 0x60;
  static final byte INS_BIP32_IMPORT_SEED = (byte) 0x6C;
  static final byte INS_BIP32_GET_EXTENDED_KEY = (byte) 0x6D;
  static final byte INS_SIGN_TRANSACTION_HASH = (byte) 0x7A;
  static final byte INS_SIGN_SCHNORR_HASH = (byte) 0x7B;
  static final byte INS_TAPROOT_TWEAK_PRIVKEY = (byte) 0x7C;
  static final byte INS_LIST_PINS = (byte) 0x48;
  static final byte INS_CREATE_PIN = (byte) 0x40;

  static final int SW_OK = 0x9000;
  static final int SW_UNAUTHORIZED = 0x9C06;
  static final int SW_SETUP_ALREADY_DONE = 0x9C07;
  static final int SW_INVALID_PARAMETER = 0x9C0F;
  static final int SW_IDENTITY_BLOCKED = 0x9C0C;
  static final int SW_INCORRECT_P1 = 0x9C10;
  static final int SW_INCORRECT_P2 = 0x9C11;
  static final int SW_SECURE_CHANNEL_REQUIRED = 0x9C20;
  static final int SW_INS_DEPRECATED = 0x9C26;
  static final int SW_FEATURE_DISABLED = 0x9C4A;

  static final byte FEATURE_ENABLED = 0;
  static final byte FEATURE_DISABLED = 1;
  static final byte FEATURE_ID_RANDOM = 4;

  static final byte[] SATOCHIP_INSTANCE_AID = Hex.decode("5361746F4368697000");
  static final byte[] NDEF_INSTANCE_AID = Hex.decode("D2760000850101");

  // --- baseline credentials, restored by every test that touches them --------------------------
  static final byte[] PIN = "1234".getBytes();
  static final byte[] PUK = Hex.decode("0011223344556677");

  private static final int TARGET_SIMULATOR = 0;
  private static final int TARGET_CARD = 1;
  private static final int TARGET;

  static {
    String t = System.getProperty("org.satochip.test.target", "card");
    switch (t) {
      case "simulator": TARGET = TARGET_SIMULATOR; break;
      case "card":      TARGET = TARGET_CARD; break;
      default: throw new RuntimeException("Unknown test target: " + t);
    }
    Security.addProvider(new BouncyCastleProvider());
  }

  private static JavaCardEngine engine;
  private static CardTerminal cardTerminal;
  private static org.satochip.io.CardChannel sdkChannel;
  private static javax.smartcardio.CardChannel rawChannel;

  private TestSatochipCommandSet cmdSet;

  // =============================================================================================
  // Lifecycle
  // =============================================================================================

  @BeforeAll
  static void initAll() throws Exception {
    if (TARGET == TARGET_SIMULATOR) {
      openSimulatorChannel();
    } else {
      openCardChannel();
    }

    TestSatochipCommandSet boot = new TestSatochipCommandSet(sdkChannel);
    boot.setLoggerLevel("SEVERE");
    boot.cardSelect().checkOK();

    if (!isSetupDone(boot)) {
      if (TARGET == TARGET_SIMULATOR) {
        // personalization is only possible before setup: give the simulator a certificate, like
        // a real card gets at the factory, so that the certificate export can be tested
        importTestCertificate(boot);
      }
      setupCard(boot);
    }
    boot.setPin0(PIN);
    boot.cardVerifyPIN(PIN);

    if (!isSeeded(boot)) {
      assertEquals(SW_OK, boot.cardBip32ImportSeed(Vectors.BIP32_SEED).getSw(),
          "could not seed the card for the test run");
    }

    detectCapabilities(boot);
  }

  private static void openSimulatorChannel() throws Exception {
    engine = JavaCardEngine.create();
    engine.installApplet(aid(SATOCHIP_INSTANCE_AID), Satochip.class);
    // The NDEF applet takes its record from the install parameters; empty means "keep the
    // default compiled into SharedMemory".
    engine.installApplet(aid(NDEF_INSTANCE_AID), NDEFApplet.class, new byte[0]);

    TerminalFactory tf = engine.toTerminalFactory();
    cardTerminal = tf.terminals().list().get(0);
    openPCSCChannel();
  }

  private static void openCardChannel() throws Exception {
    TerminalFactory tf = TerminalFactory.getDefault();
    for (CardTerminal t : tf.terminals().list()) {
      if (t.isCardPresent()) {
        cardTerminal = t;
        break;
      }
    }
    assertNotNull(cardTerminal, "No card found in any reader");
    openPCSCChannel();
  }

  private static void openPCSCChannel() throws Exception {
    Card card = cardTerminal.connect("*");
    rawChannel = card.getBasicChannel();
    sdkChannel = new PCSCCardChannel(rawChannel);
  }

  private static AID aid(byte[] bytes) {
    return new AID(bytes, (short) 0, (byte) bytes.length);
  }

  private static void setupCard(TestSatochipCommandSet cmd) {
    byte[] unusedPin1 = new byte[8];
    byte[] unusedPuk1 = new byte[8];
    APDUResponse r = cmd.cardSetup(
        (byte) 5, (byte) 5, PIN, PUK,
        (byte) 1, (byte) 1, unusedPin1, unusedPuk1);
    assertEquals(SW_OK, r.getSw(), "card setup failed");
  }

  /**
   * Probes the optional capabilities of the target. Feature policies come from GET_STATUS; the RSA
   * multiplication trick has to be probed behaviourally, because reading
   * {@code Biginteger.FLAG_FAST_MULT_VIA_RSA} reflectively would inspect this JVM's copy of the
   * class rather than the one the simulator loaded in its own ClassLoader.
   */
  private static void detectCapabilities(TestSatochipCommandSet cmd) {
    HashSet<String> caps = new HashSet<>();
    byte[] status = cmd.cardGetStatus().getData();
    if (status.length > 17) {
      if (status[13] == FEATURE_ENABLED) caps.add("schnorr");
      if (status[14] == FEATURE_ENABLED) caps.add("nostr");
      if (status[15] == FEATURE_ENABLED) caps.add("liquid");
      if (status[16] == FEATURE_ENABLED) caps.add("musig2");
      if (status[17] == FEATURE_ENABLED) caps.add("random");
    }

    // A taproot tweak is the cheapest command that goes through Biginteger.mult_rsa_trick().
    cmd.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/0");
    APDUResponse tweak = cmd.sendRawSecure(INS_TAPROOT_TWEAK_PRIVKEY, 0xFF, 0x00, new byte[]{0x00});
    if (tweak.getSw() == SW_OK) {
      APDUResponse sig = cmd.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00, new byte[32]);
      if (sig.getSw() == SW_OK) caps.add("rsaMult");
    }

    FeaturePolicyCondition.availableCapabilities = caps;
  }

  static final byte INS_IMPORT_PKI_CERTIFICATE = (byte) 0x92;
  static final byte INS_EXPORT_PKI_CERTIFICATE = (byte) 0x93;
  /** Test certificate for the simulator, larger than the largest chunk the secure channel can return. */
  static final byte[] TEST_CERTIFICATE = new byte[300];
  static {
    for (int i = 0; i < TEST_CERTIFICATE.length; i++) TEST_CERTIFICATE[i] = (byte) (i * 7);
  }

  private static void importTestCertificate(TestSatochipCommandSet cmd) {
    int size = TEST_CERTIFICATE.length;
    assertEquals(SW_OK, cmd.sendRawSecure(INS_IMPORT_PKI_CERTIFICATE, 0x00, 0x01,
        new byte[]{(byte) (size >> 8), (byte) size}).getSw());
    for (int off = 0; off < size; off += 128) {
      int len = Math.min(128, size - off);
      byte[] data = concat(new byte[]{(byte) (off >> 8), (byte) off, (byte) (len >> 8), (byte) len},
          Arrays.copyOfRange(TEST_CERTIFICATE, off, off + len));
      assertEquals(SW_OK, cmd.sendRawSecure(INS_IMPORT_PKI_CERTIFICATE, 0x00, 0x02, data).getSw(),
          "could not import the test certificate");
    }
  }

  private static boolean isSetupDone(TestSatochipCommandSet cmd) {
    byte[] status = cmd.cardGetStatus().getData();
    return status.length > 10 && status[10] == 0x01;
  }

  private static boolean isSeeded(TestSatochipCommandSet cmd) {
    byte[] status = cmd.cardGetStatus().getData();
    return status.length > 9 && status[9] == 0x01;
  }

  @BeforeEach
  void init() throws Exception {
    cmdSet = new TestSatochipCommandSet(sdkChannel);
    cmdSet.setLoggerLevel("SEVERE");
    // Selecting the applet clears PIN validation, so every test starts by re-authenticating over
    // a fresh secure channel. Tests therefore begin from an identical, authenticated state.
    cmdSet.cardSelect().checkOK();
    cmdSet.setPin0(PIN);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw(),
        "the PIN is no longer " + new String(PIN) + "; a previous test did not restore it");
  }

  @AfterEach
  void tearDown() {
    // Guard the shared-card contract: whatever the test did, the baseline credentials must survive.
    cmdSet.forgetSecureChannel();
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw(),
        "the PIN is no longer " + new String(PIN) + "; this test did not restore it");
  }

  // =============================================================================================
  // Tier 1 -- security boundaries
  // =============================================================================================

  @Test
  @DisplayName("SELECT returns the card status")
  void selectTest() throws Exception {
    APDUResponse r = cmdSet.cardSelect();
    assertEquals(SW_OK, r.getSw());
    byte[] data = r.getData();
    assertTrue(data.length >= 18, "SELECT should return the GET_STATUS payload, got " + data.length);
    assertEquals(0x01, data[10], "card should report setup done");
  }

  @Test
  @DisplayName("GET STATUS reports the expected fields")
  void getStatusTest() {
    byte[] s = cmdSet.cardGetStatus().getData();
    assertEquals(18, s.length, "GET_STATUS payload length");
    assertEquals(0x00, s[0], "protocol major version");
    assertEquals(0x10, s[1], "protocol minor version (0.16)");
    assertEquals(5, s[4], "PIN tries remaining should be back at the maximum");
    assertEquals(0x01, s[10], "setup done");
    assertEquals(0x01, s[11], "secure channel is always enabled");
    for (int i = 13; i <= 17; i++) {
      assertEquals(FEATURE_ENABLED, s[i],
          "feature policy at offset " + i + " should be enabled in the baseline state");
    }
  }

  @Test
  @DisplayName("Secure channel is mandatory for all but three commands")
  void secureChannelRequiredTest() {
    // Exempt in plaintext: GET_STATUS (0x3C), INIT (0x81) and PROCESS (0x82) secure channel.
    assertEquals(SW_OK, cmdSet.sendRawPlain(INS_GET_STATUS, 0x00, 0x00, new byte[0]).getSw());

    // Everything else must be refused before it is even parsed.
    int[] gated = {INS_CARD_LABEL, INS_SET_NDEF, INS_GET_RANDOM, INS_VERIFY_PIN,
                   INS_CHANGE_PIN, INS_BIP32_GET_EXTENDED_KEY, INS_SIGN_TRANSACTION_HASH,
                   INS_SET_FEATURE_POLICY};
    for (int ins : gated) {
      assertEquals(SW_SECURE_CHANNEL_REQUIRED,
          cmdSet.sendRawPlain(ins, 0x00, 0x00, new byte[0]).getSw(),
          String.format("INS 0x%02X should require the secure channel", ins));
    }
  }

  @Test
  @DisplayName("The decrypted inner command is re-validated (CLA, Lc)")
  void secureChannelInnerApduTest() {
    final int SW_CLA_NOT_SUPPORTED = 0x6E00;
    final int SW_WRONG_LENGTH = 0x6700;
    byte cla = TestSatochipCommandSet.CLA;

    // well-formed: GET RANDOM, 8 bytes
    assertEquals(SW_OK, cmdSet.sendRawSecureBytes(new byte[]{cla, INS_GET_RANDOM, 8, 0, 0}).getSw());
    // a trailing Le byte is tolerated
    assertEquals(SW_OK, cmdSet.sendRawSecureBytes(new byte[]{cla, INS_GET_RANDOM, 8, 0, 0, 0}).getSw());

    // the inner CLA must be the applet's
    assertEquals(SW_CLA_NOT_SUPPORTED,
        cmdSet.sendRawSecureBytes(new byte[]{0x00, INS_GET_RANDOM, 8, 0, 0}).getSw());

    // Lc must not point past the decrypted data. The card does not strip the PKCS#7 padding, so
    // the bound is the padded size: a 32-byte plaintext is padded to 48 bytes.
    byte[] inner = new byte[32];
    inner[0] = cla; inner[1] = INS_GET_RANDOM; inner[2] = 8;
    inner[4] = (byte) (48 - 5);
    assertEquals(SW_OK, cmdSet.sendRawSecureBytes(inner).getSw(), "Lc up to the padded size is accepted");
    inner[4] = (byte) (48 - 5 + 1);
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawSecureBytes(inner).getSw(), "one byte past is refused");
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawSecureBytes(
        new byte[]{cla, INS_GET_RANDOM, 8, 0, (byte) 200, 1, 2, 3}).getSw());

    // Lc >= 128 is read unsigned and accepted: a 130-byte CARD LABEL reaches the handler,
    // which refuses the oversized label (no state change)
    byte[] label = new byte[130];
    label[0] = 100;
    assertEquals(SW_INVALID_PARAMETER, cmdSet.sendRawSecure(INS_CARD_LABEL, 0x00, 0x00, label).getSw());
  }

  @Test
  @DisplayName("Secure channel: wrapped GET STATUS is answered encrypted, IV counter and size checks")
  void secureChannelHardeningTest() throws Exception {
    final int SW_WRONG_LENGTH = 0x6700;
    final int SW_SECURE_CHANNEL_UNINITIALIZED = 0x9C21;
    final int SW_SECURE_CHANNEL_WRONG_IV = 0x9C22;
    final byte INS_PROCESS_SECURE_CHANNEL = (byte) 0x82;

    // a GET STATUS sent through the secure channel is answered through it (it used to come back
    // in cleartext, which the client cannot decrypt)
    byte[] plainStatus = cmdSet.cardGetStatus().getData();
    APDUResponse wrapped = cmdSet.sendRawSecure(INS_GET_STATUS, 0x00, 0x00, new byte[0]);
    assertEquals(SW_OK, wrapped.getSw());
    assertArrayEquals(plainStatus, wrapped.getData());

    // the counter may jump ahead, but no counter at or below the last one is accepted afterwards
    cmdSet.setIvCounter(101);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw());
    cmdSet.setIvCounter(51);
    assertEquals(SW_SECURE_CHANNEL_WRONG_IV, cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw());
    cmdSet.setIvCounter(101);
    assertEquals(SW_SECURE_CHANNEL_WRONG_IV, cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw());

    // the last counter value would wrap the card's counter to 0: the session is closed instead
    resetSession();
    cmdSet.setIvCounter(0xFFFFFFFF);
    assertEquals(SW_SECURE_CHANNEL_WRONG_IV, cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw());
    cmdSet.setIvCounter(3);
    assertEquals(SW_SECURE_CHANNEL_UNINITIALIZED,
        cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw(), "the session must be closed");

    // the ciphertext must be a whole number of AES blocks (checked before the MAC)
    resetSession();
    byte[] iv = new byte[16];
    byte[] mac = concat(new byte[]{0x00, 0x14}, new byte[20]);
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawPlain(INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00,
        concat(iv, new byte[]{0x00, 0x0F}, new byte[15], mac)).getSw());
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawPlain(INS_PROCESS_SECURE_CHANNEL, 0x00, 0x00,
        concat(iv, new byte[]{(byte) 0xFF, (byte) 0xF0}, new byte[16], mac)).getSw());
    resetSession();
  }

  @Test
  @DisplayName("Replaying an encrypted command is rejected")
  void secureChannelReplayTest() throws Exception {
    APDUCommand encrypted = cmdSet.encrypt(INS_GET_RANDOM, 8, 0x00, new byte[0]);
    assertEquals(SW_OK, cmdSet.replay(encrypted).getSw(), "the original command should succeed");
    // The secure channel IV advances with each command, so the same bytes must not pass twice.
    assertNotEquals(SW_OK, cmdSet.replay(encrypted).getSw(),
        "a replayed encrypted APDU must not be accepted");

    // The rejected replay leaves the applet's session in an error state; re-select to clear it
    // on the card as well as in the client, so the next test starts clean.
    resetSession();
  }

  @Test
  @DisplayName("Factory reset requires the PIN (or a blocked PUK), then erases everything")
  void resetToFactoryTest() throws Exception {
    final byte INS_RESET_TO_FACTORY = (byte) 0xFD;
    final int RESET_P1 = 0xAA, RESET_P2 = 0x55;

    // without a validated PIN (and with the PUK not blocked) the reset is refused, and the card
    // is left untouched
    cmdSet.forgetSecureChannel();
    assertEquals(SW_UNAUTHORIZED,
        cmdSet.sendRawSecure(INS_RESET_TO_FACTORY, RESET_P1, RESET_P2, new byte[0]).getSw());
    assertEquals(0x01, cmdSet.cardGetStatus().getData()[9], "the card must still be seeded");
    assertEquals(0x01, cmdSet.cardGetStatus().getData()[10], "the card must still be set up");

    // with the PIN, the magic P1/P2 are still required
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
    assertEquals(0x6A86, cmdSet.sendRawSecure(INS_RESET_TO_FACTORY, RESET_P1, 0x00, new byte[0]).getSw());

    try {
      assertEquals(SW_OK,
          cmdSet.sendRawSecure(INS_RESET_TO_FACTORY, RESET_P1, RESET_P2, new byte[0]).getSw());
      byte[] status = cmdSet.cardGetStatus().getData();
      assertEquals(0x00, status[8], "2FA must be disabled");
      assertEquals(0x00, status[9], "the seed must be erased");
      assertEquals(0x00, status[10], "the card must be back to the not-set-up state");
    } finally {
      // restore the baseline: set up again with the same PIN/PUK, and re-import the seed
      if (cmdSet.cardGetStatus().getData()[10] == 0x00) {
        setupCard(cmdSet);
      }
      resetSession();
      if (cmdSet.cardGetStatus().getData()[9] == 0x00) {
        assertEquals(SW_OK, cmdSet.cardBip32ImportSeed(Vectors.BIP32_SEED).getSw());
      }
    }
  }

  @Test
  @DisplayName("Opening a new secure channel logs the PIN out")
  void secureChannelReinitLogsOutTest() {
    // the PIN was verified in init(); a second channel opened in the same card session (e.g. by
    // another process on the same reader) must not inherit that authentication
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw());
    cmdSet.forgetSecureChannel();
    assertEquals(SW_UNAUTHORIZED, cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw(),
        "a new secure channel must start unauthenticated");
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_GET_RANDOM, 8, 0x00, new byte[0]).getSw());
  }

  @Test
  @DisplayName("VERIFY PIN counts down and resets")
  void verifyPinTest() {
    // Wrong PIN decrements the counter and reports the remaining tries in the low nibble.
    APDUResponse bad = cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, "9999".getBytes());
    assertEquals(0x63C4, bad.getSw(), "wrong PIN should return 0x63Cx with 4 tries left");
    assertEquals(4, cmdSet.cardGetStatus().getData()[4], "status should show 4 tries left");

    // A correct PIN restores the counter.
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
    assertEquals(5, cmdSet.cardGetStatus().getData()[4], "status should show the counter reset");

    // P1 must be 0x00 since v0.16 removed the multi-PIN support.
    assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x01, 0x00, PIN).getSw());
  }

  @Test
  @DisplayName("CHANGE PIN round-trips")
  void changePinTest() {
    byte[] newPin = "4321".getBytes();
    byte[] data = concat(new byte[]{(byte) PIN.length}, PIN, new byte[]{(byte) newPin.length}, newPin);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_CHANGE_PIN, 0x00, 0x00, data).getSw());

    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, newPin).getSw());
    assertEquals(0x63C4, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw(),
        "the old PIN must no longer work");

    // Restore the baseline: the shared-card model requires it.
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, newPin).getSw());
    byte[] back = concat(new byte[]{(byte) newPin.length}, newPin, new byte[]{(byte) PIN.length}, PIN);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_CHANGE_PIN, 0x00, 0x00, back).getSw());
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
  }

  @Test
  @DisplayName("UNBLOCK PIN unblocks a blocked PIN, and can replace it")
  void unblockPinTest() throws Exception {
    // Blocking the PIN is the one thing in this suite that can poison the rest of the run under
    // the shared-card model, so every path out of here goes through the finally block.
    try {
      blockPin();
      assertEquals(SW_IDENTITY_BLOCKED, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw(),
          "even the correct PIN must be refused once blocked");

      // The pre-v0.16 format was a bare PUK with no length prefix. It must be rejected on parse,
      // before the PUK is checked, so it does not burn a PUK try.
      byte puk0Before = cmdSet.cardGetStatus().getData()[5];
      assertEquals(SW_INVALID_PARAMETER,
          cmdSet.sendRawSecure(INS_UNBLOCK_PIN, 0x00, 0x00, PUK).getSw(),
          "the pre-v0.16 bare-PUK format must not be accepted any more");
      assertEquals(puk0Before, cmdSet.cardGetStatus().getData()[5],
          "a malformed unblock must not consume a PUK try");

      // v0.16 format, PUK only: the PIN is unblocked and keeps its value.
      assertEquals(SW_OK,
          cmdSet.sendRawSecure(INS_UNBLOCK_PIN, 0x00, 0x00,
              concat(new byte[]{(byte) PUK.length}, PUK)).getSw());
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw(),
          "the original PIN should work again after unblocking");
      assertEquals(5, cmdSet.cardGetStatus().getData()[4], "the PIN try counter should be restored");

      // v0.16 format, PUK + new PIN: unblock and replace in one command.
      byte[] tempPin = "5678".getBytes();
      blockPin();
      assertEquals(SW_OK,
          cmdSet.sendRawSecure(INS_UNBLOCK_PIN, 0x00, 0x00,
              concat(new byte[]{(byte) PUK.length}, PUK,
                     new byte[]{(byte) tempPin.length}, tempPin)).getSw());
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, tempPin).getSw(),
          "the replacement PIN should be active");

      byte[] back = concat(new byte[]{(byte) tempPin.length}, tempPin,
                           new byte[]{(byte) PIN.length}, PIN);
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_CHANGE_PIN, 0x00, 0x00, back).getSw());
    } finally {
      restoreBaselinePin();
    }
  }

  @Test
  @DisplayName("The SDK picks the UNBLOCK PIN format matching the applet version")
  void unblockPinViaSdkTest() throws Exception {
    // Satochip-Java >= 0.2.6 selects the v0.16 length-prefixed payload from the applet type and
    // the protocol version in GET STATUS. This checks the library and the applet agree.
    assertEquals("satochip", cmdSet.getCardType());
    cmdSet.cardGetStatus();   // populates the cached ApplicationStatus the SDK branches on
    assertTrue(cmdSet.getApplicationStatus().getProtocolVersion() >= 0x0010,
        "this suite targets applet v0.16 or later");

    try {
      blockPin();
      assertEquals(SW_OK, cmdSet.cardUnblockPin(PUK).getSw(),
          "the SDK should unblock a v0.16 Satochip");
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
      assertEquals(5, cmdSet.cardGetStatus().getData()[4]);
    } finally {
      restoreBaselinePin();
    }
  }

  @Test
  @DisplayName("SETUP cannot be run twice")
  void setupAlreadyDoneTest() {
    APDUResponse r = cmdSet.sendRawSecure(INS_SETUP, 0x00, 0x00, new byte[]{0x00});
    assertEquals(SW_SETUP_ALREADY_DONE, r.getSw());
  }

  @Test
  @DisplayName("Removed commands report SW_INS_DEPRECATED")
  void deprecatedCommandsTest() {
    assertEquals(SW_INS_DEPRECATED, cmdSet.sendRawSecure(INS_CREATE_PIN, 0x00, 0x00, new byte[0]).getSw());
    assertEquals(SW_INS_DEPRECATED, cmdSet.sendRawSecure(INS_LIST_PINS, 0x00, 0x00, new byte[0]).getSw());
  }

  @Test
  @DisplayName("A disabled feature policy rejects its command, and can be re-enabled")
  @FeaturePolicies("random")
  void featurePolicyDisableTest() {
    // Never test FEATURE_BLOCKED here: it survives everything short of a factory reset and would
    // poison the rest of the run under the shared-card model.
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_GET_RANDOM, 16, 0x00, new byte[0]).getSw());

    assertEquals(SW_OK,
        cmdSet.sendRawSecure(INS_SET_FEATURE_POLICY, FEATURE_ID_RANDOM, FEATURE_DISABLED, new byte[0]).getSw());
    assertEquals(FEATURE_DISABLED, cmdSet.cardGetStatus().getData()[17]);
    assertEquals(SW_FEATURE_DISABLED,
        cmdSet.sendRawSecure(INS_GET_RANDOM, 16, 0x00, new byte[0]).getSw());

    assertEquals(SW_OK,
        cmdSet.sendRawSecure(INS_SET_FEATURE_POLICY, FEATURE_ID_RANDOM, FEATURE_ENABLED, new byte[0]).getSw());
    assertEquals(FEATURE_ENABLED, cmdSet.cardGetStatus().getData()[17]);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_GET_RANDOM, 16, 0x00, new byte[0]).getSw());
  }

  @Test
  @DisplayName("GET RANDOM honours its length bounds")
  @FeaturePolicies("random")
  void getRandomTest() {
    for (int n : new int[]{1, 32, 64}) {
      APDUResponse r = cmdSet.sendRawSecure(INS_GET_RANDOM, n, 0x00, new byte[0]);
      assertEquals(SW_OK, r.getSw(), "GET_RANDOM should accept " + n + " bytes");
      assertEquals(n, r.getData().length);
    }
    assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_GET_RANDOM, 0, 0x00, new byte[0]).getSw());
    assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_GET_RANDOM, 65, 0x00, new byte[0]).getSw());

    // Two calls must not return the same bytes.
    byte[] a = cmdSet.sendRawSecure(INS_GET_RANDOM, 32, 0x00, new byte[0]).getData();
    byte[] b = cmdSet.sendRawSecure(INS_GET_RANDOM, 32, 0x00, new byte[0]).getData();
    assertFalse(Arrays.equals(a, b), "GET_RANDOM returned identical bytes twice");
  }

  @Test
  @DisplayName("CARD LABEL round-trips")
  void cardLabelTest() {
    byte[] label = "satochip-test".getBytes();
    byte[] data = concat(new byte[]{(byte) label.length}, label);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_CARD_LABEL, 0x00, 0x00, data).getSw());

    APDUResponse r = cmdSet.sendRawSecure(INS_CARD_LABEL, 0x00, 0x01, new byte[0]);
    assertEquals(SW_OK, r.getSw());
    assertEquals(label.length, r.getData()[0]);
    assertArrayEquals(label, Arrays.copyOfRange(r.getData(), 1, 1 + label.length));

    // a label size one byte larger than the label must be refused, not padded with a stale byte
    byte[] truncated = concat(new byte[]{(byte) (label.length + 1)}, label);
    assertEquals(SW_INVALID_PARAMETER, cmdSet.sendRawSecure(INS_CARD_LABEL, 0x00, 0x00, truncated).getSw());
    r = cmdSet.sendRawSecure(INS_CARD_LABEL, 0x00, 0x01, new byte[0]);
    assertEquals(label.length, r.getData()[0], "a refused label must leave the current one unchanged");

    assertEquals(SW_INCORRECT_P2, cmdSet.sendRawSecure(INS_CARD_LABEL, 0x00, 0x7F, new byte[0]).getSw());
  }

  // =============================================================================================
  // NDEF -- the applet command and the NDEF applet that serves the record
  // =============================================================================================

  @Test
  @DisplayName("SET NDEF (0x3F) round-trips and validates its input")
  void cardNdefTest() throws Exception {
    APDUResponse initial = cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x01, new byte[0]);
    assertEquals(SW_OK, initial.getSw());
    byte[] original = initial.getData();
    assertTrue(original.length >= 1);

    // A record whose declared size disagrees with Lc must be refused.
    assertEquals(SW_INVALID_PARAMETER,
        cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x00, new byte[]{0x05, 0x01, 0x02}).getSw());

    // A well-formed record round-trips.
    byte[] record = Hex.decode("0003d00000");           // NLEN(2) + a 3-byte empty NDEF record
    byte[] payload = concat(new byte[]{(byte) record.length}, record);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x00, payload).getSw());

    APDUResponse read = cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x01, new byte[0]);
    assertEquals(SW_OK, read.getSw());
    assertArrayEquals(payload, read.getData(), "the NDEF record should read back unchanged");

    assertEquals(SW_INCORRECT_P2, cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x7F, new byte[0]).getSw());

    // Restore the record the run started with.
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x00, original).getSw());
  }

  @Test
  @DisplayName("NDEF applet serves the shared record over the Type 4 interface")
  void ndefAppletTest() throws Exception {
    // Set a known record through the Satochip applet, then read it back through NDEFApplet, proving
    // SharedMemory really is shared between the two applet instances.
    byte[] record = Hex.decode("0011d1010d55027361746f636869702e696f");  // URI "https://satochip.io"
    byte[] payload = concat(new byte[]{(byte) record.length}, record);
    byte[] original = cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x01, new byte[0]).getData();
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x00, payload).getSw());

    // Raw smartcardio here: the NDEF applet needs case-2 READ BINARY (00 B0 P1 P2 Le), which the
    // SDK's APDUCommand cannot express because it always writes an Lc.
    assertEquals(SW_OK, transmit(0x00, 0xA4, 0x04, 0x00, NDEF_INSTANCE_AID).getSW(),
        "selecting the NDEF instance AID");

    // Capability container, file E103.
    assertEquals(SW_OK, transmit(0x00, 0xA4, 0x00, 0x0C, Hex.decode("E103")).getSW());
    javax.smartcardio.ResponseAPDU caps = transmitLe(0x00, 0xB0, 0x00, 0x00, 0x0F);
    assertEquals(SW_OK, caps.getSW());
    assertEquals(0x20, caps.getData()[2] & 0xff, "CC should declare mapping version 2.0");

    // NDEF data file, E104.
    assertEquals(SW_OK, transmit(0x00, 0xA4, 0x00, 0x0C, Hex.decode("E104")).getSW());
    javax.smartcardio.ResponseAPDU data = transmitLe(0x00, 0xB0, 0x00, 0x00, record.length);
    assertEquals(SW_OK, data.getSW());
    assertArrayEquals(record, data.getData(),
        "the NDEF applet should serve the record written through INS_SET_NDEF");

    // Selecting an unknown file must fail.
    assertEquals(0x6A82, transmit(0x00, 0xA4, 0x00, 0x0C, Hex.decode("E199")).getSW());

    // Put back the original record and re-select the Satochip applet for the next test.
    cmdSet.cardSelect().checkOK();
    cmdSet.forgetSecureChannel();
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_SET_NDEF, 0x00, 0x00, original).getSw());
  }

  // =============================================================================================
  // Tier 2 -- crypto, cross-checked against independent implementations
  // =============================================================================================

  @Test
  @DisplayName("BIP32 derivation matches the specification vectors and bitcoinj")
  void bip32DerivationTest() {
    assertArrayEquals(Vectors.BIP32_M_0H_PUBKEY, compressedPubkey("m/0'"));
    assertArrayEquals(Vectors.BIP32_M_0H_1_PUBKEY, compressedPubkey("m/0'/1"));
    assertArrayEquals(Vectors.BIP32_M_0H_1_2H_PUBKEY, compressedPubkey("m/0'/1/2'"));
    assertArrayEquals(Vectors.BIP32_M_0H_1_2H_2_PUBKEY, compressedPubkey("m/0'/1/2'/2"));
    assertArrayEquals(Vectors.BIP32_M_0H_1_2H_2_1000000000_PUBKEY,
        compressedPubkey("m/0'/1/2'/2/1000000000"));

    // Independent cross-check with bitcoinj over a path not in the pinned vectors.
    DeterministicKey master = HDKeyDerivation.createMasterPrivateKey(Vectors.BIP32_SEED);
    DeterministicKey expected = HDKeyDerivation.deriveChildKey(
        HDKeyDerivation.deriveChildKey(
            HDKeyDerivation.deriveChildKey(master, new ChildNumber(44, true)),
            new ChildNumber(0, true)),
        new ChildNumber(7, false));
    assertArrayEquals(expected.getPubKeyPoint().getEncoded(true), compressedPubkey("m/44'/0'/7"));
  }

  @Test
  @DisplayName("SIGN TRANSACTION HASH produces a verifiable ECDSA signature")
  void signTransactionHashTest() throws Exception {
    byte[] pub = cmdSet.cardBip32GetExtendedKeyRaw("m/44'/0'/0'/0/0");
    byte[] hash = sha256("satochip transaction hash test".getBytes());

    APDUResponse r = cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00,
        concat(hash, new byte[]{0x00, 0x00}));
    assertEquals(SW_OK, r.getSw());
    byte[] der = r.getData();
    assertTrue(der.length > 8 && der[0] == 0x30, "expected a DER-encoded ECDSA signature");

    assertTrue(verifyEcdsa(pub, hash, der), "the card's ECDSA signature should verify");

    // A hash of the wrong length must be refused rather than silently padded.
    assertNotEquals(SW_OK,
        cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00, new byte[16]).getSw());
  }

  @Test
  @DisplayName("Schnorr signing works, and survives a second call")
  @FeaturePolicies({"schnorr", "rsaMult"})
  void signSchnorrHashTest() {
    cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/0");

    // BIP86: key-path-only, so tweak_size = 0.
    APDUResponse tweak = cmdSet.sendRawSecure(INS_TAPROOT_TWEAK_PRIVKEY, 0xFF, 0x00, new byte[]{0x00});
    assertEquals(SW_OK, tweak.getSw());

    // Response: [pubkey_size(2b) | uncompressed pubkey(65b) | sig_size(2b) | authentikey sig]
    byte[] body = tweak.getData();
    int pubkeyLen = ((body[0] & 0xff) << 8) | (body[1] & 0xff);
    assertEquals(65, pubkeyLen, "expected an uncompressed tweaked public key");
    byte[] tweakedPubkey = Arrays.copyOfRange(body, 2, 2 + pubkeyLen);

    byte[] hash = sha256("satochip schnorr test".getBytes());

    APDUResponse first = cmdSet.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00, hash);
    assertEquals(SW_OK, first.getSw());
    assertEquals(64, first.getData().length, "a BIP340 signature is 64 bytes");
    assertTrue(verifyBip340(tweakedPubkey, hash, first.getData()),
        "the first Schnorr signature should verify under the tweaked key");

    // Regression test for the v0.16 fix: SignSchnorrHash used to borrow the tweaked private key as
    // scratch space and never restore it, so every later signature was silently made with the
    // previous signature's nonce as its private key -- well-formed, but not verifiable.
    // The nonce is random, so the two signatures differ; what must hold is that both verify.
    APDUResponse second = cmdSet.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00, hash);
    assertEquals(SW_OK, second.getSw(), "a second Schnorr signature must still work");
    assertEquals(64, second.getData().length);
    assertTrue(verifyBip340(tweakedPubkey, hash, second.getData()),
        "the second Schnorr signature must also verify: if it does not, the tweaked private key "
        + "did not survive the first signature");
  }

  @Test
  @DisplayName("Blinded Schnorr signatures verify for many keys and messages")
  @FeaturePolicies({"schnorr", "rsaMult"})
  void signSchnorrHashManyTest() {
    // s = k + e*d is computed with randomly blinded scalars, twice: exercise many keys (both
    // parities of P, hence both signs of d) and messages (random nonces, both parities of R)
    for (int i = 0; i < 8; i++) {
      cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/" + i);
      APDUResponse tweak = cmdSet.sendRawSecure(INS_TAPROOT_TWEAK_PRIVKEY, 0xFF, 0x00, new byte[]{0x00});
      assertEquals(SW_OK, tweak.getSw());
      byte[] tweakedPubkey = Arrays.copyOfRange(tweak.getData(), 2, 2 + 65);
      for (int j = 0; j < 3; j++) {
        byte[] hash = sha256(("satochip schnorr test " + i + " " + j).getBytes());
        APDUResponse sig = cmdSet.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00, hash);
        assertEquals(SW_OK, sig.getSw());
        assertTrue(verifyBip340(tweakedPubkey, hash, sig.getData()),
            "Schnorr signature " + j + " for key " + i + " does not verify");
      }
    }
  }

  @Test
  @DisplayName("Taproot tweak output key matches BIP341, with and without a merkle root")
  @FeaturePolicies({"schnorr"})
  void taprootTweakVectorTest() {
    // runs without the RSA multiplication trick, so it also covers the BIP340 tagged hash on the simulator
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    byte[] pub = cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/0");
    byte[] px = Arrays.copyOfRange(pub, 1, 33);
    ECPoint p = liftX(spec, new java.math.BigInteger(1, px));
    byte[] merkleRoot = sha256("some merkle root".getBytes());

    for (byte[] h : new byte[][]{new byte[0], merkleRoot}) {
      // Q = lift_x(x(P)) + t*G, with t = tagged_hash("TapTweak", x(P) || h)
      java.math.BigInteger t = new java.math.BigInteger(1, taggedHash("TapTweak", concat(px, h)));
      byte[] expected = p.add(spec.getG().multiply(t)).normalize().getEncoded(false);

      APDUResponse r = cmdSet.sendRawSecure(INS_TAPROOT_TWEAK_PRIVKEY, 0xFF, 0x00,
          concat(new byte[]{(byte) h.length}, h));
      assertEquals(SW_OK, r.getSw());
      // Response: [pubkey_size(2b) | uncompressed pubkey(65b) | sig_size(2b) | authentikey sig]
      assertArrayEquals(expected, Arrays.copyOfRange(r.getData(), 2, 67),
          "tweaked output key, merkle root of " + h.length + " bytes");
    }
  }

  @Test
  @DisplayName("SDK taproot tweak: BIP86 (tweak_size=0) and script-path both verify")
  @FeaturePolicies({"schnorr", "rsaMult"})
  void taprootTweakViaSdkTest() throws Exception {
    cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/0");
    byte[] hash = sha256("satochip taproot sdk test".getBytes());

    // BIP86, key-path-only: tweak_size must be 0. A null tweak expresses that in the SDK from
    // 0.3.3; before that the SDK forced 32 bytes and BIP86 was simply not reachable.
    byte[] bip86Pubkey = cmdSet.cardTaprootTweakPrivateKey(0xFF, null, false);
    assertEquals(65, bip86Pubkey.length);
    byte[] bip86Sig = cmdSet.cardSignSchnorrHash(hash, null);
    assertTrue(verifyBip340(bip86Pubkey, hash, bip86Sig),
        "the BIP86 key-path signature should verify under the tweaked key");

    // Script path: a 32-byte merkle root.
    byte[] merkleRoot = sha256("some merkle root".getBytes());
    byte[] scriptPubkey = cmdSet.cardTaprootTweakPrivateKey(0xFF, merkleRoot, false);
    assertTrue(verifyBip340(scriptPubkey, hash, cmdSet.cardSignSchnorrHash(hash, null)),
        "the script-path signature should verify under the tweaked key");
    assertFalse(Arrays.equals(bip86Pubkey, scriptPubkey),
        "a script-path tweak must produce a different output key than BIP86");

    // BIP341 hashes x(P) alone for tweak_size=0 but x(P) || 32 zero bytes for an all-zero
    // 32-byte tweak, so the two are different keys. A client that sent zeros meaning "no script
    // tree" would derive the wrong address, which is why the SDK must be able to send size 0.
    byte[] zeroTweakPubkey = cmdSet.cardTaprootTweakPrivateKey(0xFF, new byte[32], false);
    assertFalse(Arrays.equals(bip86Pubkey, zeroTweakPubkey),
        "an all-zero 32-byte tweak is not equivalent to tweak_size=0");

    // Lengths other than 0 or 32 are refused client-side, before reaching the card.
    assertThrows(IllegalArgumentException.class,
        () -> cmdSet.cardTaprootTweakPrivateKey(0xFF, new byte[16], false));
  }

  // =============================================================================================
  // Tier 3 -- 2FA and MuSig2
  // =============================================================================================

  static final byte INS_IMPORT_KEY = (byte) 0x32;
  static final byte INS_RESET_KEY = (byte) 0x33;
  static final byte INS_SET_2FA_KEY = (byte) 0x79;
  static final byte INS_RESET_2FA_KEY = (byte) 0x78;
  static final byte INS_MUSIG2_GENERATE_NONCE = (byte) 0x7E;
  static final byte INS_MUSIG2_SIGN_HASH = (byte) 0x7F;
  static final int OP_INIT = 0x01;
  static final int OP_FINALIZE = 0x03;
  static final int SW_WRONG_LENGTH = 0x6700;
  static final int SW_INCORRECT_ALG = 0x9C09;
  static final int SW_SIGNATURE_INVALID = 0x9C0B;
  static final int SW_2FA_INITIALIZED_KEY = 0x9C18;
  static final int SW_ECKEYS_INITIALIZED_KEY = 0x9C1A;
  static final int SW_BIP327_WRONG_SECNONCE = 0x9C44;
  static final int SW_BIP327_PUBKEY_MISMATCH = 0x9C45;
  static final int SW_BIP327_INVALID_ID = 0x9C47;

  static final byte[] KEY_2FA = Hex.decode("00112233445566778899aabbccddeeff01234567");
  static final byte[] SLOT_PRIVKEY =
      Hex.decode("1f2e3d4c5b6a79880123456789abcdef00112233445566778899aabbccddeeff");
  static final int TEST_SLOT = 15;
  static final byte[] HMAC_FLAG_2FA = {(byte) 0x80, 0x00};

  @Test
  @DisplayName("2FA gates hash signing, key import and key reset, and can be removed")
  void twoFactorTest() throws Exception {
    APDUResponse set = cmdSet.sendRawSecure(INS_SET_2FA_KEY, 0x00, 0x00, concat(KEY_2FA, new byte[8]));
    if (set.getSw() == SW_2FA_INITIALIZED_KEY) {
      // left over from an interrupted run of this test: remove it and start again
      reset2FA();
      set = cmdSet.sendRawSecure(INS_SET_2FA_KEY, 0x00, 0x00, concat(KEY_2FA, new byte[8]));
    }
    assertEquals(SW_OK, set.getSw(), "could not enable 2FA");
    try {
      // --- SignTransactionHash: [hash | 0x8000 | hmac(hash | 0xCC*32)]
      byte[] pub = cmdSet.cardBip32GetExtendedKeyRaw("m/44'/0'/0'/0/0");
      byte[] hash = sha256("satochip 2fa test".getBytes());
      assertEquals(SW_WRONG_LENGTH,
          cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00, hash).getSw(),
          "the HMAC is mandatory once 2FA is enabled");
      assertEquals(SW_INCORRECT_ALG, cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00,
          concat(hash, new byte[2], hmac2FA(hash, 0xCC))).getSw());
      assertEquals(SW_SIGNATURE_INVALID, cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00,
          concat(hash, HMAC_FLAG_2FA, hmac2FA(hash, 0xDD))).getSw(),
          "an HMAC made for another operation must be refused");
      APDUResponse sig = cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00,
          concat(hash, HMAC_FLAG_2FA, hmac2FA(hash, 0xCC)));
      assertEquals(SW_OK, sig.getSw());
      assertTrue(verifyEcdsa(pub, hash, sig.getData()));

      // --- ImportKey: hmac(x(P) | (0x10^slot)*32)
      ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
      byte[] slotPub = spec.getG().multiply(new java.math.BigInteger(1, SLOT_PRIVKEY)).normalize().getEncoded(false);
      byte[] slotX = Arrays.copyOfRange(slotPub, 1, 33);
      byte[] blob = concat(new byte[]{0x00, 12, 0x01, 0x00}, new byte[6], new byte[]{0x00, 0x20}, SLOT_PRIVKEY);
      byte[] importHmac = hmac2FA(slotX, 0x10 ^ TEST_SLOT);
      byte[] resetHmac = hmac2FA(slotX, 0x20 ^ TEST_SLOT);
      // start from an empty slot, whatever an interrupted run left there
      int sw = cmdSet.sendRawSecure(INS_IMPORT_KEY, TEST_SLOT, 0x00, concat(blob, importHmac)).getSw();
      assertTrue(sw == SW_OK || sw == SW_ECKEYS_INITIALIZED_KEY, String.format("import: %04X", sw));
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_RESET_KEY, TEST_SLOT, 0x00, resetHmac).getSw());
      assertEquals(SW_SIGNATURE_INVALID,
          cmdSet.sendRawSecure(INS_IMPORT_KEY, TEST_SLOT, 0x00, concat(blob, resetHmac)).getSw());
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_IMPORT_KEY, TEST_SLOT, 0x00, concat(blob, importHmac)).getSw());

      sig = cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, TEST_SLOT, 0x00,
          concat(hash, HMAC_FLAG_2FA, hmac2FA(hash, 0xCC)));
      assertEquals(SW_OK, sig.getSw());
      assertTrue(verifyEcdsa(slotPub, hash, sig.getData()), "the imported key should sign");

      // --- ResetKey: hmac(x(P) | (0x20^slot)*32)
      assertEquals(SW_SIGNATURE_INVALID,
          cmdSet.sendRawSecure(INS_RESET_KEY, TEST_SLOT, 0x00, importHmac).getSw());
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_RESET_KEY, TEST_SLOT, 0x00, resetHmac).getSw());
      assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, TEST_SLOT, 0x00,
          concat(hash, HMAC_FLAG_2FA, hmac2FA(hash, 0xCC))).getSw(), "the slot should be empty again");

      // --- MuSig2: [b | ea | r | g | 0x8000 | hmac(b | 0xEE*32)]
      if (FeaturePolicyCondition.availableCapabilities.contains("musig2")) {
        byte[] secnonce = musig2NewSecnonce("m/86'/0'/0'/0/0");
        byte[] b = sha256("b".getBytes());
        byte[] ctx = concat(b, sha256("ea".getBytes()), new byte[]{0x00, 0x01});
        assertEquals(SW_OK, cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_INIT, secnonce).getSw());
        assertEquals(SW_SIGNATURE_INVALID, cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_FINALIZE,
            concat(ctx, HMAC_FLAG_2FA, hmac2FA(b, 0xCC))).getSw());
        // a failed 2FA attempt must not consume the secnonce id
        sw = cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_FINALIZE,
            concat(ctx, HMAC_FLAG_2FA, hmac2FA(b, 0xEE))).getSw();
        assertNotEquals(SW_BIP327_INVALID_ID, sw);
        assertNotEquals(SW_SIGNATURE_INVALID, sw);
        if (FeaturePolicyCondition.availableCapabilities.contains("rsaMult")) {
          assertEquals(SW_OK, sw);
        }
      }

      // --- SignSchnorrHash: hmac(hash | 0xDD*32)
      if (FeaturePolicyCondition.availableCapabilities.contains("rsaMult")) {
        byte[] tweaked = cmdSet.cardTaprootTweakPrivateKey(0xFF, null, false);
        assertEquals(SW_SIGNATURE_INVALID, cmdSet.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00,
            concat(hash, HMAC_FLAG_2FA, hmac2FA(hash, 0xCC))).getSw());
        APDUResponse schnorr = cmdSet.sendRawSecure(INS_SIGN_SCHNORR_HASH, 0x00, 0x00,
            concat(hash, HMAC_FLAG_2FA, hmac2FA(hash, 0xDD)));
        assertEquals(SW_OK, schnorr.getSw());
        assertTrue(verifyBip340(tweaked, hash, schnorr.getData()));
      }

      // --- resetBIP32Seed: [pin | hmac(authentikey_x | 0xFF*32)], P1 = pin size
      final byte INS_BIP32_RESET_SEED = (byte) 0x77;
      final byte INS_EXPORT_PKI_PUBKEY = (byte) 0x98;
      byte[] authentikey = cmdSet.sendRawSecure(INS_EXPORT_PKI_PUBKEY, 0x00, 0x00, new byte[0]).getData();
      byte[] authentikeyX = Arrays.copyOfRange(authentikey, 1, 33);
      byte[] baselinePub = cmdSet.cardBip32GetExtendedKeyRaw("m/44'/0'/0'/0/0");
      assertEquals(SW_SIGNATURE_INVALID, cmdSet.sendRawSecure(INS_BIP32_RESET_SEED, PIN.length, 0x00,
          concat(PIN, hmac2FA(authentikeyX, 0xAA))).getSw());
      assertTrue(isSeeded(cmdSet), "a refused seed reset must leave the card seeded");
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_BIP32_RESET_SEED, PIN.length, 0x00,
          concat(PIN, hmac2FA(authentikeyX, 0xFF))).getSw());
      assertFalse(isSeeded(cmdSet));
      // a seed reset logs the user out; the seed is re-imported (no 2FA needed for that)
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_BIP32_IMPORT_SEED, Vectors.BIP32_SEED.length, 0x00,
          Vectors.BIP32_SEED).getSw());
      assertArrayEquals(baselinePub, cmdSet.cardBip32GetExtendedKeyRaw("m/44'/0'/0'/0/0"));
    } finally {
      // a failure may have left the session closed or the user logged out
      resetSession();
      if (!isSeeded(cmdSet)) {
        assertEquals(SW_OK, cmdSet.sendRawSecure(INS_BIP32_IMPORT_SEED, Vectors.BIP32_SEED.length, 0x00,
            Vectors.BIP32_SEED).getSw(), "could not restore the baseline seed");
      }
      reset2FA();
    }
    // 2FA is gone: the plain form works again
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, 0xFF, 0x00,
        concat(sha256("x".getBytes()), new byte[2])).getSw());
  }

  @Test
  @DisplayName("MuSig2 secnonces are authenticated, bound to their key and single-use")
  @FeaturePolicies({"musig2"})
  void musig2NonceTest() {
    // Pubnonce format: [R1(33b) | R2(33b) | id(2b)], both R compressed points on secp256k1
    cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/1");
    APDUResponse init = cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_INIT,
        new byte[]{0x00, (byte) 0xFF, 0x00});
    assertEquals(SW_OK, init.getSw());
    assertEquals(68, init.getData().length);
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    spec.getCurve().decodePoint(Arrays.copyOfRange(init.getData(), 0, 33));
    spec.getCurve().decodePoint(Arrays.copyOfRange(init.getData(), 33, 66));
    APDUResponse fin = cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_FINALIZE, new byte[0]);
    assertEquals(SW_OK, fin.getSw());
    assertEquals(144, fin.getData().length);

    // a tampered secnonce is refused, without consuming the id
    byte[] secnonce = fin.getData();
    byte[] tampered = secnonce.clone();
    tampered[5] ^= 0x01;
    byte[] ctx = concat(sha256("b".getBytes()), sha256("ea".getBytes()), new byte[]{0x00, 0x01});
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_INIT, tampered).getSw());
    assertEquals(SW_BIP327_WRONG_SECNONCE,
        cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_FINALIZE, ctx).getSw());

    // the secnonce is bound to the key it was generated for
    cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/2");
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_INIT, secnonce).getSw());
    assertEquals(SW_BIP327_PUBKEY_MISMATCH,
        cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_FINALIZE, ctx).getSw());

    // ... and single-use: the mismatch above already consumed its id
    cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/1");
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_INIT, secnonce).getSw());
    assertEquals(SW_BIP327_INVALID_ID,
        cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_FINALIZE, ctx).getSw());
  }

  @Test
  @DisplayName("MuSig2 partial signatures satisfy the BIP327 verification equation")
  @FeaturePolicies({"musig2", "rsaMult"})
  void musig2PartialSignatureTest() {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    java.math.BigInteger n = Vectors.SECP256K1_N;
    byte[] pub = cmdSet.cardBip32GetExtendedKeyRaw("m/86'/0'/0'/0/3");
    ECPoint p = spec.getCurve().decodePoint(pub);
    java.math.BigInteger b = new java.math.BigInteger(1, sha256("musig2 b".getBytes())).mod(n);
    java.math.BigInteger ea = new java.math.BigInteger(1, sha256("musig2 ea".getBytes())).mod(n);

    // (r_has_odd_y, g*gacc = -1) for each case; both flip the sign of the whole equation
    byte[][] flags = {{0x00, 0x01}, {0x01, 0x00}};
    for (byte[] f : flags) {
      APDUResponse init = cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_INIT,
          new byte[]{0x00, (byte) 0xFF, 0x00});
      assertEquals(SW_OK, init.getSw());
      ECPoint r1 = spec.getCurve().decodePoint(Arrays.copyOfRange(init.getData(), 0, 33));
      ECPoint r2 = spec.getCurve().decodePoint(Arrays.copyOfRange(init.getData(), 33, 66));
      byte[] secnonce = cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_FINALIZE, new byte[0]).getData();

      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_INIT, secnonce).getSw());
      APDUResponse psig = cmdSet.sendRawSecure(INS_MUSIG2_SIGN_HASH, 0xFF, OP_FINALIZE,
          concat(bytes32(b), bytes32(ea), f));
      assertEquals(SW_OK, psig.getSw());
      assertEquals(32, psig.getData().length);

      // psig*G == +/-(R1 + b*R2 + ea*P)
      ECPoint lhs = spec.getG().multiply(new java.math.BigInteger(1, psig.getData())).normalize();
      ECPoint rhs = r1.add(r2.multiply(b)).add(p.multiply(ea));
      if (f[0] == 0x01) rhs = rhs.negate();
      assertEquals(rhs.normalize(), lhs, "partial signature equation, flags " + Hex.toHexString(f));
    }
  }

  @Test
  @DisplayName("Keyslot commands reject out-of-range keyslots, including 0xFF")
  void keyslotRangeTest() {
    final byte INS_GET_PUBLIC_FROM_PRIVATE = (byte) 0x35;
    byte[] blob = concat(new byte[]{0x00, 12, 0x01, 0x00}, new byte[6], new byte[]{0x00, 0x20}, SLOT_PRIVKEY);
    // 0xFF selects the BIP32 extended key for signing commands only: it must never reach a keyslot command
    for (int p1 : new int[]{16, 0x7F, 0x80, 0xFF}) {
      assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_IMPORT_KEY, p1, 0x00, blob).getSw(),
          String.format("IMPORT_KEY, P1=%02X", p1));
      assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_RESET_KEY, p1, 0x00, new byte[0]).getSw(),
          String.format("RESET_KEY, P1=%02X", p1));
      assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_GET_PUBLIC_FROM_PRIVATE, p1, 0x00, new byte[0]).getSw(),
          String.format("GET_PUBLIC_FROM_PRIVATE, P1=%02X", p1));
    }
    for (int p1 : new int[]{16, 0x80}) {
      assertEquals(SW_INCORRECT_P1, cmdSet.sendRawSecure(INS_SIGN_TRANSACTION_HASH, p1, 0x00,
          concat(new byte[32], new byte[2])).getSw(), String.format("SIGN_TRANSACTION_HASH, P1=%02X", p1));
    }
  }

  @Test
  @DisplayName("Encrypted secret import validates the decrypted secret before using it")
  void importEncryptedSecretTest() throws Exception {
    final byte INS_BIP32_RESET_SEED = (byte) 0x77;
    final byte INS_IMPORT_TRUSTED_PUBKEY = (byte) 0xAA;
    final byte INS_IMPORT_ENCRYPTED_SECRET = (byte) 0xAC;
    final byte INS_EXPORT_PKI_PUBKEY = (byte) 0x98;
    final byte TYPE_SEED = 0x10;
    final byte TYPE_2FA = (byte) 0xB0;
    final int SW_SECURE_IMPORT_WRONG_MAC = 0x9C33;
    final int SW_UNSUPPORTED_FEATURE = 0x9C05;

    // play the SeedKeeper: the shared key is ECDH between its authentikey and the card's
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    java.math.BigInteger hostPriv = new java.math.BigInteger(1, sha256("test seedkeeper".getBytes()));
    byte[] hostPub = spec.getG().multiply(hostPriv).normalize().getEncoded(false);
    APDUResponse pki = cmdSet.sendRawSecure(INS_EXPORT_PKI_PUBKEY, 0x00, 0x00, new byte[0]);
    assertEquals(SW_OK, pki.getSw());
    byte[] sharedX = spec.getCurve().decodePoint(pki.getData()).multiply(hostPriv).normalize()
        .getAffineXCoord().getEncoded();

    byte[] baselinePub = cmdSet.cardBip32GetExtendedKeyRaw("m/44'/0'/0'/0/0");
    // a trusted pubkey can only be imported on an unseeded card; the seed is restored below
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_BIP32_RESET_SEED, PIN.length, 0x00, PIN).getSw());
    // a seed reset logs the user out
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
    boolean twoFactorSet = false;
    try {
      if (!FeaturePolicyCondition.availableCapabilities.contains("rsaMult")) {
        // without the RSA engine the card cannot check that the trusted pubkey is on the curve,
        // so it refuses it rather than expose the authentikey to an invalid-curve attack
        assertEquals(SW_UNSUPPORTED_FEATURE, cmdSet.sendRawSecure(INS_IMPORT_TRUSTED_PUBKEY, 0x00, 0x00,
            concat(new byte[]{0x00, 0x41}, hostPub)).getSw());
        return; // the seed is restored in the finally block
      }
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_IMPORT_TRUSTED_PUBKEY, 0x00, 0x00,
          concat(new byte[]{0x00, 0x41}, hostPub)).getSw());

      // all the blobs below carry a valid MAC, so they reach the checks on the decrypted secret
      byte[] seed = Vectors.BIP32_SEED;
      assertEquals(SW_SECURE_IMPORT_WRONG_MAC, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_SEED, concat(new byte[]{(byte) seed.length}, seed), sharedX, -1, true)).getSw());
      assertEquals(SW_INVALID_PARAMETER, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_SEED, concat(new byte[]{(byte) seed.length}, seed), sharedX, 0, false)).getSw(),
          "a zero PKCS#7 padding byte must be refused");
      assertEquals(SW_INVALID_PARAMETER, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_SEED, concat(new byte[]{100}, seed), sharedX, -1, false)).getSw(),
          "a seed size larger than the plaintext must be refused");
      assertEquals(SW_INVALID_PARAMETER, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_SEED, concat(new byte[]{(byte) 0x90}, seed), sharedX, -1, false)).getSw(),
          "a negative seed size must be refused");
      assertEquals(SW_INVALID_PARAMETER, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_2FA, concat(new byte[]{19}, Arrays.copyOf(KEY_2FA, 19)), sharedX, -1, false)).getSw(),
          "a 2FA secret must be exactly 20 bytes");
      assertEquals(SW_INVALID_PARAMETER, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_2FA, concat(new byte[]{(byte) 0x80}, KEY_2FA), sharedX, -1, false)).getSw(),
          "a negative 2FA secret size must be refused");

      // a valid 2FA secret enables 2FA with that key
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_2FA, concat(new byte[]{20}, KEY_2FA), sharedX, -1, false)).getSw());
      twoFactorSet = true;
      reset2FA();   // only succeeds if the imported key is KEY_2FA
      twoFactorSet = false;

      // a valid seed restores the baseline
      assertEquals(SW_OK, cmdSet.sendRawSecure(INS_IMPORT_ENCRYPTED_SECRET, 0x00, 0x00,
          encryptedSecret(TYPE_SEED, concat(new byte[]{(byte) seed.length}, seed), sharedX, -1, false)).getSw());
    } finally {
      // a failure may have left the session closed (e.g. an uncaught exception on the card)
      resetSession();
      if (twoFactorSet) reset2FA();
      if (!isSeeded(cmdSet)) {
        assertEquals(SW_OK, cmdSet.sendRawSecure(INS_BIP32_IMPORT_SEED, Vectors.BIP32_SEED.length, 0x00,
            Vectors.BIP32_SEED).getSw(), "could not restore the baseline seed");
      }
    }
    assertArrayEquals(baselinePub, cmdSet.cardBip32GetExtendedKeyRaw("m/44'/0'/0'/0/0"),
        "the encrypted import should restore the same seed");
  }

  /**
   * Builds a SeedKeeper encrypted secret blob:
   * [header(12b) | IV(16b) | size(2b) | AES-CBC(plaintext + PKCS#7) | 20 | HMAC-SHA1(mackey, sha256(header | ciphertext))],
   * with key = HMAC-SHA1(x, "seckey")[0..16) and mackey = HMAC-SHA1(x, "secmac").
   *
   * @param padOverride if >= 0, the value written in the last padding byte instead of the correct one
   * @param badMac if true, the HMAC is corrupted
   */
  private static byte[] encryptedSecret(byte type, byte[] plaintext, byte[] sharedX, int padOverride, boolean badMac)
      throws Exception {
    byte[] header = new byte[12];
    header[0] = type;
    System.arraycopy(sha256(plaintext), 0, header, 6, 4);   // fingerprint
    int pad = 16 - plaintext.length % 16;
    byte[] padded = Arrays.copyOf(plaintext, plaintext.length + pad);
    Arrays.fill(padded, plaintext.length, padded.length, (byte) pad);
    if (padOverride >= 0) padded[padded.length - 1] = (byte) padOverride;

    byte[] key = Arrays.copyOf(hmacSha1(sharedX, "seckey".getBytes()), 16);
    byte[] macKey = hmacSha1(sharedX, "secmac".getBytes());
    byte[] iv = sha256("iv".getBytes());
    iv = Arrays.copyOf(iv, 16);
    javax.crypto.Cipher aes = javax.crypto.Cipher.getInstance("AES/CBC/NoPadding");
    aes.init(javax.crypto.Cipher.ENCRYPT_MODE, new javax.crypto.spec.SecretKeySpec(key, "AES"),
        new javax.crypto.spec.IvParameterSpec(iv));
    byte[] ct = aes.doFinal(padded);
    byte[] mac = hmacSha1(macKey, sha256(concat(header, ct)));
    if (badMac) mac[0] ^= 0x01;
    return concat(header, iv, new byte[]{(byte) (ct.length >> 8), (byte) ct.length}, ct, new byte[]{20}, mac);
  }

  @Test
  @DisplayName("Certificate export bounds the requested chunk")
  void exportCertificateChunkTest() {
    final int SW_WRONG_LENGTH = 0x6700;
    APDUResponse init = cmdSet.sendRawSecure(INS_EXPORT_PKI_CERTIFICATE, 0x00, 0x01, new byte[0]);
    assertEquals(SW_OK, init.getSw());
    int size = ((init.getData()[0] & 0xff) << 8) | (init.getData()[1] & 0xff);
    Assumptions.assumeTrue(size >= 224, "needs a certificate of at least 224 bytes, card has " + size);

    // the largest chunk that fits a secure channel response is accepted...
    APDUResponse chunk = cmdSet.sendRawSecure(INS_EXPORT_PKI_CERTIFICATE, 0x00, 0x02, chunkRequest(0, 223));
    assertEquals(SW_OK, chunk.getSw());
    assertEquals(223, chunk.getData().length);
    // ... one more byte, a negative size, or an offset+size overflowing a short are refused
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawSecure(INS_EXPORT_PKI_CERTIFICATE, 0x00, 0x02, chunkRequest(0, 224)).getSw());
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawSecure(INS_EXPORT_PKI_CERTIFICATE, 0x00, 0x02, chunkRequest(0, 0xFFFF)).getSw());
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawSecure(INS_EXPORT_PKI_CERTIFICATE, 0x00, 0x02, chunkRequest(size - 1, 0x7FFF)).getSw());
    assertEquals(SW_WRONG_LENGTH, cmdSet.sendRawSecure(INS_EXPORT_PKI_CERTIFICATE, 0x00, 0x02, chunkRequest(size - 10, 11)).getSw());

    // the whole certificate still exports in 128-byte chunks, as the SDK does
    byte[] cert = new byte[0];
    for (int off = 0; off < size; off += 128) {
      APDUResponse r = cmdSet.sendRawSecure(INS_EXPORT_PKI_CERTIFICATE, 0x00, 0x02,
          chunkRequest(off, Math.min(128, size - off)));
      assertEquals(SW_OK, r.getSw());
      cert = concat(cert, r.getData());
    }
    assertEquals(size, cert.length);
    assertArrayEquals(Arrays.copyOfRange(cert, 0, 223), chunk.getData());
    if (TARGET == TARGET_SIMULATOR) {
      assertArrayEquals(TEST_CERTIFICATE, cert);
    }
  }

  /** Certificate export request: [chunk_offset(2b) | chunk_size(2b)]. */
  private static byte[] chunkRequest(int offset, int size) {
    return new byte[]{(byte) (offset >> 8), (byte) offset, (byte) (size >> 8), (byte) size};
  }

  /** Generates a MuSig2 nonce for the given path and returns the 144-byte encrypted secnonce. */
  private byte[] musig2NewSecnonce(String path) {
    cmdSet.cardBip32GetExtendedKeyRaw(path);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_INIT,
        new byte[]{0x00, (byte) 0xFF, 0x00}).getSw());
    APDUResponse fin = cmdSet.sendRawSecure(INS_MUSIG2_GENERATE_NONCE, 0xFF, OP_FINALIZE, new byte[0]);
    assertEquals(SW_OK, fin.getSw());
    return fin.getData();
  }

  /** 2FA approval: HMAC-SHA1(KEY_2FA, value(32b) | 32 bytes of padding). */
  private static byte[] hmac2FA(byte[] value32, int padding) {
    byte[] pad = new byte[32];
    Arrays.fill(pad, (byte) padding);
    return hmacSha1(KEY_2FA, concat(value32, pad));
  }

  /** Removes the test 2FA key: HMAC-SHA1(KEY_2FA, id_2FA(20b) | 44 bytes 0xAA). */
  private void reset2FA() {
    byte[] id = hmacSha1(KEY_2FA, "id_2FA".getBytes());
    byte[] pad = new byte[44];
    Arrays.fill(pad, (byte) 0xAA);
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_RESET_2FA_KEY, 0x00, 0x00,
        hmacSha1(KEY_2FA, concat(id, pad))).getSw(), "could not remove the test 2FA key");
  }

  private static byte[] hmacSha1(byte[] key, byte[] msg) {
    try {
      javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA1");
      mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA1"));
      return mac.doFinal(msg);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  private static byte[] bytes32(java.math.BigInteger v) {
    byte[] raw = v.toByteArray();
    byte[] out = new byte[32];
    int len = Math.min(32, raw.length);
    System.arraycopy(raw, raw.length - len, out, 32 - len, len);
    return out;
  }

  // =============================================================================================
  // Helpers
  // =============================================================================================

  private byte[] compressedPubkey(String path) {
    byte[] uncompressed = cmdSet.cardBip32GetExtendedKeyRaw(path);
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPoint point = spec.getCurve().decodePoint(uncompressed);
    return point.getEncoded(true);
  }

  private static javax.smartcardio.ResponseAPDU transmit(int cla, int ins, int p1, int p2, byte[] data)
      throws Exception {
    return rawChannel.transmit(new javax.smartcardio.CommandAPDU(cla, ins, p1, p2, data));
  }

  private static javax.smartcardio.ResponseAPDU transmitLe(int cla, int ins, int p1, int p2, int le)
      throws Exception {
    return rawChannel.transmit(new javax.smartcardio.CommandAPDU(cla, ins, p1, p2, le));
  }

  private static boolean verifyEcdsa(byte[] uncompressedPubkey, byte[] hash, byte[] derSignature)
      throws Exception {
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");
    ECPoint q = spec.getCurve().decodePoint(uncompressedPubkey);
    java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC", "BC");
    org.bouncycastle.jce.spec.ECPublicKeySpec pubSpec =
        new org.bouncycastle.jce.spec.ECPublicKeySpec(q,
            new org.bouncycastle.jce.spec.ECParameterSpec(
                spec.getCurve(), spec.getG(), spec.getN(), spec.getH()));
    java.security.PublicKey pub = kf.generatePublic(pubSpec);
    Signature verifier = Signature.getInstance("NONEwithECDSA", "BC");
    verifier.initVerify(pub);
    verifier.update(hash);
    return verifier.verify(derSignature);
  }

  /**
   * BIP340 verification, written out here rather than pulled from a library so that the applet is
   * checked against the specification itself.
   *
   * <p>verify(pk, m, sig): P = lift_x(pk.x); r = sig[0..32); s = sig[32..64);
   * e = int(tagged_hash("BIP0340/challenge", r || pk.x || m)) mod n; R = s*G - e*P;
   * accept iff R is not infinity, R.y is even and R.x == r.
   */
  private static boolean verifyBip340(byte[] uncompressedPubkey, byte[] msg, byte[] sig) {
    if (sig.length != 64 || msg.length != 32) return false;
    ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp256k1");

    java.math.BigInteger px =
        new java.math.BigInteger(1, Arrays.copyOfRange(uncompressedPubkey, 1, 33));
    ECPoint p = liftX(spec, px);
    if (p == null) return false;

    java.math.BigInteger r = new java.math.BigInteger(1, Arrays.copyOfRange(sig, 0, 32));
    java.math.BigInteger sv = new java.math.BigInteger(1, Arrays.copyOfRange(sig, 32, 64));
    if (r.compareTo(Vectors.SECP256K1_P) >= 0 || sv.compareTo(Vectors.SECP256K1_N) >= 0) {
      return false;
    }

    byte[] challenge = taggedHash("BIP0340/challenge",
        concat(Arrays.copyOfRange(sig, 0, 32), Arrays.copyOfRange(uncompressedPubkey, 1, 33), msg));
    java.math.BigInteger e = new java.math.BigInteger(1, challenge).mod(Vectors.SECP256K1_N);

    ECPoint rPoint = spec.getG().multiply(sv).add(p.multiply(Vectors.SECP256K1_N.subtract(e))).normalize();
    if (rPoint.isInfinity()) return false;
    if (rPoint.getAffineYCoord().toBigInteger().testBit(0)) return false;   // y must be even
    return rPoint.getAffineXCoord().toBigInteger().equals(r);
  }

  /** lift_x from BIP340: the point with x = px and even y, or null if x is not on the curve. */
  private static ECPoint liftX(ECNamedCurveParameterSpec spec, java.math.BigInteger px) {
    if (px.compareTo(Vectors.SECP256K1_P) >= 0) return null;
    byte[] compressed = new byte[33];
    compressed[0] = 0x02;                       // 0x02 selects the even-y root
    byte[] xb = px.toByteArray();
    int len = Math.min(32, xb.length);
    System.arraycopy(xb, xb.length - len, compressed, 33 - len, len);
    try {
      return spec.getCurve().decodePoint(compressed).normalize();
    } catch (IllegalArgumentException e) {
      return null;                              // x is not on the curve
    }
  }

  /** BIP340 tagged hash: SHA256(SHA256(tag) || SHA256(tag) || msg). */
  private static byte[] taggedHash(String tag, byte[] msg) {
    byte[] tagHash = sha256(tag.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    return sha256(concat(tagHash, tagHash, msg));
  }

  private static byte[] sha256(byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** Re-selects the applet and re-authenticates, clearing any session state on the card. */
  private void resetSession() throws Exception {
    cmdSet.cardSelect().checkOK();
    cmdSet.forgetSecureChannel();
    assertEquals(SW_OK, cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw());
  }

  /** Exhausts the PIN try counter so the PIN ends up blocked. */
  private void blockPin() {
    byte[] wrong = "9999".getBytes();
    for (int i = 0; i < 8 && cmdSet.cardGetStatus().getData()[4] != 0; i++) {
      cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, wrong);
    }
    assertEquals(0, cmdSet.cardGetStatus().getData()[4], "the PIN should now be blocked");
  }

  /**
   * Brings the card back to the baseline PIN whatever state a test left it in. Called from a
   * finally block, so it must not throw before it has had a chance to repair things.
   */
  private void restoreBaselinePin() {
    if (cmdSet.sendRawSecure(INS_VERIFY_PIN, 0x00, 0x00, PIN).getSw() == SW_OK) {
      return;
    }
    // Blocked, or set to something else: the PUK recovers both at once.
    cmdSet.sendRawSecure(INS_UNBLOCK_PIN, 0x00, 0x00,
        concat(new byte[]{(byte) PUK.length}, PUK, new byte[]{(byte) PIN.length}, PIN));
  }

  private static byte[] concat(byte[]... parts) {
    int len = 0;
    for (byte[] p : parts) len += p.length;
    byte[] out = new byte[len];
    int off = 0;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, off, p.length);
      off += p.length;
    }
    return out;
  }
}
