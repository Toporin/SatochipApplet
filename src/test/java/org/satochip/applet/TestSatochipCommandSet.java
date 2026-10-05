package org.satochip.applet;

import org.satochip.client.SatochipCommandSet;
import org.satochip.client.SecureChannelSession;
import org.satochip.io.APDUCommand;
import org.satochip.io.APDUResponse;
import org.satochip.io.CardChannel;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;

/**
 * Adds test-only APDU helpers on top of the production command set.
 *
 * <p>The production {@link SatochipCommandSet#cardTransmit} is deliberately forgiving: it opens the
 * secure channel on demand and re-verifies the PIN when the card answers 0x9C06. That is exactly
 * what an application wants and exactly what a negative test must not have, since it silently turns
 * an authorization failure into a success. Status-word assertions therefore go through
 * {@link #sendRawSecure} or {@link #sendRawPlain}, which send precisely the bytes given and return
 * precisely what the card answered.
 */
public class TestSatochipCommandSet extends SatochipCommandSet {
  public static final byte CLA = (byte) 0xB0;

  private final CardChannel channel;

  public TestSatochipCommandSet(CardChannel apduChannel) {
    super(apduChannel);
    this.channel = apduChannel;
  }

  /**
   * Sends an APDU without the secure channel, so that the card's own rejection can be observed
   * (e.g. asserting SW_SECURE_CHANNEL_REQUIRED, 0x9C20).
   */
  public APDUResponse sendRawPlain(int ins, int p1, int p2, byte[] data) {
    return send(new APDUCommand(CLA & 0xff, ins, p1, p2, data));
  }

  /**
   * Encrypts an arbitrary APDU through the secure channel and decrypts the response, with no
   * retry-on-0x9C06 and no other client-side recovery. Malformed commands are sent as given.
   *
   * <p>A card error is reported as the returned status word; only 0x9000 responses carry a
   * decryptable payload, so the response is decrypted only in that case.
   */
  public APDUResponse sendRawSecure(int ins, int p1, int p2, byte[] data) {
    SecureChannelSession sc = openedSecureChannel();
    APDUCommand plain = new APDUCommand(CLA & 0xff, ins, p1, p2, data);
    APDUResponse response = send(sc.encrypt_secure_channel(plain));
    if (response.getSw() == 0x9000) {
      return sc.decrypt_secure_channel(response);
    }
    return response;
  }

  /**
   * Like {@link #sendRawSecure}, but encrypts {@code innerApdu} verbatim instead of a well-formed
   * APDU, so that a malformed inner command (wrong CLA, Lc not matching the data...) reaches the card.
   */
  public APDUResponse sendRawSecureBytes(byte[] innerApdu) {
    SecureChannelSession sc = openedSecureChannel();
    APDUCommand plain = new APDUCommand(CLA & 0xff, 0, 0, 0, new byte[0]) {
      @Override
      public byte[] serialize() {
        return innerApdu.clone();
      }
    };
    APDUResponse response = send(sc.encrypt_secure_channel(plain));
    if (response.getSw() == 0x9000) {
      return sc.decrypt_secure_channel(response);
    }
    return response;
  }

  /**
   * Sets the IV counter of the SDK secure channel (opening one first if needed), so that the next
   * secure command is sent with this counter. The SDK sends odd counters, starting at 1, +2 each time.
   */
  public void setIvCounter(int counter) {
    SecureChannelSession sc = openedSecureChannel();
    try {
      Field f = SecureChannelSession.class.getDeclaredField("ivCounter");
      f.setAccessible(true);
      f.setInt(sc, counter);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Cannot reach the SDK IV counter", e);
    }
  }

  /** Drops the current secure channel so the next secure command negotiates a fresh one. */
  public void forgetSecureChannel() {
    try {
      Field f = SatochipCommandSet.class.getDeclaredField("secureChannel");
      f.setAccessible(true);
      f.set(this, new SecureChannelSession());
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Cannot reset the secure channel", e);
    }
  }

  /** Replays an already-encrypted command verbatim, to check the card rejects it. */
  public APDUResponse replay(APDUCommand encrypted) {
    return send(encrypted);
  }

  /** Encrypts a command without sending it, so a test can tamper with the bytes first. */
  public APDUCommand encrypt(int ins, int p1, int p2, byte[] data) {
    return openedSecureChannel().encrypt_secure_channel(new APDUCommand(CLA & 0xff, ins, p1, p2, data));
  }

  /** Sends a command, turning the SDK's checked IOException into an unchecked one. */
  private APDUResponse send(APDUCommand command) {
    try {
      return channel.send(command);
    } catch (IOException e) {
      throw new UncheckedIOException("APDU transmission failed", e);
    }
  }

  /** Returns the SDK secure channel, negotiating one first if it is not open yet. */
  private SecureChannelSession openedSecureChannel() {
    SecureChannelSession sc = secureChannel();
    if (!sc.initializedSecureChannel()) {
      try {
        cardInitiateSecureChannel();
      } catch (IOException e) {
        throw new UncheckedIOException("Could not open the secure channel", e);
      }
      sc = secureChannel();
    }
    return sc;
  }

  public CardChannel channel() {
    return channel;
  }

  /**
   * Derives a BIP32 path and returns the uncompressed public key, unwrapping the SDK's
   * {@code byte[][]} result and its checked exception.
   */
  public byte[] cardBip32GetExtendedKeyRaw(String path) {
    try {
      return cardBip32GetExtendedKey(path, null, null)[0];
    } catch (Exception e) {
      throw new IllegalStateException("BIP32 derivation failed for " + path, e);
    }
  }

  /**
   * The SDK keeps its SecureChannelSession private, so reach it reflectively. The same technique is
   * already used against GlobalPlatformCommandSet in buildSrc's LockTask.
   */
  private SecureChannelSession secureChannel() {
    try {
      Field f = SatochipCommandSet.class.getDeclaredField("secureChannel");
      f.setAccessible(true);
      return (SecureChannelSession) f.get(this);
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException("Cannot reach the SDK secure channel", e);
    }
  }
}
