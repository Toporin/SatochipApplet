// based on https://github.com/status-im/status-keycard/blob/master/buildSrc/src/main/java/im/status/keycard/build/LockTask.java
package org.satochip.build;

import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.globalplatform.GlobalPlatformCommandSet;
import im.status.keycard.globalplatform.SecureChannel;
import im.status.keycard.io.APDUCommand;

import org.bouncycastle.util.encoders.Hex;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.TaskAction;

import javax.smartcardio.*;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.SecureRandom;

import apdu4j.pcsc.TerminalManager;

/**
 * DESTRUCTIVE. Replaces the card's GlobalPlatform keys with random keys that are never displayed
 * nor saved, then moves the card to the SECURED state. After this, nobody (including the card
 * owner) can delete, update or reinstall the applet, or load any other applet on the card.
 * This cannot be undone. Only intended for production cards, after final testing.
 */
public class LockTask extends DefaultTask {

  public static final byte[] SATOCHIP_AID = Hex.decode("5361746F4368697000");

  @TaskAction
  public void install() {
    Logger logger = getLogger();

    // Guard: locking is irreversible, so require an explicit confirmation on the command line.
    Object confirm = getProject().findProperty("confirmLock");
    if (confirm == null || !confirm.toString().equals("YES")) {
      throw new GradleException(
          "Refusing to lock the card.\n" +
          "This task permanently replaces the card's GlobalPlatform keys with random keys that are\n" +
          "never displayed nor saved, and moves the card to the SECURED state. Afterwards the applet\n" +
          "can never be deleted, updated or reinstalled, and no other applet can be loaded. This\n" +
          "cannot be undone. Only run it on production cards, after final testing.\n" +
          "If you are sure, run: ./gradlew lock -PconfirmLock=YES");
    }

    TerminalFactory tf = TerminalManager.getTerminalFactory();
    CardTerminal cardTerminal = null;

    try {
      for (CardTerminal t : tf.terminals().list()) {
        if (t.isCardPresent()) {
          cardTerminal = t;
          break;
        }
      }
    } catch(CardException e) {
      throw new GradleException("Error listing card terminals", e);
    }

    if (cardTerminal == null) {
      throw new GradleException("No available PC/SC terminal");
    }

    Card apduCard;

    try {
      apduCard = cardTerminal.connect("*");
    } catch(CardException e) {
      throw new GradleException("Couldn't connect to the card", e);
    }

    logger.info("Connected to " + cardTerminal.getName());
    PCSCCardChannel sdkChannel = new PCSCCardChannel(apduCard.getBasicChannel());
    GlobalPlatformCommandSet cmdSet = new GlobalPlatformCommandSet(sdkChannel);

    try {
      logger.info("Selecting the Satochip applet (don't lock if not installed)");
      sdkChannel.send(new APDUCommand(0x00, 0xa4, 0x04, 0x00, SATOCHIP_AID)).checkOK();

      logger.info("Selecting the ISD");
      cmdSet.select().checkOK();
      logger.info("Opening a SecureChannel");
      cmdSet.openSecureChannel(false);

      logger.info("Changing SCP02 keys to random ones");
      SecureRandom rand = new SecureRandom();
      byte[] enck = new byte[16];
      rand.nextBytes(enck);
      byte[] mack = new byte[16];
      rand.nextBytes(mack);
      byte[] deck = new byte[16];
      rand.nextBytes(deck);
      cmdSet.putSCP02Keys(enck, mack, deck, 0, 1).checkOK();

      logger.info("Switching to SECURED");
      Field f = cmdSet.getClass().getDeclaredField("secureChannel");
      f.setAccessible(true);
      SecureChannel sc = (SecureChannel) f.get(cmdSet);
      APDUCommand cmd = new APDUCommand(0x84, 0xf0, 0x80, 0x07, new byte[0]);
      sc.send(cmd).checkSW(0x9000, 0x6985);
      cmd = new APDUCommand(0x84, 0xf0, 0x80, 0x0f, new byte[0]);
      sc.send(cmd).checkSW(0x9000, 0x6985);
    } catch (IOException e) {
      throw new GradleException("I/O error", e);
    } catch (Exception e) {
      throw new GradleException(e.getMessage(), e);
    }
  }
}
