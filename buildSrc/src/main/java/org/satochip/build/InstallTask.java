// based on https://github.com/Toporin/Seedkeeper-Applet/blob/master/buildSrc/src/main/java/org/seedkeeper/build/InstallTask.java
package org.satochip.build;

import im.status.keycard.desktop.PCSCCardChannel;
import im.status.keycard.globalplatform.GlobalPlatformCommandSet;
import im.status.keycard.globalplatform.Load;
import im.status.keycard.globalplatform.LoadCallback;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;

import org.bouncycastle.util.encoders.Hex;
import org.gradle.api.DefaultTask;
import org.gradle.api.GradleException;
import org.gradle.api.logging.Logger;
import org.gradle.api.tasks.TaskAction;

import javax.smartcardio.*;
import java.io.InputStream;
import java.io.FileInputStream;
import java.io.IOException;

import apdu4j.pcsc.TerminalManager;

public class InstallTask extends DefaultTask {

  // Satochip constants
  public static final byte[] PACKAGE_AID = Hex.decode("5361746F43686970");
  public static final byte[] SATOCHIP_AID = Hex.decode("5361746F4368697000");
  public static final byte[] SATOCHIP_INSTANCE_AID = Hex.decode("5361746F4368697000");
  public static final byte[] NDEF_AID = Hex.decode("5361746F4368697001");
  // standard NFC Forum Type 4 tag application AID, do not change
  public static final byte[] NDEF_INSTANCE_AID = Hex.decode("D2760000850101");

  // empty install parameters: the NDEF applet keeps the default record compiled into SharedMemory
  public static final byte[] NDEF_TAG = new byte[0];

  @TaskAction
  public void install() {
    Logger logger = getLogger();

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
      logger.info("Selecting the ISD");
      cmdSet.select().checkOK();
      logger.info("Opening a SecureChannel");
      cmdSet.openSecureChannel(false); // false to use default GP keys 0x4041...4F

      logger.info("Deleting the old instances and package (if present)");
      cmdSet.delete(PACKAGE_AID, (byte) 0x80).checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);

      logger.info("Loading the new package");
      InputStream in = new FileInputStream(this.getProject().file("build/javacard/org/satochip/applet/javacard/applet.cap"));
      cmdSet.installForLoad(PACKAGE_AID).checkOK();
      Load load = new Load(in);
      byte[] block;
      int steps = load.blocksCount();

      while((block = load.nextDataBlock()) != null) {
        cmdSet.load(block, (load.getCount() - 1), load.hasMore()).checkOK();
        logger.info("Loaded block " + load.getCount() + "/" + steps);
      }
      logger.info("Finished loading the new package!");

      logger.info("Installing the Satochip Applet");
      cmdSet.installForInstall(PACKAGE_AID, SATOCHIP_AID, SATOCHIP_INSTANCE_AID, new byte[0]).checkOK();

      logger.info("Installing the NDEF Applet");
      cmdSet.installForInstall(PACKAGE_AID, NDEF_AID, NDEF_INSTANCE_AID, NDEF_TAG).checkOK();

    } catch (IOException e) {
      throw new GradleException("I/O error", e);
    } catch (APDUException e) {
      throw new GradleException(e.getMessage(), e);
    }
  }
}
