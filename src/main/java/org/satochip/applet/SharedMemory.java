// based on https://github.com/status-im/status-keycard/blob/146c049b45c2c20989214d2b37818e7b6222b0dd/src/main/java/im/status/keycard/SharedMemory.java
package org.satochip.applet;

import javacard.framework.Util;

/**
 * Keep references to data structures shared across applet instances of this package.
 */
public class SharedMemory {

  /**
   * Maximum size of the NDEF data file [NLEN(2b) | NDEF record], as declared in the capability
   * container. Bounded so that INS_SET_NDEF can read the buffer back: [size(1b) | file] must fit in
   * a secure channel response (SecureChannel.MAX_WRAP_SIZE, 223 bytes).
   **/
  static final short MAX_NDEF_DATA_FILE_SIZE = 222;

  // The NDEF data file. Read through the NDEFApplet.
  // The first byte is the size of the remaining (meaningful) bytes, the rest is zero padding,
  // hence 1 + MAX_NDEF_DATA_FILE_SIZE bytes. The file itself is [NLEN(2b) | NDEF record].
  //
  // Default record: an NDEF URI record (universal link, works on both Android and iOS)
  // pointing to the Satochip quick-start guide.
  // https://developer.android.com/training/app-links
  // https://developer.apple.com/documentation/xcode/supporting-associated-domains?language=objc
  //
  // https://satochip.io/quick-start/satochip/
  // 0026d1012255047361746f636869702e696f2f717569636b2d73746172742f7361746f636869702f
  //
  // The record can be replaced at install time through the NDEF applet install parameters,
  // or at any time afterwards with the Satochip applet's INS_SET_NDEF (0x3F) command.
  static byte[] ndefDataFile = {
    (byte) 0x28, (byte) 0x00, (byte) 0x26, (byte) 0xd1, (byte) 0x01, (byte) 0x22, (byte) 0x55, (byte) 0x04,
    (byte) 0x73, (byte) 0x61, (byte) 0x74, (byte) 0x6f, (byte) 0x63, (byte) 0x68, (byte) 0x69, (byte) 0x70,
    (byte) 0x2e, (byte) 0x69, (byte) 0x6f, (byte) 0x2f, (byte) 0x71, (byte) 0x75, (byte) 0x69, (byte) 0x63,
    (byte) 0x6b, (byte) 0x2d, (byte) 0x73, (byte) 0x74, (byte) 0x61, (byte) 0x72, (byte) 0x74, (byte) 0x2f,
    (byte) 0x73, (byte) 0x61, (byte) 0x74, (byte) 0x6f, (byte) 0x63, (byte) 0x68, (byte) 0x69, (byte) 0x70,
    (byte) 0x2f, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
    (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00
  };

  /**
   * Checks that buf[off..off+size) is a well-formed NDEF data file that fits in ndefDataFile:
   * [NLEN(2b) | NDEF record], with a non-empty record of exactly NLEN bytes.
   */
  static boolean isValidNdefFile(byte[] buf, short off, short size) {
    if (size <= 2 || size > MAX_NDEF_DATA_FILE_SIZE) {
      return false;
    }
    return (short)(size - 2) == Util.getShort(buf, off);
  }
}
