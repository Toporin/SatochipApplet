/*
 * JavaCard software implementation of SHA2-384 and SHA2-512 as defined in FIPS PUB 180-2.
 * Based on source code from BouncyCastle (www.bouncycastle.org) and jsSha project ttp://jssha.sourceforge.net/
 * Ported by Petr Svenda http://www.svenda.com/petr

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
USAGE:
  // allocate SHA2 engine (use SHA_512 or SHA_384 constant)
  Sha2 sha2 = new Sha2(Sha2.SHA_512);
  // reset internal state of engine
  sha2.reset();
  // call (possibly multiple times) update function over parts of data you like to hash
  sha2.update(array_to_hash, start_offset_of_data, hash_data_length);
  // finalize hashing and read out hash result into array_for_hash_output array
  sha2.doFinal(another_part_of_array_to_hash, start_offset_of_data, hash_data_length, array_for_hash_output, start_offset_of_hash_output);
*/

/*
* Test vectors: "" empty string =>
* SHA-512: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
*/

package org.satochip.applet;

import javacard.framework.*;
import javacard.security.*;

public class Sha2 extends MessageDigest {
//public class Sha2 {
  public static final byte SHA_384 = (byte) 5;
  public static final byte SHA_512 = (byte) 6;
  public static final short SHA2_BLOCK_LENGTH = 128; // in bytes
  public static final short SHA512_DIGEST_LENGTH = 64; // in bytes
  public static final short SHA384_DIGEST_LENGTH = 48; // in bytes
  public static final short LONG_LENGTH = 8; // in bytes

  public static final short NUM_INT64_VARIABLES = 25;

  private byte    m_shaType = SHA_512;
  private byte[]  xBuf = null;

  public Int_64 K[] = null;
  Int_64 H[] = null;
  short[] W = null;

  public short int64Variables[] = null;

  public static final short OFFSET_a = (short) 0;
  public static final short OFFSET_b = (short) 4;
  public static final short OFFSET_c = (short) 8;
  public static final short OFFSET_d = (short) 12;
  public static final short OFFSET_e = (short) 16;
  public static final short OFFSET_f = (short) 20;
  public static final short OFFSET_g = (short) 24;
  public static final short OFFSET_h = (short) 28;
  public static final short OFFSET_T1 = (short) 32;
  public static final short OFFSET_T2 = (short) 36;

  public static final short OFFSET_result1 = (short) 40;
  public static final short OFFSET_result2 = (short) 44;
  public static final short OFFSET_result3 = (short) 48;
  public static final short OFFSET_result4 = (short) 52;

  public static final short OFFSET_rotl_1 = (short) 56;
  public static final short OFFSET_rotl_2 = (short) 60;
  public static final short OFFSET_rotl_3 = (short) 64;

  public static final short OFFSET_rotr_1 = (short) 68;
  public static final short OFFSET_rotr_2 = (short) 72;
  public static final short OFFSET_rotr_3 = (short) 76;

  public static final short OFFSET_safeAdd = (short) 80;
  public static final short OFFSET_safeAdd2 = (short) 84;
  public static final short OFFSET_Sigma0 = (short) 88;
  public static final short OFFSET_Sigma1 = (short) 92;

  public static final short OFFSET_xBufOff = (short) 96;
  public static final short OFFSET_wOff = (short) 97;
  public static final short OFFSET_byteCount1 = (short) 98;
  public static final short OFFSET_byteCount2 = (short) 99;

/*
short rotr_counter = 0;
short rotl_counter = 0;
short ch_counter = 0;
short maj_counter = 0;
short sigma0_counter = 0;
short sigma1_counter = 0;
short sum0_counter = 0;
short sum1_counter = 0;
short add_counter = 0;
/**/

public Sha2(byte shaType){
  this.m_shaType = shaType;

  int64Variables = JCSystem.makeTransientShortArray((short) (NUM_INT64_VARIABLES * 4), JCSystem.CLEAR_ON_DESELECT);
//int64Variables = new short[(short) (NUM_INT64_VARIABLES * 4)];

  xBuf = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
//xBuf = new byte[8];

// TODO - MOVE VALUES INTO short[] ARRAY AND INTO RAM MEMORY (if available)
  K = new Int_64[80];
  K[0] = new Int_64((short) 0x428a,(short) 0x2f98,(short) 0xd728,(short) 0xae22);
  K[1] = new Int_64((short) 0x7137,(short) 0x4491,(short) 0x23ef,(short) 0x65cd);
  K[2] = new Int_64((short) 0xb5c0,(short) 0xfbcf,(short) 0xec4d,(short) 0x3b2f);
  K[3] = new Int_64((short) 0xe9b5,(short) 0xdba5,(short) 0x8189,(short) 0xdbbc);
  K[4] = new Int_64((short) 0x3956,(short) 0xc25b,(short) 0xf348,(short) 0xb538);
  K[5] = new Int_64((short) 0x59f1,(short) 0x11f1,(short) 0xb605,(short) 0xd019);
  K[6] = new Int_64((short) 0x923f,(short) 0x82a4,(short) 0xaf19,(short) 0x4f9b);
  K[7] = new Int_64((short) 0xab1c,(short) 0x5ed5,(short) 0xda6d,(short) 0x8118);
  K[8] = new Int_64((short) 0xd807,(short) 0xaa98,(short) 0xa303,(short) 0x0242);
  K[9] = new Int_64((short) 0x1283,(short) 0x5b01,(short) 0x4570,(short) 0x6fbe);
  K[10] = new Int_64((short) 0x2431,(short) 0x85be,(short) 0x4ee4,(short) 0xb28c);
  K[11] = new Int_64((short) 0x550c,(short) 0x7dc3,(short) 0xd5ff,(short) 0xb4e2);
  K[12] = new Int_64((short) 0x72be,(short) 0x5d74,(short) 0xf27b,(short) 0x896f);
  K[13] = new Int_64((short) 0x80de,(short) 0xb1fe,(short) 0x3b16,(short) 0x96b1);
  K[14] = new Int_64((short) 0x9bdc,(short) 0x06a7,(short) 0x25c7,(short) 0x1235);
  K[15] = new Int_64((short) 0xc19b,(short) 0xf174,(short) 0xcf69,(short) 0x2694);
  K[16] = new Int_64((short) 0xe49b,(short) 0x69c1,(short) 0x9ef1,(short) 0x4ad2);
  K[17] = new Int_64((short) 0xefbe,(short) 0x4786,(short) 0x384f,(short) 0x25e3);
  K[18] = new Int_64((short) 0x0fc1,(short) 0x9dc6,(short) 0x8b8c,(short) 0xd5b5);
  K[19] = new Int_64((short) 0x240c,(short) 0xa1cc,(short) 0x77ac,(short) 0x9c65);
  K[20] = new Int_64((short) 0x2de9,(short) 0x2c6f,(short) 0x592b,(short) 0x0275);
  K[21] = new Int_64((short) 0x4a74,(short) 0x84aa,(short) 0x6ea6,(short) 0xe483);
  K[22] = new Int_64((short) 0x5cb0,(short) 0xa9dc,(short) 0xbd41,(short) 0xfbd4);
  K[23] = new Int_64((short) 0x76f9,(short) 0x88da,(short) 0x8311,(short) 0x53b5);
  K[24] = new Int_64((short) 0x983e,(short) 0x5152,(short) 0xee66,(short) 0xdfab);
  K[25] = new Int_64((short) 0xa831,(short) 0xc66d,(short) 0x2db4,(short) 0x3210);
  K[26] = new Int_64((short) 0xb003,(short) 0x27c8,(short) 0x98fb,(short) 0x213f);
  K[27] = new Int_64((short) 0xbf59,(short) 0x7fc7,(short) 0xbeef,(short) 0x0ee4);
  K[28] = new Int_64((short) 0xc6e0,(short) 0x0bf3,(short) 0x3da8,(short) 0x8fc2);
  K[29] = new Int_64((short) 0xd5a7,(short) 0x9147,(short) 0x930a,(short) 0xa725);
  K[30] = new Int_64((short) 0x06ca,(short) 0x6351,(short) 0xe003,(short) 0x826f);
  K[31] = new Int_64((short) 0x1429,(short) 0x2967,(short) 0x0a0e,(short) 0x6e70);
  K[32] = new Int_64((short) 0x27b7,(short) 0x0a85,(short) 0x46d2,(short) 0x2ffc);
  K[33] = new Int_64((short) 0x2e1b,(short) 0x2138,(short) 0x5c26,(short) 0xc926);
  K[34] = new Int_64((short) 0x4d2c,(short) 0x6dfc,(short) 0x5ac4,(short) 0x2aed);
  K[35] = new Int_64((short) 0x5338,(short) 0x0d13,(short) 0x9d95,(short) 0xb3df);
  K[36] = new Int_64((short) 0x650a,(short) 0x7354,(short) 0x8baf,(short) 0x63de);
  K[37] = new Int_64((short) 0x766a,(short) 0x0abb,(short) 0x3c77,(short) 0xb2a8);
  K[38] = new Int_64((short) 0x81c2,(short) 0xc92e,(short) 0x47ed,(short) 0xaee6);
  K[39] = new Int_64((short) 0x9272,(short) 0x2c85,(short) 0x1482,(short) 0x353b);
  K[40] = new Int_64((short) 0xa2bf,(short) 0xe8a1,(short) 0x4cf1,(short) 0x0364);
  K[41] = new Int_64((short) 0xa81a,(short) 0x664b,(short) 0xbc42,(short) 0x3001);
  K[42] = new Int_64((short) 0xc24b,(short) 0x8b70,(short) 0xd0f8,(short) 0x9791);
  K[43] = new Int_64((short) 0xc76c,(short) 0x51a3,(short) 0x0654,(short) 0xbe30);
  K[44] = new Int_64((short) 0xd192,(short) 0xe819,(short) 0xd6ef,(short) 0x5218);
  K[45] = new Int_64((short) 0xd699,(short) 0x0624,(short) 0x5565,(short) 0xa910);
  K[46] = new Int_64((short) 0xf40e,(short) 0x3585,(short) 0x5771,(short) 0x202a);
  K[47] = new Int_64((short) 0x106a,(short) 0xa070,(short) 0x32bb,(short) 0xd1b8);
  K[48] = new Int_64((short) 0x19a4,(short) 0xc116,(short) 0xb8d2,(short) 0xd0c8);
  K[49] = new Int_64((short) 0x1e37,(short) 0x6c08,(short) 0x5141,(short) 0xab53);
  K[50] = new Int_64((short) 0x2748,(short) 0x774c,(short) 0xdf8e,(short) 0xeb99);
  K[51] = new Int_64((short) 0x34b0,(short) 0xbcb5,(short) 0xe19b,(short) 0x48a8);
  K[52] = new Int_64((short) 0x391c,(short) 0x0cb3,(short) 0xc5c9,(short) 0x5a63);
  K[53] = new Int_64((short) 0x4ed8,(short) 0xaa4a,(short) 0xe341,(short) 0x8acb);
  K[54] = new Int_64((short) 0x5b9c,(short) 0xca4f,(short) 0x7763,(short) 0xe373);
  K[55] = new Int_64((short) 0x682e,(short) 0x6ff3,(short) 0xd6b2,(short) 0xb8a3);
  K[56] = new Int_64((short) 0x748f,(short) 0x82ee,(short) 0x5def,(short) 0xb2fc);
  K[57] = new Int_64((short) 0x78a5,(short) 0x636f,(short) 0x4317,(short) 0x2f60);
  K[58] = new Int_64((short) 0x84c8,(short) 0x7814,(short) 0xa1f0,(short) 0xab72);
  K[59] = new Int_64((short) 0x8cc7,(short) 0x0208,(short) 0x1a64,(short) 0x39ec);
  K[60] = new Int_64((short) 0x90be,(short) 0xfffa,(short) 0x2363,(short) 0x1e28);
  K[61] = new Int_64((short) 0xa450,(short) 0x6ceb,(short) 0xde82,(short) 0xbde9);
  K[62] = new Int_64((short) 0xbef9,(short) 0xa3f7,(short) 0xb2c6,(short) 0x7915);
  K[63] = new Int_64((short) 0xc671,(short) 0x78f2,(short) 0xe372,(short) 0x532b);
  K[64] = new Int_64((short) 0xca27,(short) 0x3ece,(short) 0xea26,(short) 0x619c);
  K[65] = new Int_64((short) 0xd186,(short) 0xb8c7,(short) 0x21c0,(short) 0xc207);
  K[66] = new Int_64((short) 0xeada,(short) 0x7dd6,(short) 0xcde0,(short) 0xeb1e);
  K[67] = new Int_64((short) 0xf57d,(short) 0x4f7f,(short) 0xee6e,(short) 0xd178);
  K[68] = new Int_64((short) 0x06f0,(short) 0x67aa,(short) 0x7217,(short) 0x6fba);
  K[69] = new Int_64((short) 0x0a63,(short) 0x7dc5,(short) 0xa2c8,(short) 0x98a6);
  K[70] = new Int_64((short) 0x113f,(short) 0x9804,(short) 0xbef9,(short) 0x0dae);
  K[71] = new Int_64((short) 0x1b71,(short) 0x0b35,(short) 0x131c,(short) 0x471b);
  K[72] = new Int_64((short) 0x28db,(short) 0x77f5,(short) 0x2304,(short) 0x7d84);
  K[73] = new Int_64((short) 0x32ca,(short) 0xab7b,(short) 0x40c7,(short) 0x2493);
  K[74] = new Int_64((short) 0x3c9e,(short) 0xbe0a,(short) 0x15c9,(short) 0xbebc);
  K[75] = new Int_64((short) 0x431d,(short) 0x67c4,(short) 0x9c10,(short) 0x0d4c);
  K[76] = new Int_64((short) 0x4cc5,(short) 0xd4be,(short) 0xcb3e,(short) 0x42b6);
  K[77] = new Int_64((short) 0x597f,(short) 0x299c,(short) 0xfc65,(short) 0x7e2a);
  K[78] = new Int_64((short) 0x5fcb,(short) 0x6fab,(short) 0x3ad6,(short) 0xfaec);
  K[79] = new Int_64((short) 0x6c44,(short) 0x198c,(short) 0x4a47,(short) 0x5817);

  H = new Int_64[8];
  for (byte i=0; i < (short) H.length; i++) H[i] = new Int_64();
  clearState(m_shaType);

  //W = new short[(short) (80 * 4)];
  W = JCSystem.makeTransientShortArray((short) (80 * 4), JCSystem.CLEAR_ON_DESELECT);
}

public void int64Set(short[] array, short offset, short highest, short higher, short lower, short lowest) {
  array[offset] = highest;
  array[(short)(offset + 1)] = higher;
  array[(short)(offset + 2)] = lower;
  array[(short)(offset + 3)] = lowest;
}

public void int64Set(short[] destArray, short destOffset, short[] srcArray, short srcOffset) {
  destArray[destOffset] = srcArray[srcOffset]; destArray[(short) (destOffset + 1)] = srcArray[(short) (srcOffset + 1)]; destArray[(short) (destOffset + 2)] = srcArray[(short) (srcOffset + 2)]; destArray[(short) (destOffset + 3)] = srcArray[(short) (srcOffset + 3)];
}

private void int64Set(short[] array, short offset, Int_64 template) {
  array[offset] = template.highest;
  array[(short)(offset + 1)] = template.higher;
  array[(short)(offset + 2)] = template.lower;
  array[(short)(offset + 3)] = template.lowest;
}

private void int64Set(short[] array, short offset, byte[] srcArray, short srcOffset) {
  array[offset] = (short) (srcArray[srcOffset] << 8 | (short) ( srcArray[(short) (srcOffset + 1)] & 0xff));
  array[(short) (offset + 1)] = (short) (srcArray[(short) (srcOffset + 2)] << 8 |(short) ( srcArray[(short) (srcOffset + 3)] & 0xff));
  array[(short) (offset + 2)] = (short) (srcArray[(short) (srcOffset + 4)] << 8 | (short) ( srcArray[(short) (srcOffset + 5)] & 0xff));
  array[(short) (offset + 3)] = (short) (srcArray[(short) (srcOffset + 6)] << 8 | (short) ( srcArray[(short) (srcOffset + 7)] & 0xff));
}

void clearState(short variant) {
if (variant == SHA_384) {
        H[0].set((short) 0xcbbb, (short) 0x9d5d, (short) 0xc105, (short) 0x9ed8);
        H[1].set((short) 0x629a, (short) 0x292a, (short) 0x367c, (short) 0xd507);
        H[2].set((short) 0x9159, (short) 0x015a, (short) 0x3070, (short) 0xdd17);
        H[3].set((short) 0x152f, (short) 0xecd8, (short) 0xf70e, (short) 0x5939);
        H[4].set((short) 0x6733, (short) 0x2667, (short) 0xffc0, (short) 0x0b31);
        H[5].set((short) 0x8eb4, (short) 0x4a87, (short) 0x6858, (short) 0x1511);
        H[6].set((short) 0xdb0c, (short) 0x2e0d, (short) 0x64f9, (short) 0x8fa7);
        H[7].set((short) 0x47b5, (short) 0x481d, (short) 0xbefa, (short) 0x4fa4);
    }
    if (variant == SHA_512) {
        H[0].set((short) 0x6a09, (short) 0xe667, (short) 0xf3bc, (short) 0xc908);
        H[1].set((short) 0xbb67, (short) 0xae85, (short) 0x84ca, (short) 0xa73b);
        H[2].set((short) 0x3c6e, (short) 0xf372, (short) 0xfe94, (short) 0xf82b);
        H[3].set((short) 0xa54f, (short) 0xf53a, (short) 0x5f1d, (short) 0x36f1);
        H[4].set((short) 0x510e, (short) 0x527f, (short) 0xade6, (short) 0x82d1);
        H[5].set((short) 0x9b05, (short) 0x688c, (short) 0x2b3e, (short) 0x6c1f);
        H[6].set((short) 0x1f83, (short) 0xd9ab, (short) 0xfb41, (short) 0xbd6b);
        H[7].set((short) 0x5be0, (short) 0xcd19, (short) 0x137e, (short) 0x2179);
    }
}


public void update(byte in) {
  xBuf[int64Variables[OFFSET_xBufOff]++] = in;
  if (int64Variables[OFFSET_xBufOff] == (short) xBuf.length) {
    //processWord(xBuf, (short) 0);
    //W[int64Variables[OFFSET_wOff]].set(xBuf, (short) 0);
    int64Set(W, int64Variables[OFFSET_wOff], xBuf, (short) 0);
    int64Variables[OFFSET_wOff] += 4;
    if (int64Variables[OFFSET_wOff] == (short) (16 * 4)) processBlock();

    int64Variables[OFFSET_xBufOff] = 0;
  }
  int64Variables[OFFSET_byteCount1]++;
}
/**/
public void update(byte[] strToHash, short startOffset, short strLen) {
   //
   // fill the current word
   //
  while ((int64Variables[OFFSET_xBufOff] != 0) && (strLen > 0)) {
    //    update(strToHash[startOffset]);
    xBuf[int64Variables[OFFSET_xBufOff]++] = strToHash[startOffset];
    if (int64Variables[OFFSET_xBufOff] == (short) xBuf.length) {
      //processWord(xBuf, (short) 0);
      //    W[int64Variables[OFFSET_wOff]].set(xBuf, (short) 0);
      int64Set(W, int64Variables[OFFSET_wOff], xBuf, (short) 0);
      int64Variables[OFFSET_wOff] += 4;
      if (int64Variables[OFFSET_wOff] == (short) (16 * 4)) processBlock();

      int64Variables[OFFSET_xBufOff] = 0;
    }
    int64Variables[OFFSET_byteCount1]++;

    startOffset++;
    strLen--;
  }

//
// process whole words.
//
  while (strLen > xBuf.length)
  {
    //processWord(strToHash, startOffset);
//  W[int64Variables[OFFSET_wOff]].set(strToHash, startOffset);
    int64Set(W, int64Variables[OFFSET_wOff], strToHash, startOffset);
    int64Variables[OFFSET_wOff] += 4;
    if (int64Variables[OFFSET_wOff] == (short) (16 * 4)) processBlock();

    startOffset += xBuf.length;
    strLen -= xBuf.length;
    int64Variables[OFFSET_byteCount1] += xBuf.length;
  }

//
// load in the remainder.
//
  while (strLen > 0)
  {
//    update(strToHash[startOffset]);
    xBuf[int64Variables[OFFSET_xBufOff]++] = strToHash[startOffset];
    if (int64Variables[OFFSET_xBufOff] == (short) xBuf.length) {
      //processWord(xBuf, (short) 0);
//    W[int64Variables[OFFSET_wOff]].set(xBuf, (short) 0);
      int64Set(W, int64Variables[OFFSET_wOff], xBuf, (short) 0);
      int64Variables[OFFSET_wOff] += 4;
      if (int64Variables[OFFSET_wOff] == (short) (16 * 4)) processBlock();

      int64Variables[OFFSET_xBufOff] = 0;
    }
    int64Variables[OFFSET_byteCount1]++;

    startOffset++;
    strLen--;
  }
}

public short doFinal(byte[] strToHash, short startOffset, short strLen, byte[] hash, short hashOffset) {
// PROCESS GIVEN DATA
  update(strToHash, startOffset, strLen);

  int64Set(int64Variables, OFFSET_a, (short) 0, (short) 0, (short) 0, int64Variables[OFFSET_byteCount1]);
// shift length by 3
  rotl(OFFSET_a, (byte) 3, OFFSET_a);

//
// add the pad bytes.
//
  update((byte)128);
  while (int64Variables[OFFSET_xBufOff] != 0) update((byte)0);

  if (int64Variables[OFFSET_wOff] > (short) (14 * 4)) processBlock();
//W[14].set((short) 0, (short) 0, (short) 0, (short) 0);
  int64Set(W, (short) (14 * 4), (short) 0, (short) 0, (short) 0, (short) 0);
//W[15].set(int64Variables, OFFSET_a);
  int64Set(W, (short) (15 * 4), int64Variables, OFFSET_a);

  processBlock();

// RETRIEVE HASH
  switch (m_shaType) {
    case SHA_384: {
      //return[H[0].highOrder,H[0].lowOrder,H[1].highOrder,H[1].lowOrder,H[2].highOrder,H[2].lowOrder,H[3].highOrder,H[3].lowOrder,H[4].highOrder,H[4].lowOrder,H[5].highOrder,H[5].lowOrder];
      for (short i = 0; i < 6; i++) {
        H[i].get(hash, (short) (hashOffset + (short) (i * LONG_LENGTH)));
      }
      break;
    }
    case SHA_512: {
      //return[H[0].highOrder,H[0].lowOrder,H[1].highOrder,H[1].lowOrder,H[2].highOrder,H[2].lowOrder,H[3].highOrder,H[3].lowOrder,H[4].highOrder,H[4].lowOrder,H[5].highOrder,H[5].lowOrder,H[6].highOrder,H[6].lowOrder,H[7].highOrder,H[7].lowOrder];
      for (short i = 0; i < 8; i++) {
        H[i].get(hash, (short) (hashOffset + (short) (i * LONG_LENGTH)));
      }
      break;
    }
    default:return (short) -1;
  }

  reset();

  return (short) 0;
}

public void reset() {
  clearState(m_shaType);
  int64Variables[OFFSET_byteCount1] = 0;
  int64Variables[OFFSET_byteCount2] = 0;

  int64Variables[OFFSET_xBufOff] = 0;
  for (short i = 0; i < xBuf.length; i++) xBuf[i] = 0;

  int64Variables[OFFSET_wOff] = 0;
  for (short i = 0; i != (short) W.length; i++) W[i] = 0;
}
/*
protected void processWord(
byte[]  in,
short     inOff) {
W[int64Variables[OFFSET_wOff]].set(in, inOff);
int64Variables[OFFSET_wOff] += 4;
if (int64Variables[OFFSET_wOff] == (short) (16 * 4)) processBlock();
}
/**/

public byte getLength() {
  switch (m_shaType) {
    case SHA_512: return SHA512_DIGEST_LENGTH;
    case SHA_384: return SHA384_DIGEST_LENGTH;
  }

  return (short) 0;
}

public byte getDigestSize() {
    return getLength();
}

public byte getAlgorithm() {
  return m_shaType;
}
/* // THIS IS ORIGINAL VERSION OF SHA2 IMPLEMENTATION THAT WAS NOT ABLE TO PERFORM update() OPERATION
   // BUT ONLY WHOLE ARRAY HASHING AT ONCE. IT IS FASTER, BUT LESS FLEXIBLE.
   // NOTE: TO MAKE THIS WORKING, YOU NEED TO SET FIRST 16 VALUES OF W ARRAY in processBlock()!!!!!!
short getHash512(byte[] strToHash, short startOffset, short strLen, byte[] hash, short hashOffset) {
clearState(SHA_512);
coreSHA2(strToHash, startOffset, strLen, SHA_512, hash, hashOffset);

return SHA512_DIGEST_LENGTH;
}

short getHash384(byte[] strToHash, short startOffset, short strLen, byte[] hash, short hashOffset) {
clearState(SHA_512);
coreSHA2(strToHash, startOffset, strLen, SHA_384, hash, hashOffset);
return SHA384_DIGEST_LENGTH;
}

short coreSHA2(byte[] strToHash, short startOffset, short strLen, short variant, byte[] hash, short hashOffset){
  // PADDING
  // strLen + 2 * LONG_LENGTH  + 1 - 1 ... we must accomodate also 2 x 64bit value of size and starting padd value (0x80),
  // final -1 is to capture situation, when data + padding + length is exactly rounded to multiple of SHA-2 blocks
  short paddedLength = (short) (((short) ((short) ((short) (strLen + 2 * LONG_LENGTH + 1 - 1) / SHA2_BLOCK_LENGTH) * SHA2_BLOCK_LENGTH)) + SHA2_BLOCK_LENGTH);
  //short appendedMessageLength = paddedLength;
  strToHash[(short) (startOffset + strLen)] = (byte) 0x80;
  for (short i = (short) (strLen + 1); i < paddedLength; i++) strToHash[(short) (startOffset + i)] = 0;

  int64Set(int64Variables, OFFSET_a, (short) 0, (short) 0, (short) 0, strLen);
  // shift length by 3
  rotl(OFFSET_a, (byte) 3, OFFSET_a);

  strToHash[(short) (startOffset + paddedLength - 4)] = (byte) 0;
  strToHash[(short) (startOffset + paddedLength - 3)] = (byte) (int64Variables[(short) (OFFSET_a + 2)] & 0xff);
  strToHash[(short) (startOffset + paddedLength - 2)] = (byte) ((int64Variables[(short) (OFFSET_a + 3)] >> 8) & 0xff);
  strToHash[(short) (startOffset + paddedLength - 1)] = (byte) (int64Variables[(short) (OFFSET_a + 3)] & 0xff);

  for (short i=0; i< paddedLength; i += SHA2_BLOCK_LENGTH){
      processBlock(strToHash, (short) (startOffset + i));
  }

  switch (variant) {
      case SHA_384: {
          //return[H[0].highOrder,H[0].lowOrder,H[1].highOrder,H[1].lowOrder,H[2].highOrder,H[2].lowOrder,H[3].highOrder,H[3].lowOrder,H[4].highOrder,H[4].lowOrder,H[5].highOrder,H[5].lowOrder];
          for (short i = 0; i < 6; i++) {
                  H[i].get(hash, (short) (hashOffset + (short) (i * LONG_LENGTH)));
          }
          break;
      }
      case SHA_512: {
            //return[H[0].highOrder,H[0].lowOrder,H[1].highOrder,H[1].lowOrder,H[2].highOrder,H[2].lowOrder,H[3].highOrder,H[3].lowOrder,H[4].highOrder,H[4].lowOrder,H[5].highOrder,H[5].lowOrder,H[6].highOrder,H[6].lowOrder,H[7].highOrder,H[7].lowOrder];
            for (short i = 0; i < 8; i++) {
                    H[i].get(hash, (short) (hashOffset + (short) (i * LONG_LENGTH)));
            }
            break;
      }
      default:return -1;
  }

  return 0;
}
/**/

void processBlock() {
//
// expand 16 word block into 80 word blocks.
//

  for (short t = 16; t < 80; t++)
  {
//  W[t]=safeAdd(safeAdd(safeAdd(Sigma1(W[(short)(t-2)], OFFSET_result1),W[(short)(t-7)], OFFSET_result2),Sigma0(W[(short)(t-15)], OFFSET_result3), OFFSET_result4),W[(short)(t-16)], W[t]);
    safeAdd(safeAdd(safeAdd(Sigma1(W, (short)((t-2) * 4), OFFSET_result1),W, (short)((short)(t-7) * 4), OFFSET_result2),Sigma0(W, (short)((short) (t-15) * 4), OFFSET_result3), OFFSET_result4),W, (short)((short)(t-16) * 4), W, (short) (t * 4));
  }

//
// set up working variables.
//
  int64Set(int64Variables, OFFSET_a, H[0]);
  int64Set(int64Variables, OFFSET_b, H[1]);
  int64Set(int64Variables, OFFSET_c, H[2]);
  int64Set(int64Variables, OFFSET_d, H[3]);
  int64Set(int64Variables, OFFSET_e, H[4]);
  int64Set(int64Variables, OFFSET_f, H[5]);
  int64Set(int64Variables, OFFSET_g, H[6]);
  int64Set(int64Variables, OFFSET_h, H[7]);

  short resultOffset = 0;
  short t = 0;     // this value is incremented in W[t++]
  for(short i = 0; i < 10; i ++) { // TODO: enable all rounds (should be 10)
    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_h,Sum1(OFFSET_e, OFFSET_result1), OFFSET_h),ch(OFFSET_e, OFFSET_f,OFFSET_g,OFFSET_result3), OFFSET_h),K[t],OFFSET_h),W,(short) (t * 4),OFFSET_h);
    t++;
/*
    resultOffset = safeAdd(OFFSET_h,Sum1(OFFSET_e, OFFSET_result1), OFFSET_h);
    resultOffset = safeAdd(OFFSET_h, ch(OFFSET_e, OFFSET_f,OFFSET_g,OFFSET_result3), OFFSET_h);
    resultOffset = safeAdd(OFFSET_h, K[t],OFFSET_h);
    resultOffset = safeAdd(OFFSET_h,W[t++],OFFSET_h);
    /**/
    resultOffset = safeAdd(OFFSET_d,OFFSET_h,OFFSET_d);
    resultOffset = safeAdd(Sum0(OFFSET_a, OFFSET_result1),maj(OFFSET_a,OFFSET_b,OFFSET_c, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_h,OFFSET_T2,OFFSET_h);

    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_g,Sum1(OFFSET_d, OFFSET_result1), OFFSET_g),ch(OFFSET_d,OFFSET_e,OFFSET_f,OFFSET_result3), OFFSET_g),K[t],OFFSET_g),W,(short) (t * 4),OFFSET_g);
    t++;
    resultOffset = safeAdd(OFFSET_c,OFFSET_g,OFFSET_c);
    resultOffset = safeAdd(Sum0(OFFSET_h, OFFSET_result1),maj(OFFSET_h,OFFSET_a,OFFSET_b, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_g,OFFSET_T2,OFFSET_g);

    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_f,Sum1(OFFSET_c, OFFSET_result1), OFFSET_f),ch(OFFSET_c,OFFSET_d,OFFSET_e,OFFSET_result3), OFFSET_f),K[t],OFFSET_f),W,(short) (t * 4),OFFSET_f);
    t++;
    resultOffset = safeAdd(OFFSET_b,OFFSET_f,OFFSET_b);
    resultOffset = safeAdd(Sum0(OFFSET_g, OFFSET_result1),maj(OFFSET_g,OFFSET_h,OFFSET_a, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_f,OFFSET_T2,OFFSET_f);

    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_e,Sum1(OFFSET_b, OFFSET_result1), OFFSET_e),ch(OFFSET_b,OFFSET_c,OFFSET_d, OFFSET_result3), OFFSET_e),K[t],OFFSET_e),W,(short) (t * 4),OFFSET_e);
    t++;
    resultOffset = safeAdd(OFFSET_a,OFFSET_e,OFFSET_a);
    resultOffset = safeAdd(Sum0(OFFSET_f, OFFSET_result1),maj(OFFSET_f,OFFSET_g,OFFSET_h, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_e,OFFSET_T2,OFFSET_e);

    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_d,Sum1(OFFSET_a, OFFSET_result1), OFFSET_d),ch(OFFSET_a, OFFSET_b,OFFSET_c, OFFSET_result3), OFFSET_d),K[t],OFFSET_d),W,(short) (t * 4),OFFSET_d);
    t++;
    resultOffset = safeAdd(OFFSET_h,OFFSET_d,OFFSET_h);
    resultOffset = safeAdd(Sum0(OFFSET_e, OFFSET_result1),maj(OFFSET_e,OFFSET_f,OFFSET_g, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_d,OFFSET_T2,OFFSET_d);

    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_c,Sum1(OFFSET_h, OFFSET_result1), OFFSET_c),ch(OFFSET_h,OFFSET_a,OFFSET_b, OFFSET_result3), OFFSET_c),K[t],OFFSET_c),W,(short) (t * 4),OFFSET_c);
    t++;
    resultOffset = safeAdd(OFFSET_g,OFFSET_c,OFFSET_g);
    resultOffset = safeAdd(Sum0(OFFSET_d, OFFSET_result1),maj(OFFSET_d,OFFSET_e,OFFSET_f, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_c,OFFSET_T2,OFFSET_c);

    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_b,Sum1(OFFSET_g, OFFSET_result1), OFFSET_b),ch(OFFSET_g,OFFSET_h,OFFSET_a, OFFSET_result3), OFFSET_b),K[t],OFFSET_b),W,(short) (t * 4),OFFSET_b);
    t++;
    resultOffset = safeAdd(OFFSET_f,OFFSET_b,OFFSET_f);
    resultOffset = safeAdd(Sum0(OFFSET_c, OFFSET_result1),maj(OFFSET_c,OFFSET_d,OFFSET_e, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_b,OFFSET_T2,OFFSET_b);

    resultOffset = safeAdd(safeAdd(safeAdd(safeAdd(OFFSET_a,Sum1(OFFSET_f, OFFSET_result1), OFFSET_a),ch(OFFSET_f,OFFSET_g,OFFSET_h, OFFSET_result3), OFFSET_a),K[t],OFFSET_a),W,(short) (t * 4),OFFSET_a);
    t++;
    resultOffset = safeAdd(OFFSET_e,OFFSET_a,OFFSET_e);
    resultOffset = safeAdd(Sum0(OFFSET_b, OFFSET_result1),maj(OFFSET_b,OFFSET_c,OFFSET_d, OFFSET_result2),OFFSET_T2);
    resultOffset = safeAdd(OFFSET_a,OFFSET_T2,OFFSET_a);

  }

  safeAdd(OFFSET_a,H[0],OFFSET_a);
  H[0].set(int64Variables, OFFSET_a);
  safeAdd(OFFSET_b,H[1],OFFSET_b);
  H[1].set(int64Variables, OFFSET_b);
  safeAdd(OFFSET_c,H[2],OFFSET_c);
  H[2].set(int64Variables, OFFSET_c);
  safeAdd(OFFSET_d,H[3],OFFSET_d);
  H[3].set(int64Variables, OFFSET_d);
  safeAdd(OFFSET_e,H[4],OFFSET_e);
  H[4].set(int64Variables, OFFSET_e);
  safeAdd(OFFSET_f,H[5],OFFSET_f);
  H[5].set(int64Variables, OFFSET_f);
  safeAdd(OFFSET_g,H[6],OFFSET_g);
  H[6].set(int64Variables, OFFSET_g);
  safeAdd(OFFSET_h,H[7],OFFSET_h);
  H[7].set(int64Variables, OFFSET_h);

//
// reset the offset and clean out the word buffer.
//
  int64Variables[OFFSET_wOff] = 0;
  for (short i = 0; i < (short) W.length; i++) W[i] = 0;
}

public short rotr(short offset_x, byte n, short offset_result){
//if (rotr_counter < 16000) rotr_counter++;

// right rotation
//int64Set(int64Variables, offset_result, int64Variables, offset_x);
  int64Variables[offset_result] = int64Variables[offset_x];
  int64Variables[(short) (offset_result + 1)] = int64Variables[(short) (offset_x + 1)];
  int64Variables[(short) (offset_result + 2)] = int64Variables[(short) (offset_x + 2)];
  int64Variables[(short) (offset_result + 3)] = int64Variables[(short) (offset_x + 3)];
//    int64Variables[offset_result] = int64Variables[offset_x]; int64Variables[(short) (offset_result + 1)] = int64Variables[(short) (offset_x + 1)]; int64Variables[(short) (offset_result + 2)] = int64Variables[(short) (offset_x + 2)]; int64Variables[(short) (offset_result + 3)] = int64Variables[(short) (offset_x + 3)];
//    result.set(x);

// ROTATE BY 16 UNTIL
  while (n >= 16) {
    int64Variables[(short) (offset_result + 3)] = int64Variables[(short) (offset_result + 2)];
    int64Variables[(short) (offset_result + 2)] = int64Variables[(short) (offset_result + 1)];
    int64Variables[(short) (offset_result + 1)] = int64Variables[(short) (offset_result)];
    int64Variables[offset_result] = (short) 0;
    n = (byte) (n - 16);
  }

// ROTATE REST
  if (n > 0) {
    short mask = 0;
    switch (n) {
      case 1: mask = (short)0x7fff; break;
      case 2: mask = (short)0x3fff; break;
      case 3: mask = (short)0x1fff; break;
      case 4: mask = (short)0x0fff; break;
      case 5: mask = (short)0x07ff; break;
      case 6: mask = (short)0x03ff; break;
      case 7: mask = (short)0x01ff; break;

      case 8: mask = (short)0x00ff; break;
      case 9: mask = (short)0x007f; break;
      case 10: mask = (short)0x003f; break;
      case 11: mask = (short)0x001f; break;
      case 12: mask = (short)0x000f; break;
      case 13: mask = (short)0x0007; break;
      case 14: mask = (short)0x0003; break;
      case 15: mask = (short)0x0001; break;
    }
    int64Variables[(short) (offset_result + 3)] = (short) ((short) (int64Variables[(short) (offset_result + 2)] << (16 - n))  | (short) (int64Variables[(short) (offset_result + 3)] >> n & mask));
    int64Variables[(short) (offset_result + 2)] = (short) ((short) (int64Variables[(short) (offset_result + 1)]  << (16 - n))  | (short) (int64Variables[(short) (offset_result + 2)] >> n & mask));
    int64Variables[(short) (offset_result + 1)] = (short) ((short) (int64Variables[(short) (offset_result)] << (16 - n))  | (short) (int64Variables[(short) (offset_result + 1)] >> n & mask));
    int64Variables[offset_result] = (short) ((int64Variables[(short) (offset_result)] >> n) & mask);
  }
  return offset_result;
}

public short rotl(short offset_x, byte n, short offset_result){
//if (rotl_counter < 16000) rotl_counter++;
// left rotation
//int64Set(int64Variables, offset_result, int64Variables, offset_x);
  int64Variables[offset_result] = int64Variables[offset_x];
  int64Variables[(short) (offset_result + 1)] = int64Variables[(short) (offset_x + 1)];
  int64Variables[(short) (offset_result + 2)] = int64Variables[(short) (offset_x + 2)];
  int64Variables[(short) (offset_result + 3)] = int64Variables[(short) (offset_x + 3)];

// ROTATE BY 16 UNTIL
  while (n >= 16) {
//int64Set(int64Variables, offset_result, int64Variables[(short) (offset_result + 1)], int64Variables[(short) (offset_result + 2)], int64Variables[(short) (offset_result + 3)], (short) 0);
    int64Variables[offset_result] = int64Variables[(short) (offset_result + 1)];
    int64Variables[(short) (offset_result + 1)] = int64Variables[(short) (offset_result + 2)];
    int64Variables[(short) (offset_result + 2)] = int64Variables[(short) (offset_result + 3)];
    int64Variables[(short) (offset_result + 3)] = 0;
    n = (byte) (n - 16);
  }

// ROTATE BY 8 UNTIL
  while (n >= 8) {
//  int64Set(int64Variables, offset_result, (short) ((short) (int64Variables[(short) (offset_result)] << 8) | (short) (int64Variables[(short) (offset_result + 1)] >> 8 & 0xff)), (short) ((short) (int64Variables[(short) (offset_result + 1)] << 8) | (short) (int64Variables[(short) (offset_result + 2)] >> 8 & 0xff)),  (short) ((short) (int64Variables[(short) (offset_result + 2)] << 8) | (short) (int64Variables[(short) (offset_result + 3)] >> 8 & 0xff)),  (short) (int64Variables[(short) (offset_result + 3)] << 8));
    int64Variables[offset_result] = (short) ((short) (int64Variables[(short) (offset_result)] << 8) | (short) (int64Variables[(short) (offset_result + 1)] >> 8 & 0xff));
    int64Variables[(short) (offset_result + 1)] = (short) ((short) (int64Variables[(short) (offset_result + 1)] << 8) | (short) (int64Variables[(short) (offset_result + 2)] >> 8 & 0xff));
    int64Variables[(short) (offset_result + 2)] = (short) ((short) (int64Variables[(short) (offset_result + 2)] << 8) | (short) (int64Variables[(short) (offset_result + 3)] >> 8 & 0xff));
    int64Variables[(short) (offset_result + 3)] = (short) (int64Variables[(short) (offset_result + 3)] << 8);
    n = (byte) (n - 8);
  }

// ROTATE REMAINING
  if (n > 0) {
    short mask = 0;
    switch (n) {
      case 1: mask = (short)0x0001; break;
      case 2: mask = (short)0x0003; break;
      case 3: mask = (short)0x0007; break;
      case 4: mask = (short)0x000f; break;
      case 5: mask = (short)0x001f; break;
      case 6: mask = (short)0x003f; break;
      case 7: mask = (short)0x007f; break;
    }
//int64Set(int64Variables, offset_result, (short) ((short) (int64Variables[(short) (offset_result)] << n) | (short) (int64Variables[(short) (offset_result + 1)] >> (16 - n) & mask)),  (short) ((short) (int64Variables[(short) (offset_result + 1)] << n) | (short) (int64Variables[(short) (offset_result + 2)] >> (16 - n) & mask)),  (short) ((short) (int64Variables[(short) (offset_result + 2)] << n) | (short) (int64Variables[(short) (offset_result + 3)] >> (16 - n) & mask)), (short) (int64Variables[(short) (offset_result + 3)] << n));
    int64Variables[offset_result] = (short) ((short) (int64Variables[(short) (offset_result)] << n) | (short) (int64Variables[(short) (offset_result + 1)] >> (16 - n) & mask));
    int64Variables[(short) (offset_result + 1)] = (short) ((short) (int64Variables[(short) (offset_result + 1)] << n) | (short) (int64Variables[(short) (offset_result + 2)] >> (16 - n) & mask));
    int64Variables[(short) (offset_result + 2)] = (short) ((short) (int64Variables[(short) (offset_result + 2)] << n) | (short) (int64Variables[(short) (offset_result + 3)] >> (16 - n) & mask));
    int64Variables[(short) (offset_result + 3)] = (short) (int64Variables[(short) (offset_result + 3)] << n);
  }
  return offset_result;
}

//  Int_64 ch(Int_64 x, Int_64 y, Int_64 z, Int_64 result){
short ch(short offset_x, short offset_y, short offset_z, short offset_result){
//if (ch_counter < 16000) ch_counter++;
// (x and y) xor ((not x) and z)
  int64Variables[offset_result] = (short) ((short) (int64Variables[(short) (offset_x)] &     int64Variables[(short) (offset_y)]) ^    (short) (~(int64Variables[(short) (offset_x)]) &     int64Variables[(short) (offset_z)]));
  int64Variables[(short) (offset_result + 1)] = (short) ((short) (int64Variables[(short) (offset_x + 1)] & int64Variables[(short) (offset_y + 1)])^ (short) (~(int64Variables[(short) (offset_x + 1)]) & int64Variables[(short) (offset_z + 1)]));
  int64Variables[(short) (offset_result + 2)] = (short) ((short) (int64Variables[(short) (offset_x + 2)] & int64Variables[(short) (offset_y + 2)])^ (short) (~(int64Variables[(short) (offset_x + 2)]) & int64Variables[(short) (offset_z + 2)]));
  int64Variables[(short) (offset_result + 3)] = (short) ((short) (int64Variables[(short) (offset_x + 3)] & int64Variables[(short) (offset_y + 3)])^ (short) (~(int64Variables[(short) (offset_x + 3)]) & int64Variables[(short) (offset_z + 3)]));

  return offset_result;
}

short maj(short offset_x, short offset_y, short offset_z, short offset_result){
//if (maj_counter < 16000) maj_counter++;
// (x and y) xor (x and z) xor (y and z)
//int64Set(int64Variables, offset_result, (short) ((short) (int64Variables[(short) (offset_x)] & int64Variables[(short) (offset_y)]) ^ (short)(int64Variables[(short) (offset_x)] & int64Variables[(short) (offset_z)])^ (short) (int64Variables[(short) (offset_y)] & int64Variables[(short) (offset_z)])), (short) ((short) (int64Variables[(short) (offset_x + 1)] & int64Variables[(short) (offset_y + 1)]) ^ (short)(int64Variables[(short) (offset_x + 1)] & int64Variables[(short) (offset_z + 1)])^ (short) (int64Variables[(short) (offset_y + 1)] & int64Variables[(short) (offset_z + 1)])), (short) ((short) (int64Variables[(short) (offset_x + 2)] & int64Variables[(short) (offset_y + 2)]) ^ (short)(int64Variables[(short) (offset_x + 2)] & int64Variables[(short) (offset_z + 2)])^ (short) (int64Variables[(short) (offset_y + 2)] & int64Variables[(short) (offset_z + 2)])), (short) ((short) (int64Variables[(short) (offset_x + 3)] & int64Variables[(short) (offset_y + 3)]) ^ (short)(int64Variables[(short) (offset_x + 3)] & int64Variables[(short) (offset_z + 3)])^ (short) (int64Variables[(short) (offset_y + 3)] & int64Variables[(short) (offset_z + 3)])));
  int64Variables[offset_result] = (short) ((short) (int64Variables[(short) (offset_x)] & int64Variables[(short) (offset_y)]) ^ (short)(int64Variables[(short) (offset_x)] & int64Variables[(short) (offset_z)])^ (short) (int64Variables[(short) (offset_y)] & int64Variables[(short) (offset_z)]));
  int64Variables[(short) (offset_result + 1)] = (short) ((short) (int64Variables[(short) (offset_x + 1)] & int64Variables[(short) (offset_y + 1)]) ^ (short)(int64Variables[(short) (offset_x + 1)] & int64Variables[(short) (offset_z + 1)])^ (short) (int64Variables[(short) (offset_y + 1)] & int64Variables[(short) (offset_z + 1)]));
  int64Variables[(short) (offset_result + 2)] = (short) ((short) (int64Variables[(short) (offset_x + 2)] & int64Variables[(short) (offset_y + 2)]) ^ (short)(int64Variables[(short) (offset_x + 2)] & int64Variables[(short) (offset_z + 2)])^ (short) (int64Variables[(short) (offset_y + 2)] & int64Variables[(short) (offset_z + 2)]));
  int64Variables[(short) (offset_result + 3)] = (short) ((short) (int64Variables[(short) (offset_x + 3)] & int64Variables[(short) (offset_y + 3)]) ^ (short)(int64Variables[(short) (offset_x + 3)] & int64Variables[(short) (offset_z + 3)])^ (short) (int64Variables[(short) (offset_y + 3)] & int64Variables[(short) (offset_z + 3)]));

  return offset_result;
}


short Sum0(short offset_x, short offset_result)  {
//if (sum0_counter < 16000) sum0_counter++;

//return ((x << 36)|(x >>> 28)) ^ ((x << 30)|(x >>> 34)) ^ ((x << 25)|(x >>> 39));
  rotl(offset_x,(byte)36,OFFSET_rotl_1);
  rotr(offset_x,(byte)28,OFFSET_rotr_1);

  rotl(offset_x,(byte)30,OFFSET_rotl_2);
  rotr(offset_x,(byte)34,OFFSET_rotr_2);

  rotl(offset_x,(byte)25,OFFSET_rotl_3);
  rotr(offset_x,(byte)39,OFFSET_rotr_3);

  int64Variables[offset_result] = (short) ((short) ((short) (int64Variables[(OFFSET_rotr_1)] | int64Variables[(OFFSET_rotl_1)])) ^ (short) ((short) (int64Variables[(OFFSET_rotl_2)] | int64Variables[(OFFSET_rotr_2)])) ^ (short) ((short) (int64Variables[(OFFSET_rotl_3)] | int64Variables[(OFFSET_rotr_3)])));
  int64Variables[(short) (offset_result + 1)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 1)] | int64Variables[(short) (OFFSET_rotr_1 + 1)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 1)] | int64Variables[(short) (OFFSET_rotr_2 + 1)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_3 + 1)] | int64Variables[(short) (OFFSET_rotr_3 + 1)])));
  int64Variables[(short) (offset_result + 2)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 2)] | int64Variables[(short) (OFFSET_rotr_1 + 2)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 2)] | int64Variables[(short) (OFFSET_rotr_2 + 2)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_3 + 2)] | int64Variables[(short) (OFFSET_rotr_3 + 2)])));
  int64Variables[(short) (offset_result + 3)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 3)] | int64Variables[(short) (OFFSET_rotr_1 + 3)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 3)] | int64Variables[(short) (OFFSET_rotr_2 + 3)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_3 + 3)] | int64Variables[(short) (OFFSET_rotr_3 + 3)])));

  return offset_result;
}

short Sum1(short offset_x, short offset_result) {
//if (sum1_counter < 16000) sum1_counter++;

//return ((x << 50)|(x >>> 14)) ^ ((x << 46)|(x >>> 18)) ^ ((x << 23)|(x >>> 41));
  rotl(offset_x,(byte)50,OFFSET_rotl_1);
  rotr(offset_x,(byte)14,OFFSET_rotr_1);

  rotl(offset_x,(byte)46,OFFSET_rotl_2);
  rotr(offset_x,(byte)18,OFFSET_rotr_2);

  rotl(offset_x,(byte)23,OFFSET_rotl_3);
  rotr(offset_x,(byte)41,OFFSET_rotr_3);

  int64Variables[offset_result] = (short) ((short) ((short) (int64Variables[(OFFSET_rotl_1)] | int64Variables[(OFFSET_rotr_1)])) ^ (short) ((short) (int64Variables[(OFFSET_rotl_2)] | int64Variables[(OFFSET_rotr_2)])) ^ (short) ((short) (int64Variables[(OFFSET_rotl_3)] | int64Variables[(OFFSET_rotr_3)])));
  int64Variables[(short) (offset_result + 1)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 1)] | int64Variables[(short) (OFFSET_rotr_1 + 1)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 1)] | int64Variables[(short) (OFFSET_rotr_2 + 1)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_3 + 1)] | int64Variables[(short) (OFFSET_rotr_3 + 1)])));
  int64Variables[(short) (offset_result + 2)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 2)] | int64Variables[(short) (OFFSET_rotr_1 + 2)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 2)] | int64Variables[(short) (OFFSET_rotr_2 + 2)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_3 + 2)] | int64Variables[(short) (OFFSET_rotr_3 + 2)])));
  int64Variables[(short) (offset_result + 3)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 3)] | int64Variables[(short) (OFFSET_rotr_1 + 3)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 3)] | int64Variables[(short) (OFFSET_rotr_2 + 3)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_3 + 3)] | int64Variables[(short) (OFFSET_rotr_3 + 3)])));

  return offset_result;
}

short Sigma0(Int_64 x, short offset_result) {
  x.get(int64Variables, OFFSET_Sigma0);
  return Sigma0(OFFSET_Sigma0, offset_result);
}
short Sigma0(short[] xArray, short xOffset, short offset_result) {
  for (short i = 0; i < (short) 4; i++) int64Variables[(short) (OFFSET_Sigma0 + i)] = xArray[(short) (xOffset + i)];
  return Sigma0(OFFSET_Sigma0, offset_result);
}
short Sigma0(short offset_x, short offset_result) {
//if (sigma0_counter < 16000) sigma0_counter++;
//return ((x << 63)|(x >>> 1)) ^ ((x << 56)|(x >>> 8)) ^ (x >>> 7);
  rotl(offset_x,(byte)63,OFFSET_rotl_1);
  rotr(offset_x,(byte)1,OFFSET_rotr_1);

  rotl(offset_x,(byte)56,OFFSET_rotl_2);
  rotr(offset_x,(byte)8,OFFSET_rotr_2);

  rotr(offset_x,(byte)7,OFFSET_rotr_3);

  int64Variables[offset_result] = (short) ((short) ((short) (int64Variables[(OFFSET_rotl_1)] | int64Variables[(OFFSET_rotr_1)])) ^ (short) ((short) (int64Variables[(OFFSET_rotl_2)] | int64Variables[(OFFSET_rotr_2)])) ^ int64Variables[(OFFSET_rotr_3)]);
  int64Variables[(short) (offset_result + 1)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 1)] | int64Variables[(short) (OFFSET_rotr_1 + 1)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 1)] | int64Variables[(short) (OFFSET_rotr_2 + 1)])) ^ int64Variables[(short) (OFFSET_rotr_3 + 1)]);
  int64Variables[(short) (offset_result + 2)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 2)] | int64Variables[(short) (OFFSET_rotr_1 + 2)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 2)] | int64Variables[(short) (OFFSET_rotr_2 + 2)])) ^ int64Variables[(short) (OFFSET_rotr_3 + 2)]);
  int64Variables[(short) (offset_result + 3)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 3)] | int64Variables[(short) (OFFSET_rotr_1 + 3)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 3)] | int64Variables[(short) (OFFSET_rotr_2 + 3)])) ^ int64Variables[(short) (OFFSET_rotr_3 + 3)]);

  return offset_result;
}

short Sigma1(Int_64 x, short offset_result) {
  x.get(int64Variables, OFFSET_Sigma1);
  return Sigma1(OFFSET_Sigma1, offset_result);
}

short Sigma1(short[] xArray, short xOffset, short offset_result) {
  for (short i = 0; i < (short) 4; i++) int64Variables[(short) (OFFSET_Sigma1 + i)] = xArray[(short) (xOffset + i)];
  return Sigma1(OFFSET_Sigma1, offset_result);
}

short Sigma1(short offset_x, short offset_result) {
//if (sigma1_counter < 16000) sigma1_counter++;

//return ((x << 45)|(x >>> 19)) ^ ((x << 3)|(x >>> 61)) ^ (x >>> 6);
  rotl(offset_x,(byte)45,OFFSET_rotl_1);
  rotr(offset_x,(byte)19,OFFSET_rotr_1);

  rotl(offset_x,(byte)3,OFFSET_rotl_2);
  rotr(offset_x,(byte)61,OFFSET_rotr_2);

  rotr(offset_x,(byte)6,OFFSET_rotr_3);

  int64Variables[offset_result] = (short) ((short) ((short) (int64Variables[(OFFSET_rotl_1)] | int64Variables[(OFFSET_rotr_1)])) ^ (short) ((short) (int64Variables[(OFFSET_rotl_2)] | int64Variables[(OFFSET_rotr_2)])) ^ int64Variables[(OFFSET_rotr_3)]);
  int64Variables[(short) (offset_result + 1)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 1)] | int64Variables[(short) (OFFSET_rotr_1 + 1)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 1)] | int64Variables[(short) (OFFSET_rotr_2 + 1)])) ^ int64Variables[(short) (OFFSET_rotr_3 + 1)]);
  int64Variables[(short) (offset_result + 2)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 2)] | int64Variables[(short) (OFFSET_rotr_1 + 2)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 2)] | int64Variables[(short) (OFFSET_rotr_2 + 2)])) ^ int64Variables[(short) (OFFSET_rotr_3 + 2)]);
  int64Variables[(short) (offset_result + 3)] = (short) ((short) ((short) (int64Variables[(short) (OFFSET_rotl_1 + 3)] | int64Variables[(short) (OFFSET_rotr_1 + 3)])) ^ (short) ((short) (int64Variables[(short) (OFFSET_rotl_2 + 3)] | int64Variables[(short) (OFFSET_rotr_2 + 3)])) ^ int64Variables[(short) (OFFSET_rotr_3 + 3)]);

  return offset_result;
}

short safeAdd(short offset_x, Int_64 y, short offset_result) {
  y.get(int64Variables, OFFSET_safeAdd);
  return safeAdd(offset_x, OFFSET_safeAdd, offset_result);
}

Int_64 safeAdd(short offset_x, Int_64 y, Int_64 result) {
  y.get(int64Variables, OFFSET_safeAdd);
  safeAdd(offset_x, OFFSET_safeAdd, OFFSET_safeAdd2);
  result.set(int64Variables, OFFSET_safeAdd2);
  return result;
}

short safeAdd(short offset_x, short[] yArray, short yOffset, short[] resultArray, short resultOffset) {
  int64Variables[(short) (OFFSET_safeAdd + 0)] = yArray[(short) (yOffset + 0)];
  int64Variables[(short) (OFFSET_safeAdd + 1)] = yArray[(short) (yOffset + 1)];
  int64Variables[(short) (OFFSET_safeAdd + 2)] = yArray[(short) (yOffset + 2)];
  int64Variables[(short) (OFFSET_safeAdd + 3)] = yArray[(short) (yOffset + 3)];

  safeAdd(offset_x, OFFSET_safeAdd, OFFSET_safeAdd2);

  resultArray[(short) (resultOffset + 0)] = int64Variables[(short) (OFFSET_safeAdd2 + 0)];
  resultArray[(short) (resultOffset + 1)] = int64Variables[(short) (OFFSET_safeAdd2 + 1)];
  resultArray[(short) (resultOffset + 2)] = int64Variables[(short) (OFFSET_safeAdd2 + 2)];
  resultArray[(short) (resultOffset + 3)] = int64Variables[(short) (OFFSET_safeAdd2 + 3)];
  return resultOffset;
}

short safeAdd(short offset_x, short[] yArray, short yOffset, short offset_result) {
  int64Variables[(short) (OFFSET_safeAdd + 0)] = yArray[(short) (yOffset + 0)];
  int64Variables[(short) (OFFSET_safeAdd + 1)] = yArray[(short) (yOffset + 1)];
  int64Variables[(short) (OFFSET_safeAdd + 2)] = yArray[(short) (yOffset + 2)];
  int64Variables[(short) (OFFSET_safeAdd + 3)] = yArray[(short) (yOffset + 3)];
  return safeAdd(offset_x, OFFSET_safeAdd, offset_result);
}


short safeAdd(short offset_x, short offset_y, short offset_result) {
//if (add_counter < 16000) add_counter++;

  boolean bOverflow = false;
  short a1 = (short) ((int64Variables[(short) (offset_x + 3)] & 0xFF) + (int64Variables[(short) (offset_y + 3)] & 0xFF));
  short a2 = (short) ((int64Variables[(short) (offset_x + 3)] >> 8)+(int64Variables[(short) (offset_y + 3)] >> 8)+(a1 >>> 8));
  short lowest = (short) (((a2 & 0xFF)<< 8)|(a1 & 0xFF));

  a1 = (short) ((int64Variables[(short) (offset_x + 2)] & 0xFF) + (int64Variables[(short) (offset_y + 2)] & 0xFF) + (a2 >>> 8));
  a2 = (short) ((int64Variables[(short) (offset_x + 2)] >> 8)+(int64Variables[(short) (offset_y + 2)] >> 8)+(a1 >>> 8));
  short lower = (short) (((a2 & 0xFF)<< 8)|(a1 & 0xFF));
// compensate detected overflow from previous subpart add
  if (bOverflow) {
    lower++;
    bOverflow = false;
    if (lower == 0) bOverflow = true;
  }
// compensate missing sign bit, but detect possible overflow
  if (int64Variables[(short) (offset_x + 3)] < 0) {
    lower++;
    if (lower == 0) bOverflow = true;
  }
  if (int64Variables[(short) (offset_y + 3)] < 0) {
    lower++;
    if (lower == 0) bOverflow = true;
  }


  a1 = (short) ((int64Variables[(short) (offset_x + 1)] & 0xFF) + (int64Variables[(short) (offset_y + 1)] & 0xFF) + (a2 >>> 8));
  a2 = (short) ((int64Variables[(short) (offset_x + 1)] >> 8)+(int64Variables[(short) (offset_y + 1)] >> 8)+(a1 >>> 8));
  short higher = (short) (((a2 & 0xFF)<< 8)|(a1 & 0xFF));
// compensate detected overflow from previous subpart add
  if (bOverflow) {
    higher++;
    bOverflow = false;
    if (higher == 0) bOverflow = true;
  }
// compensate missing sign bit, but detect possible overflow
  if (int64Variables[(short) (offset_x + 2)] < 0) {
    higher++;
    if (higher == 0) bOverflow = true;
  }
  if (int64Variables[(short) (offset_y + 2)] < 0) {
    higher++;
    if (higher == 0) bOverflow = true;
  }

  a1 = (short) ((int64Variables[(short) (offset_x)] & 0xFF) + (int64Variables[(short) (offset_y)] & 0xFF) + (a2 >>> 8));
  a2 = (short) ((int64Variables[(short) (offset_x)] >> 8)+(int64Variables[(short) (offset_y)] >> 8)+(a1 >>> 8));
  short highest = (short) (((a2 & 0xFF)<< 8)|(a1 & 0xFF));

// compensate detected overflow from previous subpart add
  if (bOverflow) {
    highest++;
    bOverflow = false;
    if (highest == 0) bOverflow = true;
  }
// compensate missing sign bit, but detect possible overflow
  if (int64Variables[(short) (offset_x + 1)] < 0) {
    highest++;
    if (highest == 0) bOverflow = true;
  }
  if (int64Variables[(short) (offset_y + 1)] < 0) {
    highest++;
    if (highest == 0) bOverflow = true;
  }

//int64Set(int64Variables, offset_result, highest, higher, lower, lowest);
  int64Variables[offset_result] = highest;
  int64Variables[(short) (offset_result + 1)] = higher;
  int64Variables[(short) (offset_result + 2)] = lower;
  int64Variables[(short) (offset_result + 3)] = lowest;
  /**/
  return offset_result;
}


}
