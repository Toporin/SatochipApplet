/*
 * JavaCard class for work with 64bits long numbers.
 * Created by Petr Svenda http://www.svenda.com/petr

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
   2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
   3. The name of the author may not be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package org.satochip.applet;

public class Int_64 {
          public final static byte INT_64_LENGTH = 8;
          public short highest;
          public short higher;
          public short lower;
          public short lowest;

          public Int_64() {
          }
          public Int_64(short highest, short higher, short lower, short lowest) {
            set(highest, higher, lower, lowest);
          }
          public Int_64(Int_64 template) {
            set(template);
          }
          public void set(short highest, short higher, short lower, short lowest) {
            this.highest=highest;
            this.higher=higher;
            this.lower=lower;
            this.lowest=lowest;
          }
          public void set(Int_64 template) {
            this.highest=template.highest;
            this.higher=template.higher;
            this.lower=template.lower;
            this.lowest=template.lowest;
          }
          public void set(byte[] value, short offset) {
            this.highest = (short) (value[offset] << 8 | (short) ( value[(short) (offset + 1)] & 0xff));
            this.higher = (short) (value[(short) (offset + 2)] << 8 |(short) ( value[(short) (offset + 3)] & 0xff));
            this.lower = (short) (value[(short) (offset + 4)] << 8 | (short) ( value[(short) (offset + 5)] & 0xff));
            this.lowest = (short) (value[(short) (offset + 6)] << 8 | (short) ( value[(short) (offset + 7)] & 0xff));
          }

          public void set(short[] value, short offset) {
            this.highest = value[offset];
            this.higher = value[(short) (offset + 1)];
            this.lower = value[(short) (offset + 2)];
            this.lowest = value[(short) (offset + 3)];
          }

          public void get(byte[] value, short offset) {
            value[(short) (offset + 0)] = (byte) (highest >> 8);
            value[(short) (offset + 1)] = (byte) (highest & 0xff);
            value[(short) (offset + 2)] = (byte) (higher >> 8);
            value[(short) (offset + 3)] = (byte) (higher & 0xff);
            value[(short) (offset + 4)] = (byte) (lower >> 8);
            value[(short) (offset + 5)] = (byte) (lower & 0xff);
            value[(short) (offset + 6)] = (byte) (lowest >> 8);
            value[(short) (offset + 7)] = (byte) (lowest & 0xff);
          }
          public void get(short[] value, short offset) {
            value[(short) (offset + 0)] = highest;
            value[(short) (offset + 1)] = higher;
            value[(short) (offset + 2)] = lower;
            value[(short) (offset + 3)] = lowest;
          }
}