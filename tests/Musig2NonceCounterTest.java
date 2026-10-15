import com.licel.jcardsim.base.Simulator;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Arrays;
import javacard.framework.AID;
import javacard.framework.APDU;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.security.ECPrivateKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import org.satochip.applet.CardEdge;
import org.satochip.applet.Secp256k1;

/** Simulator-only regression: invoke the real nonce handler with disposable state. */
public final class Musig2NonceCounterTest extends Simulator {
    private final CardEdge applet;

    private Musig2NonceCounterTest() throws Exception {
        byte[] aidBytes = {0x53, 0x61, 0x74, 0x6f, 0x43, 0x68, 0x69, 0x70, 0};
        AID aid = new AID(aidBytes, (short) 0, (byte) aidBytes.length);
        installApplet(aid, CardEdge.class);
        selectApplet(aid);
        applet = (CardEdge) runtime.lookupApplet(aid).getApplet();

        // Set up a validated test PIN and the public fixture private key 1.
        // Reflection bypasses transport/setup only; production handlers are unchanged.
        byte[] pinBytes = {1, 2, 3, 4};
        OwnerPIN pin = new OwnerPIN((byte) 3, (byte) pinBytes.length);
        pin.update(pinBytes, (short) 0, (byte) pinBytes.length);
        require(pin.check(pinBytes, (short) 0, (byte) pinBytes.length), "test PIN");
        ((OwnerPIN[]) field("pins").get(applet))[0] = pin;
        ECPrivateKey key = (ECPrivateKey) KeyBuilder.buildKey(
                KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false);
        Secp256k1.setCommonCurveParameters(key);
        byte[] scalar = new byte[32];
        scalar[31] = 1;
        key.setS(scalar, (short) 0, (short) scalar.length);
        ((Key[]) field("eckeys").get(applet))[0] = key;
    }

    private static Field field(String name) throws Exception {
        Field field = CardEdge.class.getDeclaredField(name);
        field.setAccessible(true);
        return field;
    }

    private short invoke(String name, byte[] buffer) throws Exception {
        Method method = CardEdge.class.getDeclaredMethod(name, APDU.class, byte[].class);
        method.setAccessible(true);
        try {
            return (Short) method.invoke(applet, null, buffer);
        } catch (InvocationTargetException exception) {
            Throwable cause = exception.getCause();
            if (cause instanceof Exception) throw (Exception) cause;
            throw exception;
        }
    }

    private void counter(int value) throws Exception {
        field("bip327_counter").setShort(applet, (short) value);
    }

    private byte[] nonce(int expectedId) throws Exception {
        byte[] buffer = new byte[260];
        buffer[3] = 1; // OP_INIT, key slot 0
        buffer[4] = 3;
        buffer[5] = 0; // no aggregate public key
        buffer[6] = (byte) 0xff; // no message
        buffer[7] = 0; // no extra input
        require(invoke("Musig2GenerateNonce", buffer) == 68, "public nonce length");
        int id = ((buffer[66] & 0xff) << 8) | (buffer[67] & 0xff);
        require(id == expectedId, "returned ID " + id + " != " + expectedId);
        short[] ids = (short[]) field("bip327_valid_ids").get(applet);
        require(ids[expectedId % ids.length] == (short) expectedId, "stored ID slot");
        buffer = new byte[260];
        buffer[3] = 3; // OP_FINALIZE exports the authenticated encrypted nonce
        require(invoke("Musig2GenerateNonce", buffer) == 144, "encrypted nonce length");
        return Arrays.copyOf(buffer, 144);
    }

    private void rejectToken(byte[] token, int expectedStatus) throws Exception {
        byte[] buffer = new byte[260];
        buffer[3] = 1;
        buffer[4] = (byte) token.length;
        System.arraycopy(token, 0, buffer, 5, token.length);
        require(invoke("Musig2SignHash", buffer) == 0, "sign init length");
        buffer = new byte[260];
        buffer[3] = 3;
        buffer[4] = 66;
        try {
            invoke("Musig2SignHash", buffer);
            throw new AssertionError("expected token rejection");
        } catch (ISOException exception) {
            require((exception.getReason() & 0xffff) == expectedStatus, "token status");
        }
    }

    private static void require(boolean condition, String message) {
        if (!condition) throw new AssertionError(message);
    }

    public static void main(String[] args) throws Exception {
        Musig2NonceCounterTest test = new Musig2NonceCounterTest();
        test.counter(32767);
        for (int id = 32767; id <= 32769; id++) {
            test.nonce(id);
            System.out.println("counter " + id + ": PASS");
        }
        // Continue across the sign boundary until the ring evicts its first token.
        test.counter(32767);
        byte[] oldest = test.nonce(32767);
        for (int id = 32768; id <= 32783; id++) test.nonce(id);
        test.rejectToken(oldest, 0x9c47);
        System.out.println("17 outstanding nonces across sign boundary: oldest rejected (9c47)");

        test.counter(65535);
        byte[] beforeWrap = test.nonce(65535);
        try {
            test.nonce(0);
            throw new AssertionError("expected counter overflow");
        } catch (ISOException exception) {
            require((exception.getReason() & 0xffff) == 0x9c46, "overflow status");
        }
        for (short id : (short[]) field("bip327_valid_ids").get(test.applet)) {
            require(id == 0, "overflow clears valid IDs");
        }
        test.rejectToken(beforeWrap, 0x9c44);
        test.nonce(1);
        require((field("bip327_counter").getShort(test.applet) & 0xffff) == 2,
                "counter advances after restart");
        System.out.println("65535 -> overflow (9c46) -> restart at 1: PASS");
        System.out.println("pre-overflow token rejected after MAC-key rotation (9c44): PASS");
    }
}
