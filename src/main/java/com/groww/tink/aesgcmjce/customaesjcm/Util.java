/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

import java.security.SecureRandom;

public final class Util {

    private Util() {
    }

    public static int randKeyId() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] rand = new byte[4];

        int result;
        for (result = 0; result == 0; result = (rand[0] & 127) << 24 | (rand[1] & 255) << 16 | (rand[2] & 255) << 8 | rand[3] & 255) {
            secureRandom.nextBytes(rand);
        }

        return result;
    }

    private static byte toByteFromPrintableAscii(char c) {
        if (c >= '!' && c <= '~') {
            return (byte) c;
        } else {
            throw new TinkBugException("Not a printable ASCII character: " + c);
        }
    }

    public static Bytes toBytesFromPrintableAscii(String s) {
        byte[] result = new byte[s.length()];

        for (int i = 0; i < s.length(); ++i) {
            result[i] = toByteFromPrintableAscii(s.charAt(i));
        }

        return Bytes.copyFrom(result);
    }

    public static Integer getAndroidApiLevel() {
        return BuildDispatchedCode.getApiLevel();
    }
}
