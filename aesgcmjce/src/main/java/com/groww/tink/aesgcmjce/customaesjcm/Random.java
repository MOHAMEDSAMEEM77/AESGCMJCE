/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

import java.security.SecureRandom;

public final class Random {

    private static final ThreadLocal<SecureRandom> localRandom = new ThreadLocal<SecureRandom>() {
        protected SecureRandom initialValue() {
            return Random.newDefaultSecureRandom();
        }
    };

    private Random() {
    }

    private static SecureRandom newDefaultSecureRandom() {
        SecureRandom retval = new SecureRandom();
        retval.nextLong();
        return retval;
    }

    public static byte[] randBytes(int size) {
        byte[] rand = new byte[size];
        localRandom.get()
                .nextBytes(rand);
        return rand;
    }

    public static int randInt(int max) {
        return localRandom.get()
                .nextInt(max);
    }

    public static int randInt() {
        return localRandom.get()
                .nextInt();
    }
}
