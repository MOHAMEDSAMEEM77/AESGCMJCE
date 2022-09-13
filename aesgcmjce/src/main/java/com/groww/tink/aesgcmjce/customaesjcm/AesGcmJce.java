/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

import java.security.GeneralSecurityException;
import java.util.Arrays;

import com.groww.crypto.customaesjcm.TinkFipsUtil.AlgorithmFipsCompatibility;

public final class AesGcmJce {

    public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS;

    static {
        FIPS = AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
    }

    private final InsecureNonceAesGcmJce insecureNonceAesGcmJce;

    public AesGcmJce(final byte[] key)
            throws GeneralSecurityException {
        if (!FIPS.isCompatible()) {
            throw new GeneralSecurityException("Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
        } else {
            this.insecureNonceAesGcmJce = new InsecureNonceAesGcmJce(key, true);
        }
    }

    public byte[] encrypt(final byte[] plaintext, final byte[] associatedData)
            throws GeneralSecurityException {
        byte[] iv = Random.randBytes(12);
        return this.insecureNonceAesGcmJce.encrypt(iv, plaintext, associatedData);
    }

    public byte[] decrypt(final byte[] ciphertext, final byte[] associatedData)
            throws GeneralSecurityException {
        byte[] iv = Arrays.copyOf(ciphertext, 12);
        return this.insecureNonceAesGcmJce.decrypt(iv, ciphertext, associatedData);
    }
}
