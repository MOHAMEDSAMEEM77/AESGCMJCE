/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.groww.crypto.customaesjcm.TinkFipsUtil.AlgorithmFipsCompatibility;

public final class InsecureNonceAesGcmJce {

    public static final TinkFipsUtil.AlgorithmFipsCompatibility FIPS;
    public static final int IV_SIZE_IN_BYTES = 12;
    public static final int TAG_SIZE_IN_BYTES = 16;
    private static final ThreadLocal<Cipher> localCipher;

    static {
        FIPS = AlgorithmFipsCompatibility.ALGORITHM_REQUIRES_BORINGCRYPTO;
        localCipher = new ThreadLocal<Cipher>() {
            protected Cipher initialValue() {
                try {
                    return EngineFactory.CIPHER.getInstance("AES/GCM/NoPadding");
                } catch (GeneralSecurityException var2) {
                    throw new IllegalStateException(var2);
                }
            }
        };
    }

    private final SecretKey keySpec;
    private final boolean prependIv;

    public InsecureNonceAesGcmJce(final byte[] key, boolean prependIv)
            throws GeneralSecurityException {
        if (!FIPS.isCompatible()) {
            throw new GeneralSecurityException("Can not use AES-GCM in FIPS-mode, as BoringCrypto module is not available.");
        } else {
            Validators.validateAesKeySize(key.length);
            this.keySpec = new SecretKeySpec(key, "AES");
            this.prependIv = prependIv;
        }
    }

    private static AlgorithmParameterSpec getParams(final byte[] iv)
            throws GeneralSecurityException {
        return getParams(iv, 0, iv.length);
    }

    private static AlgorithmParameterSpec getParams(final byte[] buf, int offset, int len)
            throws GeneralSecurityException {
        return SubtleUtil.isAndroid() && SubtleUtil.androidApiLevel() <= 19 ? new IvParameterSpec(buf, offset, len) : new GCMParameterSpec(128, buf,
                offset, len);
    }

    public byte[] encrypt(final byte[] iv, final byte[] plaintext, final byte[] associatedData)
            throws GeneralSecurityException {
        if (iv.length != 12) {
            throw new GeneralSecurityException("iv is wrong size");
        } else if (plaintext.length > 2147483619) {
            throw new GeneralSecurityException("plaintext too long");
        } else {
            int ciphertextLength = this.prependIv ? 12 + plaintext.length + 16 : plaintext.length + 16;
            byte[] ciphertext = new byte[ciphertextLength];
            if (this.prependIv) {
                System.arraycopy(iv, 0, ciphertext, 0, 12);
            }

            AlgorithmParameterSpec params = getParams(iv);
            localCipher.get()
                    .init(1, this.keySpec, params);
            if (associatedData != null && associatedData.length != 0) {
                localCipher.get()
                        .updateAAD(associatedData);
            }

            int ciphertextOutputOffset = this.prependIv ? 12 : 0;
            int written = localCipher.get()
                    .doFinal(plaintext, 0, plaintext.length, ciphertext, ciphertextOutputOffset);
            if (written != plaintext.length + 16) {
                int actualTagSize = written - plaintext.length;
                throw new GeneralSecurityException(
                        String.format("encryption failed; GCM tag must be %s bytes, but got only %s bytes", 16, actualTagSize));
            } else {
                return ciphertext;
            }
        }
    }

    public byte[] decrypt(final byte[] iv, final byte[] ciphertext, final byte[] associatedData)
            throws GeneralSecurityException {
        if (iv.length != 12) {
            throw new GeneralSecurityException("iv is wrong size");
        } else {
            int minimumCiphertextLength = this.prependIv ? 28 : 16;
            if (ciphertext.length < minimumCiphertextLength) {
                throw new GeneralSecurityException("ciphertext too short");
            } else if (this.prependIv && !ByteBuffer.wrap(iv)
                    .equals(ByteBuffer.wrap(ciphertext, 0, 12))) {
                throw new GeneralSecurityException("iv does not match prepended iv");
            } else {
                AlgorithmParameterSpec params = getParams(iv);
                localCipher.get()
                        .init(2, this.keySpec, params);
                if (associatedData != null && associatedData.length != 0) {
                    localCipher.get()
                            .updateAAD(associatedData);
                }

                int ciphertextInputOffset = this.prependIv ? 12 : 0;
                int ciphertextLength = this.prependIv ? ciphertext.length - 12 : ciphertext.length;
                return localCipher.get()
                        .doFinal(ciphertext, ciphertextInputOffset, ciphertextLength);
            }
        }
    }
}
