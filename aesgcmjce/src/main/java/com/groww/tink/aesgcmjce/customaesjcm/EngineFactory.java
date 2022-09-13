/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

public final class EngineFactory<T_WRAPPER extends EngineWrapper<T_ENGINE>, T_ENGINE> {

    public static final EngineFactory<EngineWrapper.TCipher, Cipher> CIPHER;
    public static final EngineFactory<EngineWrapper.TMac, Mac> MAC;
    public static final EngineFactory<EngineWrapper.TSignature, Signature> SIGNATURE;
    public static final EngineFactory<EngineWrapper.TMessageDigest, MessageDigest> MESSAGE_DIGEST;
    public static final EngineFactory<EngineWrapper.TKeyAgreement, KeyAgreement> KEY_AGREEMENT;
    public static final EngineFactory<EngineWrapper.TKeyPairGenerator, KeyPairGenerator> KEY_PAIR_GENERATOR;
    public static final EngineFactory<EngineWrapper.TKeyFactory, KeyFactory> KEY_FACTORY;
    private static final Logger logger = Logger.getLogger(EngineFactory.class.getName());
    private static final List<Provider> policy;
    private static final boolean LET_FALLBACK;

    static {
        if (TinkFipsUtil.useOnlyFips()) {
            policy = toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL", "Conscrypt");
            LET_FALLBACK = false;
        } else if (SubtleUtil.isAndroid()) {
            policy = toProviderList("GmsCore_OpenSSL", "AndroidOpenSSL");
            LET_FALLBACK = true;
        } else {
            policy = new ArrayList();
            LET_FALLBACK = true;
        }

        CIPHER = new EngineFactory(new EngineWrapper.TCipher());
        MAC = new EngineFactory(new EngineWrapper.TMac());
        SIGNATURE = new EngineFactory(new EngineWrapper.TSignature());
        MESSAGE_DIGEST = new EngineFactory(new EngineWrapper.TMessageDigest());
        KEY_AGREEMENT = new EngineFactory(new EngineWrapper.TKeyAgreement());
        KEY_PAIR_GENERATOR = new EngineFactory(new EngineWrapper.TKeyPairGenerator());
        KEY_FACTORY = new EngineFactory(new EngineWrapper.TKeyFactory());
    }

    private final T_WRAPPER instanceBuilder;

    public EngineFactory(T_WRAPPER instanceBuilder) {
        this.instanceBuilder = instanceBuilder;
    }

    public static List<Provider> toProviderList(String... providerNames) {
        List<Provider> providers = new ArrayList();
        String[] var2 = providerNames;
        int var3 = providerNames.length;

        for (int var4 = 0; var4 < var3; ++var4) {
            String s = var2[var4];
            Provider p = Security.getProvider(s);
            if (p != null) {
                providers.add(p);
            } else {
                logger.info(String.format("Provider %s not available", s));
            }
        }

        return providers;
    }

    public T_ENGINE getInstance(String algorithm)
            throws GeneralSecurityException {
        Exception cause = null;
        Iterator var3 = policy.iterator();

        while (var3.hasNext()) {
            Provider provider = (Provider) var3.next();

            try {
                return this.instanceBuilder.getInstance(algorithm, provider);
            } catch (Exception var6) {
                if (cause == null) {
                    cause = var6;
                }
            }
        }

        if (LET_FALLBACK) {
            return this.instanceBuilder.getInstance(algorithm, null);
        } else {
            throw new GeneralSecurityException("No good Provider found.", cause);
        }
    }
}
