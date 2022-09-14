/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

import java.lang.reflect.Method;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Logger;

public final class TinkFipsUtil {

    private static final Logger logger = Logger.getLogger(TinkFipsUtil.class.getName());
    private static final AtomicBoolean isRestrictedToFips = new AtomicBoolean(false);

    private TinkFipsUtil() {
    }

    public static void setFipsRestricted() {
        isRestrictedToFips.set(true);
    }

    public static void unsetFipsRestricted() {
        isRestrictedToFips.set(false);
    }

    public static boolean useOnlyFips() {
        return TinkFipsStatus.useOnlyFips() || isRestrictedToFips.get();
    }

    public static boolean fipsModuleAvailable() {
        return checkConscryptIsAvailableAndUsesFipsBoringSsl();
    }

    static Boolean checkConscryptIsAvailableAndUsesFipsBoringSsl() {
        try {
            Class<?> cls = Class.forName("org.conscrypt.Conscrypt");
            Method isBoringSslFIPSBuild = cls.getMethod("isBoringSslFIPSBuild");
            return (Boolean) isBoringSslFIPSBuild.invoke(null);
        } catch (Exception var2) {
            logger.info("Conscrypt is not available or does not support checking for FIPS build.");
            return false;
        }
    }

    public enum AlgorithmFipsCompatibility {
        ALGORITHM_NOT_FIPS {
            public boolean isCompatible() {
                return !TinkFipsUtil.useOnlyFips();
            }
        },
        ALGORITHM_REQUIRES_BORINGCRYPTO {
            public boolean isCompatible() {
                return !TinkFipsUtil.useOnlyFips() || TinkFipsUtil.fipsModuleAvailable();
            }
        };

        AlgorithmFipsCompatibility() {
        }

        public abstract boolean isCompatible();
    }
}
