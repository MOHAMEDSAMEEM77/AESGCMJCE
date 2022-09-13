/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;//

public final class TinkFipsStatus {

    private TinkFipsStatus() {
    }

    public static boolean useOnlyFips() {
        return false;
    }
}
