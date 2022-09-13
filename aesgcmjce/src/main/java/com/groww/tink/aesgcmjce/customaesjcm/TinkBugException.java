/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

public final class TinkBugException extends RuntimeException {

    public TinkBugException(String message) {
        super(message);
    }

    public TinkBugException(String message, Throwable cause) {
        super(message, cause);
    }

    public TinkBugException(Throwable cause) {
        super(cause);
    }
}
