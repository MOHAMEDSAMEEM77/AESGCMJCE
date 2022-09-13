/*
Custom Tink AESGCMJCE Implementation
Author : Mohamed Sameem
 */
package com.groww.crypto.customaesjcm;

import java.util.Arrays;

@Immutable
public final class Bytes {

    private final byte[] data;

    private Bytes(final byte[] buf, final int start, final int len) {
        this.data = new byte[len];
        System.arraycopy(buf, start, this.data, 0, len);
    }

    public static Bytes copyFrom(final byte[] data) {
        if (data == null) {
            throw new NullPointerException("data must be non-null");
        } else {
            return copyFrom(data, 0, data.length);
        }
    }

    public static Bytes copyFrom(final byte[] data, final int start, final int len) {
        if (data == null) {
            throw new NullPointerException("data must be non-null");
        } else {
            return new Bytes(data, start, len);
        }
    }

    public byte[] toByteArray() {
        byte[] result = new byte[this.data.length];
        System.arraycopy(this.data, 0, result, 0, this.data.length);
        return result;
    }

    public int size() {
        return this.data.length;
    }

    public boolean equals(Object o) {
        if (!(o instanceof Bytes)) {
            return false;
        } else {
            Bytes other = (Bytes) o;
            return Arrays.equals(other.data, this.data);
        }
    }

    public int hashCode() {
        return Arrays.hashCode(this.data);
    }

    public String toString() {
        return "Bytes(" + Hex.encode(this.data) + ")";
    }
}
