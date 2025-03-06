package com.tiger.common.secure;

import java.util.Base64;

public final class Base64Util {

    // Chuyển byte[] sang Base64 (để dễ hiển thị)
    public static String toBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    // Chuyển Base64 sang byte[]
    public static byte[] fromBase64(String base64) {
        return Base64.getDecoder().decode(base64);
    }
}
