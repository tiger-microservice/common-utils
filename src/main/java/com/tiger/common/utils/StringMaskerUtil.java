package com.tiger.common.utils;

public final class StringMaskerUtil {

    private StringMaskerUtil() {}

    /**
     * Thay thế một số ký tự ở đầu và cuối chuỗi bằng dấu '*'.
     *
     * @param str Chuỗi đầu vào cần xử lý.
     * @param x   Số ký tự đầu tiên cần thay thế bằng '*'.
     * @param y   Số ký tự cuối cùng cần thay thế bằng '*'.
     * @return Chuỗi đã được thay thế các ký tự đầu và cuối bằng '*'.
     *         Nếu tổng số ký tự cần thay thế lớn hơn hoặc bằng độ dài chuỗi, toàn bộ chuỗi sẽ bị thay thế bằng '*'.
     */
    public static String markString(String str, int x, int y) {
        if (str == null || str.isEmpty()) {
            return str;
        }

        int length = str.length();

        // Nếu x + y lớn hơn hoặc bằng độ dài chuỗi, trả về toàn dấu '*'
        if (x + y >= length || x < 0 || y < 0 || (x + y == 0)) {
            return "*".repeat(length);
        }

        // Xử lý phần đầu và phần cuối
        String start = x > 0 ? "*".repeat(x) : "";
        String end = y > 0 ? "*".repeat(y) : "";
        String middle = str.substring(x, length - y);

        return start + middle + end;
    }
}
