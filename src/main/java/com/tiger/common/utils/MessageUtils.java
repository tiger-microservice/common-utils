package com.tiger.common.utils;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MessageUtils {
    public static String mapAttributes(String message, Map<String, Object> attributes) {
        // extract key from message
        List<String> keys = extractKeyFromMessage(message);

        // replace attributes by key
        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            String value = String.valueOf(attributes.get(key));
            message = message.replace("{" + key + "}", value);
        }

        return message;
    }

    private static List<String> extractKeyFromMessage(String message) {
        // Tạo mẫu regex
        Pattern pattern = Pattern.compile("\\{([^{}]*)\\}");

        // Tạo matcher cho chuỗi message
        Matcher matcher = pattern.matcher(message);

        List<String> keys = new ArrayList<>();

        // Duyệt qua tất cả các match và trích xuất key
        while (matcher.find()) {
            String key = matcher.group(1);
            System.out.println("Key: " + key);
            keys.add(key);
        }

        return keys;
    }
}
