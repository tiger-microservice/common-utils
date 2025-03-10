package com.tiger.common.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class DateUtil {

    public static final String FM_DATE_1 = "yyyy-MM-dd'T'HH:mm:ss.SSS";

    public static String convertToStr(LocalDateTime dateTime, String pattern) {
        // Desired format
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(pattern);

        // Convert to string
        return dateTime.format(formatter);
    }

    private static LocalDateTime stringToLocaldateTime(String inputDate) {
        if (inputDate == null || inputDate.isEmpty()) return null;

        DateTimeFormatter inputFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss[.SSS]");

        return LocalDateTime.parse(inputDate, inputFormatter);
    }
}
