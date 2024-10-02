package com.tiger.common.utils;

import org.apache.commons.text.StringEscapeUtils;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class LoggingUtil {

    public static String secured(String msg, Object... params) {
        List<Object> paramList = new ArrayList<>();

        for (Object o : params) {
            if (Objects.nonNull(o) && o instanceof String) {
                paramList.add(StringEscapeUtils.escapeJava((String) o));
            } else {
                paramList.add(o);
            }
        }

        // paramList MessageFormatter.arrayFormat(msg, paramList.toArray()).getMessage()
        return "";
    }

    public static String markToken(String value) {
        return value.replace("\\.([^\\.]*)$", "*");
    }
}
