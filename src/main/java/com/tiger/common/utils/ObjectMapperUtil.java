package com.tiger.common.utils;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.fasterxml.jackson.datatype.jsr310.deser.LocalDateTimeDeserializer;

public final class ObjectMapperUtil {

    public static ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper()
                // ignore value null
                .setSerializationInclusion(JsonInclude.Include.NON_NULL);
        // setting format date
        JavaTimeModule javaTimeModule = new JavaTimeModule();
        // Hack time module to allow 'Z' at the end of string (i.e. javascript json's)
        javaTimeModule.addDeserializer(
                LocalDateTime.class, new LocalDateTimeDeserializer(DateTimeFormatter.ISO_DATE_TIME));
        mapper.registerModule(javaTimeModule);
        mapper.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.configure(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT, true);
        mapper.configure(JsonParser.Feature.AUTO_CLOSE_SOURCE, true);
        mapper.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false);

        return mapper;
    }

    public static String castToString(Object value) {
        if (value == null) return "";

        try {
            return objectMapper().writeValueAsString(value);
        } catch (Exception e) {
            return "";
        }
    }

    public static <T> T castToObject(String value, Class<T> clazz) {
        if (value == null || value.isEmpty()) return null;

        try {
            return objectMapper().readValue(value, clazz);
        } catch (Exception e) {
            return null;
        }
    }
}
