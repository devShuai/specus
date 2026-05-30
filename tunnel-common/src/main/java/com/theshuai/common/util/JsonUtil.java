package com.theshuai.common.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang3.StringUtils;

public class JsonUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    static {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public static JsonNode readString(String jsonString) {
        try {
            return objectMapper.readTree(jsonString);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String objectToString(Object object) {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static <T> T bytesToObject(byte[] bytes, TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(bytes, typeReference);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static <T> T stringToObject(String message, Class<T> clazz) {
        try {
            return objectMapper.readValue(message, clazz);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static <T> T stringToObject(String message, TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(message, typeReference);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static ObjectNode createNode() {
        return objectMapper.createObjectNode();
    }

    public static String prettyJsonStr(String message) {
        try {
            return objectMapper.readTree(message).toPrettyString();
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static <T> T parseObject(String result, Class<T> clazz) {
        if (StringUtils.isEmpty(result)) {
            return null;
        }
        try {
            return objectMapper.readValue(result, clazz);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static ObjectNode createObjectNode() {
        return objectMapper.createObjectNode();
    }
}
