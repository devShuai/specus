package com.theshuai.common.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.core.json.JsonReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.apache.commons.lang3.StringUtils;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JsonUtil {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    static {
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.getFactory().configure(JsonReadFeature.ALLOW_JAVA_COMMENTS.mappedFeature(), true);
        objectMapper.getFactory().configure(JsonReadFeature.ALLOW_YAML_COMMENTS.mappedFeature(), true);
        objectMapper.getFactory().configure(JsonReadFeature.ALLOW_TRAILING_COMMA.mappedFeature(), true);
    }

    public static JsonNode readString(String jsonString) {
        try {
            return objectMapper.readTree(jsonString);
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    public static String objectToString(Object object) {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            log.error("处理失败", e);
            return null;
        }
    }

    public static <T> T bytesToObject(byte[] bytes, TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(bytes, typeReference);
        } catch (Exception e) {
            log.error("处理失败", e);
        }
        return null;
    }

    public static <T> T bytesToObjectStrict(byte[] bytes, TypeReference<T> typeReference) {
        if (bytes == null || typeReference == null) {
            throw new IllegalArgumentException("bytes and typeReference are required");
        }
        try {
            return objectMapper.readValue(bytes, typeReference);
        } catch (Exception e) {
            throw new IllegalArgumentException("invalid JSON payload", e);
        }
    }

    public static <T> T bytesToObjectQuietly(byte[] bytes, int offset, int length, Class<T> clazz) {
        if (bytes == null || clazz == null || offset < 0 || length < 0 || offset > bytes.length - length) {
            return null;
        }
        try {
            return objectMapper.readValue(bytes, offset, length, clazz);
        } catch (Exception ignored) {
            return null;
        }
    }

    public static <T> T stringToObject(String message, Class<T> clazz) {
        try {
            return objectMapper.readValue(message, clazz);
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    public static <T> T stringToObject(String message, TypeReference<T> typeReference) {
        try {
            return objectMapper.readValue(message, typeReference);
        } catch (Exception e) {
            log.error("处理失败", e);
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
            log.error("处理失败", e);
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
            log.error("处理失败", e);
            return null;
        }
    }

    public static ObjectNode createObjectNode() {
        return objectMapper.createObjectNode();
    }
}
