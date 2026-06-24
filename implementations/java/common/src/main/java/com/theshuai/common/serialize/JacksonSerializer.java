package com.theshuai.common.serialize;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class JacksonSerializer implements Serializer {
    private static final ObjectMapper objectMapper;

    static {
        objectMapper = new ObjectMapper();
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    @Override
    public byte getSerializerAlgorithm() {
        return SerializerAlgorithm.JACKSON;
    }

    @Override
    public byte[] serialize(Object object) {
        try {
            return objectMapper.writeValueAsBytes(object);
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    @Override
    public <T> T deserialize(Class<T> clazz, byte[] bytes) {
        try {
            return objectMapper.readValue(bytes, clazz);
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }
}
