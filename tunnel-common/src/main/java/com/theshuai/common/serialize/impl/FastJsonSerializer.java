package com.theshuai.common.serialize.impl;

import com.alibaba.fastjson2.JSON;
import com.theshuai.common.serialize.Serializer;
import com.theshuai.common.serialize.SerializerAlgorithm;

public class FastJsonSerializer implements Serializer {
    @Override
    public byte getSerializerAlgorithm() {
        return SerializerAlgorithm.FASTJSON;
    }

    @Override
    public byte[] serialize(Object object) {
        return JSON.toJSONBytes(object);
    }

    @Override
    public <T> T deserialize(Class<T> clazz, byte[] bytes) {
        return JSON.parseObject(bytes, clazz);
    }
}
