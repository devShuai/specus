package com.theshuai.common.serialize;


import com.theshuai.common.serialize.impl.CompactBinarySerializer;

public interface Serializer {

    Serializer COMPACT_BINARY = new CompactBinarySerializer();

    /**
     * 序列化算法
     *
     * @return 返回算法标志
     */
    byte getSerializerAlgorithm();

    /**
     * java 对象转换为byte数组
     *
     * @param object 对象
     * @return byte数组
     */
    byte[] serialize(Object object);

    /**
     * 反序列化 将二进制数据转换为java对象
     *
     * @param clazz 对象信息
     * @param bytes 数组
     * @param <T>   对象泛型
     * @return java对象
     */
    <T> T deserialize(Class<T> clazz, byte[] bytes);
}
