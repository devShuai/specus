package com.theshuai.common.serialize;

public interface SerializerAlgorithm {

    /**
     * json序列化算法标志
     */
    byte FASTJSON = 1;

    byte JACKSON = 2;

    byte XML = 3;

    byte BIN = 4;

    byte PROTOBUF = 5;
}
