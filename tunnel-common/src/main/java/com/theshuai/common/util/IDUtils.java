package com.theshuai.common.util;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufAllocator;
import io.netty.buffer.ByteBufUtil;
import io.netty.util.AsciiString;

import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class IDUtils {

    private static AtomicLong startValue = new AtomicLong(System.currentTimeMillis());

    public static String generateIncreaseId() {
        return String.valueOf(startValue.getAndIncrement());
    }

    public static void main(String[] args) {
        ByteBuf buf = ByteBufAllocator.DEFAULT.buffer();
//        buf.alloc();
        buf.writeByte(0);
        buf.writeByte(0);
        buf.writeByte(1);

        buf.writeByte(0);
        buf.writeByte(2);
            buf.writeBytes("0000001".getBytes());
        buf.writeByte('|');

        log.info(ByteBufUtil.prettyHexDump(buf));

    }
}
