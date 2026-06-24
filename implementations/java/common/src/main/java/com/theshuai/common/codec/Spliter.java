package com.theshuai.common.codec;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Spliter extends LengthFieldBasedFrameDecoder {
    public static final int DEFAULT_MAX_FRAME_SIZE = 32 * 1024 * 1024;
    private static final int LENGTH_FIELD_OFFSET = 7;
    private static final int LENGTH_FIELD_LENGTH = 4;

    public Spliter() {
        this(DEFAULT_MAX_FRAME_SIZE);
    }

    public Spliter(int maxFrameSize) {
        super(validateMaxFrameSize(maxFrameSize), LENGTH_FIELD_OFFSET, LENGTH_FIELD_LENGTH);
    }

    @Override
    protected Object decode(ChannelHandlerContext ctx, ByteBuf in) throws Exception {
        return super.decode(ctx, in);
    }

    private static int validateMaxFrameSize(int maxFrameSize) {
        if (maxFrameSize <= 0) {
            throw new IllegalArgumentException("maxFrameSize must be positive");
        }
        return maxFrameSize;
    }
}
