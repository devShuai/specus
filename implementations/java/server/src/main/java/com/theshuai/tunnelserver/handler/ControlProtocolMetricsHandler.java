package com.theshuai.tunnelserver.handler;

import com.theshuai.common.protocol.ProtocolException;
import com.theshuai.tunnelserver.session.SessionUtil;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.handler.codec.TooLongFrameException;
import org.springframework.stereotype.Component;

import java.util.EnumMap;
import java.util.Map;

@Component
@ChannelHandler.Sharable
public class ControlProtocolMetricsHandler extends ChannelInboundHandlerAdapter {
    private final Map<ProtocolException.Reason, Counter> rejected;
    private final Counter preAuthOversize;

    public ControlProtocolMetricsHandler(MeterRegistry meterRegistry) {
        rejected = new EnumMap<>(ProtocolException.Reason.class);
        for (ProtocolException.Reason reason : ProtocolException.Reason.values()) {
            rejected.put(reason, Counter.builder("tunnel.control.protocol.rejected")
                    .tag("reason", reason.name().toLowerCase())
                    .register(meterRegistry));
        }
        preAuthOversize = Counter.builder("tunnel.control.preauth.oversize.rejected")
                .register(meterRegistry);
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        if (cause instanceof ProtocolException protocolException) {
            rejected.get(protocolException.getReason()).increment();
        } else if (cause instanceof TooLongFrameException && !SessionUtil.hasLogin(ctx.channel())) {
            preAuthOversize.increment();
        }
        ctx.close();
    }
}
