package com.theshuai.specusserver.testsupport;

import com.theshuai.common.session.Session;
import com.theshuai.specusserver.attribute.ServerAttributes;
import com.theshuai.specusserver.session.SessionUtil;
import io.netty.channel.Channel;
import io.netty.channel.embedded.EmbeddedChannel;

/** Explicit synthetic CONTROL/DATA pair; never replace production ownership guards for tests. */
public final class PairedDataFixture implements AutoCloseable {
    private final EmbeddedChannel control=new EmbeddedChannel();
    public PairedDataFixture(String name,Channel data) {
        control.attr(ServerAttributes.CLIENT_SESSION_ID).set(7L);
        SessionUtil.bindControlSession(new Session(name),control);
        if(!SessionUtil.bindDataSession(new Session(name),data,control,7L)) throw new AssertionError("fixture DATA pair was rejected");
    }
    @Override public void close() {control.finishAndReleaseAll();}
}
