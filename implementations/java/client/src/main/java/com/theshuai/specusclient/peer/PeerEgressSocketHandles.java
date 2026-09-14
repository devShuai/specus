package com.theshuai.specusclient.peer;

import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.channels.NetworkChannel;

/**
 * The operating system's handle for a JDK socket channel, which the JDK does not expose.
 *
 * <p>Binding a socket to an interface is one setsockopt call, and the JDK offers neither the option
 * nor the handle to call it on. The handle is read through {@code sun.nio.ch.SelChImpl.getFDVal()},
 * the interface every NIO socket channel has implemented since the package existed; on Windows the
 * value it returns is the SOCKET.
 *
 * <p>The package is not exported, so the JVM has to be started with
 * {@value #EXPORT_OPTION}. The released jar declares it in its manifest, which {@code java -jar}
 * honours; the Maven test and run configurations pass it on the command line. Started any other way
 * without it, every egress dial on Windows and macOS is refused with a message naming the option,
 * rather than opening a socket that might follow the tunnel.
 */
final class PeerEgressSocketHandles {

    static final String EXPORT_OPTION = "--add-exports java.base/sun.nio.ch=ALL-UNNAMED";

    private static final Method FD_VAL;
    private static final String UNAVAILABLE;

    static {
        Method method = null;
        String unavailable = null;
        try {
            method = Class.forName("sun.nio.ch.SelChImpl").getMethod("getFDVal");
        } catch (ReflectiveOperationException | RuntimeException missing) {
            unavailable = missing.toString();
        }
        FD_VAL = method;
        UNAVAILABLE = unavailable;
    }

    private PeerEgressSocketHandles() {
    }

    static int of(NetworkChannel channel) throws IOException {
        if (FD_VAL == null) {
            throw new IOException("this JDK has no socket handle to bind: " + UNAVAILABLE);
        }
        try {
            return (int) FD_VAL.invoke(channel);
        } catch (IllegalAccessException denied) {
            throw new IOException("binding the egress socket to an interface needs the JVM option "
                    + EXPORT_OPTION, denied);
        } catch (InvocationTargetException | IllegalArgumentException | ClassCastException failed) {
            throw new IOException("cannot read the socket handle of " + channel.getClass().getName(), failed);
        }
    }
}
