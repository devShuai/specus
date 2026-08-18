package com.theshuai.specus.android;

import android.app.Service;
import android.content.Context;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;

import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;

import org.junit.Test;
import org.junit.runner.RunWith;

import java.lang.reflect.Method;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * On-device checks for the foreground-service contract.
 *
 * Android 15 puts a running-time budget on {@code dataSync} foreground services and calls
 * {@code onTimeout} when it is spent; a service that ignores the callback is killed with an ANR.
 * None of this is reachable from a JVM unit test, because it depends on the real framework class
 * and the manifest the platform actually parses.
 */
@RunWith(AndroidJUnit4.class)
public class ForegroundServiceTimeoutInstrumentationTest {
    /**
     * The platform only delivers the timeout to a service that declares the override. Resolving it
     * on the concrete class is what proves the callback is wired rather than inherited as a no-op.
     */
    @Test
    public void serviceOverridesTheDataSyncTimeoutCallbacks() throws Exception {
        Method singleArgument = SpecusForegroundService.class.getDeclaredMethod(
                "onTimeout", int.class);
        assertNotNull(singleArgument);
        assertEquals(SpecusForegroundService.class, singleArgument.getDeclaringClass());

        Method withServiceType = SpecusForegroundService.class.getDeclaredMethod(
                "onTimeout", int.class, int.class);
        assertNotNull(withServiceType);
        assertEquals(SpecusForegroundService.class, withServiceType.getDeclaringClass());

        // Both must be public overrides of the framework hooks, not private helpers that happen to
        // share the name.
        assertTrue(java.lang.reflect.Modifier.isPublic(singleArgument.getModifiers()));
        assertTrue(java.lang.reflect.Modifier.isPublic(withServiceType.getModifiers()));
        assertTrue(Service.class.isAssignableFrom(SpecusForegroundService.class));
    }

    /**
     * The timeout only applies to the service type the manifest declares, so the declaration and
     * the callback have to agree.
     */
    @Test
    public void manifestDeclaresTheDataSyncForegroundServiceType() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        ServiceInfo info = context.getPackageManager().getServiceInfo(
                new android.content.ComponentName(context, SpecusForegroundService.class),
                PackageManager.GET_META_DATA);

        assertEquals("the timeout contract applies to dataSync services",
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC,
                info.getForegroundServiceType() & ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
    }

    /** Calling the timeout must return promptly; the platform gives the service only moments. */
    @Test
    public void timeoutHandlerReturnsWithoutBlocking() throws Exception {
        SpecusForegroundService service = new SpecusForegroundService();

        long start = System.nanoTime();
        try {
            service.onTimeout(1, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } catch (RuntimeException expected) {
            // A service built with new() has no attached context, so the stop calls throw. What is
            // being checked here is that the handler does not park before reaching them.
        }
        long elapsedMillis = (System.nanoTime() - start) / 1_000_000L;

        assertTrue("onTimeout took " + elapsedMillis + "ms; the platform will not wait",
                elapsedMillis < 1_000L);
    }
}
