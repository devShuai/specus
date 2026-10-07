package com.theshuai.specus.android;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * Replays the client cases of protocol/test-vectors/http-route-lifecycle-v1.json: every NAT_CONTROL
 * replaces the whole HTTP route table, and a missing or null list empties it.
 */
public class HttpRouteLifecycleVectorTest {

    @Test
    public void natControlReplacesTheWholeRouteTable() throws Exception {
        JSONArray cases = ProtocolVectorTestSupport.read("http-route-lifecycle-v1.json")
                .getJSONObject("client")
                .getJSONArray("cases");
        for (int i = 0; i < cases.length(); i++) {
            JSONObject testCase = cases.getJSONObject(i);
            String id = testCase.getString("id");
            JSONObject login = new JSONObject()
                    .put("clientName", "route-lifecycle")
                    .put("clientSessionId", 1L)
                    .put("accessToken", "cs_token")
                    .put("nettyHost", "127.0.0.1")
                    .put("nettyPort", 7010)
                    .put("httpSpecusConfigList", testCase.getJSONArray("loginSnapshot"));
            SpecusCore.SpecusSession session = SpecusCore.SpecusSession.fromLoginJson(login);

            JSONArray steps = testCase.getJSONArray("steps");
            for (int step = 0; step < steps.length(); step++) {
                JSONObject current = steps.getJSONObject(step);
                session.applyRuntimeJson(current.getString("natControl"));
                assertEquals(id + " step " + step,
                        toMap(current.getJSONObject("expectRoutes")), session.routeMap());
            }
        }
    }

    private static Map<String, String> toMap(JSONObject routes) throws Exception {
        Map<String, String> map = new HashMap<>();
        for (Iterator<String> names = routes.keys(); names.hasNext(); ) {
            String route = names.next();
            map.put(route, routes.getString(route));
        }
        return map;
    }
}
