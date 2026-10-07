package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.HttpSpecusConfig;
import com.theshuai.specusclient.bean.SpecusBean;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A NAT_CONTROL is the client's full route snapshot. Without a live data connection it only updates
 * the bean the next data connection builds its {@code NatClientHandler} from, which is how a route
 * deleted while the client was away must disappear once it reconnects.
 */
class NettyClientNatControlTests {

    @Test
    void natControlWithoutTheHttpListClearsTheRoutesTheNextDataConnectionUses() {
        SpecusBean bean = bean();
        NettyClient client = new NettyClient(bean);

        SpecusBean pushed = new SpecusBean();
        pushed.setSpecusConfigList(List.of());
        client.applyNatControl(pushed);

        assertThat(bean.getHttpSpecusConfigList()).isEmpty();
    }

    @Test
    void natControlWithAnEmptyHttpListClearsTheRoutesTheNextDataConnectionUses() {
        SpecusBean bean = bean();
        NettyClient client = new NettyClient(bean);

        SpecusBean pushed = new SpecusBean();
        pushed.setSpecusConfigList(List.of());
        pushed.setHttpSpecusConfigList(List.of());
        client.applyNatControl(pushed);

        assertThat(bean.getHttpSpecusConfigList()).isEmpty();
    }

    @Test
    void natControlReplacesTheRoutesTheNextDataConnectionUses() {
        SpecusBean bean = bean();
        NettyClient client = new NettyClient(bean);

        SpecusBean pushed = new SpecusBean();
        pushed.setSpecusConfigList(List.of());
        pushed.setHttpSpecusConfigList(List.of(route("api", "http://127.0.0.1:9000")));
        client.applyNatControl(pushed);

        assertThat(bean.getHttpSpecusConfigList()).extracting(HttpSpecusConfig::getRoute).containsExactly("api");
    }

    private static SpecusBean bean() {
        SpecusBean bean = new SpecusBean();
        bean.setClientName("unit-client");
        bean.setClientSessionId(1L);
        bean.setAccessToken("cs_unit_token");
        bean.setRemoteAddress("127.0.0.1");
        bean.setRemotePort(7010);
        bean.setSpecusConfigList(List.of());
        bean.setHttpSpecusConfigList(List.of(route("web", "http://127.0.0.1:8080")));
        return bean;
    }

    private static HttpSpecusConfig route(String route, String targetBaseUrl) {
        HttpSpecusConfig config = new HttpSpecusConfig();
        config.setRoute(route);
        config.setTargetBaseUrl(targetBaseUrl);
        return config;
    }
}
