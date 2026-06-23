package com.theshuai.tunnelclient.client;

import com.theshuai.tunnelclient.bean.TunnelBean;

@FunctionalInterface
public interface ClientAuthRefresher {
    TunnelBean refresh();
}
