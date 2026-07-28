package com.theshuai.specusclient.client;

import com.theshuai.specusclient.bean.SpecusBean;

@FunctionalInterface
public interface ClientAuthRefresher {
    SpecusBean refresh();
}
