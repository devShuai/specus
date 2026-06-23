package com.theshuai.tunnelserver.management.storage;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;

public interface HttpTrafficExchangeStore {
    void saveAll(List<HttpTrafficExchange> exchanges);

    Page<HttpTrafficExchangeView> search(TenantContext tenant,
                                         Long clientId,
                                         String route,
                                         String responseBodyType,
                                         HttpTrafficSearchField field,
                                         String keyword,
                                         Pageable pageable);

    String backend();
}
