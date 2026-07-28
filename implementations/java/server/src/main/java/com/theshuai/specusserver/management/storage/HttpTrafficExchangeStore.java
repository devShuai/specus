package com.theshuai.specusserver.management.storage;

import com.theshuai.specusserver.management.model.HttpTrafficExchange;
import com.theshuai.specusserver.management.model.HttpTrafficExchangeView;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.List;
import java.util.Optional;
import java.util.Set;

public interface HttpTrafficExchangeStore {
    void saveAll(List<HttpTrafficExchange> exchanges);

    Page<HttpTrafficExchangeView> search(TenantContext tenant,
                                         Long clientId,
                                         Set<Long> visibleClientIds,
                                         String route,
                                         String responseBodyType,
                                         HttpTrafficSearchField field,
                                         String keyword,
                                         Pageable pageable);

    Optional<HttpTrafficExchangeView> findById(TenantContext tenant,
                                               long id,
                                               Set<Long> visibleClientIds);

    String backend();
}
