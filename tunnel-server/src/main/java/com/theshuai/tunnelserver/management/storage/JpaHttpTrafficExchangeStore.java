package com.theshuai.tunnelserver.management.storage;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.model.HttpBodyTypeClassifier;
import com.theshuai.tunnelserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

public class JpaHttpTrafficExchangeStore implements HttpTrafficExchangeStore {
    private final HttpTrafficExchangeRepository repository;

    public JpaHttpTrafficExchangeStore(HttpTrafficExchangeRepository repository) {
        this.repository = repository;
    }

    @Override
    public void saveAll(List<HttpTrafficExchange> exchanges) {
        repository.saveAll(exchanges);
    }

    @Override
    public Page<HttpTrafficExchangeView> search(TenantContext tenant,
                                                Long clientId,
                                                String route,
                                                String responseBodyType,
                                                HttpTrafficSearchField field,
                                                String keyword,
                                                Pageable pageable) {
        return repository
                .findAll(httpExchangeSpec(tenant, clientId, normalizeRoute(route),
                        HttpBodyTypeClassifier.normalize(responseBodyType), field, normalizeKeyword(keyword)), pageable)
                .map(JpaHttpTrafficExchangeStore::toView);
    }

    @Override
    public String backend() {
        return "db";
    }

    private static HttpTrafficExchangeView toView(HttpTrafficExchange exchange) {
        return new HttpTrafficExchangeView(
                exchange.getId(),
                exchange.getClientId(),
                exchange.getClientName(),
                exchange.getRoute(),
                exchange.getResourceId(),
                exchange.getResourceName(),
                exchange.getMethod(),
                exchange.getRelativePath(),
                exchange.getRawQuery(),
                exchange.getStatusCode(),
                exchange.isSuccess(),
                exchange.getError(),
                exchange.getRemoteAddress(),
                exchange.getRequestBytes(),
                exchange.getResponseBytes(),
                exchange.getElapsedMs(),
                exchange.getRequestContentType(),
                exchange.getResponseContentType(),
                HttpBodyTypeClassifier.normalizeOrClassify(
                        exchange.getResponseBodyType(), exchange.getResponseContentType(), exchange.getResponseBytes()),
                exchange.getRequestHeaders(),
                exchange.getResponseHeaders(),
                exchange.getRequestPreviewHex(),
                exchange.getRequestPreviewText(),
                exchange.getResponsePreviewHex(),
                exchange.getResponsePreviewText(),
                exchange.isRequestTruncated(),
                exchange.isResponseTruncated(),
                exchange.getCapturedAt()
        );
    }

    private static String normalizeRoute(String route) {
        if (route == null || route.isBlank()) {
            return null;
        }
        return route.trim();
    }

    private static String normalizeKeyword(String keyword) {
        if (keyword == null || keyword.isBlank()) {
            return null;
        }
        return keyword.trim();
    }

    private static Specification<HttpTrafficExchange> httpExchangeSpec(TenantContext tenant,
                                                                       Long clientId,
                                                                       String route,
                                                                       String responseBodyType,
                                                                       HttpTrafficSearchField field,
                                                                       String keyword) {
        return (root, query, cb) -> {
            HttpTrafficSearchField searchField = field == null ? HttpTrafficSearchField.SUMMARY : field;
            List<Predicate> predicates = new ArrayList<>();
            predicates.add(cb.equal(root.get("tenantId"), tenant.tenantId()));
            if (clientId != null) {
                predicates.add(cb.equal(root.get("clientId"), clientId));
            }
            if (route != null) {
                predicates.add(cb.equal(root.get("route"), route));
            }
            if (responseBodyType != null) {
                predicates.add(responseBodyTypePredicate(root, cb, responseBodyType));
            }
            for (String token : keywordTokens(keyword)) {
                List<Predicate> tokenPredicates = new ArrayList<>();
                String pattern = likePattern(token);
                if (searchField == HttpTrafficSearchField.METHOD) {
                    tokenPredicates.add(cb.equal(
                            cb.lower(stringPath(root.get("method"))),
                            token.toLowerCase(Locale.ROOT)));
                } else {
                    for (String stringField : searchField.jpaStringFields()) {
                        tokenPredicates.add(cb.like(cb.lower(stringPath(root.get(stringField))), pattern, '\\'));
                    }
                    // requestPreviewText / responsePreviewText 标注了 @Lob，Hibernate 7 将其映射为 CLOB，
                    // lower() 会抛 FunctionArgumentException（"argument is of type ... mapped to 'CLOB'"）。
                    // 这里对 CLOB 字段跳过 lower()：SQLite 默认对 ASCII 字母大小写不敏感，小写 pattern 仍能命中；
                    // MySQL/PostgreSQL 下 LIKE 大小写敏感，但仍可用。
                    for (String clobField : searchField.jpaClobFields()) {
                        tokenPredicates.add(cb.like(stringPath(root.get(clobField)), pattern, '\\'));
                    }
                }
                Long number = parseLong(token);
                if (number != null) {
                    if (searchField.searchId()) {
                        tokenPredicates.add(cb.equal(root.get("id"), number));
                    }
                    if (searchField.searchClientId()) {
                        tokenPredicates.add(cb.equal(root.get("clientId"), number));
                    }
                    if (searchField.searchStatusCode() && number >= Integer.MIN_VALUE && number <= Integer.MAX_VALUE) {
                        tokenPredicates.add(cb.equal(root.get("statusCode"), number.intValue()));
                    }
                    if (searchField.searchResourceId()) {
                        tokenPredicates.add(cb.equal(root.get("resourceId"), number));
                    }
                }
                predicates.add(tokenPredicates.isEmpty()
                        ? cb.disjunction()
                        : cb.or(tokenPredicates.toArray(Predicate[]::new)));
            }
            return cb.and(predicates.toArray(Predicate[]::new));
        };
    }

    private static Predicate responseBodyTypePredicate(jakarta.persistence.criteria.Root<HttpTrafficExchange> root,
                                                       jakarta.persistence.criteria.CriteriaBuilder cb,
                                                       String responseBodyType) {
        List<Predicate> candidates = new ArrayList<>();
        candidates.add(cb.equal(root.get("responseBodyType"), responseBodyType));
        if (HttpBodyTypeClassifier.EMPTY.equals(responseBodyType)) {
            candidates.add(cb.equal(root.get("responseBytes"), 0L));
        } else {
            for (String pattern : responseContentTypePatterns(responseBodyType)) {
                candidates.add(cb.like(cb.lower(stringPath(root.get("responseContentType"))), pattern, '\\'));
            }
        }
        return cb.or(candidates.toArray(Predicate[]::new));
    }

    private static List<String> responseContentTypePatterns(String responseBodyType) {
        return switch (responseBodyType) {
            case HttpBodyTypeClassifier.JSON -> List.of("%application/json%", "%+json%");
            case HttpBodyTypeClassifier.HTML -> List.of("%text/html%");
            case HttpBodyTypeClassifier.XML -> List.of("%application/xml%", "%text/xml%", "%+xml%");
            case HttpBodyTypeClassifier.IMAGE -> List.of("image/%");
            case HttpBodyTypeClassifier.VIDEO -> List.of("video/%");
            case HttpBodyTypeClassifier.AUDIO -> List.of("audio/%");
            case HttpBodyTypeClassifier.FORM -> List.of("%application/x-www-form-urlencoded%", "%multipart/form-data%");
            case HttpBodyTypeClassifier.SCRIPT -> List.of("%javascript%", "%ecmascript%");
            case HttpBodyTypeClassifier.TEXT -> List.of("text/%");
            case HttpBodyTypeClassifier.BINARY -> List.of("%application/octet-stream%", "%application/pdf%",
                    "%application/zip%", "%application/x-%", "%application/vnd.%");
            default -> List.of();
        };
    }

    private static List<String> keywordTokens(String keyword) {
        if (keyword == null || keyword.isBlank()) {
            return List.of();
        }
        return Arrays.stream(keyword.trim().split("\\s+"))
                .filter(token -> !token.isBlank())
                .toList();
    }

    private static Path<String> stringPath(Path<?> path) {
        @SuppressWarnings("unchecked")
        Path<String> stringPath = (Path<String>) path;
        return stringPath;
    }

    private static String likePattern(String keyword) {
        String escaped = keyword.toLowerCase(Locale.ROOT)
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
        return "%" + escaped + "%";
    }

    private static Long parseLong(String value) {
        try {
            return Long.parseLong(value);
        } catch (NumberFormatException ignored) {
            return null;
        }
    }
}
