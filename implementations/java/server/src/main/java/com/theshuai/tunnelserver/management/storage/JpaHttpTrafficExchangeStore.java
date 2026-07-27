package com.theshuai.tunnelserver.management.storage;

import com.theshuai.tunnelserver.management.model.HttpTrafficExchange;
import com.theshuai.tunnelserver.management.model.HttpTrafficExchangeView;
import com.theshuai.tunnelserver.management.model.HttpBodyTypeClassifier;
import com.theshuai.tunnelserver.management.model.HttpBodyDataCodec;
import com.theshuai.tunnelserver.management.repository.HttpTrafficExchangeRepository;
import com.theshuai.tunnelserver.management.tenant.TenantContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.TypedQuery;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

public class JpaHttpTrafficExchangeStore implements HttpTrafficExchangeStore {
    private final HttpTrafficExchangeRepository repository;
    private final EntityManager entityManager;

    public JpaHttpTrafficExchangeStore(HttpTrafficExchangeRepository repository,
                                       EntityManager entityManager) {
        this.repository = repository;
        this.entityManager = entityManager;
    }

    @Override
    public void saveAll(List<HttpTrafficExchange> exchanges) {
        repository.saveAll(exchanges);
    }

    @Override
    public Page<HttpTrafficExchangeView> search(TenantContext tenant,
                                                Long clientId,
                                                Set<Long> visibleClientIds,
                                                String route,
                                                String responseBodyType,
                                                HttpTrafficSearchField field,
                                                String keyword,
                                                Pageable pageable) {
        if (isDenied(clientId, visibleClientIds)) {
            return Page.empty(pageable);
        }

        String normalizedRoute = normalizeRoute(route);
        String normalizedBodyType = HttpBodyTypeClassifier.normalize(responseBodyType);
        String normalizedKeyword = normalizeKeyword(keyword);

        CriteriaBuilder cb = entityManager.getCriteriaBuilder();
        CriteriaQuery<Object[]> query = cb.createQuery(Object[].class);
        Root<HttpTrafficExchange> root = query.from(HttpTrafficExchange.class);
        query.multiselect(
                root.get("id"),
                root.get("clientId"),
                root.get("clientName"),
                root.get("route"),
                root.get("resourceId"),
                root.get("resourceName"),
                root.get("method"),
                root.get("relativePath"),
                root.get("rawQuery"),
                root.get("statusCode"),
                root.get("success"),
                root.get("error"),
                root.get("remoteAddress"),
                root.get("requestBytes"),
                root.get("responseBytes"),
                root.get("elapsedMs"),
                root.get("requestContentType"),
                root.get("responseContentType"),
                root.get("responseBodyType"),
                root.get("requestTruncated"),
                root.get("responseTruncated"),
                root.get("capturedAt"));
        query.where(httpExchangePredicate(
                root,
                cb,
                tenant,
                clientId,
                visibleClientIds,
                normalizedRoute,
                normalizedBodyType,
                field,
                normalizedKeyword));
        query.orderBy(pageable.getSort().isSorted()
                ? pageable.getSort().stream()
                        .map(order -> order.isAscending()
                                ? cb.asc(root.get(order.getProperty()))
                                : cb.desc(root.get(order.getProperty())))
                        .toList()
                : List.of(cb.desc(root.get("id"))));

        TypedQuery<Object[]> typedQuery = entityManager.createQuery(query);
        if (pageable.isPaged()) {
            typedQuery.setFirstResult(Math.toIntExact(pageable.getOffset()));
            typedQuery.setMaxResults(pageable.getPageSize());
        }
        List<HttpTrafficExchangeView> content = typedQuery.getResultList().stream()
                .map(JpaHttpTrafficExchangeStore::toSummaryView)
                .toList();

        CriteriaQuery<Long> countQuery = cb.createQuery(Long.class);
        Root<HttpTrafficExchange> countRoot = countQuery.from(HttpTrafficExchange.class);
        countQuery.select(cb.count(countRoot));
        countQuery.where(httpExchangePredicate(
                countRoot,
                cb,
                tenant,
                clientId,
                visibleClientIds,
                normalizedRoute,
                normalizedBodyType,
                field,
                normalizedKeyword));
        long total = entityManager.createQuery(countQuery).getSingleResult();
        return new PageImpl<>(content, pageable, total);
    }

    @Override
    public Optional<HttpTrafficExchangeView> findById(TenantContext tenant,
                                                      long id,
                                                      Set<Long> visibleClientIds) {
        if (visibleClientIds != null && visibleClientIds.isEmpty()) {
            return Optional.empty();
        }
        Optional<HttpTrafficExchange> found = visibleClientIds == null
                ? repository.findByTenantIdAndId(tenant.tenantId(), id)
                : repository.findByTenantIdAndIdAndClientIdIn(
                        tenant.tenantId(), id, List.copyOf(visibleClientIds));
        return found.map(exchange -> toView(exchange, true));
    }

    @Override
    public String backend() {
        return "db";
    }

    static HttpTrafficExchangeView toView(HttpTrafficExchange exchange, boolean includeBody) {
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
                includeBody ? exchange.getRequestHeaders() : null,
                includeBody ? exchange.getResponseHeaders() : null,
                includeBody ? exchange.getRequestPreviewHex() : null,
                includeBody
                        ? HttpBodyDataCodec.toDisplayText(exchange.getRequestBodyData(),
                                exchange.getRequestContentType(), exchange.getRequestHeaders(), exchange.getRequestPreviewText())
                        : null,
                includeBody ? exchange.getResponsePreviewHex() : null,
                includeBody
                        ? HttpBodyDataCodec.toDisplayText(exchange.getResponseBodyData(),
                                exchange.getResponseContentType(), exchange.getResponseHeaders(), exchange.getResponsePreviewText())
                        : null,
                exchange.isRequestTruncated(),
                exchange.isResponseTruncated(),
                exchange.getCapturedAt()
        );
    }

    private static HttpTrafficExchangeView toSummaryView(Object[] exchange) {
        if (exchange[0] == null) {
            throw new IllegalStateException("HTTP exchange summary row has no id: " + Arrays.toString(exchange));
        }
        String responseContentType = stringValue(exchange, 17);
        String responseBodyType = stringValue(exchange, 18);
        long responseBytes = longValue(exchange, 14);
        return new HttpTrafficExchangeView(
                longValue(exchange, 0),
                longValue(exchange, 1),
                stringValue(exchange, 2),
                stringValue(exchange, 3),
                nullableLongValue(exchange, 4),
                stringValue(exchange, 5),
                stringValue(exchange, 6),
                stringValue(exchange, 7),
                stringValue(exchange, 8),
                intValue(exchange, 9),
                booleanValue(exchange, 10),
                stringValue(exchange, 11),
                stringValue(exchange, 12),
                longValue(exchange, 13),
                responseBytes,
                longValue(exchange, 15),
                stringValue(exchange, 16),
                responseContentType,
                HttpBodyTypeClassifier.normalizeOrClassify(
                        responseBodyType, responseContentType, responseBytes),
                null,
                null,
                null,
                null,
                null,
                null,
                booleanValue(exchange, 19),
                booleanValue(exchange, 20),
                stringValue(exchange, 21)
        );
    }

    private static long longValue(Object[] tuple, int index) {
        Number value = (Number) tuple[index];
        return value == null ? 0L : value.longValue();
    }

    private static Long nullableLongValue(Object[] tuple, int index) {
        Number value = (Number) tuple[index];
        return value == null ? null : value.longValue();
    }

    private static int intValue(Object[] tuple, int index) {
        Number value = (Number) tuple[index];
        return value == null ? 0 : value.intValue();
    }

    private static boolean booleanValue(Object[] tuple, int index) {
        Object value = tuple[index];
        if (value instanceof Boolean booleanValue) {
            return booleanValue;
        }
        return value instanceof Number numberValue && numberValue.intValue() != 0;
    }

    private static String stringValue(Object[] tuple, int index) {
        Object value = tuple[index];
        return value == null ? null : value.toString();
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

    private static Predicate httpExchangePredicate(Root<HttpTrafficExchange> root,
                                                   CriteriaBuilder cb,
                                                   TenantContext tenant,
                                                   Long clientId,
                                                   Set<Long> visibleClientIds,
                                                   String route,
                                                   String responseBodyType,
                                                   HttpTrafficSearchField field,
                                                   String keyword) {
        HttpTrafficSearchField searchField = field == null ? HttpTrafficSearchField.SUMMARY : field;
        List<Predicate> predicates = new ArrayList<>();
        predicates.add(cb.equal(root.get("tenantId"), tenant.tenantId()));
        if (clientId != null) {
            predicates.add(cb.equal(root.get("clientId"), clientId));
        } else if (visibleClientIds != null) {
            predicates.add(root.get("clientId").in(visibleClientIds));
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
                // Hibernate maps these @Lob fields to CLOB, so lower() is not portable.
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
    }

    private static boolean isDenied(Long clientId, Set<Long> visibleClientIds) {
        if (visibleClientIds == null) {
            return false;
        }
        if (visibleClientIds.isEmpty()) {
            return true;
        }
        return clientId != null && !visibleClientIds.contains(clientId);
    }

    private static Predicate responseBodyTypePredicate(Root<HttpTrafficExchange> root,
                                                       CriteriaBuilder cb,
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
