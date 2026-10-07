package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.config.ObjectStorageProperties;
import com.theshuai.specusserver.config.PublicTransferProperties;
import com.theshuai.specusserver.management.model.SortableInstant;
import com.theshuai.specusserver.management.model.TransferAttachment;
import com.theshuai.specusserver.management.model.TransferAttachmentDownloadUsage;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadGrantRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentDownloadUsageRepository;
import com.theshuai.specusserver.management.repository.TransferAttachmentRepository;
import com.theshuai.specusserver.management.security.ManagementContext;
import com.theshuai.specusserver.management.storage.object.AliyunOssObjectStorageService;
import com.theshuai.specusserver.management.tenant.TenantContext;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Replays {@code protocol/test-vectors/transfer-capabilities-v1.json}: the rows of each case go into
 * the SQLite store through the JPA repositories the upload and download paths write with, the
 * service clock is fixed at the case instant, and the snapshot must match the vector field by field.
 */
@SpringBootTest(properties = {
        "spring.datasource.url=jdbc:sqlite::memory:",
        "spring.jpa.database-platform=org.hibernate.community.dialect.SQLiteDialect",
        "spring.jpa.hibernate.ddl-auto=create-drop",
        "specus.netty.port=0",
        "specus.database.seed-demo-client=false"
})
@Transactional
class TransferCapabilitiesVectorTests {
    private static final ObjectMapper JSON = new ObjectMapper();
    /** The vector's two scopes stand for two distinct attachment scopes: usage is account-wide. */
    private static final Map<String, String> SCOPES = Map.of(
            "ROOM", TransferAttachmentService.SCOPE_PUBLIC_TRANSFER,
            "LINK", TransferAttachmentService.SCOPE_ADMIN_CLIENT_MESSAGE);

    @Autowired private TransferAttachmentRepository repository;
    @Autowired private TransferAttachmentDownloadGrantRepository downloadGrantRepository;
    @Autowired private TransferAttachmentDownloadUsageRepository downloadUsageRepository;
    @Autowired private ClientAccountService clientAccountService;
    @Autowired private PublicTransferRoomService publicTransferRoomService;

    static List<Arguments> cases() throws IOException {
        List<Arguments> cases = new ArrayList<>();
        readVector().path("cases").forEach(node -> cases.add(Arguments.of(node.path("name").asText(), node)));
        assertThat(cases).isNotEmpty();
        return cases;
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("cases")
    void snapshotMatchesTheSharedVector(String name, JsonNode testCase) {
        Instant now = Instant.parse(testCase.path("now").asText());
        long id = 95_000L;
        for (JsonNode row : testCase.path("attachments")) {
            id++;
            TransferAttachment attachment = new TransferAttachment();
            attachment.setId(id);
            attachment.setTenantId(row.path("tenantId").asText());
            attachment.setOwnerUsername(row.path("username").asText());
            attachment.setScope(scope(row.path("scope").asText()));
            attachment.setObjectKey("vector/" + id);
            attachment.setFileName("vector.bin");
            attachment.setMimeType("application/octet-stream");
            attachment.setSizeBytes(row.path("sizeBytes").asLong());
            attachment.setStatus(row.path("status").asText());
            attachment.setCreatedAt(now.toString());
            attachment.setUpdatedAt(now.toString());
            attachment.setUploadExpiresAt(SortableInstant.normalize(row.path("uploadExpiresAt").asText()));
            attachment.setExpiresAt(SortableInstant.normalize(row.path("expiresAt").asText()));
            repository.saveAndFlush(attachment);
        }
        for (JsonNode row : testCase.path("downloadUsage")) {
            id++;
            TransferAttachmentDownloadUsage usage = new TransferAttachmentDownloadUsage();
            usage.setId(id);
            usage.setTenantId(row.path("tenantId").asText());
            usage.setUsername(row.path("username").asText());
            usage.setAttachmentId(95_001L);
            usage.setSizeBytes(row.path("sizeBytes").asLong());
            usage.setUsageMonth(row.path("usageMonth").asText());
            usage.setCreatedAt(now.toString());
            downloadUsageRepository.saveAndFlush(usage);
        }

        JsonNode config = testCase.path("config");
        ObjectStorageProperties properties = new ObjectStorageProperties();
        if (config.path("storageEnabled").asBoolean()) {
            properties.setProvider("aliyun-oss");
            properties.setEndpoint("oss.example.com");
            properties.setRegion("cn-hangzhou");
            properties.setBucket("private");
            properties.setAccessKeyId("key");
            properties.setAccessKeySecret("secret");
        }
        properties.setMaxAttachmentBytes(config.path("maxAttachmentBytes").asLong());
        properties.setRetentionHours(config.path("retentionHours").asLong());
        properties.setPerUserStorageQuotaBytes(config.path("storageQuotaBytes").asLong());
        properties.setPerUserMonthlyDownloadQuotaBytes(config.path("monthlyDownloadQuotaBytes").asLong());
        TransferAttachmentService service = new TransferAttachmentService(repository, downloadGrantRepository,
                downloadUsageRepository, new AliyunOssObjectStorageService(properties), properties,
                new PublicTransferProperties(), clientAccountService, publicTransferRoomService,
                Clock.fixed(now, ZoneOffset.UTC));

        JsonNode account = testCase.path("account");
        var snapshot = service.capabilities(new ManagementContext(
                new TenantContext(account.path("tenantId").asText()), account.path("username").asText(), false));

        JsonNode expect = testCase.path("expect");
        assertThat(snapshot.schemaVersion()).as(name + " schemaVersion").isEqualTo(expect.path("schemaVersion").asInt());
        assertThat(Instant.parse(snapshot.checkedAt())).as(name + " checkedAt")
                .isEqualTo(Instant.parse(expect.path("checkedAt").asText()));
        assertThat(snapshot.storageEnabled()).as(name + " storageEnabled").isEqualTo(expect.path("storageEnabled").asBoolean());
        assertThat(snapshot.maxAttachmentBytes()).as(name + " maxAttachmentBytes")
                .isEqualTo(expect.path("maxAttachmentBytes").asLong());
        assertThat(snapshot.retentionHours()).as(name + " retentionHours").isEqualTo(expect.path("retentionHours").asLong());
        assertThat(snapshot.storageQuotaBytes()).as(name + " storageQuotaBytes")
                .isEqualTo(expect.path("storageQuotaBytes").asLong());
        assertThat(snapshot.storageUsedBytes()).as(name + " storageUsedBytes")
                .isEqualTo(expect.path("storageUsedBytes").asLong());
        assertThat(snapshot.storageRemainingBytes()).as(name + " storageRemainingBytes")
                .isEqualTo(expect.path("storageRemainingBytes").asLong());
        assertThat(snapshot.monthlyDownloadQuotaBytes()).as(name + " monthlyDownloadQuotaBytes")
                .isEqualTo(expect.path("monthlyDownloadQuotaBytes").asLong());
        assertThat(snapshot.monthlyDownloadUsedBytes()).as(name + " monthlyDownloadUsedBytes")
                .isEqualTo(expect.path("monthlyDownloadUsedBytes").asLong());
        assertThat(snapshot.monthlyDownloadRemainingBytes()).as(name + " monthlyDownloadRemainingBytes")
                .isEqualTo(expect.path("monthlyDownloadRemainingBytes").asLong());
        assertThat(snapshot.downloadUsageMonth()).as(name + " downloadUsageMonth")
                .isEqualTo(expect.path("downloadUsageMonth").asText());
        assertThat(Instant.parse(snapshot.downloadResetsAt())).as(name + " downloadResetsAt")
                .isEqualTo(Instant.parse(expect.path("downloadResetsAt").asText()));
        assertThat(snapshot.downloadGrantSingleUse()).as(name + " downloadGrantSingleUse")
                .isEqualTo(expect.path("downloadGrantSingleUse").asBoolean());
    }

    private static String scope(String vectorScope) {
        String scope = SCOPES.get(vectorScope);
        assertThat(scope).as("scope " + vectorScope).isNotNull();
        return scope;
    }

    private static JsonNode readVector() throws IOException {
        Path current = Path.of("").toAbsolutePath();
        for (int depth = 0; current != null && depth < 8; depth++, current = current.getParent()) {
            Path candidate = current.resolve("protocol/test-vectors/transfer-capabilities-v1.json");
            if (Files.isRegularFile(candidate)) {
                return JSON.readTree(Files.readString(candidate));
            }
        }
        throw new IllegalStateException("cannot locate transfer-capabilities-v1.json");
    }
}
