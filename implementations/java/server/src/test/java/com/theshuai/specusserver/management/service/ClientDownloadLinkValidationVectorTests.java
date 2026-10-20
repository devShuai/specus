package com.theshuai.specusserver.management.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.theshuai.specusserver.management.model.ClientDownloadLink;
import com.theshuai.specusserver.management.model.ClientDownloadLinkView;
import com.theshuai.specusserver.management.repository.ClientDownloadLinkRepository;
import org.junit.jupiter.api.Test;
import org.springframework.transaction.PlatformTransactionManager;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * protocol/test-vectors/client-download-link-validation-v1.json is what this service and
 * java.net.URI do; the C server replays the same cases over HTTP.
 */
class ClientDownloadLinkValidationVectorTests {
    private final ObjectMapper mapper = new ObjectMapper();

    private static JsonNode vector() throws Exception {
        Path root = Path.of("").toAbsolutePath();
        String relative = "protocol/test-vectors/client-download-link-validation-v1.json";
        while (root != null && !Files.isRegularFile(root.resolve(relative))) root = root.getParent();
        if (root == null) throw new IllegalStateException("Client download link vector missing");
        return new ObjectMapper().readTree(Files.readString(root.resolve(relative)));
    }

    @Test
    void uriCasesAreWhatJavaNetUriParses() throws Exception {
        JsonNode fixture = vector();
        assertEquals(1, fixture.path("version").asInt());
        for (JsonNode item : fixture.path("uriCases")) {
            String input = item.path("input").asText();
            if (item.has("error")) {
                URISyntaxException error = assertThrows(URISyntaxException.class, () -> new URI(input), input);
                assertEquals(item.path("error").asText(), error.getMessage(), input);
            } else {
                URI uri = new URI(input);
                assertEquals(text(item, "scheme"), uri.getScheme(), input);
                assertEquals(text(item, "userInfo"), uri.getRawUserInfo(), input);
                assertEquals(text(item, "host"), uri.getHost(), input);
                assertEquals(text(item, "rawAuthority"), uri.getRawAuthority(), input);
                assertEquals(text(item, "rawPath"), uri.getRawPath(), input);
                assertEquals(text(item, "rawQuery"), uri.getRawQuery(), input);
                assertEquals(text(item, "rawFragment"), uri.getRawFragment(), input);
            }
        }
    }

    @Test
    void createCasesAreWhatTheServiceAnswers() throws Exception {
        for (JsonNode item : vector().path("createCases")) {
            Harness harness = new Harness();
            check(item, () -> harness.service.create(mutation(item.path("body"))));
        }
    }

    @Test
    void updateCasesAreWhatTheServiceAnswers() throws Exception {
        JsonNode fixture = vector();
        for (JsonNode item : fixture.path("updateCases")) {
            Harness harness = new Harness();
            ClientDownloadLinkView seed = harness.service.create(mutation(fixture.path("seed")));
            ClientDownloadLink row = harness.saved.get(harness.saved.size() - 1);
            if (item.path("seedHosted").asBoolean()) {
                row.setHosted(true);
            }
            when(harness.repository.findById(seed.id())).thenReturn(Optional.of(row));
            check(item, () -> harness.service.update(seed.id(), mutation(item.path("body"))));
        }
    }

    private void check(JsonNode item, Supplier<ClientDownloadLinkView> call) {
        String name = item.path("name").asText();
        if (item.has("error") || item.has("errorPrefix")) {
            IllegalArgumentException error = assertThrows(IllegalArgumentException.class, call::get, name);
            if (item.has("error")) {
                assertEquals(item.path("error").asText(), error.getMessage(), name);
            } else {
                assertTrue(error.getMessage().startsWith(item.path("errorPrefix").asText()), name);
            }
            return;
        }
        JsonNode stored = item.path("stored");
        ClientDownloadLinkView view = call.get();
        assertEquals(text(stored, "implementation"), view.implementation(), name);
        assertEquals(text(stored, "platform"), view.platform(), name);
        assertEquals(text(stored, "arch"), view.arch(), name);
        assertEquals(text(stored, "displayName"), view.displayName(), name);
        assertEquals(text(stored, "downloadUrl"), view.downloadUrl(), name);
        assertEquals(text(stored, "description"), view.description(), name);
        assertEquals(stored.path("displayOrder").asInt(), view.displayOrder(), name);
        assertEquals(stored.path("enabled").asBoolean(), view.enabled(), name);
        assertEquals(text(stored, "version"), view.version(), name);
        assertEquals(text(stored, "sha256"), view.sha256(), name);
        assertEquals(stored.path("fileSize").asLong(), view.fileSize(), name);
        assertEquals(stored.path("isLatest").asBoolean(), view.isLatest(), name);
        assertEquals(text(stored, "changelogUrl"), view.changelogUrl(), name);
        assertEquals(text(stored, "minSupportedVersion"), view.minSupportedVersion(), name);
    }

    private ClientDownloadLinkService.LinkMutation mutation(JsonNode body) {
        try {
            return mapper.treeToValue(body, ClientDownloadLinkService.LinkMutation.class);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.path(field);
        return value.isNull() || value.isMissingNode() ? null : value.asText();
    }

    private static final class Harness {
        final ClientDownloadLinkRepository repository = mock(ClientDownloadLinkRepository.class);
        final List<ClientDownloadLink> saved = new ArrayList<>();
        final ClientDownloadLinkService service;

        Harness() {
            when(repository.saveAndFlush(any())).thenAnswer(invocation -> {
                ClientDownloadLink row = invocation.getArgument(0);
                saved.add(row);
                return row;
            });
            service = new ClientDownloadLinkService(
                    repository, mock(ClientPackageStorage.class), mock(PlatformTransactionManager.class));
        }
    }
}
