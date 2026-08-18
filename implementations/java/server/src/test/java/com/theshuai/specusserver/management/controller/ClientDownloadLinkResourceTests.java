package com.theshuai.specusserver.management.controller;

import com.theshuai.specusserver.management.security.ManagementContextResolver;
import com.theshuai.specusserver.management.service.ClientDownloadLinkService;
import com.theshuai.specusserver.management.service.ClientDownloadLinkService.DownloadablePackage;
import com.theshuai.specusserver.management.service.ClientPackageRateLimiter;
import com.theshuai.specusserver.management.service.ManagementUserService;
import com.theshuai.specusserver.security.ClientAddressResolver;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.hamcrest.Matchers.containsString;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.setup.MockMvcBuilders.standaloneSetup;

class ClientDownloadLinkResourceTests {
    @TempDir
    Path temporaryDirectory;

    @Test
    void packageGetAndHeadUseNoStoreAndApkAttachmentName() throws Exception {
        byte[] bytes = "android-apk".getBytes(StandardCharsets.UTF_8);
        Path file = Files.write(temporaryDirectory.resolve("61"), bytes);
        ClientDownloadLinkService service = mock(ClientDownloadLinkService.class);
        when(service.downloadable(61L)).thenReturn(new DownloadablePackage(
                file, "Specus Android.apk", bytes.length, "a".repeat(64)));
        ClientAddressResolver resolver = mock(ClientAddressResolver.class);
        when(resolver.resolve(any(HttpServletRequest.class))).thenReturn("192.0.2.61");
        ClientDownloadLinkResource resource = new ClientDownloadLinkResource(
                service,
                mock(ClientPackageRateLimiter.class),
                resolver,
                mock(ManagementContextResolver.class),
                mock(ManagementUserService.class));
        MockMvc mvc = standaloneSetup(resource).build();
        String route = "/api/public/client-packages/61/download";

        mvc.perform(get(route))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("Specus Android.apk")))
                .andExpect(header().string(HttpHeaders.ETAG, "\"sha256-" + "a".repeat(64) + "\""))
                .andExpect(header().string("X-Content-Type-Options", "nosniff"))
                .andExpect(content().bytes(bytes));

        mvc.perform(head(route))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.CONTENT_DISPOSITION, containsString("Specus Android.apk")))
                .andExpect(header().string(HttpHeaders.ETAG, "\"sha256-" + "a".repeat(64) + "\""))
                .andExpect(header().longValue(HttpHeaders.CONTENT_LENGTH, bytes.length));

        mvc.perform(get(route).header(HttpHeaders.RANGE, "bytes=0-2"))
                .andExpect(status().isPartialContent())
                .andExpect(header().string(HttpHeaders.CACHE_CONTROL, "no-store"))
                .andExpect(header().string(HttpHeaders.CONTENT_RANGE, "bytes 0-2/" + bytes.length))
                .andExpect(content().bytes("and".getBytes(StandardCharsets.UTF_8)));
    }
}
