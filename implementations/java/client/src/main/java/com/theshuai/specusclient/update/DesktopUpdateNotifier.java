package com.theshuai.specusclient.update;

import com.theshuai.specusclient.bean.ClientStartupConfig;
import lombok.extern.slf4j.Slf4j;

import java.awt.Desktop;
import java.net.URI;

/** Prominent console/log notification with an optional best-effort browser handoff. */
@Slf4j
public final class DesktopUpdateNotifier implements ClientUpdateChecker.UpdateNotifier {
    private final ClientStartupConfig config;

    public DesktopUpdateNotifier(ClientStartupConfig config) {
        this.config = config;
    }

    @Override
    public void notifyUpdate(String currentVersion, ClientUpdateChecker.UpdateCheckResponse response,
                             URI guidePage, URI downloadUri) {
        String level = response.mandatory() ? "当前版本已低于最低支持版本" : "发现新版本";
        log.warn("[client-update] {}: {} -> {}, packageSize={} bytes, 下载={}, 说明={}",
                level, currentVersion, response.latestVersion(), response.fileSize(), downloadUri,
                response.changelogUrl() == null ? guidePage : response.changelogUrl());
        if (!config.isOpenUpdatePage()) {
            return;
        }
        try {
            if (Desktop.isDesktopSupported()
                    && Desktop.getDesktop().isSupported(Desktop.Action.BROWSE)) {
                Desktop.getDesktop().browse(guidePage);
            }
        } catch (Exception exception) {
            log.debug("无法自动打开客户端下载页: {}", exception.getMessage());
        }
    }
}
