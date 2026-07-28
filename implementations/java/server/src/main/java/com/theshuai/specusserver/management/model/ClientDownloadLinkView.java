package com.theshuai.specusserver.management.model;

/**
 * 客户端下载链接的展示视图。管理端与公开接口共用同一个 record——公开接口不返回敏感字段，
 * 当前所有字段都是公开可见的，所以无需薄/厚两个版本。
 */
public record ClientDownloadLinkView(
        Long id,
        String implementation,
        String platform,
        String arch,
        String displayName,
        String downloadUrl,
        String description,
        int displayOrder,
        boolean enabled,
        String createdAt,
        String updatedAt
) {
}
