package com.theshuai.tunnelserver.management.storage.object;

import java.time.Duration;

public interface ObjectStorageService {
    boolean isEnabled();

    void validateObjectKey(String objectKey);

    PresignedObjectUrl presignUpload(String objectKey, String contentType, Duration ttl);

    PresignedObjectUrl presignDownload(String objectKey, Duration ttl);

    default PresignedObjectUrl presignDownload(String objectKey, Duration ttl, String downloadGrantId) {
        return presignDownload(objectKey, ttl);
    }

    default boolean verifyUploadCallback(String requestTarget, byte[] body,
                                         String authorization, String publicKeyUrl) {
        return false;
    }

    void deleteObject(String objectKey);

    /**
     * HEAD 对象,读取实际存在性与字节大小。用于 complete 阶段校验客户端是否真的上传、
     * 以及实际大小是否超限(预签名 PUT 不绑定 Content-Length,声明大小不可信)。
     */
    ObjectStat statObject(String objectKey);

    /** {@code contentLength} 为 -1 表示对象不存在或响应未带长度。 */
    record ObjectStat(boolean exists, long contentLength) {
    }
}
