package com.theshuai.tunnelserver.management.storage.object;

import java.time.Duration;

public interface ObjectStorageService {
    boolean isEnabled();

    void validateObjectKey(String objectKey);

    PresignedObjectUrl presignUpload(String objectKey, String contentType, Duration ttl);

    PresignedObjectUrl presignDownload(String objectKey, Duration ttl);

    void deleteObject(String objectKey);
}
