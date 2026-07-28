package com.theshuai.specusserver.management.storage.media;

import com.theshuai.specusserver.config.MediaCaptureProperties;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.ResponseInputStream;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.AbortMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CompleteMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.CompletedMultipartUpload;
import software.amazon.awssdk.services.s3.model.CompletedPart;
import software.amazon.awssdk.services.s3.model.CreateBucketRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadRequest;
import software.amazon.awssdk.services.s3.model.CreateMultipartUploadResponse;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectRequest;
import software.amazon.awssdk.services.s3.model.GetObjectResponse;
import software.amazon.awssdk.services.s3.model.HeadBucketRequest;
import software.amazon.awssdk.services.s3.model.HeadObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Exception;
import software.amazon.awssdk.services.s3.model.UploadPartRequest;
import software.amazon.awssdk.services.s3.model.UploadPartResponse;

import java.net.URI;
import java.util.List;

@Service
@Slf4j
public class RustFsMediaStorage {
    private final MediaCaptureProperties properties;
    private volatile S3Client client;

    public RustFsMediaStorage(MediaCaptureProperties properties) {
        this.properties = properties;
    }

    @PostConstruct
    public void initialize() {
        if (!properties.isReady()) {
            log.info("[media-capture] RustFS media storage disabled or incomplete");
            return;
        }
        S3Client built = S3Client.builder()
                .endpointOverride(URI.create(properties.getEndpoint().trim()))
                .region(Region.of(normalizedRegion()))
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(
                        properties.getAccessKeyId().trim(),
                        properties.getAccessKeySecret().trim())))
                .forcePathStyle(properties.isPathStyle())
                .build();
        client = built;
        verifyBucket(built);
        log.info("[media-capture] RustFS ready endpoint={} bucket={} pathStyle={} partSizeBytes={}",
                properties.getEndpoint(), properties.getBucket(), properties.isPathStyle(),
                properties.normalizedPartSizeBytes());
    }

    public boolean isReady() {
        return client != null && properties.isReady();
    }

    public MultipartUpload beginMultipart(String objectKey, String contentType, String contentEncoding) {
        S3Client s3 = requireClient();
        CreateMultipartUploadRequest.Builder request = CreateMultipartUploadRequest.builder()
                .bucket(properties.getBucket().trim())
                .key(objectKey);
        if (hasText(contentType)) {
            request.contentType(contentType);
        }
        if (hasText(contentEncoding)) {
            request.contentEncoding(contentEncoding);
        }
        CreateMultipartUploadResponse response = s3.createMultipartUpload(request.build());
        return new MultipartUpload(objectKey, response.uploadId());
    }

    public CompletedPart uploadPart(MultipartUpload upload, int partNumber, byte[] bytes) {
        UploadPartResponse response = requireClient().uploadPart(
                UploadPartRequest.builder()
                        .bucket(properties.getBucket().trim())
                        .key(upload.objectKey())
                        .uploadId(upload.uploadId())
                        .partNumber(partNumber)
                        .contentLength((long) bytes.length)
                        .build(),
                RequestBody.fromBytes(bytes));
        return CompletedPart.builder().partNumber(partNumber).eTag(response.eTag()).build();
    }

    public String completeMultipart(MultipartUpload upload, List<CompletedPart> completedParts) {
        CompleteMultipartUploadResponse response = requireClient().completeMultipartUpload(
                CompleteMultipartUploadRequest.builder()
                        .bucket(properties.getBucket().trim())
                        .key(upload.objectKey())
                        .uploadId(upload.uploadId())
                        .multipartUpload(CompletedMultipartUpload.builder().parts(completedParts).build())
                        .build());
        return response.eTag();
    }

    public void abortMultipart(MultipartUpload upload) {
        if (upload == null || !isReady()) {
            return;
        }
        requireClient().abortMultipartUpload(AbortMultipartUploadRequest.builder()
                .bucket(properties.getBucket().trim())
                .key(upload.objectKey())
                .uploadId(upload.uploadId())
                .build());
    }

    public ResponseInputStream<GetObjectResponse> open(String objectKey, Long start, Long end) {
        GetObjectRequest.Builder request = GetObjectRequest.builder()
                .bucket(properties.getBucket().trim())
                .key(objectKey);
        if (start != null) {
            request.range(end == null ? "bytes=" + start + "-" : "bytes=" + start + "-" + end);
        }
        return requireClient().getObject(request.build());
    }

    public byte[] readAll(String objectKey, long maxBytes) {
        S3Client s3 = requireClient();
        long length = s3.headObject(HeadObjectRequest.builder()
                .bucket(properties.getBucket().trim())
                .key(objectKey)
                .build()).contentLength();
        if (maxBytes > 0 && length > maxBytes) {
            throw new IllegalArgumentException("媒体清单超过解析上限");
        }
        return s3.getObjectAsBytes(GetObjectRequest.builder()
                .bucket(properties.getBucket().trim())
                .key(objectKey)
                .build()).asByteArray();
    }

    public void delete(String objectKey) {
        if (!isReady() || !hasText(objectKey)) {
            return;
        }
        requireClient().deleteObject(DeleteObjectRequest.builder()
                .bucket(properties.getBucket().trim())
                .key(objectKey)
                .build());
    }

    @PreDestroy
    public void close() {
        S3Client current = client;
        client = null;
        if (current != null) {
            current.close();
        }
    }

    private void verifyBucket(S3Client s3) {
        String bucket = properties.getBucket().trim();
        try {
            s3.headBucket(HeadBucketRequest.builder().bucket(bucket).build());
        } catch (S3Exception exception) {
            if (!properties.isCreateBucketIfMissing() || exception.statusCode() != 404) {
                s3.close();
                client = null;
                throw exception;
            }
            s3.createBucket(CreateBucketRequest.builder().bucket(bucket).build());
        }
    }

    private S3Client requireClient() {
        S3Client current = client;
        if (current == null) {
            throw new IllegalStateException("RustFS 媒体存储未配置");
        }
        return current;
    }

    private String normalizedRegion() {
        return hasText(properties.getRegion()) ? properties.getRegion().trim() : "us-east-1";
    }

    private boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    public record MultipartUpload(String objectKey, String uploadId) {
    }
}
