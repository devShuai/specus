package com.theshuai.tunnelserver.management.storage;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

@Document(indexName = "#{@elasticsearchProperties.index}")
@Getter
@Setter
public class HttpTrafficExchangeDocument {
    @Id
    private String documentId;

    @Field(name = "id", type = FieldType.Long)
    private long exchangeId;

    @Field(type = FieldType.Keyword)
    private String tenantId;

    @Field(type = FieldType.Long)
    private long clientId;

    @Field(type = FieldType.Keyword)
    private String clientName;

    @Field(type = FieldType.Keyword)
    private String route;

    @Field(type = FieldType.Long)
    private Long resourceId;

    @Field(type = FieldType.Text)
    private String resourceName;

    @Field(type = FieldType.Keyword)
    private String method;

    @Field(type = FieldType.Text)
    private String relativePath;

    @Field(type = FieldType.Text)
    private String rawQuery;

    @Field(type = FieldType.Integer)
    private int statusCode;

    @Field(type = FieldType.Boolean)
    private boolean success;

    @Field(type = FieldType.Text)
    private String error;

    @Field(type = FieldType.Keyword)
    private String remoteAddress;

    @Field(type = FieldType.Long)
    private long requestBytes;

    @Field(type = FieldType.Long)
    private long responseBytes;

    @Field(type = FieldType.Long)
    private long elapsedMs;

    @Field(type = FieldType.Keyword)
    private String requestContentType;

    @Field(type = FieldType.Keyword)
    private String responseContentType;

    @Field(type = FieldType.Keyword)
    private String responseBodyType;

    @Field(type = FieldType.Text)
    private String requestHeaders;

    @Field(type = FieldType.Text)
    private String responseHeaders;

    @Field(type = FieldType.Text)
    private String requestPreviewHex;

    @Field(type = FieldType.Binary)
    private byte[] requestBodyData;

    @Field(type = FieldType.Text)
    private String requestPreviewText;

    @Field(type = FieldType.Text)
    private String responsePreviewHex;

    @Field(type = FieldType.Binary)
    private byte[] responseBodyData;

    @Field(type = FieldType.Text)
    private String responsePreviewText;

    @Field(type = FieldType.Boolean)
    private boolean requestTruncated;

    @Field(type = FieldType.Boolean)
    private boolean responseTruncated;

    @Field(type = FieldType.Keyword)
    private String capturedAt;
}
