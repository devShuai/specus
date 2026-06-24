package com.theshuai.tunnelserver.management.storage;

import lombok.Getter;
import lombok.Setter;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

@Document(indexName = "#{@elasticsearchProperties.tcpIndex}")
@Getter
@Setter
public class TcpTrafficFrameDocument {
    @Id
    private String documentId;

    @Field(name = "id", type = FieldType.Long)
    private long frameId;

    @Field(type = FieldType.Keyword)
    private String tenantId;

    @Field(type = FieldType.Long)
    private long clientId;

    @Field(type = FieldType.Keyword)
    private String clientName;

    @Field(type = FieldType.Integer)
    private int listenPort;

    @Field(type = FieldType.Long)
    private Long resourceId;

    @Field(type = FieldType.Text)
    private String resourceName;

    @Field(type = FieldType.Keyword)
    private String channelId;

    @Field(type = FieldType.Keyword)
    private String direction;

    @Field(type = FieldType.Keyword)
    private String remoteAddress;

    @Field(type = FieldType.Keyword)
    private String sourceAddress;

    @Field(type = FieldType.Integer)
    private Integer sourcePort;

    @Field(type = FieldType.Keyword)
    private String destinationAddress;

    @Field(type = FieldType.Integer)
    private Integer destinationPort;

    @Field(type = FieldType.Long)
    private Long streamOffset;

    @Field(type = FieldType.Long)
    private Long streamEndOffset;

    @Field(type = FieldType.Long)
    private Long frameIndex;

    @Field(type = FieldType.Long)
    private long payloadBytes;

    @Field(type = FieldType.Binary)
    private byte[] payloadData;

    @Field(type = FieldType.Text)
    private String payloadPreviewHex;

    @Field(type = FieldType.Text)
    private String payloadPreviewText;

    @Field(type = FieldType.Boolean)
    private boolean truncated;

    @Field(type = FieldType.Keyword)
    private String frameTime;
}
