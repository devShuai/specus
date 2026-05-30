package com.theshuai.common.util;

import com.alibaba.fastjson2.JSONObject;
import com.theshuai.common.manager.SyncFutureTaskManager;
import org.apache.hc.client5.http.classic.methods.*;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.entity.UrlEncodedFormEntity;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.apache.hc.core5.http.io.entity.InputStreamEntity;
import org.apache.hc.core5.http.io.entity.StringEntity;
import org.apache.hc.core5.http.message.BasicNameValuePair;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.hc.core5.util.Timeout;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HttpUtil {

    public static final String HTTP_GET = "GET";
    public static final String HTTP_POST = "POST";
    public static final String HTTP_PUT = "PUT";
    public static final String HTTP_DELETE = "DELETE";

    private static final CloseableHttpClient httpClient = HttpClients.createDefault();

    public static String sendRequest(String method, String url, Map<String, String> paramMap, Map<String, String> headerMap, String body) throws Exception {
        switch (method) {
            case HTTP_GET:
                return getRequest(url, paramMap, headerMap);
            case HTTP_POST:
                return postRequest(url, paramMap, headerMap, body);
            case HTTP_DELETE:
                return deleteRequest(url, paramMap, headerMap);
            case HTTP_PUT:
                return putRequest(url, paramMap, headerMap, body);
            default:
                return null;
        }
    }

    public static String postRequest(String url, Map<String, String> paramMap, Map<String, String> headerMap, String jsonString) throws Exception {
        URIBuilder builder = new URIBuilder(url);
        if (paramMap != null) {
            for (Map.Entry<String, String> entry : paramMap.entrySet()) {
                builder.setParameter(entry.getKey(), entry.getValue());
            }
        }
        HttpPost request = new HttpPost(builder.build());
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.ofSeconds(30))
                .setConnectionRequestTimeout(Timeout.ofSeconds(30))
                .build();
        request.setConfig(requestConfig);

        request.setHeader("Content-Type", "application/json");
        if (headerMap != null) {
            for (Map.Entry<String, String> entry : headerMap.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
            }
        }

        if (jsonString != null && !jsonString.isEmpty()) {
            StringEntity stringEntity = new StringEntity(jsonString, ContentType.APPLICATION_JSON);
            request.setEntity(stringEntity);
        }

        return httpClient.execute(request, response -> {
            HttpEntity entity = response.getEntity();
            return EntityUtils.toString(entity);
        });
    }

    public static String putRequest(String url, Map<String, String> paramMap, Map<String, String> headerMap, String jsonString) throws Exception {
        URIBuilder builder = new URIBuilder(url);

        if (paramMap != null) {
            for (Map.Entry<String, String> entry : paramMap.entrySet()) {
                builder.setParameter(entry.getKey(), entry.getValue());
            }
        }

        HttpPut request = new HttpPut(builder.build());

        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.ofSeconds(30))
                .setConnectionRequestTimeout(Timeout.ofSeconds(30))
                .build();
        request.setConfig(requestConfig);

        request.setHeader("Content-Type", "application/json");
        if (headerMap != null) {
            for (Map.Entry<String, String> entry : headerMap.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
            }
        }

        if (jsonString != null && !jsonString.isEmpty()) {
            StringEntity stringEntity = new StringEntity(jsonString, ContentType.APPLICATION_JSON);
            request.setEntity(stringEntity);
        }

        return httpClient.execute(request, response -> {
            HttpEntity entity = response.getEntity();
            return EntityUtils.toString(entity);
        });
    }

    public static String getRequest(String url, Map<String, String> paramMap, Map<String, String> headerMap) throws Exception {
        URIBuilder builder = new URIBuilder(url);

        if (paramMap != null) {
            for (Map.Entry<String, String> entry : paramMap.entrySet()) {
                builder.setParameter(entry.getKey(), entry.getValue());
            }
        }
        HttpGet request = new HttpGet(builder.build());
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.ofSeconds(30))
                .setConnectionRequestTimeout(Timeout.ofSeconds(30))
                .build();
        request.setConfig(requestConfig);

        request.setHeader("Content-Type", "application/json");
        if (headerMap != null) {
            for (Map.Entry<String, String> entry : headerMap.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
            }
        }

        return httpClient.execute(request, response -> {
            HttpEntity entity = response.getEntity();
            return EntityUtils.toString(entity);
        });
    }

    public static String putFile(String url, InputStream file, Map<String, String> headerMap) throws Exception {

        HttpPut request = new HttpPut(url);

        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.ofSeconds(30))
                .setConnectionRequestTimeout(Timeout.ofSeconds(30))
                .build();
        request.setConfig(requestConfig);

        if (headerMap != null) {
            for (Map.Entry<String, String> entry : headerMap.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
            }
        }

        if (file != null && file.available() > 0) {
            InputStreamEntity inputStreamEntity = new InputStreamEntity(file, ContentType.APPLICATION_OCTET_STREAM);
            request.setEntity(inputStreamEntity);
        }

        return httpClient.execute(request, response -> {
            HttpEntity entity = response.getEntity();
            return EntityUtils.toString(entity);
        });
    }

    public static String deleteRequest(String url, Map<String, String> paramMap, Map<String, String> headerMap) throws Exception {
        URIBuilder builder = new URIBuilder(url);

        if (paramMap != null) {
            for (Map.Entry<String, String> entry : paramMap.entrySet()) {
                builder.setParameter(entry.getKey(), entry.getValue());
            }
        }
        HttpDelete request = new HttpDelete(builder.build());
        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.ofSeconds(30))
                .setConnectionRequestTimeout(Timeout.ofSeconds(30))
                .build();
        request.setConfig(requestConfig);

        request.setHeader("Content-Type", "application/json");
        if (headerMap != null) {
            for (Map.Entry<String, String> entry : headerMap.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
            }
        }

        return httpClient.execute(request, response -> {
            HttpEntity entity = response.getEntity();
            return EntityUtils.toString(entity);
        });
    }

    public static String getImage(String imgUrl) throws IOException {
        HttpGet httpGet = new HttpGet(imgUrl);
        return httpClient.execute(httpGet, response -> {
            return ImageUtil.imageToBase64(response.getEntity().getContent());
        });
    }

    public static String sendPostParam(String url, Map<String, String> paramMap, Map<String, String> headerMap, String jsonString) throws Exception {
        URIBuilder builder = new URIBuilder(url);

        if (paramMap != null) {
            for (Map.Entry<String, String> entry : paramMap.entrySet()) {
                builder.setParameter(entry.getKey(), entry.getValue());
            }
        }

        HttpPost request = new HttpPost(builder.build());

        RequestConfig requestConfig = RequestConfig.custom()
                .setResponseTimeout(Timeout.ofSeconds(30))
                .setConnectionRequestTimeout(Timeout.ofSeconds(30))
                .build();
        request.setConfig(requestConfig);

        request.setHeader("Content-Type", "application/json");
        if (headerMap != null) {
            for (Map.Entry<String, String> entry : headerMap.entrySet()) {
                request.setHeader(entry.getKey(), entry.getValue());
            }
        }

        if (jsonString != null && !jsonString.isEmpty()) {
            StringEntity stringEntity = new StringEntity(jsonString, ContentType.APPLICATION_JSON);
            request.setEntity(stringEntity);
        }

        return httpClient.execute(request, response -> {
            HttpEntity entity = response.getEntity();
            return EntityUtils.toString(entity);
        });
    }

    public static String gatewayRequest(String url, Map<String, String> paramMap, Map<String, String> headerMap, String bodyString) {
        return SyncFutureTaskManager.sendSyncMsg("java client", url, "POST", paramMap, headerMap, bodyString);
    }

    public static String sendPostForm(String url, Map<String, String> params) throws Exception {
        HttpPost request = new HttpPost(url);
        RequestConfig requestConfig = RequestConfig.custom()
                .setConnectionRequestTimeout(Timeout.ofSeconds(10))
                .setResponseTimeout(Timeout.ofSeconds(30))
                .build();
        request.setConfig(requestConfig);

        if (params != null) {
            List<NameValuePair> nameValuePairList = new ArrayList<>();
            request.setHeader("X-Http-Demo", HttpUtil.class.getSimpleName());
            request.addHeader("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8");
            for (Map.Entry<String, String> entry : params.entrySet()) {
                nameValuePairList.add(new BasicNameValuePair(entry.getKey(), entry.getValue()));
            }
            UrlEncodedFormEntity bodyEntity = new UrlEncodedFormEntity(nameValuePairList, StandardCharsets.UTF_8);
            request.setEntity(bodyEntity);
        }

        return httpClient.execute(request, response -> EntityUtils.toString(response.getEntity()));
    }

    public static JSONObject createHeadJson() {
        long timestamp = System.currentTimeMillis();
        JSONObject jsonObject = new JSONObject();
        jsonObject.put("timestamp", timestamp);
        jsonObject.put("md5Code", MD5Util.getSaltMd5(String.valueOf(timestamp)));
        return jsonObject;
    }
}
