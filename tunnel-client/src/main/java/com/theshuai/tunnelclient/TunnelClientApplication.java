package com.theshuai.tunnelclient;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelclient.bean.TunnelBean;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
@Slf4j
public class TunnelClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(TunnelClientApplication.class, args);
    }

    @Bean
    public TunnelBean tunnelBean() {
        TunnelBean tunnelBean = loadTunnelClientConfig();
        if (tunnelBean == null) {
            throw new IllegalStateException("未找到 tunnelClientConfig.json 配置，无法启动 tunnel client");
        }
        return tunnelBean;
    }

    private static TunnelBean loadTunnelClientConfig() {
        String configString = "";
        File primaryFile = new File(System.getProperty("user.dir") + File.separator + "tunnelClientConfig.json");
        File fallbackFile = new File("tunnelClientConfig.json");

        try {
            if (primaryFile.exists()) {
                configString = readFile(primaryFile);
                log.info("加载 tunnel client 配置: {}", primaryFile.getAbsolutePath());
            } else {
                if (fallbackFile.exists()) {
                    configString = readFile(fallbackFile);
                    log.info("加载 tunnel client 配置: {}", fallbackFile.getAbsolutePath());
                } else {
                    log.warn("未找到 tunnelClientConfig.json。已检查路径: [{}], [{}]", primaryFile.getAbsolutePath(), fallbackFile.getAbsolutePath());
                }
            }
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }

        if (StringUtils.hasLength(configString)) {
            return JsonUtil.stringToObject(configString, TunnelBean.class);
        } else {
            return null;
        }
    }

    private static String readFile(File file) throws IOException {
        try (FileInputStream fileInputStream = new FileInputStream(file)) {
            byte[] bytes = new byte[fileInputStream.available()];
            IOUtils.readFully(fileInputStream, bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

}
