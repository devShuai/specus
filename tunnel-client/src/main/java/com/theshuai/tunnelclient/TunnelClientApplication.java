package com.theshuai.tunnelclient;

import com.theshuai.common.util.JsonUtil;
import com.theshuai.tunnelclient.bean.TunnelBean;
import com.theshuai.tunnelclient.client.NettyClient;
import org.apache.commons.io.IOUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.util.StringUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@SpringBootApplication
public class TunnelClientApplication {

    public static void main(String[] args) throws InterruptedException {
        TunnelBean tunnelBean = loadTunnelClientConfig();
        if (tunnelBean == null) {
            System.out.println("未找到配置");
            return;
        }
        SpringApplication.run(TunnelClientApplication.class, args);
        NettyClient nettyClient = new NettyClient(tunnelBean);
        nettyClient.start();
    }

    private static TunnelBean loadTunnelClientConfig() {
        String configString = "";
        File file = new File(System.getProperty("user.dir") + File.separator + "tunnelClientConfig.json");
        FileInputStream fileInputStream = null;
        try {
            if (file.exists()) {
                fileInputStream = new FileInputStream(file);
                byte[] bytes = new byte[fileInputStream.available()];
                IOUtils.readFully(fileInputStream, bytes);
                configString = new String(bytes, StandardCharsets.UTF_8);
            } else {
                file = new File("tunnelClientConfig.json");
                if (file.exists()) {
                    fileInputStream = new FileInputStream(file);
                    byte[] bytes = new byte[fileInputStream.available()];
                    IOUtils.readFully(fileInputStream, bytes);
                    configString = new String(bytes, StandardCharsets.UTF_8);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            if (fileInputStream != null) {
                try {
                    fileInputStream.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }

        if (StringUtils.hasLength(configString)) {
            return JsonUtil.stringToObject(configString, TunnelBean.class);
        } else {
            return null;
        }
    }

}
