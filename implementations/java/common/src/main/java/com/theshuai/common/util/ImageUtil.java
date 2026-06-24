package com.theshuai.common.util;

import javax.imageio.ImageIO;
import javax.imageio.stream.ImageOutputStream;
import java.awt.*;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Base64;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class ImageUtil {

    public static String imageToBase64(InputStream inputStream) {
        if (inputStream == null) {
            return null;
        }

        try {
            BufferedImage bufferedImage = ImageIO.read(inputStream);
            return Base64.getEncoder().encodeToString(imageToBytes(scale(bufferedImage, 960, 960)));
        } catch (Exception e) {
            log.error("处理失败", e);
            return null;
        }
    }

    public static byte[] base64StringToByteArray(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    /**
     * 将图片转换为base64加密字符串
     *
     * @param image 图片数据
     * @return base64加密字符串
     * @throws IOException io异常
     */
    private static byte[] imageToBytes(BufferedImage image) throws IOException {
        ByteArrayOutputStream bas = new ByteArrayOutputStream();
        ImageOutputStream ios = ImageIO.createImageOutputStream(bas);
        ImageIO.write(image, "jpg", ios);
        return bas.toByteArray();
    }

    /**
     * scale图片分辨率
     *
     * @param image     图片
     * @param maxWidth  最大宽度
     * @param maxHeight 最大高度
     * @return scale后图片
     */
    public static BufferedImage scale(BufferedImage image, int maxWidth, int maxHeight) {
        int width = image.getWidth();
        int height = image.getHeight();

        boolean needScale = false;

        int targetWidth = width;
        int targetHeight = height;

        if (width > height) {
            if (width > maxHeight) {
                needScale = true;
                targetWidth = maxWidth;
                targetHeight = height * maxWidth / width;
            }
        } else {
            if (height > maxHeight) {
                needScale = true;
                targetHeight = maxHeight;
                targetWidth = width * maxHeight / height;
            }
        }

        if (needScale) {
            Image outImage = image.getScaledInstance(targetWidth, targetHeight, Image.SCALE_DEFAULT);
            BufferedImage bufferedImage = new BufferedImage(targetWidth, targetHeight, BufferedImage.TYPE_INT_RGB);
            Graphics2D graphics2D = bufferedImage.createGraphics();
            graphics2D.drawImage(outImage, 0, 0, null);
            graphics2D.dispose();
            return bufferedImage;
        }

        return image;

    }
}
