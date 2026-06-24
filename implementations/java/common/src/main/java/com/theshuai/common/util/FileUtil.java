package com.theshuai.common.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class FileUtil {

    /**
     * 运行文件所在目录
     */
    public static String CUR_PATH;

    static {
        String path = System.getProperty("java.class.path");
        int firstIndex = path.lastIndexOf(System.getProperty("path.separator")) + 1;
        int lastIndex = path.lastIndexOf(File.separator) + 1;
        path = path.substring(firstIndex, lastIndex);
        CUR_PATH = path;
    }

    public static String getCurPath() {
        return CUR_PATH;
    }

    public static void save(String filePath, String imgBase64) throws IOException {
        byte[] imgByteArray = ImageUtil.base64StringToByteArray(imgBase64);
        File saveFile = new File(filePath);
        FileOutputStream fos = new FileOutputStream(saveFile);
        fos.write(imgByteArray);
        fos.close();
    }
}
