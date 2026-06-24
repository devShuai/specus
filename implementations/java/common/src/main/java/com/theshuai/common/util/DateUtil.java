package com.theshuai.common.util;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class DateUtil {

    private static final DateFormat yyyyMMddFormat = new SimpleDateFormat("yyyyMMdd");
    private static final DateFormat fullTimeFormat = new SimpleDateFormat("yyyy-MM-dd_HHmmss");


    public static String getTimeStr() {
        return yyyyMMddFormat.format(Calendar.getInstance().getTime());
    }

    public static String getFullTimeStr() {
        return fullTimeFormat.format(Calendar.getInstance().getTime());
    }

    public static void main(String[] args) {
        log.info(getFullTimeStr());
    }
}
