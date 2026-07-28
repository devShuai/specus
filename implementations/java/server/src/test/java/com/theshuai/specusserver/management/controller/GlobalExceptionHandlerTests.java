package com.theshuai.specusserver.management.controller;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GlobalExceptionHandlerTests {

    @Test
    void responseStatusReasonIsReturnedToTheClient() {
        var response = new GlobalExceptionHandler().handleResponseStatus(
                new ResponseStatusException(HttpStatus.BAD_REQUEST, "配对码无效或已过期"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("配对码无效或已过期", response.getBody().get("error"));
    }
}
