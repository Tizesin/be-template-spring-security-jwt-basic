package com.springboot.auth.utils;

import com.google.gson.Gson;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ErrorResponse {
    public static void sendErrorReskponse(HttpServletResponse response,
                                         HttpStatus status) throws IOException {
        Gson gson = new Gson();
        com.springboot.response.ErrorResponse errorResponse =
                com.springboot.response.ErrorResponse.of(status);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(status.value());
        response.getWriter().write(gson.toJson(errorResponse,
                com.springboot.response.ErrorResponse.class));
    }
}
