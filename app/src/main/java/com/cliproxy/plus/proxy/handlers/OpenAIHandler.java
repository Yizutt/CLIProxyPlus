package com.cliproxy.plus.proxy.handlers;

import android.util.Log;

import com.cliproxy.plus.auth.AuthManager;
import com.cliproxy.plus.proxy.RequestRouter;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import fi.iki.elonen.NanoHTTPD;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

/**
 * OpenAIHandler - 处理 /v1/chat/completions 等 OpenAI 兼容请求
 * 支持流式 (SSE) 和非流式响应
 * 对应原版 internal/api/handlers/openai/
 */
public class OpenAIHandler {

    private static final String TAG = "OpenAIHandler";

    private final OkHttpClient httpClient;

    public OpenAIHandler() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    /**
     * 处理 OpenAI 聊天完成请求
     */
    public NanoHTTPD.Response handleChatCompletion(Map<String, String> headers, String body) {
        if (body == null || body.isEmpty()) {
            return RequestRouter.jsonResponse(400, "{\"error\":{\"message\":\"Empty request body\"}}");
        }

        try {
            JsonObject requestObj = JsonParser.parseString(body).getAsJsonObject();
            boolean stream = requestObj.has("stream") && requestObj.get("stream").getAsBoolean();
            String model = requestObj.has("model") ? requestObj.get("model").getAsString() : "gpt-4";

            // 选择上游账号
            AuthManager authManager = AuthManager.getInstance();
            AuthManager.AuthCredential credential = authManager.selectCredential("openai");
            if (credential == null) {
                credential = authManager.selectCredential("codex");
            }

            // 未配置账号时返回模拟数据以便测试
            if (credential == null) {
                return handleNoCredential(model, stream);
            }

            // 转发到上游
            return proxyToUpstream(credential, model, body, stream);

        } catch (Exception e) {
            Log.e(TAG, "Failed to handle chat completion", e);
            return RequestRouter.jsonResponse(500,
                    "{\"error\":{\"message\":\"Internal error: " + e.getMessage() + "\"}}");
        }
    }

    private NanoHTTPD.Response handleNoCredential(String model, boolean stream) {
        if (stream) {
            String response = "data: {\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\"," +
                    "\"model\":\"" + model + "\",\"choices\":[{\"index\":0," +
                    "\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n" +
                    "data: {\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\"," +
                    "\"model\":\"" + model + "\",\"choices\":[{\"index\":0," +
                    "\"delta\":{\"content\":\"Hello from CLIProxy Plus!\"}" +
                    ",\"finish_reason\":null}]}\n\n" +
                    "data: {\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\"," +
                    "\"model\":\"" + model + "\",\"choices\":[{\"index\":0," +
                    "\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n" +
                    "data: [DONE]\n\n";
            return RequestRouter.sseResponse(response);
        } else {
            String response = "{\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion\"," +
                    "\"model\":\"" + model + "\",\"choices\":[{\"index\":0," +
                    "\"message\":{\"role\":\"assistant\",\"content\":\"Hello from CLIProxy Plus! " +
                    "No upstream configured.\"},\"finish_reason\":\"stop\"}]}";
            return RequestRouter.jsonResponse(200, response);
        }
    }

    private NanoHTTPD.Response proxyToUpstream(AuthManager.AuthCredential credential,
                                                String model, String body, boolean stream) {
        try {
            String upstreamUrl = determineUpstreamUrl(credential);
            String apiKey = credential.metadata.get("api_key");

            Request.Builder requestBuilder = new Request.Builder()
                    .url(upstreamUrl + "/v1/chat/completions")
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Authorization", "Bearer " + (apiKey != null ? apiKey : ""));

            RequestBody requestBody = RequestBody.create(body, MediaType.get("application/json"));
            requestBuilder.post(requestBody);

            Request upstreamRequest = requestBuilder.build();
            okhttp3.Call call = httpClient.newCall(upstreamRequest);

            if (stream) {
                okhttp3.Response upstreamResponse = call.execute();
                okhttp3.ResponseBody responseBody = upstreamResponse.body();
                String bodyStr = responseBody != null ? responseBody.string() : "{}";
                return RequestRouter.sseResponse(bodyStr);
            } else {
                try (okhttp3.Response upstreamResponse = call.execute()) {
                    String responseBody = upstreamResponse.body() != null ?
                            upstreamResponse.body().string() : "{}";
                    return RequestRouter.jsonResponse(upstreamResponse.code(), responseBody);
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Upstream request failed", e);
            return RequestRouter.jsonResponse(502,
                    "{\"error\":{\"message\":\"Upstream request failed: " + e.getMessage() + "\"}}");
        }
    }

    private String determineUpstreamUrl(AuthManager.AuthCredential credential) {
        String baseUrl = credential.metadata.get("base_url");
        if (baseUrl != null && !baseUrl.isEmpty()) {
            return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        }
        return "https://api.openai.com";
    }
}