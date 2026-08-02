package com.cliproxy.plus.proxy.handlers;

import android.util.Log;

import com.cliproxy.plus.auth.AuthManager;
import com.cliproxy.plus.proxy.RequestRouter;

import org.json.JSONArray;
import org.json.JSONObject;

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
 * ClaudeHandler - 处理 /v1/messages 请求（Claude API）
 * <p>
 * 支持流式（SSE）和非流式响应。
 * 使用 okhttp3 转发请求到上游 Anthropic API。
 * 通过 AuthManager 选择 'claude' 提供商凭证进行认证。
 * 对应原版 internal/api/handlers/claude/
 */
public class ClaudeHandler {

    private static final String TAG = "ClaudeHandler";

    /** Anthropic API 默认基础地址 */
    private static final String DEFAULT_BASE_URL = "https://api.anthropic.com";

    /** Anthropic API 版本头 */
    private static final String ANTHROPIC_VERSION = "2023-06-01";

    /** 默认最大 Token 数 */
    private static final int DEFAULT_MAX_TOKENS = 1024;

    /** 默认模型 */
    private static final String DEFAULT_MODEL = "claude-3-5-sonnet-20241022";

    private final OkHttpClient httpClient;

    /**
     * 已知的 Claude 模型映射表
     * key: 短名称/别名, value: 完整模型 ID
     */
    private static final java.util.Map<String, String> MODEL_MAP = java.util.Map.ofEntries(
            java.util.Map.entry("claude", "claude-3-5-sonnet-20241022"),
            java.util.Map.entry("claude-sonnet", "claude-3-5-sonnet-20241022"),
            java.util.Map.entry("claude-3.5-sonnet", "claude-3-5-sonnet-20241022"),
            java.util.Map.entry("claude-haiku", "claude-3-5-haiku-20241022"),
            java.util.Map.entry("claude-3.5-haiku", "claude-3-5-haiku-20241022"),
            java.util.Map.entry("claude-opus", "claude-3-opus-20240229"),
            java.util.Map.entry("claude-3-opus", "claude-3-opus-20240229"),
            java.util.Map.entry("claude-3-sonnet", "claude-3-sonnet-20240229"),
            java.util.Map.entry("claude-3-haiku", "claude-3-haiku-20240307"),
            java.util.Map.entry("claude-2", "claude-2.1"),
            java.util.Map.entry("claude-2.0", "claude-2.0"),
            java.util.Map.entry("claude-2.1", "claude-2.1"),
            java.util.Map.entry("claude-instant", "claude-instant-1.2")
    );

    public ClaudeHandler() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    /**
     * 处理 /v1/messages 请求
     *
     * @param headers 请求头
     * @param body    请求体 JSON 字符串
     * @return NanoHTTPD 响应
     */
    public NanoHTTPD.Response handleMessage(Map<String, String> headers, String body) {
        if (body == null || body.isEmpty()) {
            return RequestRouter.jsonResponse(400,
                    "{\"type\":\"error\",\"error\":{\"type\":\"invalid_request_error\"," +
                    "\"message\":\"Empty request body\"}}");
        }

        try {
            JSONObject requestObj = new JSONObject(body);
            boolean stream = requestObj.optBoolean("stream", false);
            String model = resolveModel(requestObj.optString("model", DEFAULT_MODEL));

            // 选择上游账号
            AuthManager authManager = AuthManager.getInstance();
            AuthManager.AuthCredential credential = authManager.selectCredential("claude");
            if (credential == null) {
                credential = authManager.selectCredential("anthropic");
            }

            // 未配置账号时返回模拟数据以便测试
            if (credential == null) {
                return handleNoCredential(model, stream, requestObj);
            }

            // 转发到上游
            return proxyToUpstream(credential, model, body, stream);

        } catch (Exception e) {
            Log.e(TAG, "Failed to handle message", e);
            return RequestRouter.jsonResponse(500,
                    "{\"type\":\"error\",\"error\":{\"type\":\"internal_error\"," +
                    "\"message\":\"Internal error: " + e.getMessage() + "\"}}");
        }
    }

    /**
     * 解析 Claude 模型名称，将别名映射为完整模型 ID
     *
     * @param model 原始模型名称
     * @return 完整的模型 ID
     */
    private String resolveModel(String model) {
        if (model == null || model.isEmpty()) {
            return DEFAULT_MODEL;
        }
        // 如果已经是完整模型 ID 则直接返回
        if (model.startsWith("claude-") && model.matches("^claude[-.\\w]+$")) {
            return model;
        }
        // 从映射表中查找别名
        String resolved = MODEL_MAP.get(model.toLowerCase());
        return resolved != null ? resolved : model;
    }

    /**
     * 未配置凭证时返回模拟响应
     */
    private NanoHTTPD.Response handleNoCredential(String model, boolean stream, JSONObject requestObj) {
        if (stream) {
            // 构造模拟 SSE 流式响应（Claude 事件格式）
            StringBuilder sb = new StringBuilder();

            // message_start 事件
            sb.append("event: message_start\n");
            sb.append("data: {\"type\":\"message_start\",\"message\":{")
              .append("\"id\":\"msg_mock_001\",\"type\":\"message\",\"role\":\"assistant\",")
              .append("\"model\":\"").append(model).append("\",")
              .append("\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,")
              .append("\"usage\":{\"input_tokens\":10,\"output_tokens\":0}}")
              .append("\n\n");

            // content_block_start 事件
            sb.append("event: content_block_start\n");
            sb.append("data: {\"type\":\"content_block_start\",\"index\":0,")
              .append("\"content_block\":{\"type\":\"text\",\"text\":\"\"}}")
              .append("\n\n");

            // content_block_delta 事件
            sb.append("event: content_block_delta\n");
            sb.append("data: {\"type\":\"content_block_delta\",\"index\":0,")
              .append("\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello from CLIProxy Plus!\"}}")
              .append("\n\n");

            // content_block_stop 事件
            sb.append("event: content_block_stop\n");
            sb.append("data: {\"type\":\"content_block_stop\",\"index\":0}\n\n");

            // message_delta 事件
            sb.append("event: message_delta\n");
            sb.append("data: {\"type\":\"message_delta\",\"delta\":{")
              .append("\"stop_reason\":\"end_turn\",\"stop_sequence\":null},")
              .append("\"usage\":{\"output_tokens\":8}}")
              .append("\n\n");

            // message_stop 事件
            sb.append("event: message_stop\n");
            sb.append("data: {\"type\":\"message_stop\"}\n\n");

            return RequestRouter.sseResponse(sb.toString());
        } else {
            // 非流式模拟响应
            JSONObject response = new JSONObject();
            try {
                response.put("id", "msg_mock_001");
                response.put("type", "message");
                response.put("role", "assistant");
                response.put("model", model);
                response.put("stop_reason", "end_turn");
                response.put("stop_sequence", JSONObject.NULL);

                JSONArray content = new JSONArray();
                JSONObject textBlock = new JSONObject();
                textBlock.put("type", "text");
                textBlock.put("text", "Hello from CLIProxy Plus! No upstream configured.");
                content.put(textBlock);
                response.put("content", content);

                JSONObject usage = new JSONObject();
                usage.put("input_tokens", 10);
                usage.put("output_tokens", 8);
                response.put("usage", usage);
            } catch (Exception e) {
                Log.w(TAG, "Failed to build mock response", e);
            }
            return RequestRouter.jsonResponse(200, response.toString());
        }
    }

    /**
     * 转发请求到上游 Anthropic API
     *
     * @param credential 认证凭证
     * @param model      模型名称
     * @param body       原始请求体
     * @param stream     是否启用流式响应
     * @return NanoHTTPD 响应
     */
    private NanoHTTPD.Response proxyToUpstream(AuthManager.AuthCredential credential,
                                                String model, String body, boolean stream) {
        try {
            String upstreamUrl = determineUpstreamUrl(credential);
            String apiKey = credential.metadata.get("api_key");

            // 确保请求体中的模型名称已解析
            String finalBody = ensureModelInBody(body, model);

            Request.Builder requestBuilder = new Request.Builder()
                    .url(upstreamUrl + "/v1/messages")
                    .addHeader("Content-Type", "application/json")
                    .addHeader("x-api-key", apiKey != null ? apiKey : "")
                    .addHeader("anthropic-version", ANTHROPIC_VERSION);

            // 添加用户代理头
            requestBuilder.addHeader("User-Agent", "CLIProxyPlus/1.0");

            RequestBody requestBody = RequestBody.create(finalBody, MediaType.get("application/json"));
            requestBuilder.post(requestBody);

            Request upstreamRequest = requestBuilder.build();
            okhttp3.Call call = httpClient.newCall(upstreamRequest);

            if (stream) {
                // 流式响应：直接转发上游的 SSE 数据
                okhttp3.Response upstreamResponse = call.execute();
                okhttp3.ResponseBody responseBody = upstreamResponse.body();
                String bodyStr = responseBody != null ? responseBody.string() : "{}";
                return RequestRouter.sseResponse(bodyStr);
            } else {
                // 非流式响应：转发上游响应
                try (okhttp3.Response upstreamResponse = call.execute()) {
                    String responseBody = upstreamResponse.body() != null ?
                            upstreamResponse.body().string() : "{}";
                    return RequestRouter.jsonResponse(upstreamResponse.code(), responseBody);
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Upstream request failed", e);
            return RequestRouter.jsonResponse(502,
                    "{\"type\":\"error\",\"error\":{\"type\":\"upstream_error\"," +
                    "\"message\":\"Upstream request failed: " + e.getMessage() + "\"}}");
        }
    }

    /**
     * 确保请求体中的 model 字段已解析为完整模型 ID
     *
     * @param body  原始请求体
     * @param model 已解析的模型名称
     * @return 更新后的请求体
     */
    private String ensureModelInBody(String body, String model) {
        try {
            JSONObject obj = new JSONObject(body);
            String currentModel = obj.optString("model", "");
            // 如果当前模型与已解析模型不同，则更新
            if (!currentModel.equals(model)) {
                obj.put("model", model);
                // 确保 max_tokens 存在
                if (!obj.has("max_tokens")) {
                    obj.put("max_tokens", DEFAULT_MAX_TOKENS);
                }
                return obj.toString();
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to ensure model in body", e);
        }
        return body;
    }

    /**
     * 从凭证中确定上游 URL
     *
     * @param credential 认证凭证
     * @return 上游基础 URL
     */
    private String determineUpstreamUrl(AuthManager.AuthCredential credential) {
        String baseUrl = credential.metadata.get("base_url");
        if (baseUrl != null && !baseUrl.isEmpty()) {
            // 移除末尾斜杠
            return baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
        }
        return DEFAULT_BASE_URL;
    }
}