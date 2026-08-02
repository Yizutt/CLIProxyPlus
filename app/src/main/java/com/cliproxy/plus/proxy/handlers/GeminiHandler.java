package com.cliproxy.plus.proxy.handlers;

import android.util.Log;

import com.cliproxy.plus.auth.AuthManager;
import com.cliproxy.plus.proxy.RequestRouter;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import fi.iki.elonen.NanoHTTPD;
import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;

/**
 * GeminiHandler - 处理 /v1beta/* 请求（Gemini API）
 * <p>
 * 支持 generateContent、streamGenerateContent、models/list 以及交互操作。
 * 使用 okhttp3 转发请求到上游 Google AI API（生成式 AI 服务）。
 * 通过 AuthManager 选择 'gemini' 提供商凭证进行认证。
 * 流式响应使用 SSE 格式传输。
 * 对应原版 internal/api/handlers/gemini/
 */
public class GeminiHandler {

    private static final String TAG = "GeminiHandler";

    /** Google AI API 默认基础地址 */
    private static final String DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com";

    /** 默认模型 */
    private static final String DEFAULT_MODEL = "gemini-2.0-flash";

    /** 已知的 Gemini 模型映射表 */
    private static final Map<String, String> MODEL_MAP = Map.ofEntries(
            Map.entry("gemini", "gemini-2.0-flash"),
            Map.entry("gemini-flash", "gemini-2.0-flash"),
            Map.entry("gemini-2.0-flash", "gemini-2.0-flash"),
            Map.entry("gemini-pro", "gemini-1.5-pro"),
            Map.entry("gemini-1.5-pro", "gemini-1.5-pro"),
            Map.entry("gemini-1.5-flash", "gemini-1.5-flash"),
            Map.entry("gemini-1.0-pro", "gemini-1.0-pro"),
            Map.entry("gemini-ultra", "gemini-1.0-ultra"),
            Map.entry("gemini-exp", "gemini-2.0-flash-exp")
    );

    private final OkHttpClient httpClient;

    public GeminiHandler() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
    }

    /**
     * 处理 /v1beta/* 请求
     * <p>
     * 根据 URI 路径自动路由到对应的 Gemini API 端点：
     * <ul>
     *   <li>/v1beta/models - 模型列表查询</li>
     *   <li>/v1beta/models/{model}:generateContent - 非流式内容生成</li>
     *   <li>/v1beta/models/{model}:streamGenerateContent - 流式内容生成</li>
     *   <li>/v1beta/{model}/... - 其他交互操作</li>
     * </ul>
     *
     * @param uri     请求路径（如 /v1beta/models/gemini-2.0-flash:generateContent）
     * @param headers 请求头
     * @param body    请求体 JSON 字符串
     * @return NanoHTTPD 响应
     */
    public NanoHTTPD.Response handleRequest(String uri, Map<String, String> headers, String body) {
        if (uri == null) {
            return RequestRouter.jsonResponse(400,
                    "{\"error\":{\"code\":400,\"message\":\"Empty URI\",\"status\":\"INVALID_ARGUMENT\"}}");
        }

        // 移除 /v1beta 前缀进行路由
        String path = uri.startsWith("/v1beta") ? uri.substring(7) : uri;
        if (path.isEmpty()) {
            path = "/";
        }

        try {
            // 模型列表
            if (path.equals("/models") || path.equals("/models/")) {
                return handleListModels(headers);
            }

            // 内容生成（非流式）: /models/{model}:generateContent
            if (path.contains(":generateContent")) {
                String model = extractModelFromPath(path, ":generateContent");
                return handleGenerateContent(model, headers, body, false);
            }

            // 流式内容生成: /models/{model}:streamGenerateContent
            if (path.contains(":streamGenerateContent")) {
                String model = extractModelFromPath(path, ":streamGenerateContent");
                return handleGenerateContent(model, headers, body, true);
            }

            // 其他交互操作: /{model}/...（如 countTokens、embedContent）
            return handleInteraction(path, headers, body);

        } catch (Exception e) {
            Log.e(TAG, "Failed to handle request: " + uri, e);
            return RequestRouter.jsonResponse(500,
                    "{\"error\":{\"code\":500,\"message\":\"Internal error: " +
                    e.getMessage() + "\",\"status\":\"INTERNAL\"}}");
        }
    }

    /**
     * 从路径中提取模型名称
     * <p>
     * 例如传入 /models/gemini-2.0-flash:generateContent 和 suffix :generateContent，
     * 返回 gemini-2.0-flash。
     *
     * @param path   请求路径
     * @param suffix 操作后缀（如 :generateContent）
     * @return 模型名称
     */
    private String extractModelFromPath(String path, String suffix) {
        String withoutSuffix = path.endsWith(suffix)
                ? path.substring(0, path.length() - suffix.length()) : path;
        // 移除 /models/ 前缀
        if (withoutSuffix.startsWith("/models/")) {
            return withoutSuffix.substring(8);
        }
        if (withoutSuffix.startsWith("models/")) {
            return withoutSuffix.substring(7);
        }
        return withoutSuffix;
    }

    /**
     * 处理模型列表请求 GET /v1beta/models
     *
     * @param headers 请求头
     * @return NanoHTTPD 响应，包含可用模型列表
     */
    private NanoHTTPD.Response handleListModels(Map<String, String> headers) {
        AuthManager authManager = AuthManager.getInstance();
        AuthManager.AuthCredential credential = authManager.selectCredential("gemini");
        if (credential == null) {
            // 未配置凭证时返回模拟模型列表
            return mockModelList();
        }

        try {
            String upstreamUrl = determineUpstreamUrl(credential);
            String apiKey = credential.metadata.get("api_key");

            Request.Builder requestBuilder = new Request.Builder()
                    .url(upstreamUrl + "/v1beta/models")
                    .addHeader("Content-Type", "application/json")
                    .get();

            if (apiKey != null && !apiKey.isEmpty()) {
                requestBuilder.addHeader("x-goog-api-key", apiKey);
            }

            Request upstreamRequest = requestBuilder.build();
            try (okhttp3.Response upstreamResponse = httpClient.newCall(upstreamRequest).execute()) {
                String responseBody = upstreamResponse.body() != null
                        ? upstreamResponse.body().string() : "{}";
                return RequestRouter.jsonResponse(upstreamResponse.code(), responseBody);
            }

        } catch (Exception e) {
            Log.e(TAG, "Failed to list models from upstream", e);
            return mockModelList();
        }
    }

    /**
     * 返回模拟模型列表（无上游凭证时使用）
     */
    private NanoHTTPD.Response mockModelList() {
        try {
            JSONObject response = new JSONObject();
            JSONArray models = new JSONArray();

            String[] modelIds = {
                    "gemini-2.0-flash",
                    "gemini-2.0-flash-exp",
                    "gemini-1.5-pro",
                    "gemini-1.5-flash",
                    "gemini-1.0-pro",
                    "gemini-1.0-ultra"
            };

            for (String modelId : modelIds) {
                JSONObject model = new JSONObject();
                model.put("name", "models/" + modelId);
                model.put("baseModelId", modelId);
                model.put("version", "001");
                model.put("displayName", modelId);
                model.put("description", "CLIProxy Plus simulated model: " + modelId);
                model.put("inputTokenLimit", 1048576);
                model.put("outputTokenLimit", 8192);

                JSONArray supportedMethods = new JSONArray();
                supportedMethods.put("generateContent");
                supportedMethods.put("streamGenerateContent");
                supportedMethods.put("countTokens");
                supportedMethods.put("embedContent");
                model.put("supportedGenerationMethods", supportedMethods);

                models.put(model);
            }

            response.put("models", models);
            return RequestRouter.jsonResponse(200, response.toString());
        } catch (Exception e) {
            Log.w(TAG, "Failed to build mock model list", e);
            return RequestRouter.jsonResponse(200,
                    "{\"models\":[]}");
        }
    }

    /**
     * 处理内容生成请求（非流式 + 流式）
     * <p>
     * 对于流式请求，使用 SSE 格式传输 Gemini 的流式响应。
     *
     * @param model   模型名称
     * @param headers 请求头
     * @param body    请求体 JSON 字符串
     * @param stream  是否启用流式响应
     * @return NanoHTTPD 响应
     */
    private NanoHTTPD.Response handleGenerateContent(String model, Map<String, String> headers,
                                                      String body, boolean stream) {
        if (body == null || body.isEmpty()) {
            return RequestRouter.jsonResponse(400,
                    "{\"error\":{\"code\":400,\"message\":\"Empty request body\"," +
                    "\"status\":\"INVALID_ARGUMENT\"}}");
        }

        try {
            String resolvedModel = resolveModel(model);
            String finalBody = ensureModelInBody(body, resolvedModel);

            // 选择上游账号
            AuthManager authManager = AuthManager.getInstance();
            AuthManager.AuthCredential credential = authManager.selectCredential("gemini");
            if (credential == null) {
                // 未配置账号时返回模拟数据以便测试
                return handleNoCredential(resolvedModel, stream, finalBody);
            }

            // 转发到上游
            return proxyToUpstream(credential, resolvedModel, finalBody, stream);

        } catch (Exception e) {
            Log.e(TAG, "Failed to handle generateContent", e);
            return RequestRouter.jsonResponse(500,
                    "{\"error\":{\"code\":500,\"message\":\"Internal error: " +
                    e.getMessage() + "\",\"status\":\"INTERNAL\"}}");
        }
    }

    /**
     * 处理其他交互操作（如 countTokens、embedContent 等）
     * <p>
     * 路径格式为 /{model}/{action}，例如 /models/gemini-2.0-flash:countTokens。
     *
     * @param path    请求路径（已去除 /v1beta 前缀）
     * @param headers 请求头
     * @param body    请求体 JSON 字符串
     * @return NanoHTTPD 响应
     */
    private NanoHTTPD.Response handleInteraction(String path, Map<String, String> headers,
                                                   String body) {
        // 尝试提取模型名称和操作
        String operation = "";
        String model = DEFAULT_MODEL;

        // 处理 :operation 后缀（如 :countTokens、:embedContent）
        int colonIdx = path.lastIndexOf(':');
        if (colonIdx > 0) {
            operation = path.substring(colonIdx);
            String modelPath = path.substring(0, colonIdx);
            if (modelPath.startsWith("/models/")) {
                model = modelPath.substring(8);
            } else if (modelPath.startsWith("models/")) {
                model = modelPath.substring(7);
            }
        } else {
            // 尝试从路径中提取操作
            if (path.startsWith("/")) {
                String[] segments = path.substring(1).split("/", 2);
                if (segments.length >= 2) {
                    model = segments[0];
                    operation = "/" + segments[1];
                }
            }
        }

        // 如果模型名称为空，使用默认模型
        if (model == null || model.isEmpty()) {
            model = DEFAULT_MODEL;
        }

        String resolvedModel = resolveModel(model);

        // 选择上游账号
        AuthManager authManager = AuthManager.getInstance();
        AuthManager.AuthCredential credential = authManager.selectCredential("gemini");
        if (credential == null) {
            // 无凭证时返回模拟响应
            return mockInteractionResponse(resolvedModel, operation);
        }

        try {
            String upstreamUrl = determineUpstreamUrl(credential);
            String apiKey = credential.metadata.get("api_key");

            Request.Builder requestBuilder = new Request.Builder()
                    .url(upstreamUrl + "/v1beta/models/" + resolvedModel + operation)
                    .addHeader("Content-Type", "application/json");

            if (apiKey != null && !apiKey.isEmpty()) {
                requestBuilder.addHeader("x-goog-api-key", apiKey);
            }

            if (body != null && !body.isEmpty()) {
                RequestBody requestBody = RequestBody.create(body, MediaType.get("application/json"));
                requestBuilder.post(requestBody);
            } else {
                requestBuilder.get();
            }

            Request upstreamRequest = requestBuilder.build();
            try (okhttp3.Response upstreamResponse = httpClient.newCall(upstreamRequest).execute()) {
                String responseBody = upstreamResponse.body() != null
                        ? upstreamResponse.body().string() : "{}";
                return RequestRouter.jsonResponse(upstreamResponse.code(), responseBody);
            }

        } catch (Exception e) {
            Log.e(TAG, "Upstream interaction failed", e);
            return RequestRouter.jsonResponse(502,
                    "{\"error\":{\"code\":502,\"message\":\"Upstream request failed: " +
                    e.getMessage() + "\",\"status\":\"UNAVAILABLE\"}}");
        }
    }

    /**
     * 返回模拟交互响应（无上游凭证时使用）
     */
    private NanoHTTPD.Response mockInteractionResponse(String model, String operation) {
        try {
            JSONObject response = new JSONObject();
            response.put("model", "models/" + model);

            if (operation.contains("countTokens")) {
                JSONObject tokenCount = new JSONObject();
                tokenCount.put("totalTokens", 42);
                tokenCount.put("totalBillableCharacters", 150);
                response.put("tokenCount", tokenCount);
            } else if (operation.contains("embedContent")) {
                JSONArray values = new JSONArray();
                for (int i = 0; i < 4; i++) {
                    values.put(0.1);
                }
                response.put("embedding", new JSONObject().put("values", values));
            } else {
                response.put("operation", operation);
                response.put("status", "mock_response");
            }

            return RequestRouter.jsonResponse(200, response.toString());
        } catch (Exception e) {
            Log.w(TAG, "Failed to build mock interaction response", e);
            return RequestRouter.jsonResponse(200, "{}");
        }
    }

    /**
     * 未配置凭证时返回模拟响应
     * <p>
     * 流式响应使用 SSE 格式，非流式响应返回标准 JSON。
     *
     * @param model  模型名称
     * @param stream 是否启用流式响应
     * @param body   原始请求体
     * @return NanoHTTPD 响应
     */
    private NanoHTTPD.Response handleNoCredential(String model, boolean stream, String body) {
        if (stream) {
            // 构造模拟 SSE 流式响应（Gemini 格式）
            StringBuilder sb = new StringBuilder();

            // 第一个块：角色信息
            String chunk1 = "data: " + new JSONObject()
                    .put("candidates", new JSONArray()
                            .put(new JSONObject()
                                    .put("content", new JSONObject()
                                            .put("role", "model")
                                            .put("parts", new JSONArray()
                                                    .put(new JSONObject()
                                                            .put("text", ""))))
                                    .put("finishReason", null)
                                    .put("index", 0)
                                    .put("safetyRatings", new JSONArray())))
                    .put("usageMetadata", new JSONObject()
                            .put("promptTokenCount", 10)
                            .put("candidatesTokenCount", 0)
                            .put("totalTokenCount", 10))
                    .toString() + "\n\n";
            sb.append(chunk1);

            // 第二个块：实际内容
            String chunk2 = "data: " + new JSONObject()
                    .put("candidates", new JSONArray()
                            .put(new JSONObject()
                                    .put("content", new JSONObject()
                                            .put("role", "model")
                                            .put("parts", new JSONArray()
                                                    .put(new JSONObject()
                                                            .put("text", "Hello from CLIProxy Plus!"))))
                                    .put("finishReason", null)
                                    .put("index", 0)
                                    .put("safetyRatings", new JSONArray())))
                    .put("usageMetadata", new JSONObject()
                            .put("promptTokenCount", 10)
                            .put("candidatesTokenCount", 8)
                            .put("totalTokenCount", 18))
                    .toString() + "\n\n";
            sb.append(chunk2);

            // 最后一个块：结束标记
            String chunk3 = "data: " + new JSONObject()
                    .put("candidates", new JSONArray()
                            .put(new JSONObject()
                                    .put("content", new JSONObject()
                                            .put("role", "model")
                                            .put("parts", new JSONArray()
                                                    .put(new JSONObject()
                                                            .put("text", ""))))
                                    .put("finishReason", "STOP")
                                    .put("index", 0)
                                    .put("safetyRatings", new JSONArray())))
                    .put("usageMetadata", new JSONObject()
                            .put("promptTokenCount", 10)
                            .put("candidatesTokenCount", 8)
                            .put("totalTokenCount", 18))
                    .toString() + "\n\n";
            sb.append(chunk3);

            return RequestRouter.sseResponse(sb.toString());
        } else {
            // 非流式模拟响应
            try {
                JSONObject response = new JSONObject();

                JSONArray candidates = new JSONArray();
                JSONObject candidate = new JSONObject();
                candidate.put("index", 0);

                JSONObject content = new JSONObject();
                content.put("role", "model");

                JSONArray parts = new JSONArray();
                JSONObject textPart = new JSONObject();
                textPart.put("text", "Hello from CLIProxy Plus! No upstream configured.");
                parts.put(textPart);
                content.put("parts", parts);

                candidate.put("content", content);
                candidate.put("finishReason", "STOP");

                JSONArray safetyRatings = new JSONArray();
                JSONObject safety = new JSONObject();
                safety.put("category", "HARM_CATEGORY_HARASSMENT");
                safety.put("probability", "NEGLIGIBLE");
                safetyRatings.put(safety);
                candidate.put("safetyRatings", safetyRatings);

                candidates.put(candidate);
                response.put("candidates", candidates);

                JSONObject usageMetadata = new JSONObject();
                usageMetadata.put("promptTokenCount", 10);
                usageMetadata.put("candidatesTokenCount", 8);
                usageMetadata.put("totalTokenCount", 18);
                response.put("usageMetadata", usageMetadata);

                return RequestRouter.jsonResponse(200, response.toString());
            } catch (Exception e) {
                Log.w(TAG, "Failed to build mock response", e);
                return RequestRouter.jsonResponse(200, "{}");
            }
        }
    }

    /**
     * 转发请求到上游 Google AI API
     * <p>
     * 对于流式请求，使用 SSE 格式转发上游响应。
     * 对于非流式请求，直接转发上游 JSON 响应。
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

            // 构建上游 URL
            String endpoint;
            if (stream) {
                endpoint = "/v1beta/models/" + model + ":streamGenerateContent";
            } else {
                endpoint = "/v1beta/models/" + model + ":generateContent";
            }

            Request.Builder requestBuilder = new Request.Builder()
                    .url(upstreamUrl + endpoint)
                    .addHeader("Content-Type", "application/json");

            // Gemini API 使用 x-goog-api-key 或 Authorization: Bearer 进行认证
            if (apiKey != null && !apiKey.isEmpty()) {
                // 优先使用 x-goog-api-key 头
                requestBuilder.addHeader("x-goog-api-key", apiKey);
            }

            // 检查是否有 OAuth token
            String oauthToken = credential.metadata.get("access_token");
            if (oauthToken != null && !oauthToken.isEmpty()) {
                requestBuilder.addHeader("Authorization", "Bearer " + oauthToken);
            }

            // 添加用户代理
            requestBuilder.addHeader("User-Agent", "CLIProxyPlus/1.0");

            RequestBody requestBody = RequestBody.create(body, MediaType.get("application/json"));
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
                    String responseBody = upstreamResponse.body() != null
                            ? upstreamResponse.body().string() : "{}";
                    return RequestRouter.jsonResponse(upstreamResponse.code(), responseBody);
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Upstream request failed", e);
            return RequestRouter.jsonResponse(502,
                    "{\"error\":{\"code\":502,\"message\":\"Upstream request failed: " +
                    e.getMessage() + "\",\"status\":\"UNAVAILABLE\"}}");
        }
    }

    /**
     * 解析 Gemini 模型名称，将别名映射为完整模型 ID
     *
     * @param model 原始模型名称
     * @return 完整的模型 ID
     */
    private String resolveModel(String model) {
        if (model == null || model.isEmpty()) {
            return DEFAULT_MODEL;
        }
        // 如果已经是完整模型 ID 则直接返回
        if (model.startsWith("gemini-") && model.matches("^gemini[-.\\w]+$")) {
            return model;
        }
        // 从映射表中查找别名
        String resolved = MODEL_MAP.get(model.toLowerCase());
        return resolved != null ? resolved : model;
    }

    /**
     * 确保请求体中的模型名称已解析
     *
     * @param body  原始请求体
     * @param model 已解析的模型名称
     * @return 更新后的请求体
     */
    private String ensureModelInBody(String body, String model) {
        try {
            JSONObject obj = new JSONObject(body);
            // Gemini API 请求体通常不包含 model 字段，但部分 SDK 可能包含
            // 如果包含则更新为已解析的模型名称
            if (obj.has("model")) {
                String currentModel = obj.optString("model", "");
                if (!currentModel.equals(model)) {
                    obj.put("model", model);
                    return obj.toString();
                }
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