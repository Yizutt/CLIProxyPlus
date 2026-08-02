package com.cliproxy.plus.proxy.handlers;

import android.util.Log;

import com.cliproxy.plus.auth.AuthManager;

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
 * CodexHandler - 处理 /backend-api/codex/* 请求（OpenAI Codex API / GitHub Copilot）
 * <p>
 * 支持以下端点：
 * - /backend-api/codex/completions        - 代码补全
 * - /backend-api/codex/chat/completions   - 对话补全
 * - /backend-api/codex/search             - 代码搜索
 * - /backend-api/codex/live               - 实时连接检测
 * <p>
 * 使用 okhttp3 转发请求到上游 Codex API。
 * 通过 AuthManager 选择 'codex' 提供商凭证进行认证。
 * 支持 SSE 流式响应和非流式响应。
 * 包含 Codex 特定优化：模型别名解析、请求体适配、自定义提示注入。
 * 对应原版 internal/api/handlers/codex/
 */
public class CodexHandler {

    private static final String TAG = "CodexHandler";

    /** Codex API 默认基础地址 */
    private static final String DEFAULT_BASE_URL = "https://api.githubcopilot.com";

    /** 默认模型 */
    private static final String DEFAULT_MODEL = "gpt-4o";

    /** 默认最大 Token 数 */
    private static final int DEFAULT_MAX_TOKENS = 4096;

    /** 默认温度参数 */
    private static final double DEFAULT_TEMPERATURE = 0.1;

    /** 补全缓存的 Token 预算 */
    private static final int CACHE_BUDGET_TOKENS = 1024;

    private final OkHttpClient httpClient;

    /** 编辑器 User-Agent 映射表 */
    private static final java.util.Map<String, String> EDITOR_AGENTS = java.util.Map.ofEntries(
            java.util.Map.entry("vscode", "GitHubCopilot/1.0"),
            java.util.Map.entry("vim", "GitHubCopilot/1.0"),
            java.util.Map.entry("jetbrains", "GitHubCopilot/1.0"),
            java.util.Map.entry("neovim", "GitHubCopilot/1.0"),
            java.util.Map.entry("cursor", "Cursor/1.0"),
            java.util.Map.entry("windsurf", "Windsurf/1.0"),
            java.util.Map.entry("codeium", "Codeium/1.0"),
            java.util.Map.entry("default", "CLIProxyPlus/1.0")
    );

    /** 模型别名映射表 */
    private static final java.util.Map<String, String> MODEL_MAP = java.util.Map.ofEntries(
            java.util.Map.entry("gpt-4", "gpt-4"),
            java.util.Map.entry("gpt-4o", "gpt-4o"),
            java.util.Map.entry("gpt-4o-mini", "gpt-4o-mini"),
            java.util.Map.entry("gpt-4-turbo", "gpt-4-turbo"),
            java.util.Map.entry("gpt-3.5-turbo", "gpt-3.5-turbo"),
            java.util.Map.entry("gpt-3.5", "gpt-3.5-turbo"),
            java.util.Map.entry("codex", "gpt-4o"),
            java.util.Map.entry("codex-v3", "gpt-4o"),
            java.util.Map.entry("codex-v2", "gpt-3.5-turbo"),
            java.util.Map.entry("copilot", "gpt-4o"),
            java.util.Map.entry("copilot-v3", "gpt-4o"),
            java.util.Map.entry("claude-3.5-sonnet", "claude-3-5-sonnet-20241022"),
            java.util.Map.entry("claude-3-opus", "claude-3-opus-20240229"),
            java.util.Map.entry("claude-3-haiku", "claude-3-haiku-20240307"),
            java.util.Map.entry("gemini-1.5-pro", "gemini-1.5-pro"),
            java.util.Map.entry("gemini-1.5-flash", "gemini-1.5-flash")
    );

    public CodexHandler() {
        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(120, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .build();
    }

    /**
     * 处理 /backend-api/codex/* 请求的统一入口
     *
     * @param uri     请求路径（如 /backend-api/codex/completions）
     * @param headers 请求头
     * @param body    请求体 JSON 字符串
     * @return NanoHTTPD 响应
     */
    public NanoHTTPD.Response handleRequest(String uri, Map<String, String> headers, String body) {
        if (body == null || body.isEmpty()) {
            return RequestRouter.jsonResponse(400,
                    "{\"error\":{\"message\":\"Empty request body\"}}");
        }

        try {
            // 解析请求体
            JSONObject requestObj = new JSONObject(body);
            boolean stream = requestObj.optBoolean("stream", false);
            String model = resolveModel(requestObj.optString("model", DEFAULT_MODEL));

            // 识别端点类型
            String endpoint = extractEndpoint(uri);

            // 选择上游账号
            AuthManager authManager = AuthManager.getInstance();
            AuthManager.AuthCredential credential = authManager.selectCredential("codex");
            if (credential == null) {
                credential = authManager.selectCredential("copilot");
            }

            // 未配置账号时返回模拟数据以便测试
            if (credential == null) {
                return handleNoCredential(endpoint, model, stream, requestObj);
            }

            // 转发到上游
            return proxyToUpstream(credential, endpoint, model, body, stream, headers);

        } catch (Exception e) {
            Log.e(TAG, "Failed to handle codex request: " + uri, e);
            return RequestRouter.jsonResponse(500,
                    "{\"error\":{\"message\":\"Internal error: " + e.getMessage() + "\"}}");
        }
    }

    /**
     * 从 URI 中提取端点名称
     *
     * @param uri 完整请求路径
     * @return 端点名称（completions, chat/completions, search, live）
     */
    private String extractEndpoint(String uri) {
        if (uri == null) return "completions";
        // 移除 /backend-api/codex/ 前缀
        String path = uri.replaceFirst("^/backend-api/codex/?", "");
        if (path.isEmpty()) return "completions";
        // 处理 /backend-api/codex/completions 或 /backend-api/codex/chat/completions
        return path;
    }

    /**
     * 解析 Codex 模型名称，将别名映射为完整模型 ID
     *
     * @param model 原始模型名称
     * @return 完整的模型 ID
     */
    private String resolveModel(String model) {
        if (model == null || model.isEmpty()) {
            return DEFAULT_MODEL;
        }
        // 从映射表中查找别名
        String resolved = MODEL_MAP.get(model.toLowerCase().trim());
        return resolved != null ? resolved : model;
    }

    /**
     * 未配置凭证时返回模拟响应
     * 根据端点类型返回不同的模拟数据
     */
    private NanoHTTPD.Response handleNoCredential(String endpoint, String model,
                                                   boolean stream, JSONObject requestObj) {
        switch (endpoint) {
            case "search":
                return handleNoCredentialSearch(stream, model);
            case "live":
                return handleNoCredentialLive();
            case "chat/completions":
                return handleNoCredentialChat(stream, model, requestObj);
            default:
                return handleNoCredentialCompletion(stream, model, requestObj);
        }
    }

    /**
     * 未配置凭证时返回模拟补全响应
     */
    private NanoHTTPD.Response handleNoCredentialCompletion(boolean stream, String model,
                                                             JSONObject requestObj) {
        String prompt = requestObj.optString("prompt", "");
        String suffix = requestObj.optString("suffix", "");
        String language = requestObj.optString("language", "python");

        if (stream) {
            StringBuilder sb = new StringBuilder();

            // 模拟多块 SSE 流式补全
            sb.append("data: {\"id\":\"cmpl-mock\",\"object\":\"text_completion\",")
              .append("\"model\":\"").append(model).append("\",")
              .append("\"choices\":[{\"index\":0,\"text\":\"\",")
              .append("\"logprobs\":null,\"finish_reason\":null}]}\n\n");

            sb.append("data: {\"id\":\"cmpl-mock\",\"object\":\"text_completion\",")
              .append("\"model\":\"").append(model).append("\",")
              .append("\"choices\":[{\"index\":0,\"text\":\"# CLIProxy Plus mock completion\\n")
              .append("def hello():\\n    print(\\\"Hello from CLIProxy Plus!\\\")\\n\",")
              .append("\"logprobs\":null,\"finish_reason\":null}]}\n\n");

            sb.append("data: {\"id\":\"cmpl-mock\",\"object\":\"text_completion\",")
              .append("\"model\":\"").append(model).append("\",")
              .append("\"choices\":[{\"index\":0,\"text\":\"\",")
              .append("\"logprobs\":null,\"finish_reason\":\"stop\"}]}\n\n");

            sb.append("data: [DONE]\n\n");
            return RequestRouter.sseResponse(sb.toString());
        } else {
            JSONObject response = new JSONObject();
            try {
                response.put("id", "cmpl-mock");
                response.put("object", "text_completion");
                response.put("model", model);

                JSONArray choices = new JSONArray();
                JSONObject choice = new JSONObject();
                choice.put("text", "# CLIProxy Plus mock completion\n" +
                        "def hello():\n    print(\"Hello from CLIProxy Plus!\")\n");
                choice.put("index", 0);
                choice.put("logprobs", JSONObject.NULL);
                choice.put("finish_reason", "stop");
                choices.put(choice);
                response.put("choices", choices);

                JSONObject usage = new JSONObject();
                usage.put("prompt_tokens", prompt.length() / 4);
                usage.put("completion_tokens", 20);
                usage.put("total_tokens", (prompt.length() / 4) + 20);
                response.put("usage", usage);
            } catch (Exception e) {
                Log.w(TAG, "Failed to build mock completion response", e);
            }
            return RequestRouter.jsonResponse(200, response.toString());
        }
    }

    /**
     * 未配置凭证时返回模拟对话补全响应
     */
    private NanoHTTPD.Response handleNoCredentialChat(boolean stream, String model,
                                                       JSONObject requestObj) {
        if (stream) {
            StringBuilder sb = new StringBuilder();

            sb.append("data: {\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\",")
              .append("\"model\":\"").append(model).append("\",")
              .append("\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},")
              .append("\"finish_reason\":null}]}\n\n");

            sb.append("data: {\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\",")
              .append("\"model\":\"").append(model).append("\",")
              .append("\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello from CLIProxy Plus! ")
              .append("Codex chat handler ready.\"},\"finish_reason\":null}]}\n\n");

            sb.append("data: {\"id\":\"chatcmpl-mock\",\"object\":\"chat.completion.chunk\",")
              .append("\"model\":\"").append(model).append("\",")
              .append("\"choices\":[{\"index\":0,\"delta\":{},")
              .append("\"finish_reason\":\"stop\"}]}\n\n");

            sb.append("data: [DONE]\n\n");
            return RequestRouter.sseResponse(sb.toString());
        } else {
            JSONObject response = new JSONObject();
            try {
                response.put("id", "chatcmpl-mock");
                response.put("object", "chat.completion");
                response.put("model", model);
                response.put("created", System.currentTimeMillis() / 1000);

                JSONArray choices = new JSONArray();
                JSONObject choice = new JSONObject();
                choice.put("index", 0);

                JSONObject message = new JSONObject();
                message.put("role", "assistant");
                message.put("content", "Hello from CLIProxy Plus! Codex chat handler ready.");
                choice.put("message", message);
                choice.put("finish_reason", "stop");
                choices.put(choice);
                response.put("choices", choices);

                JSONObject usage = new JSONObject();
                usage.put("prompt_tokens", 10);
                usage.put("completion_tokens", 12);
                usage.put("total_tokens", 22);
                response.put("usage", usage);
            } catch (Exception e) {
                Log.w(TAG, "Failed to build mock chat response", e);
            }
            return RequestRouter.jsonResponse(200, response.toString());
        }
    }

    /**
     * 未配置凭证时返回模拟搜索响应
     */
    private NanoHTTPD.Response handleNoCredentialSearch(boolean stream, String model) {
        JSONObject response = new JSONObject();
        try {
            response.put("object", "list");

            JSONArray results = new JSONArray();
            JSONObject result = new JSONObject();
            result.put("id", "result-mock");
            result.put("object", "search_result");
            result.put("score", 0.95);
            result.put("text", "Mock search result from CLIProxy Plus. " +
                    "No upstream configured for Codex search.");
            results.put(result);
            response.put("data", results);
        } catch (Exception e) {
            Log.w(TAG, "Failed to build mock search response", e);
        }
        return RequestRouter.jsonResponse(200, response.toString());
    }

    /**
     * 未配置凭证时返回模拟实时连接检测响应
     */
    private NanoHTTPD.Response handleNoCredentialLive() {
        JSONObject response = new JSONObject();
        try {
            response.put("status", "ok");
            response.put("service", "CLIProxy Plus");
            response.put("version", "6.9.45");
            response.put("handler", "codex");
            response.put("configured", false);
        } catch (Exception e) {
            Log.w(TAG, "Failed to build live response", e);
        }
        return RequestRouter.jsonResponse(200, response.toString());
    }

    /**
     * 转发请求到上游 Codex API
     *
     * @param credential 认证凭证
     * @param endpoint   端点名称（completions, chat/completions, search, live）
     * @param model      模型名称
     * @param body       原始请求体
     * @param stream     是否启用流式响应
     * @param headers    原始请求头
     * @return NanoHTTPD 响应
     */
    private NanoHTTPD.Response proxyToUpstream(AuthManager.AuthCredential credential,
                                                String endpoint, String model, String body,
                                                boolean stream, Map<String, String> headers) {
        try {
            String upstreamUrl = determineUpstreamUrl(credential);
            String apiKey = credential.metadata.get("api_key");
            String tokenType = credential.metadata.getOrDefault("token_type", "Bearer");

            // 构建适配后的请求体
            String adaptedBody = adaptRequestBody(endpoint, model, body);

            // 构建上游请求路径
            String upstreamPath = buildUpstreamPath(endpoint);

            // 构建请求
            Request.Builder requestBuilder = new Request.Builder()
                    .url(upstreamUrl + upstreamPath)
                    .addHeader("Content-Type", "application/json")
                    .addHeader("Authorization", tokenType + " " + (apiKey != null ? apiKey : ""))
                    .addHeader("User-Agent", resolveUserAgent(headers));

            // 添加编辑器特定头（Codex 专用）
            String editorVersion = headers != null ? headers.get("x-editor-version") : null;
            if (editorVersion != null) {
                requestBuilder.addHeader("X-Editor-Version", editorVersion);
            }

            // 添加机器 ID 头（用于 Copilot 认证）
            String machineId = headers != null ? headers.get("x-machine-id") : null;
            if (machineId != null) {
                requestBuilder.addHeader("X-Machine-Id", machineId);
            }

            // 如果是搜索端点，使用 GET 请求
            if ("search".equals(endpoint)) {
                requestBuilder.get();
            } else {
                RequestBody requestBody = RequestBody.create(adaptedBody,
                        MediaType.get("application/json"));
                requestBuilder.post(requestBody);
            }

            Request upstreamRequest = requestBuilder.build();
            okhttp3.Call call = httpClient.newCall(upstreamRequest);

            if (stream && !"search".equals(endpoint) && !"live".equals(endpoint)) {
                // 流式响应：直接转发上游的 SSE 数据
                okhttp3.Response upstreamResponse = call.execute();
                okhttp3.ResponseBody responseBody = upstreamResponse.body();
                String bodyStr = responseBody != null ? responseBody.string() : "{}";

                // 标记认证成功
                authManager.markSuccess(credential.id);

                return RequestRouter.sseResponse(bodyStr);
            } else {
                // 非流式响应：转发上游响应
                try (okhttp3.Response upstreamResponse = call.execute()) {
                    String responseBody = upstreamResponse.body() != null ?
                            upstreamResponse.body().string() : "{}";

                    // 标记认证成功
                    authManager.markSuccess(credential.id);

                    return RequestRouter.jsonResponse(upstreamResponse.code(), responseBody);
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Upstream request failed for endpoint: " + endpoint, e);
            // 标记认证失败
            AuthManager authManager = AuthManager.getInstance();
            authManager.markFailure(credential.id);

            return RequestRouter.jsonResponse(502,
                    "{\"error\":{\"message\":\"Upstream request failed: " +
                    e.getMessage() + "\"}}");
        }
    }

    /**
     * 根据端点名称构建上游请求路径
     *
     * @param endpoint 端点名称
     * @return 上游请求路径
     */
    private String buildUpstreamPath(String endpoint) {
        switch (endpoint) {
            case "chat/completions":
                return "/v1/chat/completions";
            case "completions":
                return "/v1/completions";
            case "search":
                return "/v1/search";
            case "live":
                return "/v1/live";
            default:
                return "/v1/completions";
        }
    }

    /**
     * 适配请求体以适应 Codex API 格式
     * 包含模型名修正、Codex 参数注入等优化
     *
     * @param endpoint 端点名称
     * @param model    已解析的模型名称
     * @param body     原始请求体
     * @return 适配后的请求体
     */
    private String adaptRequestBody(String endpoint, String model, String body) {
        try {
            JSONObject obj = new JSONObject(body);

            // 设置模型
            obj.put("model", model);

            // Codex 特定优化：为代码补全设置合理的默认参数
            if ("completions".equals(endpoint)) {
                // 设置默认温度（代码补全使用较低温度以保证确定性）
                if (!obj.has("temperature")) {
                    obj.put("temperature", DEFAULT_TEMPERATURE);
                }
                // 设置最大 Token 数
                if (!obj.has("max_tokens")) {
                    obj.put("max_tokens", DEFAULT_MAX_TOKENS);
                }
                // 启用缓存提示（Codex 专用优化）
                if (!obj.has("cache_prompt")) {
                    obj.put("cache_prompt", true);
                }
                // 设置补全缓存预算
                if (!obj.has("cache_budget_tokens")) {
                    obj.put("cache_budget_tokens", CACHE_BUDGET_TOKENS);
                }
                // 设置 stop 序列（如果未指定）
                if (!obj.has("stop")) {
                    JSONArray stopTokens = new JSONArray();
                    stopTokens.put("\n");
                    obj.put("stop", stopTokens);
                }
            } else if ("chat/completions".equals(endpoint)) {
                // 对话补全参数优化
                if (!obj.has("temperature")) {
                    obj.put("temperature", 0.3);
                }
                if (!obj.has("max_tokens")) {
                    obj.put("max_tokens", DEFAULT_MAX_TOKENS);
                }
            }

            // 注入 Codex 专用系统提示（如果请求中包含代码文件上下文）
            injectCodexPrompt(obj, endpoint);

            return obj.toString();

        } catch (Exception e) {
            Log.w(TAG, "Failed to adapt request body", e);
            return body;
        }
    }

    /**
     * 注入 Codex 专用系统提示以优化代码生成质量
     * 根据请求中的语言和文件扩展名自动注入上下文
     *
     * @param obj      请求体 JSON 对象
     * @param endpoint 端点名称
     */
    private void injectCodexPrompt(JSONObject obj, String endpoint) {
        try {
            String language = obj.optString("language", "");
            String languageHint = obj.optString("lang", language);

            if (languageHint.isEmpty()) {
                return;
            }

            // 构建代码提示注入
            String codexInstruction = "You are a code completion assistant. " +
                    "Provide concise, idiomatic code completions. " +
                    "Focus on the most likely continuation. " +
                    "Keep responses brief and precise.";

            if ("completions".equals(endpoint)) {
                // 补全端点：注入代码风格提示
                String prompt = obj.optString("prompt", "");
                String suffix = obj.optString("suffix", "");

                // 如果有后缀（fill-in-the-middle 模式），添加特殊提示
                if (!suffix.isEmpty()) {
                    codexInstruction += " The user has provided a suffix context. " +
                            "Complete the code in the middle appropriately.";
                }

                // 将提示注入到 prompt 中或作为系统消息
                if (!prompt.isEmpty()) {
                    obj.put("prompt", codexInstruction + "\n\n" + prompt);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to inject codex prompt", e);
        }
    }

    /**
     * 从请求头中解析合适的 User-Agent
     *
     * @param headers 原始请求头
     * @return 解析后的 User-Agent 字符串
     */
    private String resolveUserAgent(Map<String, String> headers) {
        if (headers == null) return EDITOR_AGENTS.get("default");

        // 优先使用原始 User-Agent
        String originalUA = headers.get("user-agent");
        if (originalUA != null && !originalUA.isEmpty()) {
            return originalUA;
        }

        // 尝试从编辑器类型推断
        String editor = headers.get("x-editor-type");
        if (editor != null) {
            String agent = EDITOR_AGENTS.get(editor.toLowerCase());
            if (agent != null) return agent;
        }

        return EDITOR_AGENTS.get("default");
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