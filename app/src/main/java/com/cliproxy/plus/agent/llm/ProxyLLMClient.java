package com.cliproxy.plus.agent.llm;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.ConnectException;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;
import okhttp3.ResponseBody;

/**
 * ProxyLLMClient - 通过代理服务器调用 LLM 的客户端实现
 * <p>
 * 将请求发送到本地 CLIProxy Plus 代理服务器的 {@code /v1/chat/completions} 端点，
 * 由代理负责路由到已配置的 LLM 提供商（OpenAI、Claude、Gemini 等）。
 * 若代理服务器未启动或不可达，则自动回退到外部 API 直接调用。
 * 支持流式（SSE）和非流式两种响应模式。
 * </p>
 *
 * <p>
 * 使用示例：
 * <pre>
 * ProxyLLMClient client = new ProxyLLMClient();
 * String reply = client.generateResponse("你是一个助手", "你好", null);
 *
 * // 流式调用
 * client.generateStreaming("你是一个助手", "讲个故事", null,
 *     new LLMClient.StreamCallback() {
 *         public void onToken(String token) { /* 逐 token 更新 UI * / }
 *         public void onComplete(String full) { /* 流式完成 * / }
 *         public void onError(Exception e) { /* 处理异常 * / }
 *     });
 * </pre>
 * </p>
 *
 * @author CLIProxy Plus
 * @version 1.0
 * @see LLMClient
 * @see LLMClient.StreamCallback
 */
public class ProxyLLMClient implements LLMClient {

    private static final String TAG = "ProxyLLMClient";

    // ======================== 默认常量 ========================

    /** 默认代理主机地址（本地回环） */
    private static final String DEFAULT_PROXY_HOST = "127.0.0.1";

    /** 默认代理端口，与 ProxyServer 默认端口一致 */
    private static final int DEFAULT_PROXY_PORT = 8317;

    /** 默认回退 API 基础地址 */
    private static final String DEFAULT_FALLBACK_URL = "https://api.openai.com";

    /** 默认模型名称 */
    private static final String DEFAULT_MODEL = "gpt-4";

    /** 连接超时（秒） */
    private static final int CONNECT_TIMEOUT_SECONDS = 5;

    /** 读取超时（秒），流式场景需要较长超时 */
    private static final int READ_TIMEOUT_SECONDS = 120;

    /** 写入超时（秒） */
    private static final int WRITE_TIMEOUT_SECONDS = 30;

    /** OpenAI API 路径 */
    private static final String CHAT_COMPLETIONS_PATH = "/v1/chat/completions";

    /** SSE 行前缀 */
    private static final String SSE_DATA_PREFIX = "data: ";

    /** SSE 结束标记 */
    private static final String SSE_DONE_MARKER = "[DONE]";

    /** MediaType 常量 */
    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    // ======================== 字段 ========================

    /** OkHttp 客户端，用于发起 HTTP 请求 */
    private final OkHttpClient httpClient;

    /** 代理服务器基础 URL，例如 http://127.0.0.1:8317 */
    private final String proxyBaseUrl;

    /** 回退外部 API 的基础 URL */
    private final String fallbackBaseUrl;

    /** 回退外部 API 的密钥 */
    private final String fallbackApiKey;

    /** 请求使用的模型名称 */
    private final String model;

    // ======================== 构造方法 ========================

    /**
     * 构造 ProxyLLMClient，使用全部默认配置。
     * <p>
     * 代理地址为 {@code http://127.0.0.1:8317}，回退地址为 {@code https://api.openai.com}，
     * 模型为 {@code gpt-4}。
     * </p>
     */
    public ProxyLLMClient() {
        this(DEFAULT_PROXY_HOST, DEFAULT_PROXY_PORT, DEFAULT_FALLBACK_URL, null, DEFAULT_MODEL);
    }

    /**
     * 构造 ProxyLLMClient，指定代理主机和端口，其余使用默认值。
     *
     * @param proxyHost 代理主机地址（例如 "127.0.0.1"）
     * @param proxyPort 代理端口（例如 8317）
     */
    public ProxyLLMClient(String proxyHost, int proxyPort) {
        this(proxyHost, proxyPort, DEFAULT_FALLBACK_URL, null, DEFAULT_MODEL);
    }

    /**
     * 构造 ProxyLLMClient，指定全部配置参数。
     *
     * @param proxyHost      代理主机地址，为 null 时使用默认值
     * @param proxyPort      代理端口，小于等于 0 时使用默认值
     * @param fallbackUrl    回退 API 基础 URL，为 null 时使用默认值
     * @param fallbackApiKey 回退 API 密钥，为 null 时使用空字符串
     * @param model          模型名称，为 null 时使用默认值
     */
    public ProxyLLMClient(String proxyHost, int proxyPort,
                          String fallbackUrl, String fallbackApiKey,
                          String model) {
        this.proxyBaseUrl = "http://" + (proxyHost != null ? proxyHost : DEFAULT_PROXY_HOST)
                + ":" + (proxyPort > 0 ? proxyPort : DEFAULT_PROXY_PORT);
        this.fallbackBaseUrl = fallbackUrl != null ? fallbackUrl : DEFAULT_FALLBACK_URL;
        this.fallbackApiKey = fallbackApiKey != null ? fallbackApiKey : "";
        this.model = model != null ? model : DEFAULT_MODEL;

        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .build();

        Log.i(TAG, "ProxyLLMClient 初始化完成，代理地址: " + proxyBaseUrl
                + "，回退地址: " + fallbackBaseUrl + "，模型: " + this.model);
    }

    // ======================== LLMClient 接口实现 ========================

    /**
     * {@inheritDoc}
     * <p>
     * 实现逻辑：首试通过本地代理服务器调用 {@code /v1/chat/completions} 端点，
     * 若代理不可达则自动回退到外部 API。两种方式均使用非流式模式。
     * </p>
     */
    @Override
    public String generateResponse(String systemPrompt, String userMessage,
                                   List<String> tools) throws Exception {
        Log.d(TAG, "generateResponse - 开始非流式生成");

        JSONObject requestBody = buildRequestBody(systemPrompt, userMessage, tools, false);

        // 步骤 1：优先尝试通过代理调用
        try {
            String result = doHttpPost(proxyBaseUrl + CHAT_COMPLETIONS_PATH, requestBody, null, false, null);
            Log.d(TAG, "代理非流式调用成功，响应长度: " + (result != null ? result.length() : 0));
            return result;
        } catch (Exception e) {
            Log.w(TAG, "代理非流式调用失败，准备回退: " + e.getMessage());
        }

        // 步骤 2：代理不可用，回退到外部 API
        try {
            String result = doHttpPost(fallbackBaseUrl + CHAT_COMPLETIONS_PATH,
                    requestBody, fallbackApiKey, false, null);
            Log.d(TAG, "回退非流式调用成功，响应长度: " + (result != null ? result.length() : 0));
            return result;
        } catch (Exception e) {
            Log.e(TAG, "回退非流式调用也失败", e);
            throw e;
        }
    }

    /**
     * {@inheritDoc}
     * <p>
     * 实现逻辑：通过 SSE（Server-Sent Events）协议逐 Token 接收 LLM 输出。
     * 优先使用本地代理，代理不可用时回退到外部 API。
     * 每个收到的 Token 通过 {@link StreamCallback#onToken(String)} 通知调用方，
     * 全部接收完毕后通过 {@link StreamCallback#onComplete(String)} 通知。
     * </p>
     */
    @Override
    public String generateStreaming(String systemPrompt, String userMessage,
                                    List<String> tools,
                                    StreamCallback callback) throws Exception {
        Log.d(TAG, "generateStreaming - 开始流式生成");

        if (callback == null) {
            throw new IllegalArgumentException("StreamCallback must not be null");
        }

        JSONObject requestBody = buildRequestBody(systemPrompt, userMessage, tools, true);

        // 步骤 1：优先尝试通过代理进行流式调用
        try {
            String result = doHttpPost(proxyBaseUrl + CHAT_COMPLETIONS_PATH,
                    requestBody, null, true, callback);
            callback.onComplete(result);
            Log.d(TAG, "代理流式调用完成，响应长度: " + (result != null ? result.length() : 0));
            return result;
        } catch (Exception e) {
            Log.w(TAG, "代理流式调用失败，准备回退: " + e.getMessage());
        }

        // 步骤 2：代理不可用，回退到外部 API 流式调用
        try {
            String result = doHttpPost(fallbackBaseUrl + CHAT_COMPLETIONS_PATH,
                    requestBody, fallbackApiKey, true, callback);
            callback.onComplete(result);
            Log.d(TAG, "回退流式调用完成，响应长度: " + (result != null ? result.length() : 0));
            return result;
        } catch (Exception e) {
            Log.e(TAG, "回退流式调用也失败", e);
            callback.onError(e);
            throw e;
        }
    }

    // ======================== 请求构建 ========================

    /**
     * 构建 OpenAI 兼容的聊天完成请求体。
     *
     * @param systemPrompt 系统提示词
     * @param userMessage  用户消息
     * @param tools        工具名称列表（可为 null 或空）
     * @param stream       是否启用流式输出
     * @return 构建完成的 JSONObject 请求体
     * @throws Exception JSON 构造失败时抛出
     */
    private JSONObject buildRequestBody(String systemPrompt, String userMessage,
                                        List<String> tools, boolean stream) throws Exception {
        JSONObject body = new JSONObject();
        body.put("model", model);
        body.put("stream", stream);

        // 构建 messages 数组
        JSONArray messages = new JSONArray();

        // 添加系统提示词
        if (systemPrompt != null && !systemPrompt.isEmpty()) {
            JSONObject systemMsg = new JSONObject();
            systemMsg.put("role", "system");
            systemMsg.put("content", systemPrompt);
            messages.put(systemMsg);
        }

        // 添加用户消息
        JSONObject userMsg = new JSONObject();
        userMsg.put("role", "user");
        userMsg.put("content", userMessage != null ? userMessage : "");
        messages.put(userMsg);

        body.put("messages", messages);

        // 添加工具定义（如果有）
        if (tools != null && !tools.isEmpty()) {
            JSONArray toolsArray = new JSONArray();
            for (String toolName : tools) {
                if (toolName == null || toolName.isEmpty()) {
                    continue;
                }
                JSONObject toolDef = new JSONObject();
                toolDef.put("type", "function");
                JSONObject function = new JSONObject();
                function.put("name", toolName);
                function.put("description", "工具: " + toolName);
                function.put("parameters", new JSONObject());
                toolDef.put("function", function);
                toolsArray.put(toolDef);
            }
            if (toolsArray.length() > 0) {
                body.put("tools", toolsArray);
            }
        }

        return body;
    }

    // ======================== HTTP 调用 ========================

    /**
     * 执行 HTTP POST 请求到指定的 LLM API 端点。
     * <p>
     * 非流式模式：同步等待完整响应后解析并返回文本内容。
     * 流式模式：逐行读取 SSE 响应体，通过回调逐 Token 通知调用方，
     * 同时拼接完整文本返回。
     * </p>
     *
     * @param url        请求目标 URL
     * @param bodyJson   请求体 JSON
     * @param apiKey     外部 API 密钥（代理调用时传 null）
     * @param stream     是否启用流式解析
     * @param callback   流式回调（非流式时传 null）
     * @return 完整的回复文本
     * @throws Exception 网络错误、认证失败或 JSON 解析异常时抛出
     */
    private String doHttpPost(String url, JSONObject bodyJson, String apiKey,
                              boolean stream, StreamCallback callback) throws Exception {
        Log.d(TAG, "HTTP POST - " + url + " (stream=" + stream + ")");

        // 构建 OkHttp Request
        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .addHeader("Content-Type", "application/json");

        // 外部 API 调用时需要添加认证头
        if (apiKey != null && !apiKey.isEmpty()) {
            requestBuilder.addHeader("Authorization", "Bearer " + apiKey);
        }

        String bodyString = bodyJson.toString();
        RequestBody requestBody = RequestBody.create(bodyString, JSON_MEDIA_TYPE);
        requestBuilder.post(requestBody);

        Request request = requestBuilder.build();
        Response response = httpClient.newCall(request).execute();

        // 检查响应状态码
        if (!response.isSuccessful()) {
            String errorBody = response.body() != null ? response.body().string() : "无响应体";
            Log.e(TAG, "API 返回错误状态码: " + response.code() + "，响应: " + errorBody);
            throw new IOException("API 请求失败，状态码: " + response.code()
                    + "，响应: " + errorBody);
        }

        ResponseBody responseBody = response.body();
        if (responseBody == null) {
            throw new IOException("响应体为空");
        }

        if (stream) {
            // 流式模式：逐行解析 SSE
            return parseSseStream(responseBody, callback);
        } else {
            // 非流式模式：解析完整 JSON 响应
            String jsonStr = responseBody.string();
            return parseNonStreamingResponse(jsonStr);
        }
    }

    // ======================== SSE 流式解析 ========================

    /**
     * 解析 SSE（Server-Sent Events）流式响应。
     * <p>
     * OpenAI 兼容格式示例：
     * <pre>
     * data: {"id":"...","object":"chat.completion.chunk","choices":[{"delta":{"content":"你好"},"finish_reason":null}]}
     *
     * data: [DONE]
     * </pre>
     * </p>
     *
     * @param responseBody OkHttp 响应体
     * @param callback     流式回调
     * @return 所有 Token 拼接而成的完整回复文本
     * @throws Exception 读取或解析失败时抛出
     */
    private String parseSseStream(ResponseBody responseBody,
                                  StreamCallback callback) throws Exception {
        StringBuilder fullResponse = new StringBuilder();
        BufferedReader reader = null;

        try {
            reader = new BufferedReader(
                    new InputStreamReader(responseBody.byteStream(), StandardCharsets.UTF_8));

            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isEmpty()) {
                    continue;
                }

                // 跳过非 data 行（如注释、事件类型等）
                if (!line.startsWith(SSE_DATA_PREFIX)) {
                    continue;
                }

                // 提取 data: 后面的内容
                String data = line.substring(SSE_DATA_PREFIX.length()).trim();

                // 检查结束标记
                if (SSE_DONE_MARKER.equals(data)) {
                    Log.d(TAG, "SSE 流式响应结束");
                    break;
                }

                // 解析 JSON 数据，提取 delta.content
                try {
                    JSONObject jsonObj = new JSONObject(data);
                    JSONArray choices = jsonObj.optJSONArray("choices");
                    if (choices != null && choices.length() > 0) {
                        JSONObject choice = choices.optJSONObject(0);
                        if (choice != null) {
                            JSONObject delta = choice.optJSONObject("delta");
                            if (delta != null) {
                                String content = delta.optString("content", "");
                                if (!content.isEmpty()) {
                                    fullResponse.append(content);
                                    // 通过回调通知调用方
                                    callback.onToken(content);
                                }
                            }

                            // 检查 finish_reason，若不为 null 表示流结束
                            String finishReason = choice.optString("finish_reason", null);
                            if (finishReason != null && !finishReason.isEmpty()
                                    && !"null".equals(finishReason)) {
                                Log.d(TAG, "SSE 流完成，finish_reason: " + finishReason);
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    Log.w(TAG, "SSE 行解析失败，跳过: " + data, e);
                }
            }

            Log.d(TAG, "SSE 流式解析完成，共收到 " + fullResponse.length() + " 个字符");
            return fullResponse.toString();

        } catch (Exception e) {
            Log.e(TAG, "SSE 流式解析异常", e);
            throw e;
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException ignored) {
                    // 忽略关闭时的异常
                }
            }
        }
    }

    // ======================== 非流式响应解析 ========================

    /**
     * 解析非流式 JSON 响应，提取助手的回复文本。
     * <p>
     * OpenAI 格式示例：
     * <pre>
     * {
     *   "id": "chatcmpl-xxx",
     *   "choices": [{
     *     "index": 0,
     *     "message": { "role": "assistant", "content": "回复文本..." },
     *     "finish_reason": "stop"
     *   }]
     * }
     * </pre>
     * </p>
     *
     * @param jsonStr 原始 JSON 响应字符串
     * @return 提取的助手回复文本，提取失败时返回空字符串
     * @throws Exception JSON 解析失败时抛出
     */
    private String parseNonStreamingResponse(String jsonStr) throws Exception {
        if (jsonStr == null || jsonStr.isEmpty()) {
            Log.w(TAG, "非流式响应体为空");
            return "";
        }

        try {
            JSONObject jsonObj = new JSONObject(jsonStr);
            JSONArray choices = jsonObj.optJSONArray("choices");
            if (choices != null && choices.length() > 0) {
                JSONObject choice = choices.optJSONObject(0);
                if (choice != null) {
                    // 尝试从 message 字段提取（标准格式）
                    JSONObject message = choice.optJSONObject("message");
                    if (message != null) {
                        String content = message.optString("content", "");
                        if (!content.isEmpty()) {
                            return content;
                        }
                    }

                    // 兼容某些代理返回的 text 字段
                    String text = choice.optString("text", "");
                    if (!text.isEmpty()) {
                        return text;
                    }
                }
            }

            // 兼容某些代理直接返回 content 字段
            String content = jsonObj.optString("content", "");
            if (!content.isEmpty()) {
                return content;
            }

            // 兼容某些代理返回 response 字段
            String response = jsonObj.optString("response", "");
            if (!response.isEmpty()) {
                return response;
            }

            Log.w(TAG, "无法从响应中提取 content，原始响应: " + jsonStr);
            return "";

        } catch (Exception e) {
            Log.e(TAG, "非流式响应 JSON 解析失败", e);
            throw e;
        }
    }

    // ======================== 代理连通性检测 ========================

    /**
     * 检测本地代理服务器是否可达。
     * <p>
     * 通过尝试连接代理的 {@code /health} 端点来判断代理是否正在运行。
     * 此方法可用于外部调用方决定是否通过代理发送请求。
     * </p>
     *
     * @return true 表示代理服务器正在运行
     */
    public boolean isProxyAvailable() {
        try {
            Request request = new Request.Builder()
                    .url(proxyBaseUrl + "/health")
                    .get()
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                boolean available = response.isSuccessful();
                Log.d(TAG, "代理连通性检测: " + (available ? "可用" : "不可用")
                        + " (状态码: " + response.code() + ")");
                return available;
            }
        } catch (ConnectException e) {
            Log.d(TAG, "代理未运行 (连接被拒绝)");
            return false;
        } catch (SocketException e) {
            Log.d(TAG, "代理未运行 (Socket 异常)");
            return false;
        } catch (Exception e) {
            Log.d(TAG, "代理连通性检测异常: " + e.getMessage());
            return false;
        }
    }

    /**
     * 判断当前请求是否已回退到外部 API。
     * <p>
     * 通过尝试连接代理来判断。注意：此方法会发起一次 HTTP 请求，
     * 不应在频繁调用的热路径中使用。
     * </p>
     *
     * @return true 表示当前使用的是回退 API（代理不可达）
     */
    public boolean isUsingFallback() {
        return !isProxyAvailable();
    }

    // ======================== 配置访问器 ========================

    /**
     * 获取代理服务器基础 URL。
     *
     * @return 代理基础 URL
     */
    public String getProxyBaseUrl() {
        return proxyBaseUrl;
    }

    /**
     * 获取回退 API 基础 URL。
     *
     * @return 回退基础 URL
     */
    public String getFallbackBaseUrl() {
        return fallbackBaseUrl;
    }

    /**
     * 获取当前使用的模型名称。
     *
     * @return 模型名称
     */
    public String getModel() {
        return model;
    }
}