package com.cliproxy.plus.agent.llm;

import android.util.Log;

import com.cliproxy.plus.config.ConfigManager;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.net.ConnectException;
import java.io.InputStreamReader;
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
 * CustomLLMClient - 通过用户自定义 API 端点调用 LLM 的客户端实现
 * <p>
 * 将请求直接发送到用户配置的自定义 API 端点（而非本地代理），
 * 支持任何 OpenAI 兼容的 API（OpenAI 官方、Claude 代理、本地 LLM 等）。
 * 用户可通过 ConfigManager 配置 endpoint URL、API key 和模型名称。
 * 支持流式（SSE）和非流式两种响应模式。
 * </p>
 *
 * <p>
 * 配置存储在 ConfigManager 的 'agent' 键下，格式为：
 * <pre>
 * {
 *   "agent": {
 *     "custom_endpoint": "https://api.openai.com/v1",
 *     "custom_api_key": "sk-xxx",
 *     "custom_model": "gpt-4"
 *   }
 * }
 * </pre>
 * </p>
 *
 * <p>
 * 使用示例：
 * <pre>
 * CustomLLMClient client = new CustomLLMClient(
 *     "https://api.openai.com/v1",
 *     "sk-xxx",
 *     "gpt-4"
 * );
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
 * @see ProxyLLMClient
 */
public class CustomLLMClient implements LLMClient {

    private static final String TAG = "CustomLLMClient";

    // ======================== 默认常量 ========================

    /** 默认 API 基础地址（OpenAI 官方） */
    public static final String DEFAULT_ENDPOINT = "https://api.openai.com/v1";

    /** 默认模型名称 */
    public static final String DEFAULT_MODEL = "gpt-4o-mini";

    /** 连接超时（秒） */
    private static final int CONNECT_TIMEOUT_SECONDS = 10;

    /** 读取超时（秒），流式场景需要较长超时 */
    private static final int READ_TIMEOUT_SECONDS = 120;

    /** 写入超时（秒） */
    private static final int WRITE_TIMEOUT_SECONDS = 30;

    /** OpenAI API 聊天补全路径 */
    private static final String CHAT_COMPLETIONS_PATH = "/chat/completions";

    /** SSE 行前缀 */
    private static final String SSE_DATA_PREFIX = "data: ";

    /** SSE 结束标记 */
    private static final String SSE_DONE_MARKER = "[DONE]";

    /** MediaType 常量 */
    private static final MediaType JSON_MEDIA_TYPE = MediaType.get("application/json; charset=utf-8");

    // ======================== ConfigManager 配置键 ========================

    /** ConfigManager 中 'agent' 配置段的键名 */
    private static final String CONFIG_KEY_AGENT = "agent";

    /** 自定义端点 URL 的配置键 */
    private static final String CONFIG_KEY_ENDPOINT = "custom_endpoint";

    /** 自定义 API Key 的配置键 */
    private static final String CONFIG_KEY_API_KEY = "custom_api_key";

    /** 自定义模型名称的配置键 */
    private static final String CONFIG_KEY_MODEL = "custom_model";

    // ======================== 字段 ========================

    /** OkHttp 客户端，用于发起 HTTP 请求 */
    private final OkHttpClient httpClient;

    /** 自定义 API 端点基础 URL，例如 https://api.openai.com/v1 */
    private final String endpoint;

    /** 自定义 API 密钥 */
    private final String apiKey;

    /** 请求使用的模型名称 */
    private final String model;

    // ======================== 构造方法 ========================

    /**
     * 构造 CustomLLMClient，使用全部默认配置。
     * <p>
     * 从 ConfigManager 读取配置，若配置不存在则使用默认值
     * （{@code https://api.openai.com/v1}，空密钥，{@code gpt-4o-mini}）。
     * </p>
     */
    public CustomLLMClient() {
        this(null, null, null);
    }

    /**
     * 构造 CustomLLMClient，从 ConfigManager 读取配置，指定参数覆盖配置文件。
     * <p>
     * 参数优先级：显式传入的参数 > ConfigManager 中的配置 > 默认常量。
     * 当 endpoint 为 null 或空时，从 ConfigManager 读取；若 ConfigManager 中也没有则使用默认值。
     * 类似地处理 apiKey 和 model。
     * </p>
     *
     * @param endpoint 自定义 API 端点基础 URL（例如 "https://api.openai.com/v1"），
     *                 为 null 时从 ConfigManager 读取
     * @param apiKey   自定义 API 密钥，为 null 时从 ConfigManager 读取
     * @param model    模型名称（例如 "gpt-4"），为 null 时从 ConfigManager 读取
     */
    public CustomLLMClient(String endpoint, String apiKey, String model) {
        // 从 ConfigManager 读取配置（如果可用）
        ConfigManager configManager = null;
        try {
            configManager = ConfigManager.getInstance();
        } catch (IllegalStateException e) {
            Log.w(TAG, "ConfigManager 尚未初始化，将使用默认值或传入参数");
        }

        // 读取端点 URL：传入参数 > ConfigManager > 默认值
        String resolvedEndpoint = endpoint;
        if (resolvedEndpoint == null || resolvedEndpoint.isEmpty()) {
            if (configManager != null) {
                resolvedEndpoint = readAgentConfigString(configManager, CONFIG_KEY_ENDPOINT);
            }
            if (resolvedEndpoint == null || resolvedEndpoint.isEmpty()) {
                resolvedEndpoint = DEFAULT_ENDPOINT;
            }
        }

        // 读取 API Key：传入参数 > ConfigManager > 空字符串
        String resolvedApiKey = apiKey;
        if (resolvedApiKey == null || resolvedApiKey.isEmpty()) {
            if (configManager != null) {
                resolvedApiKey = readAgentConfigString(configManager, CONFIG_KEY_API_KEY);
            }
            if (resolvedApiKey == null) {
                resolvedApiKey = "";
            }
        }

        // 读取模型名称：传入参数 > ConfigManager > 默认值
        String resolvedModel = model;
        if (resolvedModel == null || resolvedModel.isEmpty()) {
            if (configManager != null) {
                resolvedModel = readAgentConfigString(configManager, CONFIG_KEY_MODEL);
            }
            if (resolvedModel == null || resolvedModel.isEmpty()) {
                resolvedModel = DEFAULT_MODEL;
            }
        }

        // 确保端点 URL 末尾没有多余的斜杠
        this.endpoint = resolvedEndpoint.replaceAll("/+$", "");
        this.apiKey = resolvedApiKey;
        this.model = resolvedModel;

        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(CONNECT_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .readTimeout(READ_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .writeTimeout(WRITE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
                .retryOnConnectionFailure(true)
                .build();

        Log.i(TAG, "CustomLLMClient 初始化完成，端点: " + this.endpoint
                + "，模型: " + this.model
                + "，API Key 已设置: " + !this.apiKey.isEmpty());
    }

    /**
     * 从 ConfigManager 的 'agent' 配置段中读取字符串值。
     *
     * @param configManager ConfigManager 实例
     * @param key           配置键名
     * @return 配置值，若不存在或不是字符串则返回 null
     */
    private static String readAgentConfigString(ConfigManager configManager, String key) {
        try {
            com.google.gson.JsonObject config = configManager.getConfig();
            if (config != null && config.has(CONFIG_KEY_AGENT)) {
                com.google.gson.JsonObject agentConfig = config.getAsJsonObject(CONFIG_KEY_AGENT);
                if (agentConfig != null && agentConfig.has(key)) {
                    com.google.gson.JsonElement element = agentConfig.get(key);
                    if (element != null && element.isJsonPrimitive()) {
                        return element.getAsString();
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "读取配置 '" + CONFIG_KEY_AGENT + "." + key + "' 失败", e);
        }
        return null;
    }

    /**
     * 将当前配置持久化保存到 ConfigManager 的 'agent' 配置段中。
     * <p>
     * 保存 endpoint、apiKey 和 model 到 ConfigManager，以便后续构造时自动加载。
     * 此方法会合并现有配置，不会覆盖 'agent' 段下的其他字段。
     * </p>
     */
    public void saveConfig() {
        try {
            ConfigManager configManager = ConfigManager.getInstance();
            com.google.gson.JsonObject config = configManager.getConfig();

            // 获取或创建 agent 配置段
            com.google.gson.JsonObject agentConfig;
            if (config.has(CONFIG_KEY_AGENT)) {
                agentConfig = config.getAsJsonObject(CONFIG_KEY_AGENT);
            } else {
                agentConfig = new com.google.gson.JsonObject();
            }

            // 更新配置值
            agentConfig.addProperty(CONFIG_KEY_ENDPOINT, endpoint);
            agentConfig.addProperty(CONFIG_KEY_API_KEY, apiKey);
            agentConfig.addProperty(CONFIG_KEY_MODEL, model);

            config.add(CONFIG_KEY_AGENT, agentConfig);
            configManager.saveConfig();

            Log.i(TAG, "配置已保存到 ConfigManager: " + CONFIG_KEY_AGENT + "."
                    + CONFIG_KEY_ENDPOINT + "=" + endpoint
                    + ", " + CONFIG_KEY_AGENT + "." + CONFIG_KEY_MODEL + "=" + model);
        } catch (IllegalStateException e) {
            Log.w(TAG, "ConfigManager 尚未初始化，无法保存配置", e);
        } catch (Exception e) {
            Log.e(TAG, "保存配置失败", e);
        }
    }

    // ======================== LLMClient 接口实现 ========================

    /**
     * {@inheritDoc}
     * <p>
     * 实现逻辑：将请求直接发送到用户配置的自定义 API 端点，使用非流式模式。
     * 端点支持任何 OpenAI 兼容的 API 格式。
     * </p>
     */
    @Override
    public String generateResponse(String systemPrompt, String userMessage,
                                   List<String> tools) throws Exception {
        Log.d(TAG, "generateResponse - 开始非流式生成，端点: " + endpoint);

        JSONObject requestBody = buildRequestBody(systemPrompt, userMessage, tools, false);
        String result = doHttpPost(endpoint + CHAT_COMPLETIONS_PATH, requestBody, false, null);

        if (result == null) {
            Log.e(TAG, "非流式调用返回 null");
            return null;
        }

        Log.d(TAG, "非流式调用成功，响应长度: " + result.length());
        return result;
    }

    /**
     * {@inheritDoc}
     * <p>
     * 实现逻辑：通过 SSE（Server-Sent Events）协议逐 Token 接收 LLM 输出，
     * 直接发送到用户配置的自定义 API 端点。
     * 每个收到的 Token 通过 {@link StreamCallback#onToken(String)} 通知调用方，
     * 全部接收完毕后通过 {@link StreamCallback#onComplete(String)} 通知。
     * </p>
     */
    @Override
    public String generateStreaming(String systemPrompt, String userMessage,
                                    List<String> tools,
                                    StreamCallback callback) throws Exception {
        Log.d(TAG, "generateStreaming - 开始流式生成，端点: " + endpoint);

        if (callback == null) {
            throw new IllegalArgumentException("StreamCallback must not be null");
        }

        JSONObject requestBody = buildRequestBody(systemPrompt, userMessage, tools, true);

        try {
            String result = doHttpPost(endpoint + CHAT_COMPLETIONS_PATH, requestBody, true, callback);
            callback.onComplete(result);
            Log.d(TAG, "流式调用完成，响应长度: " + (result != null ? result.length() : 0));
            return result;
        } catch (Exception e) {
            Log.e(TAG, "流式调用失败", e);
            callback.onError(e);
            throw e;
        }
    }

    // ======================== 请求构建 ========================

    /**
     * 构建 OpenAI 兼容的聊天完成请求体。
     * <p>
     * 构建格式与 OpenAI Chat Completions API 完全兼容：
     * <pre>
     * {
     *   "model": "gpt-4",
     *   "stream": false,
     *   "messages": [
     *     { "role": "system", "content": "..." },
     *     { "role": "user", "content": "..." }
     *   ],
     *   "tools": [ ... ]
     * }
     * </pre>
     * </p>
     *
     * @param systemPrompt 系统提示词
     * @param userMessage  用户消息
     * @param tools        工具名称列表（可为 null 或空）
     * @param stream       是否启用流式输出
     * @return 构建完成的 JSONObject 请求体
     * @throws Exception JSON 构造失败时抛出
     */
    protected JSONObject buildRequestBody(String systemPrompt, String userMessage,
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
     * 执行 HTTP POST 请求到自定义 API 端点。
     * <p>
     * 非流式模式：同步等待完整响应后解析并返回文本内容。
     * 流式模式：逐行读取 SSE 响应体，通过回调逐 Token 通知调用方，
     * 同时拼接完整文本返回。
     * </p>
     *
     * @param url      请求目标 URL（完整的聊天补全端点 URL）
     * @param bodyJson 请求体 JSON
     * @param stream   是否启用流式解析
     * @param callback 流式回调（非流式时传 null）
     * @return 完整的回复文本
     * @throws Exception 网络错误、认证失败或 JSON 解析异常时抛出
     */
    private String doHttpPost(String url, JSONObject bodyJson,
                              boolean stream, StreamCallback callback) throws Exception {
        Log.d(TAG, "HTTP POST - " + url + " (stream=" + stream + ")");

        // 构建 OkHttp Request
        Request.Builder requestBuilder = new Request.Builder()
                .url(url)
                .addHeader("Content-Type", "application/json");

        // 添加认证头（如果配置了 API key）
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

    // ======================== 端点连通性检测 ========================

    /**
     * 检测自定义 API 端点是否可达。
     * <p>
     * 通过尝试连接端点的 {@code /models} 或根路径来判断端点是否可用。
     * 此方法可用于外部调用方决定是否发送请求前检查连接状态。
     * </p>
     *
     * @return true 表示端点可达
     */
    public boolean isEndpointAvailable() {
        try {
            Request request = new Request.Builder()
                    .url(endpoint + "/models")
                    .addHeader("Authorization", "Bearer " + apiKey)
                    .get()
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                boolean available = response.isSuccessful();
                Log.d(TAG, "端点连通性检测: " + (available ? "可用" : "不可用")
                        + " (状态码: " + response.code() + ")");
                return available;
            }
        } catch (ConnectException e) {
            Log.d(TAG, "端点不可达 (连接被拒绝)");
            return false;
        } catch (Exception e) {
            Log.d(TAG, "端点连通性检测异常: " + e.getMessage());
            return false;
        }
    }

    // ======================== 配置访问器 ========================

    /**
     * 获取自定义 API 端点基础 URL。
     *
     * @return 端点基础 URL，例如 "https://api.openai.com/v1"
     */
    public String getEndpoint() {
        return endpoint;
    }

    /**
     * 获取 API 密钥（掩码显示，仅显示最后 4 位）。
     *
     * @return 掩码后的 API 密钥，若未设置则返回空字符串
     */
    public String getMaskedApiKey() {
        if (apiKey == null || apiKey.isEmpty()) {
            return "";
        }
        if (apiKey.length() <= 8) {
            return "****";
        }
        return apiKey.substring(0, 4) + "..." + apiKey.substring(apiKey.length() - 4);
    }

    /**
     * 获取当前使用的模型名称。
     *
     * @return 模型名称
     */
    public String getModel() {
        return model;
    }

    /**
     * 获取 API 密钥（原始值，谨慎使用）。
     *
     * @return 完整的 API 密钥
     */
    public String getApiKey() {
        return apiKey;
    }

    @Override
    public String toString() {
        return "CustomLLMClient{"
                + "endpoint='" + endpoint + '\''
                + ", model='" + model + '\''
                + ", apiKey=" + getMaskedApiKey()
                + '}';
    }
}