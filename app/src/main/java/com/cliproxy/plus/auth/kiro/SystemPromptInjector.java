package com.cliproxy.plus.auth.kiro;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

/**
 * SystemPromptInjector - Injects system prompts into Kiro/Amazon Q user messages.
 * <p>
 * Kiro (Amazon Q Developer) does not natively support a dedicated {@code system}
 * field in its chat completion API. When a system prompt is required, this injector
 * wraps the prompt with {@code --- SYSTEM PROMPT ---} / {@code --- END SYSTEM PROMPT ---}
 * markers and prepends it to the user message content. Downstream processing logic
 * (e.g. a proxy middleware) can then detect the markers, extract the prompt, and
 * handle it appropriately.
 * <p>
 * The injector supports both plain text messages and JSON-formatted request payloads
 * (e.g. {@code {"messages": [{"role": "user", "content": "..."}]}}). For JSON payloads,
 * the injection is applied to each user message's content field. An OkHttpClient
 * instance is available for sending the injected messages to an upstream endpoint.
 * <p>
 * <b>Marker format:</b>
 * <pre>
 * --- SYSTEM PROMPT ---
 * You are a helpful assistant specialized in software engineering.
 * --- END SYSTEM PROMPT ---
 *
 * What is the weather today?
 * </pre>
 * <p>
 * <b>Usage example:</b>
 * <pre>
 * SystemPromptInjector injector = new SystemPromptInjector();
 * String combined = injector.inject("Hello", "You are a helpful AI.");
 * // combined = "--- SYSTEM PROMPT ---\nYou are a helpful AI.\n--- END SYSTEM PROMPT ---\n\nHello"
 *
 * boolean hasInjected = injector.isInjected(combined);          // true
 * String extracted = injector.extract(combined);                 // "You are a helpful AI."
 * String userMsg = injector.removeInjected(combined);            // "Hello"
 * </pre>
 *
 * 对应原版 CLIProxyAPIPlus/internal/auth/kiro/ 中的 System Prompt 注入逻辑。
 */
public class SystemPromptInjector {

    private static final String TAG = "SystemPromptInjector";

    // ================================================================
    //  常量
    // ================================================================

    /** 系统提示词开始标记 */
    private static final String SYSTEM_PROMPT_START = "--- SYSTEM PROMPT ---";

    /** 系统提示词结束标记 */
    private static final String SYSTEM_PROMPT_END = "--- END SYSTEM PROMPT ---";

    /** 分隔符（两个换行，分隔系统提示词与用户消息） */
    private static final String SEPARATOR = "\n\n";

    /** 标记段与用户消息之间的分隔符 */
    private static final String MARKER_NEWLINE = "\n";

    /** 完整的注入前缀正则（用于检测和提取） */
    private static final String INJECTED_PATTERN =
            "^" + SYSTEM_PROMPT_START + MARKER_NEWLINE
                    + "(.*?)" + MARKER_NEWLINE
                    + SYSTEM_PROMPT_END + SEPARATOR;

    /** 默认 HTTP 超时（毫秒） */
    private static final int DEFAULT_TIMEOUT_MS = 15000;

    /** 默认请求的最大重试次数 */
    private static final int MAX_RETRIES = 3;

    /** JSON MediaType */
    private static final MediaType JSON_MEDIA_TYPE =
            MediaType.get("application/json; charset=utf-8");

    // ================================================================
    //  实例状态
    // ================================================================

    private final OkHttpClient httpClient;
    private volatile boolean enabled;

    // ================================================================
    //  构造
    // ================================================================

    /**
     * 创建一个默认的 SystemPromptInjector 实例。
     * <p>
     * 使用默认超时（15s）的 OkHttpClient，注入功能默认启用。
     */
    public SystemPromptInjector() {
        this(new OkHttpClient.Builder()
                .connectTimeout(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .readTimeout(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .writeTimeout(DEFAULT_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                .build());
    }

    /**
     * 使用指定的 OkHttpClient 创建 SystemPromptInjector。
     *
     * @param httpClient OkHttpClient 实例，用于后续 HTTP 请求
     */
    public SystemPromptInjector(OkHttpClient httpClient) {
        this.httpClient = httpClient;
        this.enabled = true;
        log("SystemPromptInjector initialized");
    }

    // ================================================================
    //  inject
    // ================================================================

    /**
     * 将系统提示词注入到用户消息中。
     * <p>
     * 如果注入功能已禁用或系统提示词为空，则直接返回原始用户消息不做修改。
     * 如果用户消息已经是 JSON 格式的请求体，则递归处理其中的用户消息内容。
     * 如果用户消息中已经包含注入标记，则先移除旧的系统提示词再注入新的。
     *
     * @param userMessage  用户消息内容（普通文本或 JSON 格式的请求体）
     * @param systemPrompt 要注入的系统提示词
     * @return 注入后的消息内容
     * @throws IllegalArgumentException 如果 userMessage 为 null
     */
    public String inject(String userMessage, String systemPrompt) {
        if (userMessage == null) {
            throw new IllegalArgumentException("userMessage must not be null");
        }

        if (!enabled || systemPrompt == null || systemPrompt.trim().isEmpty()) {
            log("inject skipped: enabled=" + enabled
                    + ", systemPrompt=" + (systemPrompt == null ? "null" : "empty"));
            return userMessage;
        }

        String trimmedPrompt = systemPrompt.trim();

        // 如果用户消息是 JSON 格式，尝试在 JSON 中注入
        String trimmed = userMessage.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                return injectIntoJson(userMessage, trimmedPrompt);
            } catch (JSONException e) {
                logError("Failed to parse user message as JSON, falling back to plain text injection", e);
            }
        }

        // 如果已包含注入标记，先移除旧的再注入新的
        String baseMessage = removeInjected(userMessage);

        // 构建注入后的消息
        StringBuilder sb = new StringBuilder();
        sb.append(SYSTEM_PROMPT_START).append(MARKER_NEWLINE);
        sb.append(trimmedPrompt).append(MARKER_NEWLINE);
        sb.append(SYSTEM_PROMPT_END).append(SEPARATOR);
        sb.append(baseMessage);

        String result = sb.toString();
        log("inject: system prompt injected (" + trimmedPrompt.length() + " chars)");
        return result;
    }

    /**
     * 将系统提示词注入到 JSON 格式的请求体中。
     * <p>
     * 支持标准的 OpenAI/Kiro 聊天补全请求格式：
     * <pre>
     * {
     *   "messages": [
     *     {"role": "user", "content": "..."},
     *     {"role": "assistant", "content": "..."}
     *   ]
     * }
     * </pre>
     * 对每个 role 为 "user" 的消息的 content 字段进行注入。
     *
     * @param jsonMessage   JSON 格式的请求体字符串
     * @param systemPrompt 要注入的系统提示词
     * @return 注入后的 JSON 字符串
     * @throws JSONException 如果 JSON 解析失败
     */
    private String injectIntoJson(String jsonMessage, String systemPrompt) throws JSONException {
        JSONObject json = new JSONObject(jsonMessage);
        boolean modified = false;

        // 处理 messages 数组
        if (json.has("messages")) {
            JSONArray messages = json.getJSONArray("messages");
            for (int i = 0; i < messages.length(); i++) {
                JSONObject msg = messages.getJSONObject(i);
                String role = msg.optString("role", "");
                if ("user".equals(role) && msg.has("content")) {
                    String content = msg.getString("content");
                    String injected = injectPlainText(content, systemPrompt);
                    if (!injected.equals(content)) {
                        msg.put("content", injected);
                        modified = true;
                    }
                }
            }
        }

        // 处理顶层 prompt 字段（部分 Kiro 端点使用）
        if (json.has("prompt")) {
            String prompt = json.getString("prompt");
            String injected = injectPlainText(prompt, systemPrompt);
            if (!injected.equals(prompt)) {
                json.put("prompt", injected);
                modified = true;
            }
        }

        if (modified) {
            log("injectIntoJson: system prompt injected into JSON payload");
        } else {
            log("injectIntoJson: no user messages found in JSON payload");
        }

        return json.toString();
    }

    /**
     * 对纯文本消息执行注入（不检查 JSON）。
     *
     * @param text          原始文本
     * @param systemPrompt  系统提示词
     * @return 注入后的文本
     */
    private String injectPlainText(String text, String systemPrompt) {
        String base = removeInjected(text);
        StringBuilder sb = new StringBuilder();
        sb.append(SYSTEM_PROMPT_START).append(MARKER_NEWLINE);
        sb.append(systemPrompt).append(MARKER_NEWLINE);
        sb.append(SYSTEM_PROMPT_END).append(SEPARATOR);
        sb.append(base);
        return sb.toString();
    }

    // ================================================================
    //  extract
    // ================================================================

    /**
     * 从已注入的消息中提取系统提示词。
     * <p>
     * 如果消息包含 {@code --- SYSTEM PROMPT ---} 标记，则提取标记之间的内容。
     * 支持纯文本和 JSON 格式的消息。
     *
     * @param userMessage 可能包含注入标记的消息
     * @return 提取的系统提示词，如果未找到注入标记则返回 {@code null}
     * @throws IllegalArgumentException 如果 userMessage 为 null
     */
    public String extract(String userMessage) {
        if (userMessage == null) {
            throw new IllegalArgumentException("userMessage must not be null");
        }

        // 尝试从纯文本格式中提取
        String extracted = extractFromPlainText(userMessage);
        if (extracted != null) {
            return extracted;
        }

        // 尝试从 JSON 格式中提取
        String trimmed = userMessage.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                return extractFromJson(userMessage);
            } catch (JSONException e) {
                logError("Failed to extract system prompt from JSON", e);
            }
        }

        return null;
    }

    /**
     * 从纯文本中提取系统提示词。
     *
     * @param text 文本内容
     * @return 系统提示词，或 null
     */
    private String extractFromPlainText(String text) {
        int startIdx = text.indexOf(SYSTEM_PROMPT_START);
        if (startIdx < 0) {
            return null;
        }

        int contentStart = startIdx + SYSTEM_PROMPT_START.length();
        // 跳过后面的换行
        while (contentStart < text.length() && text.charAt(contentStart) == '\n') {
            contentStart++;
        }

        int endIdx = text.indexOf(SYSTEM_PROMPT_END, contentStart);
        if (endIdx < 0) {
            log("extract: found start marker but no end marker");
            return null;
        }

        // 去除末尾的换行
        int contentEnd = endIdx;
        while (contentEnd > contentStart && text.charAt(contentEnd - 1) == '\n') {
            contentEnd--;
        }

        if (contentEnd <= contentStart) {
            log("extract: system prompt markers found but content is empty");
            return "";
        }

        String result = text.substring(contentStart, contentEnd);
        log("extract: system prompt extracted (" + result.length() + " chars)");
        return result;
    }

    /**
     * 从 JSON 格式的消息中提取系统提示词。
     * <p>
     * 遍历 messages 数组中的 user 消息，查找第一个包含注入标记的消息并提取。
     *
     * @param jsonMessage JSON 格式的消息
     * @return 系统提示词，或 null
     * @throws JSONException 如果 JSON 解析失败
     */
    private String extractFromJson(String jsonMessage) throws JSONException {
        JSONObject json = new JSONObject(jsonMessage);

        if (json.has("messages")) {
            JSONArray messages = json.getJSONArray("messages");
            for (int i = 0; i < messages.length(); i++) {
                JSONObject msg = messages.getJSONObject(i);
                String role = msg.optString("role", "");
                if ("user".equals(role) && msg.has("content")) {
                    String content = msg.getString("content");
                    String extracted = extractFromPlainText(content);
                    if (extracted != null) {
                        return extracted;
                    }
                }
            }
        }

        if (json.has("prompt")) {
            String prompt = json.getString("prompt");
            return extractFromPlainText(prompt);
        }

        return null;
    }

    // ================================================================
    //  isInjected
    // ================================================================

    /**
     * 检查消息是否已包含注入的系统提示词。
     * <p>
     * 检测 {@code --- SYSTEM PROMPT ---} 标记是否存在于消息中。
     * 支持纯文本和 JSON 格式。
     *
     * @param userMessage 要检查的消息
     * @return true 如果消息中包含系统提示词注入标记
     * @throws IllegalArgumentException 如果 userMessage 为 null
     */
    public boolean isInjected(String userMessage) {
        if (userMessage == null) {
            throw new IllegalArgumentException("userMessage must not be null");
        }

        // 快速检测：纯文本标记
        if (userMessage.contains(SYSTEM_PROMPT_START)
                && userMessage.contains(SYSTEM_PROMPT_END)) {
            return true;
        }

        // JSON 格式递归检测
        String trimmed = userMessage.trim();
        if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
            try {
                return isInjectedInJson(userMessage);
            } catch (JSONException e) {
                logError("Failed to check JSON for injection markers", e);
            }
        }

        return false;
    }

    /**
     * 检查 JSON 格式的消息中是否包含注入标记。
     *
     * @param jsonMessage JSON 格式的消息
     * @return true 如果任何 user 消息包含注入标记
     * @throws JSONException 如果 JSON 解析失败
     */
    private boolean isInjectedInJson(String jsonMessage) throws JSONException {
        JSONObject json = new JSONObject(jsonMessage);

        if (json.has("messages")) {
            JSONArray messages = json.getJSONArray("messages");
            for (int i = 0; i < messages.length(); i++) {
                JSONObject msg = messages.getJSONObject(i);
                String role = msg.optString("role", "");
                if ("user".equals(role) && msg.has("content")) {
                    String content = msg.getString("content");
                    if (content.contains(SYSTEM_PROMPT_START)
                            && content.contains(SYSTEM_PROMPT_END)) {
                        return true;
                    }
                }
            }
        }

        if (json.has("prompt")) {
            String prompt = json.getString("prompt");
            return prompt.contains(SYSTEM_PROMPT_START)
                    && prompt.contains(SYSTEM_PROMPT_END);
        }

        return false;
    }

    // ================================================================
    //  removeInjected
    // ================================================================

    /**
     * 从已注入的消息中移除系统提示词部分，只保留原始用户消息。
     * <p>
     * 如果消息不包含注入标记，则返回原始消息不变。
     *
     * @param userMessage 可能包含注入标记的消息
     * @return 移除系统提示词后的用户消息
     * @throws IllegalArgumentException 如果 userMessage 为 null
     */
    public String removeInjected(String userMessage) {
        if (userMessage == null) {
            throw new IllegalArgumentException("userMessage must not be null");
        }

        int startIdx = userMessage.indexOf(SYSTEM_PROMPT_START);
        if (startIdx < 0) {
            return userMessage;
        }

        int endIdx = userMessage.indexOf(SYSTEM_PROMPT_END, startIdx);
        if (endIdx < 0) {
            return userMessage;
        }

        // 找到结束标记后的内容（跳过结束标记本身和后面的分隔符）
        int contentStart = endIdx + SYSTEM_PROMPT_END.length();
        while (contentStart < userMessage.length()
                && (userMessage.charAt(contentStart) == '\n'
                || userMessage.charAt(contentStart) == '\r')) {
            contentStart++;
        }

        String result = userMessage.substring(contentStart);
        log("removeInjected: system prompt removed");
        return result;
    }

    // ================================================================
    //  HTTP 发送方法
    // ================================================================

    /**
     * 将注入后的消息作为 JSON 请求体发送到指定的上游端点。
     * <p>
     * 使用 OkHttpClient 发送 POST 请求，内容类型为 {@code application/json}。
     * 请求失败时会自动重试最多 {@value #MAX_RETRIES} 次。
     *
     * @param url         目标 URL
     * @param jsonPayload JSON 格式的请求体
     * @return 响应体字符串
     * @throws IOException          如果所有重试均失败或网络错误
     * @throws IllegalStateException 如果注入器被禁用
     */
    public String sendInjectedMessage(String url, String jsonPayload) throws IOException {
        if (!enabled) {
            throw new IllegalStateException("SystemPromptInjector is disabled");
        }
        if (url == null || url.trim().isEmpty()) {
            throw new IllegalArgumentException("url must not be null or empty");
        }
        if (jsonPayload == null || jsonPayload.trim().isEmpty()) {
            throw new IllegalArgumentException("jsonPayload must not be null or empty");
        }

        IOException lastError = null;

        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                try {
                    Thread.sleep(attempt * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("sendInjectedMessage retry interrupted", e);
                }
            }

            try {
                RequestBody body = RequestBody.create(jsonPayload, JSON_MEDIA_TYPE);
                Request request = new Request.Builder()
                        .url(url.trim())
                        .post(body)
                        .addHeader("Accept", "application/json")
                        .addHeader("User-Agent", "CLIProxyPlus/SystemPromptInjector")
                        .build();

                log("sendInjectedMessage: POST " + url + " (attempt " + (attempt + 1) + ")");

                try (Response response = httpClient.newCall(request).execute()) {
                    if (!response.isSuccessful()) {
                        String errorBody = response.body() != null
                                ? response.body().string() : "no body";
                        throw new IOException("HTTP " + response.code() + ": " + errorBody);
                    }

                    String responseBody = response.body() != null
                            ? response.body().string() : "";
                    log("sendInjectedMessage: response received (" + responseBody.length() + " bytes)");
                    return responseBody;
                }
            } catch (IOException e) {
                lastError = e;
                logError("sendInjectedMessage attempt " + (attempt + 1) + " failed", e);
            }
        }

        throw new IOException("sendInjectedMessage failed after " + MAX_RETRIES + " attempts",
                lastError);
    }

    /**
     * 发送注入后的消息并尝试解析响应为 JSONObject。
     *
     * @param url         目标 URL
     * @param jsonPayload JSON 格式的请求体
     * @return 解析后的 JSON 响应
     * @throws IOException  如果网络请求失败
     * @throws JSONException 如果响应不是有效的 JSON
     */
    public JSONObject sendAndParseJson(String url, String jsonPayload)
            throws IOException, JSONException {
        String responseBody = sendInjectedMessage(url, jsonPayload);
        return new JSONObject(responseBody);
    }

    // ================================================================
    //  JSON 构建工具
    // ================================================================

    /**
     * 构建一个 OpenAI/Kiro 兼容的聊天补全请求体，并注入系统提示词。
     * <p>
     * 构建格式：
     * <pre>
     * {
     *   "messages": [
     *     {"role": "user", "content": "&lt;injected message&gt;"}
     *   ],
     *   "max_tokens": 4096,
     *   "temperature": 0.7
     * }
     * </pre>
     *
     * @param userMessage  用户消息
     * @param systemPrompt 系统提示词
     * @param maxTokens    最大 Token 数
     * @param temperature  温度参数
     * @return 构建好的 JSON 请求体字符串
     */
    public String buildChatCompletionPayload(String userMessage, String systemPrompt,
                                              int maxTokens, double temperature) {
        try {
            String injectedMessage = inject(userMessage, systemPrompt);

            JSONObject payload = new JSONObject();
            JSONArray messages = new JSONArray();

            JSONObject userMsg = new JSONObject();
            userMsg.put("role", "user");
            userMsg.put("content", injectedMessage);
            messages.put(userMsg);

            payload.put("messages", messages);
            payload.put("max_tokens", maxTokens);
            payload.put("temperature", temperature);

            log("buildChatCompletionPayload: payload built (" + payload.length() + " fields)");
            return payload.toString();
        } catch (JSONException e) {
            logError("Failed to build chat completion payload", e);
            // Fallback: return a minimal payload
            return "{\"messages\":[{\"role\":\"user\",\"content\":\""
                    + escapeJson(userMessage) + "\"}],\"max_tokens\":4096,\"temperature\":0.7}";
        }
    }

    /**
     * 简单的 JSON 字符串转义。
     */
    private static String escapeJson(String value) {
        if (value == null) return "";
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    // ================================================================
    //  启用/禁用
    // ================================================================

    /**
     * 启用系统提示词注入功能。
     */
    public void enable() {
        this.enabled = true;
        log("SystemPromptInjector enabled");
    }

    /**
     * 禁用系统提示词注入功能。
     * <p>
     * 禁用后，{@link #inject(String, String)} 将直接返回原始用户消息不做修改。
     */
    public void disable() {
        this.enabled = false;
        log("SystemPromptInjector disabled");
    }

    /**
     * 检查注入功能是否已启用。
     *
     * @return true 如果注入功能已启用
     */
    public boolean isEnabled() {
        return enabled;
    }

    // ================================================================
    //  日志
    // ================================================================

    private void log(String msg) {
        Log.d(TAG, msg);
    }

    private void logError(String msg, Throwable t) {
        Log.e(TAG, msg, t);
    }
}