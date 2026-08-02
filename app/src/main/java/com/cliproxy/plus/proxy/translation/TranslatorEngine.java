package com.cliproxy.plus.proxy.translation;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * FormatTranslator - 协议格式转换器接口
 * 每种格式转换的逻辑封装在实现类中
 */
public interface FormatTranslator {

    /**
     * 将 JSON 请求体从源格式转换为目标格式
     *
     * @param jsonBody 原始请求体 JSON 字符串
     * @param headers  请求头信息
     * @return 转换后的 JSON 字符串
     */
    String translate(String jsonBody, Map<String, String> headers);
}

/**
 * TranslatorEngine - 协议翻译引擎
 * 管理源协议到目标协议的格式转换器注册与调度
 * 采用注册表模式，支持动态注册和查询格式转换器
 * <p>
 * 支持的协议格式：openai-chat, openai-responses, claude, gemini,
 * gemini-cli, codex, antigravity, interactions
 * <p>
 * 对应原版 internal/translator/engine.go
 */
public class TranslatorEngine {

    private static final String TAG = "TranslatorEngine";

    /** 格式转换器注册表：key = "sourceFormat->targetFormat" */
    private final ConcurrentHashMap<String, FormatTranslator> registry;

    /** 所有支持的协议格式列表 */
    public static final Set<String> SUPPORTED_FORMATS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    "openai-chat",
                    "openai-responses",
                    "claude",
                    "gemini",
                    "gemini-cli",
                    "codex",
                    "antigravity",
                    "interactions"
            ))
    );

    // 协议格式对应的 URL 路径前缀特征
    private static final Map<String, String[]> FORMAT_PATH_PATTERNS = new HashMap<>();

    static {
        FORMAT_PATH_PATTERNS.put("openai-chat", new String[]{"/v1/chat/completions"});
        FORMAT_PATH_PATTERNS.put("openai-responses", new String[]{"/v1/responses"});
        FORMAT_PATH_PATTERNS.put("claude", new String[]{"/v1/messages"});
        FORMAT_PATH_PATTERNS.put("gemini", new String[]{"/v1beta", "/v1/"});
        FORMAT_PATH_PATTERNS.put("gemini-cli", new String[]{"/v1beta", "/v1/"});
        FORMAT_PATH_PATTERNS.put("codex", new String[]{"/backend-api/codex"});
        FORMAT_PATH_PATTERNS.put("antigravity", new String[]{"/antigravity"});
        FORMAT_PATH_PATTERNS.put("interactions", new String[]{"/backend-api/interactions"});
    }

    // 协议格式对应的请求头特征
    private static final Map<String, String> FORMAT_HEADER_SIGNATURES = new HashMap<>();

    static {
        FORMAT_HEADER_SIGNATURES.put("openai-chat", "Authorization: Bearer");
        FORMAT_HEADER_SIGNATURES.put("openai-responses", "Authorization: Bearer");
        FORMAT_HEADER_SIGNATURES.put("claude", "x-api-key");
        FORMAT_HEADER_SIGNATURES.put("gemini", "X-Goog-Api-Key");
        FORMAT_HEADER_SIGNATURES.put("gemini-cli", "X-Goog-Api-Key");
        FORMAT_HEADER_SIGNATURES.put("codex", "Authorization: Bearer");
    }

    /**
     * 构造翻译引擎，自动注册默认格式转换器
     */
    public TranslatorEngine() {
        this.registry = new ConcurrentHashMap<>();
        registerDefaultTranslators();
        Log.i(TAG, "TranslatorEngine initialized with " + registry.size() + " translators");
    }

    /**
     * 注册格式转换器
     *
     * @param sourceFormat 源协议格式
     * @param targetFormat 目标协议格式
     * @param translator   格式转换器实例
     * @throws IllegalArgumentException 如果格式参数为 null 或空
     */
    public void registerTranslator(String sourceFormat, String targetFormat,
                                    FormatTranslator translator) {
        if (sourceFormat == null || sourceFormat.isEmpty()) {
            throw new IllegalArgumentException("sourceFormat must not be null or empty");
        }
        if (targetFormat == null || targetFormat.isEmpty()) {
            throw new IllegalArgumentException("targetFormat must not be null or empty");
        }
        if (translator == null) {
            throw new IllegalArgumentException("translator must not be null");
        }

        String key = buildKey(sourceFormat, targetFormat);
        registry.put(key, translator);
        Log.d(TAG, "Registered translator: " + sourceFormat + " -> " + targetFormat);
    }

    /**
     * 执行协议格式转换
     *
     * @param sourceFormat 源协议格式标识
     * @param targetFormat 目标协议格式标识
     * @param jsonBody     原始请求体 JSON 字符串
     * @param headers      请求头信息
     * @return 转换后的 JSON 字符串
     * @throws IllegalArgumentException 如果格式不支持或未注册转换器
     */
    public String translate(String sourceFormat, String targetFormat,
                             String jsonBody, Map<String, String> headers) {
        if (sourceFormat == null || targetFormat == null) {
            throw new IllegalArgumentException("sourceFormat and targetFormat must not be null");
        }
        if (jsonBody == null || jsonBody.isEmpty()) {
            Log.w(TAG, "translate called with empty body");
            return jsonBody;
        }

        // 如果源和目标相同，直接返回原内容
        if (sourceFormat.equals(targetFormat)) {
            Log.d(TAG, "No translation needed: " + sourceFormat + " -> " + targetFormat);
            return jsonBody;
        }

        String key = buildKey(sourceFormat, targetFormat);
        FormatTranslator translator = registry.get(key);

        if (translator == null) {
            Log.e(TAG, "No translator registered for: " + sourceFormat + " -> " + targetFormat);
            throw new IllegalArgumentException(
                    "Unsupported translation: " + sourceFormat + " -> " + targetFormat +
                    ". Available: " + registry.keySet());
        }

        Log.d(TAG, "Translating: " + sourceFormat + " -> " + targetFormat);
        long startTime = System.currentTimeMillis();

        try {
            String result = translator.translate(jsonBody, headers);
            long elapsed = System.currentTimeMillis() - startTime;
            Log.d(TAG, "Translation completed in " + elapsed + "ms");
            return result;
        } catch (Exception e) {
            Log.e(TAG, "Translation failed: " + sourceFormat + " -> " + targetFormat, e);
            throw new RuntimeException("Translation error: " + e.getMessage(), e);
        }
    }

    /**
     * 从请求头和请求体中检测协议格式
     * 优先级：请求头特征 > 请求路径模式 > 请求体内容分析
     *
     * @param headers 请求头
     * @param body    请求体字符串
     * @return 检测到的协议格式标识，无法识别时返回 "unknown"
     */
    public String detectProtocol(Map<String, String> headers, String body) {
        // 1. 通过请求头特征检测
        if (headers != null && !headers.isEmpty()) {
            String headerResult = detectByHeaders(headers);
            if (headerResult != null) {
                Log.d(TAG, "Protocol detected by headers: " + headerResult);
                return headerResult;
            }
        }

        // 2. 通过请求体内容特征检测
        if (body != null && !body.isEmpty()) {
            String bodyResult = detectByBody(body);
            if (bodyResult != null) {
                Log.d(TAG, "Protocol detected by body: " + bodyResult);
                return bodyResult;
            }
        }

        Log.w(TAG, "Unable to detect protocol from request");
        return "unknown";
    }

    /**
     * 通过请求头中的路径特征检测协议格式
     * 在已有路径信息时可调用此方法
     *
     * @param uri       请求 URI 路径
     * @param headers   请求头
     * @param body      请求体
     * @return 检测到的协议格式标识
     */
    public String detectProtocol(String uri, Map<String, String> headers, String body) {
        // 1. 通过 URI 路径匹配
        if (uri != null && !uri.isEmpty()) {
            String uriResult = detectByUri(uri);
            if (uriResult != null) {
                Log.d(TAG, "Protocol detected by URI: " + uriResult);
                return uriResult;
            }
        }

        // 2. 回退到无 URI 的检测逻辑
        return detectProtocol(headers, body);
    }

    /**
     * 获取已注册的所有转换映射
     *
     * @return 不可修改的注册表快照，key="source->target"
     */
    public Map<String, FormatTranslator> getRegisteredTranslators() {
        return Collections.unmodifiableMap(new HashMap<>(registry));
    }

    /**
     * 检查是否存在指定格式转换的转换器
     *
     * @param sourceFormat 源协议格式
     * @param targetFormat 目标协议格式
     * @return 是否存在已注册的转换器
     */
    public boolean hasTranslator(String sourceFormat, String targetFormat) {
        return registry.containsKey(buildKey(sourceFormat, targetFormat));
    }

    /**
     * 移除已注册的格式转换器
     *
     * @param sourceFormat 源协议格式
     * @param targetFormat 目标协议格式
     * @return 如果成功移除返回 true
     */
    public boolean removeTranslator(String sourceFormat, String targetFormat) {
        String key = buildKey(sourceFormat, targetFormat);
        FormatTranslator removed = registry.remove(key);
        if (removed != null) {
            Log.d(TAG, "Removed translator: " + sourceFormat + " -> " + targetFormat);
            return true;
        }
        return false;
    }

    /**
     * 注册默认的格式转换器
     * 注册所有常见协议之间的转换路径
     */
    private void registerDefaultTranslators() {
        // OpenAI Chat -> Claude
        registerTranslator("openai-chat", "claude", new OpenAIToClaudeTranslator());

        // OpenAI Chat -> Gemini
        registerTranslator("openai-chat", "gemini", new OpenAIToGeminiTranslator());

        // OpenAI Chat -> Codex
        registerTranslator("openai-chat", "codex", new OpenAIToCodexTranslator());

        // Claude -> OpenAI Chat
        registerTranslator("claude", "openai-chat", new ClaudeToOpenAITranslator());

        // Claude -> Gemini
        registerTranslator("claude", "gemini", new ClaudeToGeminiTranslator());

        // Gemini -> OpenAI Chat
        registerTranslator("gemini", "openai-chat", new GeminiToOpenAITranslator());

        // Gemini -> Claude
        registerTranslator("gemini", "claude", new GeminiToClaudeTranslator());

        // Codex -> OpenAI Chat
        registerTranslator("codex", "openai-chat", new CodexToOpenAITranslator());

        // OpenAI Responses -> OpenAI Chat
        registerTranslator("openai-responses", "openai-chat", new OpenAIToChatFallbackTranslator());

        // Antigravity -> OpenAI Chat
        registerTranslator("antigravity", "openai-chat", new AntigravityToOpenAITranslator());

        // Interactions -> OpenAI Chat
        registerTranslator("interactions", "openai-chat", new InteractionsToOpenAITranslator());

        // Gemini CLI -> OpenAI Chat (CLI 专用格式)
        registerTranslator("gemini-cli", "openai-chat", new GeminiCliToOpenAITranslator());

        Log.d(TAG, "Default translators registered");
    }

    // ========================================================================
    // 协议检测 - 内部实现
    // ========================================================================

    /**
     * 通过请求头特征检测协议
     */
    private String detectByHeaders(Map<String, String> headers) {
        // 检测 Claude：x-api-key 头
        if (headers.containsKey("x-api-key") || headers.containsKey("X-Api-Key")) {
            return "claude";
        }

        // 检测 Gemini：X-Goog-Api-Key 头
        if (headers.containsKey("X-Goog-Api-Key") || headers.containsKey("x-goog-api-key")) {
            // 进一步区分 gemini 和 gemini-cli
            String userAgent = headers.get("User-Agent");
            if (userAgent != null && userAgent.toLowerCase().contains("cliproxy")) {
                return "gemini-cli";
            }
            return "gemini";
        }

        // 检测 Authorization 头
        String auth = headers.get("Authorization");
        if (auth != null && auth.startsWith("Bearer ")) {
            // 通过 Content-Type 进一步区分
            String contentType = headers.get("Content-Type");
            if (contentType != null) {
                if (contentType.contains("claude") || contentType.contains("anthropic")) {
                    return "claude";
                }
            }
            // 默认为 OpenAI 格式，后续通过请求体再细分
            return "openai-chat";
        }

        return null;
    }

    /**
     * 通过 URI 路径特征检测协议
     */
    private String detectByUri(String uri) {
        if (uri == null) return null;

        for (Map.Entry<String, String[]> entry : FORMAT_PATH_PATTERNS.entrySet()) {
            for (String pattern : entry.getValue()) {
                if (uri.startsWith(pattern) || uri.contains(pattern)) {
                    return entry.getKey();
                }
            }
        }

        return null;
    }

    /**
     * 通过请求体内容特征检测协议
     */
    private String detectByBody(String body) {
        try {
            JSONObject json = new JSONObject(body);

            // Claude 格式：包含 anthropic_version 或 messages 数组且无 model 字段
            if (json.has("anthropic_version")) {
                return "claude";
            }
            if (json.has("messages") && !json.has("model")) {
                // 检查 messages 数组结构判断是否为 Claude 格式
                JSONArray messages = json.getJSONArray("messages");
                if (messages.length() > 0) {
                    JSONObject firstMsg = messages.getJSONObject(0);
                    if (firstMsg.has("role") && !firstMsg.has("content")) {
                        // Claude 消息可能包含多内容块
                        // 这里不做严格区分，让 header 检测优先
                    }
                }
            }

            // Gemini 格式：包含 contents 数组
            if (json.has("contents")) {
                return "gemini";
            }

            // OpenAI 格式：包含 model 和 messages
            if (json.has("model") && json.has("messages")) {
                String model = json.optString("model", "");
                if (model.contains("claude") || model.contains("anthropic")) {
                    return "claude";
                }
                return "openai-chat";
            }

            // OpenAI Responses 格式：包含 input 字段（新 API）
            if (json.has("input") && json.has("model")) {
                return "openai-responses";
            }

            // Codex 格式：包含 codex 相关字段
            if (json.has("codex") || json.has("codex_input")) {
                return "codex";
            }

            // Antigravity 格式
            if (json.has("antigravity_version") || json.has("ag_messages")) {
                return "antigravity";
            }

            // Interactions 格式
            if (json.has("interaction") || json.has("conversation_id")) {
                return "interactions";
            }

        } catch (Exception e) {
            Log.w(TAG, "Failed to parse body for protocol detection", e);
        }

        return null;
    }

    /**
     * 构建注册表 key
     */
    private static String buildKey(String source, String target) {
        return source + "->" + target;
    }

    // ========================================================================
    // 默认格式转换器实现（内部类）
    // ========================================================================

    /**
     * OpenAI Chat -> Claude 格式转换器
     * 将 OpenAI 聊天完成请求转换为 Anthropic Claude API 格式
     */
    private static class OpenAIToClaudeTranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject openAI = new JSONObject(jsonBody);
                JSONObject claude = new JSONObject();

                // 设置 Claude 版本
                claude.put("anthropic_version", "2023-06-01");

                // 映射模型名称
                String model = openAI.optString("model", "claude-3-5-sonnet-20241022");
                claude.put("model", mapToClaudeModel(model));

                // 转换消息格式
                JSONArray messages = openAI.optJSONArray("messages");
                if (messages != null) {
                    JSONArray claudeMessages = new JSONArray();
                    for (int i = 0; i < messages.length(); i++) {
                        JSONObject msg = messages.getJSONObject(i);
                        JSONObject claudeMsg = new JSONObject();
                        claudeMsg.put("role", mapToClaudeRole(msg.optString("role", "user")));
                        claudeMsg.put("content", msg.opt("content"));
                        claudeMessages.put(claudeMsg);
                    }
                    claude.put("messages", claudeMessages);
                }

                // 转换系统提示词为 system 字段
                String systemPrompt = extractSystemPrompt(openAI);
                if (systemPrompt != null) {
                    claude.put("system", systemPrompt);
                }

                // 映射参数
                if (openAI.has("max_tokens")) {
                    claude.put("max_tokens", openAI.getInt("max_tokens"));
                }
                if (openAI.has("temperature")) {
                    claude.put("temperature", openAI.getDouble("temperature"));
                }
                if (openAI.has("top_p")) {
                    claude.put("top_p", openAI.getDouble("top_p"));
                }
                if (openAI.has("stream")) {
                    claude.put("stream", openAI.getBoolean("stream"));
                }
                if (openAI.has("stop")) {
                    claude.put("stop_sequences", openAI.get("stop"));
                }

                Log.d(TAG, "OpenAI -> Claude translation completed");
                return claude.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "OpenAI -> Claude translation failed", e);
                throw new RuntimeException("OpenAI -> Claude translation failed", e);
            }
        }

        private String mapToClaudeModel(String openAIModel) {
            if (openAIModel.contains("gpt-4")) return "claude-3-5-sonnet-20241022";
            if (openAIModel.contains("gpt-3.5")) return "claude-3-haiku-20240307";
            return openAIModel;
        }

        private String mapToClaudeRole(String openAIRole) {
            switch (openAIRole) {
                case "assistant": return "assistant";
                case "system": return "user"; // Claude 系统提示通过 system 字段传递
                default: return "user";
            }
        }

        private String extractSystemPrompt(JSONObject openAI) {
            JSONArray messages = openAI.optJSONArray("messages");
            if (messages == null) return null;

            for (int i = 0; i < messages.length(); i++) {
                JSONObject msg = messages.optJSONObject(i);
                if (msg != null && "system".equals(msg.optString("role"))) {
                    return msg.optString("content", null);
                }
            }
            return null;
        }
    }

    /**
     * OpenAI Chat -> Gemini 格式转换器
     */
    private static class OpenAIToGeminiTranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject openAI = new JSONObject(jsonBody);
                JSONObject gemini = new JSONObject();

                // 转换消息为 Gemini contents 格式
                JSONArray messages = openAI.optJSONArray("messages");
                if (messages != null) {
                    JSONArray contents = new JSONArray();
                    StringBuilder systemContext = new StringBuilder();

                    for (int i = 0; i < messages.length(); i++) {
                        JSONObject msg = messages.getJSONObject(i);
                        String role = msg.optString("role", "user");
                        Object content = msg.opt("content");

                        if ("system".equals(role)) {
                            systemContext.append(content.toString()).append("\n");
                            continue;
                        }

                        JSONObject part = new JSONObject();
                        part.put("text", content != null ? content.toString() : "");

                        JSONObject contentObj = new JSONObject();
                        contentObj.put("role", "user".equals(role) ? "user" : "model");
                        contentObj.put("parts", new JSONArray().put(part));
                        contents.put(contentObj);
                    }

                    // 如果有系统提示词，作为第一条 user 消息
                    if (systemContext.length() > 0) {
                        JSONObject systemPart = new JSONObject();
                        systemPart.put("text", systemContext.toString().trim());

                        JSONObject systemContent = new JSONObject();
                        systemContent.put("role", "user");
                        systemContent.put("parts", new JSONArray().put(systemPart));
                        // 插入到开头
                        JSONArray newContents = new JSONArray();
                        newContents.put(systemContent);
                        for (int i = 0; i < contents.length(); i++) {
                            newContents.put(contents.get(i));
                        }
                        contents = newContents;
                    }

                    gemini.put("contents", contents);
                }

                // 映射参数
                JSONObject generationConfig = new JSONObject();
                if (openAI.has("temperature")) {
                    generationConfig.put("temperature", openAI.getDouble("temperature"));
                }
                if (openAI.has("max_tokens")) {
                    generationConfig.put("maxOutputTokens", openAI.getInt("max_tokens"));
                }
                if (openAI.has("top_p")) {
                    generationConfig.put("topP", openAI.getDouble("top_p"));
                }
                if (openAI.has("stop")) {
                    generationConfig.put("stopSequences", openAI.get("stop"));
                }
                if (generationConfig.length() > 0) {
                    gemini.put("generationConfig", generationConfig);
                }

                // 映射模型
                String model = openAI.optString("model", "gemini-2.0-flash");
                gemini.put("model", "models/" + model);

                Log.d(TAG, "OpenAI -> Gemini translation completed");
                return gemini.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "OpenAI -> Gemini translation failed", e);
                throw new RuntimeException("OpenAI -> Gemini translation failed", e);
            }
        }
    }

    /**
     * OpenAI Chat -> Codex 格式转换器
     */
    private static class OpenAIToCodexTranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject openAI = new JSONObject(jsonBody);
                JSONObject codex = new JSONObject();

                // 转换核心字段
                codex.put("codex_input", true);
                codex.put("model", openAI.optString("model", "codex-davinci-002"));
                codex.put("prompt", extractPrompt(openAI));
                codex.put("max_tokens", openAI.optInt("max_tokens", 2048));
                codex.put("temperature", openAI.optDouble("temperature", 0.7));

                // 复制可选参数
                if (openAI.has("top_p")) {
                    codex.put("top_p", openAI.getDouble("top_p"));
                }
                if (openAI.has("stream")) {
                    codex.put("stream", openAI.getBoolean("stream"));
                }

                Log.d(TAG, "OpenAI -> Codex translation completed");
                return codex.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "OpenAI -> Codex translation failed", e);
                throw new RuntimeException("OpenAI -> Codex translation failed", e);
            }
        }

        private String extractPrompt(JSONObject openAI) {
            JSONArray messages = openAI.optJSONArray("messages");
            if (messages == null) return "";

            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < messages.length(); i++) {
                JSONObject msg = messages.optJSONObject(i);
                if (msg != null) {
                    String role = msg.optString("role", "user");
                    String content = msg.optString("content", "");
                    sb.append(role).append(": ").append(content).append("\n");
                }
            }
            return sb.toString().trim();
        }
    }

    /**
     * Claude -> OpenAI Chat 格式转换器
     */
    private static class ClaudeToOpenAITranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject claude = new JSONObject(jsonBody);
                JSONObject openAI = new JSONObject();

                // 映射模型
                String model = claude.optString("model", "gpt-4");
                openAI.put("model", mapToOpenAIModel(model));

                // 转换消息
                JSONArray messages = new JSONArray();

                // 处理 system 提示词
                if (claude.has("system")) {
                    JSONObject systemMsg = new JSONObject();
                    systemMsg.put("role", "system");
                    systemMsg.put("content", claude.getString("system"));
                    messages.put(systemMsg);
                }

                // 处理 messages
                JSONArray claudeMessages = claude.optJSONArray("messages");
                if (claudeMessages != null) {
                    for (int i = 0; i < claudeMessages.length(); i++) {
                        JSONObject cm = claudeMessages.getJSONObject(i);
                        JSONObject openAIMsg = new JSONObject();
                        openAIMsg.put("role", mapToOpenAIRole(cm.optString("role", "user")));
                        openAIMsg.put("content", cm.opt("content"));
                        messages.put(openAIMsg);
                    }
                }

                openAI.put("messages", messages);

                // 映射参数
                if (claude.has("max_tokens")) {
                    openAI.put("max_tokens", claude.getInt("max_tokens"));
                }
                if (claude.has("temperature")) {
                    openAI.put("temperature", claude.getDouble("temperature"));
                }
                if (claude.has("top_p")) {
                    openAI.put("top_p", claude.getDouble("top_p"));
                }
                if (claude.has("stream")) {
                    openAI.put("stream", claude.getBoolean("stream"));
                }
                if (claude.has("stop_sequences")) {
                    openAI.put("stop", claude.get("stop_sequences"));
                }

                Log.d(TAG, "Claude -> OpenAI translation completed");
                return openAI.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Claude -> OpenAI translation failed", e);
                throw new RuntimeException("Claude -> OpenAI translation failed", e);
            }
        }

        private String mapToOpenAIModel(String claudeModel) {
            if (claudeModel.contains("claude-3-5-sonnet")) return "gpt-4o";
            if (claudeModel.contains("claude-3-haiku")) return "gpt-4o-mini";
            if (claudeModel.contains("claude-3-opus")) return "gpt-4-turbo";
            return "gpt-4";
        }

        private String mapToOpenAIRole(String claudeRole) {
            switch (claudeRole) {
                case "assistant": return "assistant";
                default: return "user";
            }
        }
    }

    /**
     * Claude -> Gemini 格式转换器
     */
    private static class ClaudeToGeminiTranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject claude = new JSONObject(jsonBody);
                JSONObject gemini = new JSONObject();

                // 转换 messages 为 contents
                JSONArray contents = new JSONArray();

                // 处理 system 提示词
                if (claude.has("system")) {
                    JSONObject part = new JSONObject();
                    part.put("text", claude.getString("system"));

                    JSONObject content = new JSONObject();
                    content.put("role", "user");
                    content.put("parts", new JSONArray().put(part));
                    contents.put(content);
                }

                // 处理消息
                JSONArray claudeMessages = claude.optJSONArray("messages");
                if (claudeMessages != null) {
                    for (int i = 0; i < claudeMessages.length(); i++) {
                        JSONObject cm = claudeMessages.getJSONObject(i);
                        String role = cm.optString("role", "user");
                        Object content = cm.opt("content");

                        JSONObject part = new JSONObject();
                        part.put("text", content != null ? content.toString() : "");

                        JSONObject contentObj = new JSONObject();
                        contentObj.put("role", "assistant".equals(role) ? "model" : "user");
                        contentObj.put("parts", new JSONArray().put(part));
                        contents.put(contentObj);
                    }
                }

                gemini.put("contents", contents);

                // 映射参数
                JSONObject generationConfig = new JSONObject();
                if (claude.has("max_tokens")) {
                    generationConfig.put("maxOutputTokens", claude.getInt("max_tokens"));
                }
                if (claude.has("temperature")) {
                    generationConfig.put("temperature", claude.getDouble("temperature"));
                }
                if (generationConfig.length() > 0) {
                    gemini.put("generationConfig", generationConfig);
                }

                String model = claude.optString("model", "gemini-2.0-flash");
                gemini.put("model", "models/" + model);

                Log.d(TAG, "Claude -> Gemini translation completed");
                return gemini.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Claude -> Gemini translation failed", e);
                throw new RuntimeException("Claude -> Gemini translation failed", e);
            }
        }
    }

    /**
     * Gemini -> OpenAI Chat 格式转换器
     */
    private static class GeminiToOpenAITranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject gemini = new JSONObject(jsonBody);
                JSONObject openAI = new JSONObject();

                // 模型映射
                String model = gemini.optString("model", "gpt-4o");
                if (model.startsWith("models/")) {
                    model = model.substring(7);
                }
                openAI.put("model", mapToOpenAIModel(model));

                // 转换 contents 为 messages
                JSONArray messages = new JSONArray();
                JSONArray contents = gemini.optJSONArray("contents");

                if (contents != null) {
                    for (int i = 0; i < contents.length(); i++) {
                        JSONObject c = contents.getJSONObject(i);
                        String role = c.optString("role", "user");
                        JSONArray parts = c.optJSONArray("parts");

                        StringBuilder text = new StringBuilder();
                        if (parts != null) {
                            for (int j = 0; j < parts.length(); j++) {
                                JSONObject part = parts.getJSONObject(j);
                                if (part.has("text")) {
                                    if (text.length() > 0) text.append("\n");
                                    text.append(part.getString("text"));
                                }
                            }
                        }

                        JSONObject msg = new JSONObject();
                        msg.put("role", "model".equals(role) ? "assistant" : "user");
                        msg.put("content", text.toString());
                        messages.put(msg);
                    }
                }

                openAI.put("messages", messages);

                // 映射 generationConfig 参数
                JSONObject config = gemini.optJSONObject("generationConfig");
                if (config != null) {
                    if (config.has("temperature")) {
                        openAI.put("temperature", config.getDouble("temperature"));
                    }
                    if (config.has("maxOutputTokens")) {
                        openAI.put("max_tokens", config.getInt("maxOutputTokens"));
                    }
                    if (config.has("topP")) {
                        openAI.put("top_p", config.getDouble("topP"));
                    }
                }

                Log.d(TAG, "Gemini -> OpenAI translation completed");
                return openAI.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Gemini -> OpenAI translation failed", e);
                throw new RuntimeException("Gemini -> OpenAI translation failed", e);
            }
        }

        private String mapToOpenAIModel(String geminiModel) {
            if (geminiModel.contains("gemini-2.0-flash")) return "gpt-4o";
            if (geminiModel.contains("gemini-1.5-pro")) return "gpt-4-turbo";
            if (geminiModel.contains("gemini-1.5-flash")) return "gpt-4o-mini";
            return "gpt-4";
        }
    }

    /**
     * Gemini -> Claude 格式转换器
     */
    private static class GeminiToClaudeTranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject gemini = new JSONObject(jsonBody);
                JSONObject claude = new JSONObject();

                claude.put("anthropic_version", "2023-06-01");

                // 模型映射
                String model = gemini.optString("model", "claude-3-5-sonnet-20241022");
                if (model.startsWith("models/")) {
                    model = model.substring(7);
                }
                claude.put("model", mapToClaudeModel(model));

                // 转换 contents 为 messages
                JSONArray messages = new JSONArray();
                JSONArray contents = gemini.optJSONArray("contents");

                if (contents != null) {
                    for (int i = 0; i < contents.length(); i++) {
                        JSONObject c = contents.getJSONObject(i);
                        String role = c.optString("role", "user");
                        JSONArray parts = c.optJSONArray("parts");

                        StringBuilder text = new StringBuilder();
                        if (parts != null) {
                            for (int j = 0; j < parts.length(); j++) {
                                JSONObject part = parts.getJSONObject(j);
                                if (part.has("text")) {
                                    if (text.length() > 0) text.append("\n");
                                    text.append(part.getString("text"));
                                }
                            }
                        }

                        JSONObject msg = new JSONObject();
                        msg.put("role", "model".equals(role) ? "assistant" : "user");
                        msg.put("content", text.toString());
                        messages.put(msg);
                    }
                }

                claude.put("messages", messages);

                // 映射参数
                JSONObject config = gemini.optJSONObject("generationConfig");
                if (config != null) {
                    if (config.has("temperature")) {
                        claude.put("temperature", config.getDouble("temperature"));
                    }
                    if (config.has("maxOutputTokens")) {
                        claude.put("max_tokens", config.getInt("maxOutputTokens"));
                    }
                    if (config.has("topP")) {
                        claude.put("top_p", config.getDouble("topP"));
                    }
                }

                Log.d(TAG, "Gemini -> Claude translation completed");
                return claude.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Gemini -> Claude translation failed", e);
                throw new RuntimeException("Gemini -> Claude translation failed", e);
            }
        }

        private String mapToClaudeModel(String geminiModel) {
            if (geminiModel.contains("gemini-2.0-flash")) return "claude-3-5-sonnet-20241022";
            if (geminiModel.contains("gemini-1.5-pro")) return "claude-3-opus-20240229";
            if (geminiModel.contains("gemini-1.5-flash")) return "claude-3-haiku-20240307";
            return "claude-3-5-sonnet-20241022";
        }
    }

    /**
     * Codex -> OpenAI Chat 格式转换器
     */
    private static class CodexToOpenAITranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject codex = new JSONObject(jsonBody);
                JSONObject openAI = new JSONObject();

                openAI.put("model", codex.optString("model", "gpt-4"));

                // 将 prompt 文本包装为 messages
                JSONArray messages = new JSONArray();
                JSONObject userMsg = new JSONObject();
                userMsg.put("role", "user");
                userMsg.put("content", codex.optString("prompt", ""));
                messages.put(userMsg);
                openAI.put("messages", messages);

                // 复制参数
                if (codex.has("max_tokens")) {
                    openAI.put("max_tokens", codex.getInt("max_tokens"));
                }
                if (codex.has("temperature")) {
                    openAI.put("temperature", codex.getDouble("temperature"));
                }
                if (codex.has("top_p")) {
                    openAI.put("top_p", codex.getDouble("top_p"));
                }
                if (codex.has("stream")) {
                    openAI.put("stream", codex.getBoolean("stream"));
                }

                Log.d(TAG, "Codex -> OpenAI translation completed");
                return openAI.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Codex -> OpenAI translation failed", e);
                throw new RuntimeException("Codex -> OpenAI translation failed", e);
            }
        }
    }

    /**
     * OpenAI Responses -> OpenAI Chat 格式转换器（降级 Fallback）
     */
    private static class OpenAIToChatFallbackTranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject responses = new JSONObject(jsonBody);
                JSONObject chat = new JSONObject();

                chat.put("model", responses.optString("model", "gpt-4o"));

                // 将 input 字段转换为 messages
                JSONArray messages = new JSONArray();
                Object input = responses.opt("input");

                if (input instanceof String) {
                    JSONObject msg = new JSONObject();
                    msg.put("role", "user");
                    msg.put("content", input.toString());
                    messages.put(msg);
                } else if (input instanceof JSONArray) {
                    JSONArray inputArray = (JSONArray) input;
                    for (int i = 0; i < inputArray.length(); i++) {
                        JSONObject item = inputArray.getJSONObject(i);
                        String role = item.optString("role", "user");
                        Object content = item.opt("content");

                        JSONObject msg = new JSONObject();
                        msg.put("role", role);
                        msg.put("content", content != null ? content : "");
                        messages.put(msg);
                    }
                }

                chat.put("messages", messages);

                // 复制参数
                if (responses.has("max_tokens")) {
                    chat.put("max_tokens", responses.getInt("max_tokens"));
                }
                if (responses.has("temperature")) {
                    chat.put("temperature", responses.getDouble("temperature"));
                }
                if (responses.has("stream")) {
                    chat.put("stream", responses.getBoolean("stream"));
                }

                Log.d(TAG, "OpenAI Responses -> Chat translation completed");
                return chat.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "OpenAI Responses -> Chat translation failed", e);
                throw new RuntimeException("OpenAI Responses -> Chat translation failed", e);
            }
        }
    }

    /**
     * Antigravity -> OpenAI Chat 格式转换器
     */
    private static class AntigravityToOpenAITranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject antigravity = new JSONObject(jsonBody);
                JSONObject openAI = new JSONObject();

                openAI.put("model", antigravity.optString("model", "gpt-4o"));

                // 转换 antigravity 消息格式
                JSONArray messages = new JSONArray();
                JSONArray agMessages = antigravity.optJSONArray("ag_messages");

                if (agMessages != null) {
                    for (int i = 0; i < agMessages.length(); i++) {
                        JSONObject agMsg = agMessages.getJSONObject(i);
                        JSONObject msg = new JSONObject();
                        msg.put("role", agMsg.optString("role", "user"));
                        msg.put("content", agMsg.optString("text", ""));
                        messages.put(msg);
                    }
                }

                openAI.put("messages", messages);

                // 复制参数
                if (antigravity.has("max_tokens")) {
                    openAI.put("max_tokens", antigravity.getInt("max_tokens"));
                }
                if (antigravity.has("temperature")) {
                    openAI.put("temperature", antigravity.getDouble("temperature"));
                }
                if (antigravity.has("stream")) {
                    openAI.put("stream", antigravity.getBoolean("stream"));
                }

                Log.d(TAG, "Antigravity -> OpenAI translation completed");
                return openAI.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Antigravity -> OpenAI translation failed", e);
                throw new RuntimeException("Antigravity -> OpenAI translation failed", e);
            }
        }
    }

    /**
     * Interactions -> OpenAI Chat 格式转换器
     */
    private static class InteractionsToOpenAITranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject interaction = new JSONObject(jsonBody);
                JSONObject openAI = new JSONObject();

                openAI.put("model", interaction.optString("model", "gpt-4o"));

                // 转换交互格式为 messages
                JSONArray messages = new JSONArray();
                JSONArray turns = interaction.optJSONArray("turns");

                if (turns != null) {
                    for (int i = 0; i < turns.length(); i++) {
                        JSONObject turn = turns.getJSONObject(i);
                        JSONObject msg = new JSONObject();
                        msg.put("role", turn.optString("participant", "user"));
                        msg.put("content", turn.optString("text", ""));
                        messages.put(msg);
                    }
                }

                openAI.put("messages", messages);

                // 复制参数
                if (interaction.has("max_tokens")) {
                    openAI.put("max_tokens", interaction.getInt("max_tokens"));
                }
                if (interaction.has("temperature")) {
                    openAI.put("temperature", interaction.getDouble("temperature"));
                }
                if (interaction.has("stream")) {
                    openAI.put("stream", interaction.getBoolean("stream"));
                }

                Log.d(TAG, "Interactions -> OpenAI translation completed");
                return openAI.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Interactions -> OpenAI translation failed", e);
                throw new RuntimeException("Interactions -> OpenAI translation failed", e);
            }
        }
    }

    /**
     * Gemini CLI -> OpenAI Chat 格式转换器
     * CLI 工具使用的 Gemini 格式转换
     */
    private static class GeminiCliToOpenAITranslator implements FormatTranslator {
        @Override
        public String translate(String jsonBody, Map<String, String> headers) {
            try {
                JSONObject geminiCli = new JSONObject(jsonBody);
                JSONObject openAI = new JSONObject();

                openAI.put("model", "gpt-4o");

                // 转换 contents 为 messages
                JSONArray messages = new JSONArray();
                JSONArray contents = geminiCli.optJSONArray("contents");

                if (contents != null) {
                    for (int i = 0; i < contents.length(); i++) {
                        JSONObject c = contents.getJSONObject(i);
                        String role = c.optString("role", "user");
                        JSONArray parts = c.optJSONArray("parts");

                        StringBuilder text = new StringBuilder();
                        if (parts != null) {
                            for (int j = 0; j < parts.length(); j++) {
                                JSONObject part = parts.getJSONObject(j);
                                if (part.has("text")) {
                                    if (text.length() > 0) text.append("\n");
                                    text.append(part.getString("text"));
                                }
                            }
                        }

                        JSONObject msg = new JSONObject();
                        msg.put("role", "model".equals(role) ? "assistant" : "user");
                        msg.put("content", text.toString());
                        messages.put(msg);
                    }
                }

                openAI.put("messages", messages);

                // 复制 CLI 特有参数
                if (geminiCli.has("generationConfig")) {
                    JSONObject config = geminiCli.getJSONObject("generationConfig");
                    if (config.has("temperature")) {
                        openAI.put("temperature", config.getDouble("temperature"));
                    }
                    if (config.has("maxOutputTokens")) {
                        openAI.put("max_tokens", config.getInt("maxOutputTokens"));
                    }
                }

                Log.d(TAG, "Gemini CLI -> OpenAI translation completed");
                return openAI.toString(2);

            } catch (Exception e) {
                Log.e(TAG, "Gemini CLI -> OpenAI translation failed", e);
                throw new RuntimeException("Gemini CLI -> OpenAI translation failed", e);
            }
        }
    }
}