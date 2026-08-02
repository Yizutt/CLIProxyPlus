package com.cliproxy.plus.auth.cloak;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CloakEngine - Claude Code CLI 伪装/隐身引擎
 * <p>
 * 启用后修改出站 Claude 请求，使其看起来像是从官方 Claude Code CLI 发出的。
 * 支持三种模式：auto（自动）、always（始终启用）、never（禁用）。
 * 可配置严格模式（剥离用户系统消息）、敏感词零宽字符混淆、用户 ID 缓存。
 * <p>
 * 对应原版 Claude Code CLI 的 identity/disguise 层。
 */
public class CloakEngine {

    private static final String TAG = "CloakEngine";

    // ============================================================
    // Claude Code CLI 请求头常量
    // ============================================================

    /** 官方 Claude Code CLI User-Agent */
    public static final String HEADER_USER_AGENT = "User-Agent";
    public static final String USER_AGENT_CLAUDE_CODE = "ClaudeCode/1.0 (com.anthropic.claude-code; build:1.0.0) okhttp/4.12.0";

    /** 官方 Claude Code CLI 包名 */
    public static final String HEADER_PACKAGE_VERSION = "X-Claude-Package-Version";
    public static final String CLAUDE_PACKAGE_VERSION = "claude-code@1.0.0";

    /** Anthropic API 版本头 */
    public static final String HEADER_ANTHROPIC_VERSION = "anthropic-version";
    public static final String ANTHROPIC_API_VERSION = "2023-06-01";

    /** Anthropic Beta 功能头 */
    public static final String HEADER_ANTHROPIC_BETA = "anthropic-beta";
    public static final String ANTHROPIC_BETA_VALUE = "max-tokens-3-5-sonnet-2024-07-15,message-iterations-2024-11-12";

    /** 客户端标识 */
    public static final String HEADER_X_CLIENT = "X-Client";
    public static final String X_CLIENT_VALUE = "claude-code/1.0";

    /** 请求来源标识 */
    public static final String HEADER_X_REQUEST_SOURCE = "X-Request-Source";
    public static final String X_REQUEST_SOURCE_VALUE = "claude-code-cli";

    /** 会话标识头 */
    public static final String HEADER_X_SESSION_ID = "X-Session-Id";

    // ============================================================
    // 零宽字符常量（用于敏感词混淆）
    // ============================================================

    /** 零宽空格 (ZWSP) */
    public static final char ZERO_WIDTH_SPACE = '\u200B';

    /** 零宽连字 (ZWJ) */
    public static final char ZERO_WIDTH_JOINER = '\u200D';

    /** 零宽非连字 (ZWNJ) */
    public static final char ZERO_WIDTH_NON_JOINER = '\u200C';

    /** 零宽无断空格 (BOM / ZWNBSP) */
    public static final char ZERO_WIDTH_NO_BREAK_SPACE = '\uFEFF';

    /** 所有零宽字符集合 */
    private static final Set<Character> ZERO_WIDTH_CHARS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            ZERO_WIDTH_SPACE,
            ZERO_WIDTH_JOINER,
            ZERO_WIDTH_NON_JOINER,
            ZERO_WIDTH_NO_BREAK_SPACE
    )));

    /** 零宽字符正则匹配模式 */
    private static final Pattern ZERO_WIDTH_PATTERN = Pattern.compile("[\u200B\u200C\u200D\uFEFF]");

    // ============================================================
    // 系统消息相关常量
    // ============================================================

    /** 常见的系统消息角色前缀（用于 strict 模式剥离） */
    private static final Set<String> SYSTEM_ROLE_INDICATORS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "system", "developer", "user"
    )));

    /** 可能包含用户系统消息的内容关键词 */
    private static final List<Pattern> USER_SYSTEM_PATTERNS = Collections.unmodifiableList(Arrays.asList(
            Pattern.compile("(?i)(you are|you're|you are an?|act as|扮演|你是|你是一个)"),
            Pattern.compile("(?i)(system instruction|system prompt|system message|系统提示|系统指令)"),
            Pattern.compile("(?i)(do not|never|always|must|must not|禁止|必须|不要)")
    ));

    // ============================================================
    // 实例状态
    // ============================================================

    /** 用户 ID 缓存（用户 ID -> 缓存的会话/请求标识） */
    private final ConcurrentHashMap<String, String> userIdCache = new ConcurrentHashMap<>();

    /** 单例实例 */
    private static volatile CloakEngine instance;

    // ============================================================
    // 构造与单例
    // ============================================================

    private CloakEngine() {
        Log.d(TAG, "CloakEngine initialized");
    }

    /**
     * 获取 CloakEngine 单例实例
     *
     * @return 全局唯一的 CloakEngine 实例
     */
    public static CloakEngine getInstance() {
        if (instance == null) {
            synchronized (CloakEngine.class) {
                if (instance == null) {
                    instance = new CloakEngine();
                }
            }
        }
        return instance;
    }

    // ============================================================
    // CloakConfig - 隐身配置
    // ============================================================

    /**
     * CloakConfig - 隐身引擎配置
     * <p>
     * 控制隐身引擎的行为模式、严格模式开关、敏感词列表和用户 ID 缓存策略。
     */
    public static class CloakConfig {

        /** 隐身模式 */
        private CloakMode mode = CloakMode.AUTO;

        /** 是否启用严格模式（剥离用户系统消息） */
        private boolean strictMode = false;

        /** 需要混淆的敏感词列表 */
        private final List<String> sensitiveWords = new ArrayList<>();

        /** 是否缓存用户 ID */
        private boolean cacheUserId = true;

        /** 会话 ID（用于 X-Session-Id 头） */
        private String sessionId;

        /** 自定义额外请求头 */
        private final Map<String, String> extraHeaders = new HashMap<>();

        public CloakConfig() {
            // 默认构造
        }

        /**
         * 使用指定模式创建配置
         *
         * @param mode 隐身模式
         */
        public CloakConfig(CloakMode mode) {
            this.mode = mode;
        }

        // ---- Getter / Setter ----

        public CloakMode getMode() {
            return mode;
        }

        public void setMode(CloakMode mode) {
            this.mode = mode;
        }

        public boolean isStrictMode() {
            return strictMode;
        }

        public void setStrictMode(boolean strictMode) {
            this.strictMode = strictMode;
        }

        public List<String> getSensitiveWords() {
            return sensitiveWords;
        }

        /**
         * 添加敏感词
         *
         * @param word 需要零宽字符混淆的敏感词
         */
        public void addSensitiveWord(String word) {
            if (word != null && !word.isEmpty() && !sensitiveWords.contains(word)) {
                this.sensitiveWords.add(word);
            }
        }

        /**
         * 批量添加敏感词
         *
         * @param words 敏感词列表
         */
        public void addSensitiveWords(List<String> words) {
            if (words != null) {
                for (String word : words) {
                    addSensitiveWord(word);
                }
            }
        }

        /**
         * 移除敏感词
         *
         * @param word 要移除的词
         */
        public void removeSensitiveWord(String word) {
            this.sensitiveWords.remove(word);
        }

        public boolean isCacheUserId() {
            return cacheUserId;
        }

        public void setCacheUserId(boolean cacheUserId) {
            this.cacheUserId = cacheUserId;
        }

        public String getSessionId() {
            return sessionId;
        }

        public void setSessionId(String sessionId) {
            this.sessionId = sessionId;
        }

        public Map<String, String> getExtraHeaders() {
            return extraHeaders;
        }

        /**
         * 添加自定义请求头
         *
         * @param name  头名称
         * @param value 头值
         */
        public void addExtraHeader(String name, String value) {
            if (name != null && !name.isEmpty() && value != null) {
                this.extraHeaders.put(name, value);
            }
        }

        /**
         * 批量添加自定义请求头
         *
         * @param headers 请求头映射
         */
        public void addExtraHeaders(Map<String, String> headers) {
            if (headers != null) {
                this.extraHeaders.putAll(headers);
            }
        }

        /**
         * 深拷贝当前配置
         *
         * @return 配置副本
         */
        public CloakConfig copy() {
            CloakConfig copy = new CloakConfig(this.mode);
            copy.strictMode = this.strictMode;
            copy.sensitiveWords.addAll(this.sensitiveWords);
            copy.cacheUserId = this.cacheUserId;
            copy.sessionId = this.sessionId;
            copy.extraHeaders.putAll(this.extraHeaders);
            return copy;
        }

        @Override
        public String toString() {
            return "CloakConfig{" +
                    "mode=" + mode +
                    ", strictMode=" + strictMode +
                    ", sensitiveWords=" + sensitiveWords +
                    ", cacheUserId=" + cacheUserId +
                    ", sessionId='" + sessionId + '\'' +
                    ", extraHeaders=" + extraHeaders +
                    '}';
        }
    }

    // ============================================================
    // CloakMode - 隐身模式枚举
    // ============================================================

    /**
     * CloakMode - 隐身模式
     * <p>
     * <ul>
     *   <li>AUTO  - 自动模式：检测请求是否来自 Claude Code CLI，若不是则应用伪装</li>
     *   <li>ALWAYS - 始终启用：对所有出站请求强制应用伪装</li>
     *   <li>NEVER  - 禁用：不应用任何伪装</li>
     * </ul>
     */
    public enum CloakMode {
        AUTO,
        ALWAYS,
        NEVER
    }

    // ============================================================
    // applyCloak - 对出站请求应用伪装
    // ============================================================

    /**
     * 对出站 Claude 请求应用伪装
     * <p>
     * 根据配置执行以下操作：
     * <ul>
     *   <li>根据模式决定是否应用伪装</li>
     *   <li>在严格模式下剥离用户系统消息</li>
     *   <li>对敏感词应用零宽字符混淆</li>
     *   <li>缓存用户 ID</li>
     * </ul>
     *
     * @param requestBody 原始请求体（JSON 字符串）
     * @param config      隐身配置
     * @return 伪装后的请求体，如果不需要伪装则返回原始字符串
     * @throws JSONException 如果请求体不是有效的 JSON
     * @throws IllegalArgumentException 如果 requestBody 为 null
     */
    public String applyCloak(String requestBody, CloakConfig config) {
        if (requestBody == null) {
            throw new IllegalArgumentException("requestBody must not be null");
        }
        if (config == null) {
            Log.w(TAG, "applyCloak called with null config, using defaults");
            config = new CloakConfig();
        }

        // 检查模式
        if (config.getMode() == CloakMode.NEVER) {
            Log.d(TAG, "Cloak mode is NEVER, skipping applyCloak");
            return requestBody;
        }

        if (config.getMode() == CloakMode.AUTO && isAlreadyCloaked(requestBody)) {
            Log.d(TAG, "Request already appears cloaked, skipping in AUTO mode");
            return requestBody;
        }

        try {
            String result = requestBody;

            // 步骤 1: 严格模式 - 剥离用户系统消息
            if (config.isStrictMode()) {
                result = stripUserSystemMessages(result);
                Log.d(TAG, "Strict mode applied: stripped user system messages");
            }

            // 步骤 2: 敏感词零宽字符混淆
            if (config.getSensitiveWords() != null && !config.getSensitiveWords().isEmpty()) {
                result = obfuscateSensitiveWords(result, config.getSensitiveWords());
                Log.d(TAG, "Sensitive word obfuscation applied: " + config.getSensitiveWords().size() + " words");
            }

            // 步骤 3: 缓存用户 ID（如果配置启用）
            if (config.isCacheUserId()) {
                cacheUserIdFromRequest(result, config);
            }

            Log.d(TAG, "applyCloak completed successfully");
            return result;

        } catch (JSONException e) {
            Log.e(TAG, "Failed to parse request body JSON during cloaking", e);
            // 如果 JSON 解析失败，返回原始请求体而不是让请求失败
            return requestBody;
        } catch (Exception e) {
            Log.e(TAG, "Unexpected error during applyCloak", e);
            return requestBody;
        }
    }

    /**
     * 对出站请求应用伪装，并填充请求头
     * <p>
     * 同时修改请求体和请求头，使其看起来来自官方 Claude Code CLI。
     *
     * @param requestBody 原始请求体
     * @param config      隐身配置
     * @param headers     请求头映射（会被修改填充）
     * @return 伪装后的请求体
     */
    public String applyCloakWithHeaders(String requestBody, CloakConfig config,
                                         Map<String, String> headers) {
        if (headers == null) {
            return applyCloak(requestBody, config);
        }

        String body = applyCloak(requestBody, config);

        // 填充 Claude Code CLI 请求头
        if (config == null || config.getMode() != CloakMode.NEVER) {
            boolean shouldCloak = true;
            if (config != null && config.getMode() == CloakMode.AUTO) {
                shouldCloak = !isAlreadyCloaked(requestBody);
            }

            if (shouldCloak) {
                applyCloakHeaders(headers, config);
            }
        }

        return body;
    }

    /**
     * 填充 Claude Code CLI 请求头到指定映射中
     *
     * @param headers 请求头映射（会被修改）
     * @param config  隐身配置
     */
    public void applyCloakHeaders(Map<String, String> headers, CloakConfig config) {
        // 仅在未设置时覆盖，以保留用户显式指定的值
        putIfAbsent(headers, HEADER_USER_AGENT, USER_AGENT_CLAUDE_CODE);
        putIfAbsent(headers, HEADER_PACKAGE_VERSION, CLAUDE_PACKAGE_VERSION);
        putIfAbsent(headers, HEADER_ANTHROPIC_VERSION, ANTHROPIC_API_VERSION);
        putIfAbsent(headers, HEADER_ANTHROPIC_BETA, ANTHROPIC_BETA_VALUE);
        putIfAbsent(headers, HEADER_X_CLIENT, X_CLIENT_VALUE);
        putIfAbsent(headers, HEADER_X_REQUEST_SOURCE, X_REQUEST_SOURCE_VALUE);

        // 会话 ID
        if (config != null && config.getSessionId() != null && !config.getSessionId().isEmpty()) {
            putIfAbsent(headers, HEADER_X_SESSION_ID, config.getSessionId());
        }

        // 自定义额外头
        if (config != null && config.getExtraHeaders() != null) {
            for (Map.Entry<String, String> entry : config.getExtraHeaders().entrySet()) {
                putIfAbsent(headers, entry.getKey(), entry.getValue());
            }
        }

        Log.d(TAG, "Cloak headers applied to request");
    }

    // ============================================================
    // removeCloak - 移除入站响应的伪装
    // ============================================================

    /**
     * 移除入站响应中的伪装痕迹
     * <p>
     * 清理响应中可能包含的零宽字符混淆，使内容恢复正常可读状态。
     *
     * @param responseBody 原始响应体（JSON 字符串）
     * @return 清理后的响应体，如果清理失败则返回原始字符串
     * @throws IllegalArgumentException 如果 responseBody 为 null
     */
    public String removeCloak(String responseBody) {
        if (responseBody == null) {
            throw new IllegalArgumentException("responseBody must not be null");
        }

        try {
            String result = responseBody;

            // 移除所有零宽字符
            if (containsZeroWidthChars(result)) {
                result = removeZeroWidthChars(result);
                Log.d(TAG, "Zero-width characters removed from response");
            }

            // 如果响应体是 JSON，递归清理所有字符串字段
            if (isJsonObject(result) || isJsonArray(result)) {
                try {
                    result = cleanJsonResponse(result);
                } catch (JSONException e) {
                    Log.w(TAG, "Failed to parse response JSON for cleaning, using raw text", e);
                }
            }

            Log.d(TAG, "removeCloak completed successfully");
            return result;

        } catch (Exception e) {
            Log.e(TAG, "Unexpected error during removeCloak", e);
            return responseBody;
        }
    }

    // ============================================================
    // 内部工具方法
    // ============================================================

    /**
     * 判断请求是否看起来已经伪装过
     * <p>
     * 检查请求体中是否包含 Claude Code CLI 特有的标记或格式。
     *
     * @param requestBody 请求体
     * @return 如果看起来已伪装返回 true
     */
    private boolean isAlreadyCloaked(String requestBody) {
        if (requestBody == null || requestBody.isEmpty()) {
            return false;
        }
        // 检查是否包含零宽字符（已混淆的敏感词）
        return containsZeroWidthChars(requestBody);
    }

    /**
     * 严格模式：剥离请求体中的用户系统消息
     * <p>
     * 遍历 messages 数组，移除 role 为 "system" 或 "developer"
     * 且内容符合用户自定义系统消息特征的消息。
     *
     * @param body 请求体 JSON 字符串
     * @return 剥离后的请求体 JSON 字符串
     * @throws JSONException 如果 JSON 解析失败
     */
    private String stripUserSystemMessages(String body) {
        JSONObject json = new JSONObject(body);

        if (!json.has("messages")) {
            return body;
        }

        JSONArray messages = json.getJSONArray("messages");
        if (messages.length() == 0) {
            return body;
        }

        JSONArray cleaned = new JSONArray();
        boolean stripped = false;

        for (int i = 0; i < messages.length(); i++) {
            JSONObject message = messages.getJSONObject(i);
            String role = message.optString("role", "");

            // 判断是否为需要剥离的系统消息
            if (isUserSystemMessage(role, message)) {
                stripped = true;
                Log.d(TAG, "Stripped system message at index " + i);
                continue;
            }

            // 递归处理嵌套内容（如 tool_use 等）
            if (message.has("content")) {
                Object content = message.get("content");
                if (content instanceof JSONArray) {
                    message.put("content", cleanContentArray((JSONArray) content));
                }
            }

            cleaned.put(message);
        }

        if (!stripped) {
            return body;
        }

        json.put("messages", cleaned);
        // 如果剥离后消息数组为空，添加一个占位消息
        if (cleaned.length() == 0) {
            JSONObject fallback = new JSONObject();
            fallback.put("role", "user");
            fallback.put("content", "Hello");
            JSONArray fallbackMessages = new JSONArray();
            fallbackMessages.put(fallback);
            json.put("messages", fallbackMessages);
        }

        return json.toString();
    }

    /**
     * 判断消息是否为用户系统消息（需要剥离）
     *
     * @param role    消息角色
     * @param message 消息对象
     * @return 如果是用户系统消息返回 true
     */
    private boolean isUserSystemMessage(String role, JSONObject message) {
        // 只处理 system 或 developer 角色的消息
        if (!SYSTEM_ROLE_INDICATORS.contains(role)) {
            return false;
        }

        String content = message.optString("content", "");
        if (content.isEmpty()) {
            return false;
        }

        // 检查内容是否匹配用户系统消息特征
        for (Pattern pattern : USER_SYSTEM_PATTERNS) {
            if (pattern.matcher(content).find()) {
                return true;
            }
        }

        return false;
    }

    /**
     * 清理内容数组中的嵌套消息
     *
     * @param contentArray 内容 JSON 数组
     * @return 清理后的 JSON 数组
     * @throws JSONException 如果 JSON 处理失败
     */
    private JSONArray cleanContentArray(JSONArray contentArray) throws JSONException {
        JSONArray cleaned = new JSONArray();
        for (int i = 0; i < contentArray.length(); i++) {
            JSONObject item = contentArray.getJSONObject(i);
            if (item.has("type") && "tool_use".equals(item.optString("type"))) {
                // 保留 tool_use 块
                cleaned.put(item);
            } else {
                cleaned.put(item);
            }
        }
        return cleaned;
    }

    /**
     * 对敏感词应用零宽字符混淆
     * <p>
     * 在每个敏感词的每个字符之间插入零宽字符，使常规文本搜索无法匹配，
     * 但人类阅读时不可见。
     *
     * @param text          原始文本
     * @param sensitiveWords 敏感词列表
     * @return 混淆后的文本
     */
    private String obfuscateSensitiveWords(String text, List<String> sensitiveWords) {
        String result = text;
        for (String word : sensitiveWords) {
            if (word == null || word.isEmpty()) {
                continue;
            }
            // 使用大小写不敏感匹配
            String obfuscated = obfuscateWord(word);
            result = result.replaceAll("(?i)" + Pattern.quote(word), Matcher.quoteReplacement(obfuscated));
        }
        return result;
    }

    /**
     * 对单个词应用零宽字符混淆
     * <p>
     * 在每个字符之间交替插入不同的零宽字符。
     *
     * @param word 原始词
     * @return 混淆后的词
     */
    private String obfuscateWord(String word) {
        StringBuilder sb = new StringBuilder();
        char[] zwChars = {ZERO_WIDTH_SPACE, ZERO_WIDTH_JOINER,
                          ZERO_WIDTH_NON_JOINER, ZERO_WIDTH_NO_BREAK_SPACE};

        for (int i = 0; i < word.length(); i++) {
            sb.append(word.charAt(i));
            if (i < word.length() - 1) {
                // 在字符之间插入零宽字符，循环使用不同类型的零宽字符
                sb.append(zwChars[i % zwChars.length]);
            }
        }
        return sb.toString();
    }

    /**
     * 从请求中提取并缓存用户 ID
     *
     * @param body   请求体 JSON
     * @param config 隐身配置
     */
    private void cacheUserIdFromRequest(String body, CloakConfig config) {
        try {
            JSONObject json = new JSONObject(body);
            // 尝试从不同字段提取用户标识
            String userId = null;

            if (json.has("user_id")) {
                userId = json.optString("user_id", null);
            } else if (json.has("client_id")) {
                userId = json.optString("client_id", null);
            } else if (json.has("session_id")) {
                userId = json.optString("session_id", null);
            } else if (json.has("messages")) {
                // 从消息中提取匿名用户标识（使用消息数量 + 第一条消息的哈希）
                JSONArray messages = json.optJSONArray("messages");
                if (messages != null && messages.length() > 0) {
                    JSONObject firstMsg = messages.optJSONObject(0);
                    if (firstMsg != null) {
                        String content = firstMsg.optString("content", "");
                        if (!content.isEmpty()) {
                            userId = "user_" + Integer.toHexString(content.hashCode());
                        }
                    }
                }
            }

            if (userId != null) {
                String sessionId = config.getSessionId();
                if (sessionId != null) {
                    userIdCache.put(userId, sessionId);
                } else {
                    userIdCache.put(userId, "session_" + Integer.toHexString(userId.hashCode()));
                }
                Log.d(TAG, "Cached user ID: " + userId);
            }
        } catch (JSONException e) {
            Log.w(TAG, "Failed to extract user ID from request", e);
        }
    }

    /**
     * 检查字符串是否包含零宽字符
     *
     * @param text 待检查字符串
     * @return 如果包含零宽字符返回 true
     */
    private boolean containsZeroWidthChars(String text) {
        return ZERO_WIDTH_PATTERN.matcher(text).find();
    }

    /**
     * 移除字符串中的所有零宽字符
     *
     * @param text 原始字符串
     * @return 清理后的字符串
     */
    private String removeZeroWidthChars(String text) {
        return ZERO_WIDTH_PATTERN.matcher(text).replaceAll("");
    }

    /**
     * 递归清理 JSON 响应中的所有字符串字段，移除零宽字符
     *
     * @param jsonString JSON 字符串
     * @return 清理后的 JSON 字符串
     * @throws JSONException 如果 JSON 解析失败
     */
    private String cleanJsonResponse(String jsonString) throws JSONException {
        if (isJsonObject(jsonString)) {
            JSONObject obj = new JSONObject(jsonString);
            return cleanJsonObject(obj).toString();
        } else if (isJsonArray(jsonString)) {
            JSONArray arr = new JSONArray(jsonString);
            return cleanJsonArray(arr).toString();
        }
        return jsonString;
    }

    /**
     * 递归清理 JSONObject 中的所有字符串值
     *
     * @param obj JSON 对象
     * @return 清理后的 JSON 对象
     * @throws JSONException 如果 JSON 处理失败
     */
    private JSONObject cleanJsonObject(JSONObject obj) throws JSONException {
        JSONObject cleaned = new JSONObject();
        for (String key : JSONObject.getNames(obj)) {
            Object value = obj.get(key);
            if (value instanceof String) {
                String str = (String) value;
                cleaned.put(key, containsZeroWidthChars(str) ? removeZeroWidthChars(str) : str);
            } else if (value instanceof JSONObject) {
                cleaned.put(key, cleanJsonObject((JSONObject) value));
            } else if (value instanceof JSONArray) {
                cleaned.put(key, cleanJsonArray((JSONArray) value));
            } else {
                cleaned.put(key, value);
            }
        }
        return cleaned;
    }

    /**
     * 递归清理 JSONArray 中的所有字符串值
     *
     * @param arr JSON 数组
     * @return 清理后的 JSON 数组
     * @throws JSONException 如果 JSON 处理失败
     */
    private JSONArray cleanJsonArray(JSONArray arr) throws JSONException {
        JSONArray cleaned = new JSONArray();
        for (int i = 0; i < arr.length(); i++) {
            Object value = arr.get(i);
            if (value instanceof String) {
                String str = (String) value;
                cleaned.put(containsZeroWidthChars(str) ? removeZeroWidthChars(str) : str);
            } else if (value instanceof JSONObject) {
                cleaned.put(cleanJsonObject((JSONObject) value));
            } else if (value instanceof JSONArray) {
                cleaned.put(cleanJsonArray((JSONArray) value));
            } else {
                cleaned.put(value);
            }
        }
        return cleaned;
    }

    /**
     * 判断字符串是否为 JSON 对象
     *
     * @param str 待判断字符串
     * @return 如果是 JSON 对象返回 true
     */
    private boolean isJsonObject(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        String trimmed = str.trim();
        return trimmed.startsWith("{") && trimmed.endsWith("}");
    }

    /**
     * 判断字符串是否为 JSON 数组
     *
     * @param str 待判断字符串
     * @return 如果是 JSON 数组返回 true
     */
    private boolean isJsonArray(String str) {
        if (str == null || str.isEmpty()) {
            return false;
        }
        String trimmed = str.trim();
        return trimmed.startsWith("[") && trimmed.endsWith("]");
    }

    /**
     * 仅当键不存在时设置值（不覆盖已有值）
     *
     * @param map   目标映射
     * @param key   键
     * @param value 值
     */
    private void putIfAbsent(Map<String, String> map, String key, String value) {
        if (!map.containsKey(key)) {
            map.put(key, value);
        }
    }

    // ============================================================
    // 公共查询方法
    // ============================================================

    /**
     * 获取缓存的用户 ID 映射
     *
     * @return 用户 ID -> 会话标识的不可变映射
     */
    public Map<String, String> getCachedUserIds() {
        return Collections.unmodifiableMap(new HashMap<>(userIdCache));
    }

    /**
     * 清除用户 ID 缓存
     */
    public void clearUserCache() {
        userIdCache.clear();
        Log.d(TAG, "User ID cache cleared");
    }

    /**
     * 获取缓存中的用户数量
     *
     * @return 缓存的用户数
     */
    public int getCachedUserCount() {
        return userIdCache.size();
    }

    /**
     * 检查指定文本中是否包含零宽字符
     *
     * @param text 待检查文本
     * @return 如果包含零宽字符返回 true
     */
    public static boolean hasZeroWidthChars(String text) {
        return text != null && ZERO_WIDTH_PATTERN.matcher(text).find();
    }

    /**
     * 从文本中移除所有零宽字符
     *
     * @param text 原始文本
     * @return 清理后的文本，如果输入为 null 则返回 null
     */
    public static String stripZeroWidthChars(String text) {
        if (text == null) {
            return null;
        }
        return ZERO_WIDTH_PATTERN.matcher(text).replaceAll("");
    }

    @Override
    public String toString() {
        return "CloakEngine{" +
                "mode=CloakMode, " +
                "cachedUsers=" + userIdCache.size() +
                "}";
    }
}