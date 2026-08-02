package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * XAIOAuth - xAI Grok OAuth / API Key 认证实现
 * <p>
 * xAI 提供 Grok 系列模型的 API 访问，主要通过 API Key 进行认证。
 * 支持标准的 Bearer Token 认证方式，并提供 API Key 有效性验证、
 * 余额/配额查询、可用模型列表获取等功能。
 * <p>
 * 对应原版 CLIProxyAPIPlus/internal/auth/xai/ 中的 Go 实现。
 * <p>
 * API 端点文档: https://docs.x.ai/api
 */
public class XAIOAuth extends OAuthProvider {

    private static final String TAG = "XAIOAuth";

    // ---- xAI API 常量 ----

    /** xAI API 基础地址 */
    private static final String XAI_API_BASE = "https://api.x.ai";

    /** API Key 验证端点 */
    private static final String XAI_API_KEY_VALIDATE_URL = XAI_API_BASE + "/v1/api-key";

    /** 模型列表端点 */
    private static final String XAI_MODELS_URL = XAI_API_BASE + "/v1/models";

    /** 聊天补全端点 */
    private static final String XAI_CHAT_URL = XAI_API_BASE + "/v1/chat/completions";

    /** 请求超时（毫秒） */
    private static final int REQUEST_TIMEOUT_MS = 15000;

    /** 最大重试次数 */
    private static final int MAX_RETRIES = 3;

    /** 重试基础等待时间（毫秒） */
    private static final long RETRY_BASE_DELAY_MS = 1000L;

    /** 默认 API Key 过期时间（毫秒），默认 7 天 */
    private static final long DEFAULT_API_KEY_TTL_MS = 7 * 24 * 60 * 60 * 1000L;

    // ---- 实例状态 ----

    private final String apiBaseUrl;
    private volatile String cachedApiKey;
    private volatile long lastValidationTime;
    private volatile long validationCooldownMs = 60_000L; // 1 分钟冷却

    // ---------------------------------------------------------------
    // 构造
    // ---------------------------------------------------------------

    /**
     * 创建一个 xAI OAuth 提供者实例，使用默认 API 基础地址。
     */
    public XAIOAuth() {
        this(XAI_API_BASE);
    }

    /**
     * 创建一个 xAI OAuth 提供者实例，使用指定的 API 基础地址。
     *
     * @param apiBaseUrl xAI API 基础地址，为空时使用默认值
     */
    public XAIOAuth(String apiBaseUrl) {
        this.apiBaseUrl = (apiBaseUrl != null && !apiBaseUrl.trim().isEmpty())
                ? apiBaseUrl.trim().replaceAll("/+$", "")
                : XAI_API_BASE;
    }

    // ---------------------------------------------------------------
    // OAuthProvider 抽象方法实现
    // ---------------------------------------------------------------

    /**
     * 启动 xAI 认证流程。
     * <p>
     * xAI 使用 API Key 进行认证，此方法验证提供的 API Key 是否有效。
     * 如果已配置 API Key，则验证并返回包含 API Key 的 AuthResult；
     * 否则抛出 OAuthException 提示用户配置 API Key。
     * <p>
     * xAI 不提供标准 OAuth 授权码流程，因此此方法实现为 API Key 直接认证。
     * 用户需要在 xAI 控制台 (https://console.x.ai) 生成 API Key 并配置。
     *
     * @return 包含 API Key 信息的认证结果
     * @throws OAuthException 如果未配置 API Key 或验证失败
     */
    @Override
    public AuthResult startAuth() throws OAuthException {
        log("Starting xAI OAuth flow (API Key validation)");

        String apiKey = cachedApiKey;
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new OAuthException("api_key_required",
                    "xAI API Key is not configured. Please set your API Key from https://console.x.ai");
        }

        // 验证 API Key
        XAIKeyInfo keyInfo = validateApiKeyInternal(apiKey);
        if (keyInfo == null) {
            throw new OAuthException("api_key_invalid",
                    "xAI API Key validation failed. Please check your API Key.");
        }

        TokenData tokenData = new TokenData();
        tokenData.accessToken = apiKey;
        tokenData.expiresIn = (int) (DEFAULT_API_KEY_TTL_MS / 1000L);
        tokenData.expireAt = System.currentTimeMillis() + DEFAULT_API_KEY_TTL_MS;
        tokenData.email = keyInfo.email;
        tokenData.accountId = keyInfo.accountId;

        return new AuthResult(tokenData, apiKey);
    }

    /**
     * 刷新 Access Token。
     * <p>
     * xAI 使用 API Key 而非 OAuth 令牌，不支持令牌刷新。
     * 此方法重新验证缓存的 API Key，如果有效则返回新的 TokenData。
     * 如果 API Key 已失效，需要用户重新配置。
     *
     * @param refreshToken 忽略（xAI 不使用刷新令牌）
     * @return 新的 Token 数据（包含当前 API Key）
     * @throws OAuthException 如果 API Key 无效或未配置
     */
    @Override
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        String apiKey = cachedApiKey;
        if (apiKey == null || apiKey.trim().isEmpty()) {
            throw new OAuthException("api_key_required",
                    "xAI API Key is not configured. Please set your API Key from https://console.x.ai");
        }

        // 重新验证 API Key
        XAIKeyInfo keyInfo = validateApiKeyInternal(apiKey);
        if (keyInfo == null) {
            throw new OAuthException("api_key_invalid",
                    "xAI API Key is invalid or expired. Please update your API Key.");
        }

        TokenData tokenData = new TokenData();
        tokenData.accessToken = apiKey;
        tokenData.expiresIn = (int) (DEFAULT_API_KEY_TTL_MS / 1000L);
        tokenData.expireAt = System.currentTimeMillis() + DEFAULT_API_KEY_TTL_MS;
        tokenData.email = keyInfo.email;
        tokenData.accountId = keyInfo.accountId;

        return tokenData;
    }

    // ---------------------------------------------------------------
    // API Key 管理
    // ---------------------------------------------------------------

    /**
     * 设置 API Key。
     *
     * @param apiKey xAI API Key
     */
    public void setApiKey(String apiKey) {
        this.cachedApiKey = (apiKey != null) ? apiKey.trim() : null;
        this.lastValidationTime = 0;
        log("API Key set" + (this.cachedApiKey != null && !this.cachedApiKey.isEmpty()
                ? " (" + maskApiKey(this.cachedApiKey) + ")" : " (empty)"));
    }

    /**
     * 获取当前配置的 API Key（已掩码）。
     *
     * @return 掩码后的 API Key，如 "sk-...abcd"
     */
    public String getMaskedApiKey() {
        if (cachedApiKey == null || cachedApiKey.isEmpty()) {
            return "";
        }
        return maskApiKey(cachedApiKey);
    }

    /**
     * 获取原始 API Key。
     *
     * @return 原始 API Key 字符串
     */
    public String getRawApiKey() {
        return cachedApiKey;
    }

    /**
     * 检查是否已配置 API Key。
     *
     * @return true 如果已设置非空 API Key
     */
    public boolean hasApiKey() {
        return cachedApiKey != null && !cachedApiKey.trim().isEmpty();
    }

    /**
     * 验证当前 API Key 是否有效。
     * <p>
     * 使用缓存机制避免频繁调用验证端点。验证结果在冷却时间内有效。
     *
     * @return true 如果 API Key 有效
     */
    public boolean validateApiKey() {
        if (!hasApiKey()) {
            return false;
        }

        // 检查冷却时间
        long now = System.currentTimeMillis();
        if (lastValidationTime > 0 && (now - lastValidationTime) < validationCooldownMs) {
            return true; // 缓存有效
        }

        try {
            XAIKeyInfo keyInfo = validateApiKeyInternal(cachedApiKey);
            lastValidationTime = now;
            return keyInfo != null;
        } catch (Exception e) {
            logError("API Key validation failed", e);
            return false;
        }
    }

    /**
     * 清除 API Key 缓存。
     */
    public void clearApiKey() {
        this.cachedApiKey = null;
        this.lastValidationTime = 0;
        log("API Key cleared");
    }

    /**
     * 设置验证冷却时间。
     *
     * @param cooldownMs 冷却时间（毫秒），最小 1000ms
     */
    public void setValidationCooldownMs(long cooldownMs) {
        this.validationCooldownMs = Math.max(cooldownMs, 1000L);
    }

    // ---------------------------------------------------------------
    // API Key 验证
    // ---------------------------------------------------------------

    /**
     * 验证 API Key 并返回 Key 信息。
     * <p>
     * 向 xAI API Key 验证端点发送请求，检查 API Key 的有效性。
     * xAI 的 /v1/api-key 端点返回 API Key 的元数据信息。
     *
     * @param apiKey 待验证的 API Key
     * @return Key 信息，如果无效则返回 null
     */
    private XAIKeyInfo validateApiKeyInternal(String apiKey) {
        if (apiKey == null || apiKey.trim().isEmpty()) {
            return null;
        }

        IOException lastError = null;

        for (int attempt = 0; attempt < MAX_RETRIES; attempt++) {
            if (attempt > 0) {
                try {
                    Thread.sleep(RETRY_BASE_DELAY_MS * attempt);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null;
                }
            }

            try {
                String responseBody = getWithAuth(XAI_API_KEY_VALIDATE_URL, apiKey);
                if (responseBody == null || responseBody.isEmpty()) {
                    log("API Key validation returned empty response (attempt " + (attempt + 1) + ")");
                    continue;
                }
                return parseKeyInfoResponse(responseBody);
            } catch (IOException e) {
                lastError = e;
                String msg = e.getMessage();
                // 401/403 表示 API Key 无效，不重试
                if (msg != null && (msg.contains("HTTP 401") || msg.contains("HTTP 403")
                        || msg.contains("HTTP 400"))) {
                    log("API Key rejected (HTTP 4xx), not retrying");
                    return null;
                }
                logError("API Key validation attempt " + (attempt + 1) + " failed", e);
            }
        }

        if (lastError != null) {
            logError("API Key validation failed after " + MAX_RETRIES + " attempts", lastError);
        }
        return null;
    }

    // ---------------------------------------------------------------
    // 模型查询
    // ---------------------------------------------------------------

    /**
     * 获取可用的 Grok 模型列表。
     * <p>
     * 向 xAI /v1/models 端点发送请求，返回当前账户可用的模型列表。
     *
     * @return 可用模型名称列表，失败时返回空列表
     */
    public List<String> listAvailableModels() {
        List<String> models = new ArrayList<>();
        if (!hasApiKey()) {
            log("No API Key configured, returning default model list");
            models.add("grok-1");
            models.add("grok-2");
            models.add("grok-2-vision");
            return models;
        }

        try {
            String responseBody = getWithAuth(XAI_MODELS_URL, cachedApiKey);
            if (responseBody != null && !responseBody.isEmpty()) {
                models = parseModelsResponse(responseBody);
            }
        } catch (IOException e) {
            logError("Failed to fetch model list", e);
        }

        // 如果查询失败，返回默认模型列表
        if (models.isEmpty()) {
            models.add("grok-1");
            models.add("grok-2");
            models.add("grok-2-vision");
        }

        return models;
    }

    /**
     * 检查指定模型是否可用。
     *
     * @param modelName 模型名称，如 "grok-2"
     * @return true 如果模型可用
     */
    public boolean isModelAvailable(String modelName) {
        if (modelName == null || modelName.trim().isEmpty()) {
            return false;
        }
        return listAvailableModels().contains(modelName.trim());
    }

    // ---------------------------------------------------------------
    // 配额/使用量查询
    // ---------------------------------------------------------------

    /**
     * 查询 API 使用配额信息。
     * <p>
     * 通过发送一个轻量级的请求到聊天端点来检测 API Key 的可用性。
     * xAI 目前不提供专用的配额查询端点，此方法通过验证 API Key
     * 的有效性来推断配额状态。
     *
     * @return 配额信息对象，包含可用性状态
     */
    public QuotaInfo queryQuota() {
        if (!hasApiKey()) {
            return new QuotaInfo(false, 0, "No API Key configured");
        }

        try {
            XAIKeyInfo keyInfo = validateApiKeyInternal(cachedApiKey);
            if (keyInfo == null) {
                return new QuotaInfo(false, 0, "API Key is invalid");
            }

            // 尝试轻量级模型查询以验证 API 可用性
            try {
                String responseBody = getWithAuth(XAI_MODELS_URL, cachedApiKey);
                if (responseBody != null && !responseBody.isEmpty()) {
                    JSONObject obj = new JSONObject(responseBody);
                    JSONArray data = obj.optJSONArray("data");
                    int modelCount = (data != null) ? data.length() : 0;
                    return new QuotaInfo(true, modelCount, "API Key active, " + modelCount + " models available");
                }
            } catch (Exception e) {
                // 模型查询失败但 API Key 有效，仍返回可用
                return new QuotaInfo(true, 0, "API Key active, quota check limited");
            }

            return new QuotaInfo(true, 0, "API Key active");
        } catch (Exception e) {
            logError("Quota query failed", e);
            return new QuotaInfo(false, 0, "Quota query failed: " + e.getMessage());
        }
    }

    // ---------------------------------------------------------------
    // HTTP 请求
    // ---------------------------------------------------------------

    /**
     * 发送带 Bearer 认证的 GET 请求。
     *
     * @param urlStr 请求 URL
     * @param apiKey xAI API Key
     * @return 响应体字符串
     * @throws IOException 如果请求失败
     */
    private String getWithAuth(String urlStr, String apiKey) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
            conn.setConnectTimeout(REQUEST_TIMEOUT_MS);
            conn.setReadTimeout(REQUEST_TIMEOUT_MS);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("HTTP " + responseCode + ": " + responseBody);
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 发送带 Bearer 认证的 POST 请求。
     *
     * @param urlStr  请求 URL
     * @param jsonBody JSON 请求体
     * @param apiKey  xAI API Key
     * @return 响应体字符串
     * @throws IOException 如果请求失败
     */
    public String postWithAuth(String urlStr, String jsonBody, String apiKey) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + apiKey);
            conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
            conn.setDoOutput(true);
            conn.setConnectTimeout(REQUEST_TIMEOUT_MS);
            conn.setReadTimeout(REQUEST_TIMEOUT_MS);

            try (OutputStream os = conn.getOutputStream()) {
                byte[] input = jsonBody.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("HTTP " + responseCode + ": " + responseBody);
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 读取 HTTP 响应体。
     */
    private String readResponse(HttpURLConnection conn, int responseCode) throws IOException {
        BufferedReader reader;
        if (responseCode >= HttpURLConnection.HTTP_BAD_REQUEST) {
            java.io.InputStream errorStream = conn.getErrorStream();
            if (errorStream == null) {
                return "";
            }
            reader = new BufferedReader(new InputStreamReader(errorStream, StandardCharsets.UTF_8));
        } else {
            reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8));
        }

        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            sb.append(line);
        }
        reader.close();
        return sb.toString();
    }

    // ---------------------------------------------------------------
    // JSON 解析
    // ---------------------------------------------------------------

    /**
     * 解析 API Key 验证响应。
     * <p>
     * xAI 的 /v1/api-key 端点返回类似以下格式：
     * <pre>
     * {
     *   "id": "key_xxx",
     *   "name": "my-key",
     *   "email": "user@example.com",
     *   "account_id": "acc_xxx",
     *   "created_at": "2024-01-01T00:00:00Z",
     *   "scopes": ["chat:write"]
     * }
     * </pre>
     */
    private XAIKeyInfo parseKeyInfoResponse(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            XAIKeyInfo info = new XAIKeyInfo();
            info.keyId = obj.optString("id", "");
            info.name = obj.optString("name", "");
            info.email = obj.optString("email", "");
            info.accountId = obj.optString("account_id", "");
            info.createdAt = obj.optString("created_at", "");

            // 解析权限范围
            JSONArray scopes = obj.optJSONArray("scopes");
            if (scopes != null) {
                List<String> scopeList = new ArrayList<>();
                for (int i = 0; i < scopes.length(); i++) {
                    scopeList.add(scopes.optString(i, ""));
                }
                info.scopes = scopeList;
            }

            info.valid = true;
            return info;
        } catch (org.json.JSONException e) {
            logError("Failed to parse API key info response", e);
            return null;
        }
    }

    /**
     * 解析模型列表响应。
     * <p>
     * xAI 使用 OpenAI 兼容的 /v1/models 端点格式：
     * <pre>
     * {
     *   "data": [
     *     {"id": "grok-1", "object": "model", "created": 1700000000, "owned_by": "x-ai"},
     *     {"id": "grok-2", "object": "model", "created": 1700000000, "owned_by": "x-ai"}
     *   ]
     * }
     * </pre>
     */
    private List<String> parseModelsResponse(String json) {
        List<String> models = new ArrayList<>();
        try {
            JSONObject obj = new JSONObject(json);
            JSONArray data = obj.optJSONArray("data");
            if (data != null) {
                for (int i = 0; i < data.length(); i++) {
                    JSONObject modelObj = data.optJSONObject(i);
                    if (modelObj != null) {
                        String modelId = modelObj.optString("id", "");
                        if (!modelId.isEmpty()) {
                            models.add(modelId);
                        }
                    }
                }
            }
        } catch (org.json.JSONException e) {
            logError("Failed to parse models response", e);
        }
        return models;
    }

    // ---------------------------------------------------------------
    // 工具方法
    // ---------------------------------------------------------------

    /**
     * 掩码 API Key，仅显示前 3 位和后 4 位字符。
     * <p>
     * 例如 "sk-xxxxxxxxxxxxxxxxabcd" → "sk-...abcd"
     */
    private static String maskApiKey(String apiKey) {
        if (apiKey == null || apiKey.isEmpty()) {
            return "";
        }
        int len = apiKey.length();
        if (len <= 8) {
            return apiKey.substring(0, Math.min(3, len)) + "...";
        }
        return apiKey.substring(0, Math.min(3, len)) + "..." + apiKey.substring(len - 4);
    }

    /**
     * 检查 API Key 是否为有效的 xAI 格式。
     * <p>
     * xAI API Key 通常以 "xai-" 或 "sk-" 开头。
     *
     * @param apiKey API Key 字符串
     * @return true 如果格式看起来有效
     */
    public static boolean isValidKeyFormat(String apiKey) {
        if (apiKey == null || apiKey.isEmpty()) {
            return false;
        }
        String trimmed = apiKey.trim();
        return trimmed.startsWith("xai-") || trimmed.startsWith("sk-");
    }

    /**
     * 获取 API 基础 URL。
     *
     * @return API 基础 URL 字符串
     */
    public String getApiBaseUrl() {
        return apiBaseUrl;
    }

    /**
     * 获取聊天补全端点 URL。
     *
     * @return 完整的聊天补全端点 URL
     */
    public String getChatEndpoint() {
        return apiBaseUrl + "/v1/chat/completions";
    }

    // ---------------------------------------------------------------
    // 内部类型
    // ---------------------------------------------------------------

    /**
     * xAI API Key 信息。
     * <p>
     * 包含从 API Key 验证端点返回的元数据。
     */
    public static class XAIKeyInfo {
        /** API Key ID */
        public String keyId;

        /** API Key 名称 */
        public String name;

        /** 关联的邮箱地址 */
        public String email;

        /** 账户 ID */
        public String accountId;

        /** 创建时间 */
        public String createdAt;

        /** 权限范围列表 */
        public List<String> scopes;

        /** 是否有效 */
        public boolean valid;

        XAIKeyInfo() {
            this.keyId = "";
            this.name = "";
            this.email = "";
            this.accountId = "";
            this.createdAt = "";
            this.scopes = new ArrayList<>();
            this.valid = false;
        }
    }

    /**
     * 配额信息。
     * <p>
     * 包含 API 可用性状态和模型数量信息。
     */
    public static class QuotaInfo {
        /** API 是否可用 */
        public final boolean available;

        /** 可用模型数量 */
        public final int modelCount;

        /** 状态描述 */
        public final String description;

        /** 查询时间戳 */
        public final long timestamp;

        public QuotaInfo(boolean available, int modelCount, String description) {
            this.available = available;
            this.modelCount = modelCount;
            this.description = description;
            this.timestamp = System.currentTimeMillis();
        }

        /**
         * 检查此配额信息是否已过期（超过 5 分钟）。
         *
         * @return true 如果已过期
         */
        public boolean isExpired() {
            return System.currentTimeMillis() - timestamp > TimeUnit.MINUTES.toMillis(5);
        }
    }
}