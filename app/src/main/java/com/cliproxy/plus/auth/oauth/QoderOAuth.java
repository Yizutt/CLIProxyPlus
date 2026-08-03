package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

/**
 * QoderOAuth 处理 Qoder API 的 OAuth2 设备流认证。
 * <p>
 * Qoder 使用简化的设备授权流程：本地生成 PKCE+S256 码对，
 * 构造登录 URL，轮询令牌端点，并通过 refresh_token 刷新访问令牌。
 * <p>
 * 1:1 port of internal/auth/qoder/ from CLIProxyAPIPlus.
 */
public class QoderOAuth extends OAuthProvider {

    private static final String TAG = "QoderOAuth";

    // ========================================================================
    // 常量 — 1:1 port of qoder_auth.go 常量
    // ========================================================================

    /** Qoder OpenAPI 基础 URL */
    public static final String QODER_OPENAPI_BASE = "https://openapi.qoder.sh";

    /** Qoder Center API 基础 URL */
    public static final String QODER_CENTER_BASE = "https://center.qoder.sh";

    /** Qoder 推理主机地址（聊天/模型列表端点） */
    public static final String QODER_CHAT_BASE = "https://api3.qoder.sh";

    /** 用户认证登录 URL */
    public static final String QODER_LOGIN_URL = "https://qoder.com/device/selectAccounts";

    /** 设备令牌轮询端点 */
    public static final String QODER_OAUTH_TOKEN_ENDPOINT =
            "https://openapi.qoder.sh/api/v1/deviceToken/poll";

    /** 刷新令牌端点 */
    public static final String QODER_REFRESH_TOKEN_ENDPOINT =
            "https://center.qoder.sh/algo/api/v3/user/refresh_token";

    /** 用户信息端点 */
    public static final String QODER_USER_INFO_ENDPOINT =
            "https://openapi.qoder.sh/api/v1/userinfo";

    // COSY 签名常量
    /** Qoder IDE 版本（COSY 签名所需） */
    public static final String QODER_IDE_VERSION = "1.0.0";

    /** 客户端类型（CLI 发送 "5"） */
    public static final String QODER_CLIENT_TYPE = "5";

    /** 数据策略（"disagree" = 选择退出训练数据收集） */
    public static final String QODER_DATA_POLICY = "disagree";

    /** 登录版本 */
    public static final String QODER_LOGIN_VERSION = "v2";

    /** 机器操作系统标识 */
    public static final String QODER_MACHINE_OS = "x86_64_windows";

    /** 机器类型魔法值 */
    public static final String QODER_MACHINE_TYPE_MAGIC = "5";

    /** 轮询间隔（毫秒） */
    private static final long POLL_INTERVAL_MS = 2000L;

    /** 最大轮询尝试次数（3 分钟 / 2 秒） */
    private static final int MAX_POLL_ATTEMPTS = 90;

    /** 连接超时（毫秒） */
    private static final int CONNECT_TIMEOUT_MS = 15000;

    /** 读取超时（毫秒） */
    private static final int READ_TIMEOUT_MS = 15000;

    // ========================================================================
    // 数据类 — 1:1 port of qoder_auth.go 和 qoder_token.go 结构体
    // ========================================================================

    /**
     * QoderTokenData 表示来自设备流轮询的 OAuth 凭证。
     * 1:1 port of Go QoderTokenData struct.
     */
    public static class QoderTokenData {
        /** 访问令牌 */
        public String accessToken;
        /** 刷新令牌 */
        public String refreshToken;
        /** 过期时间戳（毫秒纪元） */
        public long expireTime;
        /** 用户 ID */
        public String userId;
        /** 机器令牌 */
        public String machineToken;
        /** 机器类型 */
        public String machineType;
    }

    /**
     * DeviceFlowResponse 表示设备流初始化响应。
     * 1:1 port of Go DeviceFlowResponse struct.
     */
    public static class DeviceFlowResponse {
        /** 包含 PKCE challenge 的完整认证 URL */
        public String verificationURIComplete;
        /** PKCE 码验证器（本地生成） */
        public String codeVerifier;
        /** 请求随机数 */
        public String nonce;
        /** 机器标识符 */
        public String machineID;
    }

    /**
     * DeviceFlowPollResponse 表示 /api/v1/deviceToken/poll 的成功响应。
     * 1:1 port of Go DeviceFlowPollResponse struct.
     */
    public static class DeviceFlowPollResponse {
        public String id;
        public String token;
        public String userId;
        public String refreshToken;
        public String refreshTokenId;
        public String expiresAt;
        public long expiresIn;
        public String refreshTokenExpiresAt;
        public long refreshTokenExpiresIn;
        public String createdAt;
        public String updatedAt;
    }

    /**
     * UserInfoResponse 表示 /api/v1/userinfo 的响应。
     * 1:1 port of Go UserInfoResponse struct.
     */
    public static class UserInfoResponse {
        public String id;
        public String name;
        public String username;
        public String email;
        public String organizationId;
    }

    /**
     * QoderTokenStorage 存储 Qoder API 认证的 OAuth2 令牌信息。
     * 1:1 port of Go QoderTokenStorage struct.
     */
    public static class QoderTokenStorage {
        /** OAuth2 访问令牌 */
        public String token;
        /** 用于刷新访问令牌的刷新令牌 */
        public String refreshToken;
        /** Qoder 用户的唯一标识符 */
        public String userId;
        /** 用户显示名称 */
        public String name;
        /** Qoder 账户邮箱地址 */
        public String email;
        /** 当前访问令牌的过期时间戳（毫秒纪元） */
        public long expireTime;
        /** 认证提供商类型，始终为 "qoder" */
        public String type;
        /** 上次令牌刷新的时间戳 */
        public String lastRefresh;
        /** 持久化机器标识符 */
        public String machineID;
        /** 机器特定令牌 */
        public String machineToken;
        /** 机器注册类型 */
        public String machineType;

        /**
         * 检查令牌是否已过期或在指定缓冲时间内即将过期。
         * 1:1 port of Go IsExpired().
         *
         * @param bufferDurationMs 缓冲时间（毫秒）
         * @return 如果令牌已过期或即将过期则返回 true
         */
        public boolean isExpired(long bufferDurationMs) {
            if (expireTime == 0) {
                return true;
            }
            long now = System.currentTimeMillis();
            return expireTime - now - bufferDurationMs <= 0;
        }
    }

    // ========================================================================
    // 构造方法
    // ========================================================================

    public QoderOAuth() {
        super("qoder", QODER_LOGIN_URL, QODER_OAUTH_TOKEN_ENDPOINT,
                "", "");
    }

    // ========================================================================
    // PKCE 辅助方法 — 1:1 port of cosy.go generateDeviceCodeVerifier / Challenge
    // ========================================================================

    /**
     * 生成 PKCE 码验证器（32 字节随机数，Base64 URL 编码，无填充）。
     * 1:1 port of Go generateDeviceCodeVerifier().
     */
    private static String generateDeviceCodeVerifier() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * 创建码验证器的 SHA-256 哈希的 Base64 URL 编码。
     * 1:1 port of Go generateDeviceCodeChallenge().
     */
    private static String generateDeviceCodeChallenge(String codeVerifier) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 生成 PKCE 码验证器和码挑战对。
     * 1:1 port of Go generateDevicePKCEPair().
     */
    private static String[] generateDevicePKCEPair() {
        String codeVerifier = generateDeviceCodeVerifier();
        String codeChallenge = generateDeviceCodeChallenge(codeVerifier);
        return new String[]{codeVerifier, codeChallenge};
    }

    /**
     * 生成持久化机器 UUID。
     * 1:1 port of Go generateMachineID().
     */
    private static String generateMachineID() {
        return UUID.randomUUID().toString();
    }

    /**
     * 将毫秒纪元时间戳格式化为 RFC3339 格式。
     * 1:1 port of Go formatExpiresAt().
     */
    private static String formatExpiresAt(long expireMs) {
        return Instant.ofEpochMilli(expireMs).toString();
    }

    /**
     * 将 Qoder 上游过期提示转换为毫秒纪元时间戳。
     * 提示可以是：
     * <ul>
     *   <li>RFC3339 时间戳（如 "2026-06-16T07:15:04Z"）</li>
     *   <li>Unix 毫秒整数字符串（如 "1781594470000"）</li>
     *   <li>空或无法解析，则回退到 expiresInSeconds（从当前时间起的秒数），
     *       最后回退到 "当前时间 + 30 天"</li>
     * </ul>
     * 1:1 port of Go parseExpiresAt().
     */
    private static long parseExpiresAt(String s, long expiresInSeconds) {
        if (s != null) {
            s = s.trim();
            if (!s.isEmpty()) {
                // 尝试解析 RFC3339 格式
                try {
                    Instant instant = Instant.parse(s);
                    return instant.toEpochMilli();
                } catch (Exception ignored) {
                    // 不是 RFC3339 格式，尝试作为毫秒整数解析
                }
                try {
                    long ms = Long.parseLong(s);
                    if (ms > 0) {
                        return ms;
                    }
                } catch (NumberFormatException ignored) {
                    // 无法解析为整数
                }
            }
        }
        if (expiresInSeconds > 0) {
            return System.currentTimeMillis() + expiresInSeconds * 1000L;
        }
        return System.currentTimeMillis() + 30L * 24L * 60L * 60L * 1000L;
    }

    // ========================================================================
    // HTTP 辅助方法
    // ========================================================================

    /**
     * 执行 GET 请求并返回响应体字符串。
     */
    private String httpGet(String urlStr, String authorization) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "Go-http-client/2.0");
            if (authorization != null && !authorization.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + authorization);
            }
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            return readResponse(conn);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 执行 GET 请求（无 Authorization 头）并返回响应码和响应体。
     */
    private HttpResult httpGetWithStatus(String urlStr) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "Go-http-client/2.0");
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            int responseCode = conn.getResponseCode();
            String body = readResponseBody(conn);
            return new HttpResult(responseCode, body);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 执行 POST 请求（JSON body）并返回响应体字符串。
     */
    private String httpPostJson(String urlStr, String jsonBody, String accessToken) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            if (accessToken != null && !accessToken.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            }
            conn.setDoOutput(true);
            conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
            conn.setReadTimeout(READ_TIMEOUT_MS);
            byte[] postData = jsonBody.getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }
            return readResponse(conn);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 从 HttpURLConnection 读取响应体，如果状态码不是 2xx 则抛出 IOException。
     */
    private String readResponse(HttpURLConnection conn) throws IOException {
        int responseCode = conn.getResponseCode();
        String body = readResponseBody(conn);
        if (responseCode < 200 || responseCode >= 300) {
            throw new IOException("HTTP " + responseCode + ": " + body);
        }
        return body;
    }

    /**
     * 从 HttpURLConnection 读取响应体（不检查状态码）。
     */
    private String readResponseBody(HttpURLConnection conn) {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            java.io.InputStream is;
            try {
                is = conn.getInputStream();
            } catch (IOException e) {
                is = conn.getErrorStream();
            }
            if (is != null) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            return baos.toString("UTF-8");
        } catch (Exception e) {
            Log.e(TAG, "Failed to read response body: " + e.getMessage(), e);
            return "";
        }
    }

    // ========================================================================
    // 设备流认证 — 1:1 port of qoder_auth.go InitiateDeviceFlow
    // ========================================================================

    /**
     * 启动 OAuth 2.0 设备授权流程。
     * <p>
     * Qoder 使用简化的流程：本地生成 PKCE 码对并构造登录 URL。
     * 1:1 port of Go QoderAuth.InitiateDeviceFlow().
     *
     * @return DeviceFlowResponse 包含完整认证 URL 和 PKCE 信息
     */
    public DeviceFlowResponse initiateDeviceFlow() {
        String[] pkcePair = generateDevicePKCEPair();
        String codeVerifier = pkcePair[0];
        String codeChallenge = pkcePair[1];

        String nonce = UUID.randomUUID().toString();
        String machineID = generateMachineID();

        String verificationURI = QODER_LOGIN_URL
                + "?challenge=" + URLEncoder.encode(codeChallenge, StandardCharsets.UTF_8)
                + "&challenge_method=S256"
                + "&machine_id=" + URLEncoder.encode(machineID, StandardCharsets.UTF_8)
                + "&nonce=" + URLEncoder.encode(nonce, StandardCharsets.UTF_8);

        Log.d(TAG, "Initiated device flow, verification URI: " + verificationURI);

        DeviceFlowResponse resp = new DeviceFlowResponse();
        resp.verificationURIComplete = verificationURI;
        resp.codeVerifier = codeVerifier;
        resp.nonce = nonce;
        resp.machineID = machineID;
        return resp;
    }

    // ========================================================================
    // 令牌轮询 — 1:1 port of qoder_auth.go PollForToken
    // ========================================================================

    /**
     * 轮询令牌端点以获取访问令牌。
     * <p>
     * 使用 2 秒间隔，最多 90 次尝试（3 分钟）。
     * 1:1 port of Go QoderAuth.PollForToken().
     *
     * @param deviceFlow 设备流初始化响应（包含 codeVerifier 和 nonce）
     * @return QoderTokenData 包含访问令牌和刷新令牌
     * @throws OAuthException 如果轮询失败或超时
     * @throws InterruptedException 如果线程被中断
     */
    public QoderTokenData pollForToken(DeviceFlowResponse deviceFlow)
            throws OAuthException, InterruptedException {
        if (deviceFlow == null || deviceFlow.codeVerifier == null || deviceFlow.codeVerifier.isEmpty()
                || deviceFlow.nonce == null || deviceFlow.nonce.isEmpty()) {
            throw new OAuthException(OAuthException.TYPE_AUTH,
                    "Device flow is missing code verifier or nonce");
        }

        String pollURL = QODER_OAUTH_TOKEN_ENDPOINT
                + "?nonce=" + URLEncoder.encode(deviceFlow.nonce, StandardCharsets.UTF_8)
                + "&verifier=" + URLEncoder.encode(deviceFlow.codeVerifier, StandardCharsets.UTF_8)
                + "&challenge_method=S256";

        Log.d(TAG, "Starting token polling, URL: " + pollURL);

        for (int attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt++) {
            try {
                HttpURLConnection conn = (HttpURLConnection) new URL(pollURL).openConnection();
                try {
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("Accept", "application/json");
                    conn.setRequestProperty("User-Agent", "Go-http-client/2.0");
                    conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
                    conn.setReadTimeout(READ_TIMEOUT_MS);

                    int responseCode = conn.getResponseCode();
                    String body = readResponseBody(conn);

                    if (responseCode == HttpURLConnection.HTTP_ACCEPTED) {
                        // 202 — 仍在等待用户认证
                        Log.d(TAG, "Polling attempt " + (attempt + 1) + "/"
                                + MAX_POLL_ATTEMPTS + "... (pending)");
                        TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MS);
                        continue;
                    }

                    if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
                        // 404 — 令牌尚未创建，用户尚未认证
                        Log.d(TAG, "Polling attempt " + (attempt + 1) + "/"
                                + MAX_POLL_ATTEMPTS + "... (token not found, waiting for auth)");
                        TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MS);
                        continue;
                    }

                    if (responseCode != HttpURLConnection.HTTP_OK) {
                        // 解析错误响应
                        String errorMsg = parseErrorMessage(body);
                        if (errorMsg != null) {
                            throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                                    "Device token poll failed: " + errorMsg, responseCode);
                        }
                        throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                                "Device token poll failed: " + responseCode + ". Response: " + body,
                                responseCode);
                    }

                    // 200 — 成功，解析令牌数据
                    JSONObject json = parseJson(body);
                    String token = json.optString("token", "");
                    if (token.isEmpty()) {
                        throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                                "Device token poll returned empty access token; "
                                        + "raw response keys may have changed");
                    }

                    DeviceFlowPollResponse pollResp = new DeviceFlowPollResponse();
                    pollResp.id = json.optString("id", "");
                    pollResp.token = token;
                    pollResp.userId = json.optString("user_id", "");
                    pollResp.refreshToken = json.optString("refresh_token", "");
                    pollResp.refreshTokenId = json.optString("refresh_token_id", "");
                    pollResp.expiresAt = json.optString("expires_at", "");
                    pollResp.expiresIn = json.optLong("expires_in", 0);
                    pollResp.refreshTokenExpiresAt = json.optString("refresh_token_expires_at", "");
                    pollResp.refreshTokenExpiresIn = json.optLong("refresh_token_expires_in", 0);
                    pollResp.createdAt = json.optString("created_at", "");
                    pollResp.updatedAt = json.optString("updated_at", "");

                    long expireMs = parseExpiresAt(pollResp.expiresAt, pollResp.expiresIn);

                    QoderTokenData tokenData = new QoderTokenData();
                    tokenData.accessToken = pollResp.token;
                    tokenData.refreshToken = pollResp.refreshToken;
                    tokenData.expireTime = expireMs;
                    tokenData.userId = pollResp.userId;

                    Log.d(TAG, "Token polling succeeded, token obtained");
                    return tokenData;

                } finally {
                    conn.disconnect();
                }
            } catch (IOException e) {
                Log.w(TAG, "Polling attempt " + (attempt + 1) + "/"
                        + MAX_POLL_ATTEMPTS + " failed: " + e.getMessage());
                if (attempt < MAX_POLL_ATTEMPTS - 1) {
                    TimeUnit.MILLISECONDS.sleep(POLL_INTERVAL_MS);
                }
            }
        }

        throw new OAuthException(OAuthException.TYPE_AUTH,
                "Authentication timeout. Please restart the authentication process");
    }

    // ========================================================================
    // 令牌刷新 — 1:1 port of qoder_auth.go RefreshTokens
    // ========================================================================

    /**
     * 使用 refresh_token 交换新的访问令牌。
     * 1:1 port of Go QoderAuth.RefreshTokens().
     *
     * @param accessToken  当前访问令牌（用于 Authorization 头）
     * @param refreshToken 刷新令牌
     * @return QoderTokenData 包含新的访问令牌和刷新令牌
     * @throws OAuthException 如果刷新失败
     */
    public QoderTokenData refreshTokens(String accessToken, String refreshToken)
            throws OAuthException {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new OAuthException(OAuthException.TYPE_AUTH, "Refresh token is required");
        }

        try {
            JSONObject reqBody = new JSONObject();
            reqBody.put("refreshToken", refreshToken);
            String bodyStr = reqBody.toString();

            String responseBody = httpPostJson(QODER_REFRESH_TOKEN_ENDPOINT, bodyStr, accessToken);

            JSONObject json = parseJson(responseBody);
            String token = json.optString("token", "");
            if (token.isEmpty()) {
                throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                        "Token refresh returned empty access token; "
                                + "raw response keys may have changed");
            }

            DeviceFlowPollResponse refreshResp = new DeviceFlowPollResponse();
            refreshResp.id = json.optString("id", "");
            refreshResp.token = token;
            refreshResp.userId = json.optString("user_id", "");
            refreshResp.refreshToken = json.optString("refresh_token", "");
            refreshResp.refreshTokenId = json.optString("refresh_token_id", "");
            refreshResp.expiresAt = json.optString("expires_at", "");
            refreshResp.expiresIn = json.optLong("expires_in", 0);
            refreshResp.refreshTokenExpiresAt = json.optString("refresh_token_expires_at", "");
            refreshResp.refreshTokenExpiresIn = json.optLong("refresh_token_expires_in", 0);

            long expireMs = parseExpiresAt(refreshResp.expiresAt, refreshResp.expiresIn);

            QoderTokenData tokenData = new QoderTokenData();
            tokenData.accessToken = refreshResp.token;
            tokenData.refreshToken = refreshResp.refreshToken;
            tokenData.expireTime = expireMs;

            Log.d(TAG, "Token refresh succeeded");
            return tokenData;

        } catch (IOException e) {
            Log.e(TAG, "Token refresh request failed: " + e.getMessage(), e);
            throw new OAuthException(OAuthException.TYPE_NETWORK,
                    "Token refresh failed: " + e.getMessage(), e);
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse refresh response: " + e.getMessage(), e);
            throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                    "Failed to parse refresh response: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // 用户信息 — 1:1 port of qoder_auth.go FetchUserInfo / SaveUserInfo
    // ========================================================================

    /**
     * 从 API 获取用户信息。
     * 1:1 port of Go QoderAuth.FetchUserInfo().
     *
     * @param accessToken 访问令牌
     * @return 包含 name 和 email 的字符串数组 [name, email]
     * @throws OAuthException 如果请求失败
     */
    public String[] fetchUserInfo(String accessToken) throws OAuthException {
        if (accessToken == null || accessToken.isEmpty()) {
            throw new OAuthException(OAuthException.TYPE_AUTH, "Access token is required");
        }

        try {
            String responseBody = httpGet(QODER_USER_INFO_ENDPOINT, accessToken);

            JSONObject json = parseJson(responseBody);
            UserInfoResponse response = new UserInfoResponse();
            response.id = json.optString("id", "");
            response.name = json.optString("name", "");
            response.username = json.optString("username", "");
            response.email = json.optString("email", "");
            response.organizationId = json.optString("organization_id", "");

            String name = response.name != null ? response.name.trim() : "";
            if (name.isEmpty()) {
                name = response.username != null ? response.username.trim() : "";
            }
            String email = response.email != null ? response.email.trim() : "";

            Log.d(TAG, "Fetched user info: name=" + name + ", email=" + email);
            return new String[]{name, email};

        } catch (IOException e) {
            Log.e(TAG, "User info request failed: " + e.getMessage(), e);
            throw new OAuthException(OAuthException.TYPE_NETWORK,
                    "User info request failed: " + e.getMessage(), e);
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse user info response: " + e.getMessage(), e);
            throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                    "Failed to parse user info response: " + e.getMessage(), e);
        }
    }

    /**
     * 保存用户信息，必要时从 API 获取。
     * 1:1 port of Go QoderAuth.SaveUserInfo().
     *
     * @param accessToken 访问令牌
     * @param userId      用户 ID（可为空）
     * @param name        用户名称（可为空，为空时会尝试从 API 获取）
     * @param email       用户邮箱（可为空，为空时会尝试从 API 获取）
     * @return 包含 name 和 email 的字符串数组 [name, email]
     */
    public String[] saveUserInfo(String accessToken, String userId, String name, String email) {
        if (accessToken == null || accessToken.trim().isEmpty()) {
            return new String[]{name, email};
        }

        String currentName = name != null ? name.trim() : "";
        String currentEmail = email != null ? email.trim() : "";

        if (currentName.isEmpty() || currentEmail.isEmpty()) {
            try {
                String[] userInfo = fetchUserInfo(accessToken);
                if (currentName.isEmpty()) {
                    currentName = userInfo[0];
                }
                if (currentEmail.isEmpty()) {
                    currentEmail = userInfo[1];
                }
            } catch (OAuthException e) {
                Log.w(TAG, "Failed to fetch user info for saving: " + e.getMessage());
            }
        }

        return new String[]{currentName, currentEmail};
    }

    // ========================================================================
    // 令牌存储管理 — 1:1 port of qoder_auth.go CreateTokenStorage / UpdateTokenStorage
    // ========================================================================

    /**
     * 从 QoderTokenData 创建 QoderTokenStorage 对象。
     * 1:1 port of Go QoderAuth.CreateTokenStorage().
     *
     * @param tokenData 令牌数据
     * @param machineID 机器标识符
     * @return QoderTokenStorage 存储对象
     */
    public QoderTokenStorage createTokenStorage(QoderTokenData tokenData, String machineID) {
        QoderTokenStorage storage = new QoderTokenStorage();
        storage.token = tokenData.accessToken;
        storage.refreshToken = tokenData.refreshToken;
        storage.userId = tokenData.userId;
        storage.expireTime = tokenData.expireTime;
        storage.lastRefresh = Instant.now().toString();
        storage.machineID = machineID;
        storage.machineToken = tokenData.machineToken;
        storage.machineType = tokenData.machineType;
        return storage;
    }

    /**
     * 用新的令牌数据更新现有的 QoderTokenStorage。
     * 1:1 port of Go QoderAuth.UpdateTokenStorage().
     *
     * @param storage   现有的令牌存储对象
     * @param tokenData 新的令牌数据
     */
    public void updateTokenStorage(QoderTokenStorage storage, QoderTokenData tokenData) {
        storage.token = tokenData.accessToken;
        storage.refreshToken = tokenData.refreshToken;
        storage.expireTime = tokenData.expireTime;
        storage.lastRefresh = Instant.now().toString();
    }

    // ========================================================================
    // 带重试的令牌刷新 — 1:1 port of qoder_auth.go RefreshTokensWithRetry
    // ========================================================================

    /**
     * 尝试使用指定次数的重试来刷新令牌。
     * 1:1 port of Go QoderAuth.RefreshTokensWithRetry().
     *
     * @param accessToken  当前访问令牌
     * @param refreshToken 刷新令牌
     * @param maxRetries   最大重试次数
     * @return QoderTokenData 包含新的令牌数据
     * @throws OAuthException 如果所有重试都失败
     */
    public QoderTokenData refreshTokensWithRetry(String accessToken, String refreshToken,
                                                  int maxRetries) throws OAuthException {
        OAuthException lastErr = null;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            if (attempt > 0) {
                // 重试前等待（1:1 port of Go time.Duration(attempt) * time.Second）
                try {
                    Thread.sleep((long) attempt * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new OAuthException(OAuthException.TYPE_NETWORK,
                            "Token refresh interrupted", e);
                }
            }

            try {
                return refreshTokens(accessToken, refreshToken);
            } catch (OAuthException e) {
                lastErr = e;
                Log.w(TAG, "Token refresh attempt " + (attempt + 1) + "/"
                        + maxRetries + " failed: " + e.getMessage());
            }
        }

        throw new OAuthException(OAuthException.TYPE_NETWORK,
                "Token refresh failed after " + maxRetries + " attempts", lastErr);
    }

    // ========================================================================
    // 令牌过期检查 — 1:1 port of api.go RefreshTokenIfNeeded
    // ========================================================================

    /**
     * 当剩余生命周期低于 bufferSeconds 时刷新访问令牌。
     * 1:1 port of Go RefreshTokenIfNeeded().
     *
     * @param storage       令牌存储
     * @param bufferSeconds 缓冲时间（秒）
     * @return 如果刷新完成则返回 true，如果不需要刷新则返回 false
     * @throws OAuthException 如果刷新失败
     */
    public boolean refreshTokenIfNeeded(QoderTokenStorage storage, long bufferSeconds)
            throws OAuthException {
        if (storage.expireTime == 0) {
            return false;
        }

        long now = System.currentTimeMillis();
        long bufferMs = bufferSeconds * 1000L;

        if (storage.expireTime - now - bufferMs <= 0) {
            QoderTokenData tokenData = refreshTokens(storage.token, storage.refreshToken);
            updateTokenStorage(storage, tokenData);
            return true;
        }

        return false;
    }

    // ========================================================================
    // 内部辅助方法
    // ========================================================================

    /**
     * 内部 HTTP 结果类。
     */
    private static class HttpResult {
        final int statusCode;
        final String body;

        HttpResult(int statusCode, String body) {
            this.statusCode = statusCode;
            this.body = body;
        }
    }

    /**
     * 从 JSON 响应体中提取错误消息。
     */
    private static String parseErrorMessage(String body) {
        try {
            if (body != null && !body.isEmpty()) {
                JSONObject json = parseJson(body);
                return json.optString("message", null);
            }
        } catch (Exception ignored) {
            // 忽略解析错误
        }
        return null;
    }
    private static JSONObject parseJson(String body) throws IOException {
        try {
            return new JSONObject(body);
        } catch (org.json.JSONException e) {
            throw new IOException("qoder: failed to parse JSON", e);
        }
    }

}