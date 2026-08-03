package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalAccessor;
import java.util.Base64;
import java.util.UUID;

/**
 * QoderOAuth - Qoder AI OAuth Provider
 * <p>
 * 实现 Qoder AI 的 OAuth 2.0 Device Authorization Grant 流程 (RFC 8628)。
 * Qoder 使用本地生成的 PKCE 码对，配合 device token polling 机制完成认证。
 * 对应原版 CLIProxyAPIPlus/internal/auth/qoder/ 中的 Go 实现。
 * <p>
 * 流程说明:
 * 1. 调用 startAuth() 生成 PKCE 码对并构建验证 URL，返回用户需要访问的 URL
 * 2. 用户在浏览器中打开该 URL，完成授权
 * 3. 调用 pollAuthStatus() 轮询令牌端点，检查用户是否已完成授权
 * 4. 调用 handleCallback() 完成令牌交换，获取最终的 AuthResult
 */
public class QoderOAuth extends OAuthProvider {

    private static final String TAG = "QoderOAuth";

    // ---- Qoder OAuth 端点常量 ----

    /** Qoder OpenAPI 基础地址 */
    private static final String QODER_OPENAPI_BASE = "https://openapi.qoder.sh";

    /** Qoder Center API 基础地址 */
    private static final String QODER_CENTER_BASE = "https://center.qoder.sh";

    /** Qoder 用户登录验证 URL */
    private static final String QODER_LOGIN_URL = "https://qoder.com/device/selectAccounts";

    /** 设备令牌轮询端点 */
    private static final String QODER_DEVICE_TOKEN_POLL_URL =
            QODER_OPENAPI_BASE + "/api/v1/deviceToken/poll";

    /** 令牌刷新端点 */
    private static final String QODER_REFRESH_TOKEN_URL =
            QODER_CENTER_BASE + "/algo/api/v3/user/refresh_token";

    /** 用户信息端点 */
    private static final String QODER_USER_INFO_URL =
            QODER_OPENAPI_BASE + "/api/v1/userinfo";

    /** 默认轮询间隔（毫秒） */
    private static final long DEFAULT_POLL_INTERVAL_MS = 2000L;

    /** 最大轮询尝试次数（3 分钟 / 2 秒间隔） */
    private static final int MAX_POLL_ATTEMPTS = 90;

    /** 最大轮询持续时间（毫秒） */
    private static final long MAX_POLL_DURATION_MS = 3 * 60 * 1000L;

    /** 设备唯一标识 */
    private final String deviceId;

    /** 设备名称 */
    private final String deviceModel;

    /** 活跃的设备流会话，按 state 参数索引 */
    private final java.util.concurrent.ConcurrentHashMap<String, DeviceFlowSession> activeSessions =
            new java.util.concurrent.ConcurrentHashMap<>();

    // ---------------------------------------------------------------
    // 构造
    // ---------------------------------------------------------------

    /**
     * 创建一个 Qoder OAuth 提供者实例，使用默认配置。
     */
    public QoderOAuth() {
        this.deviceId = generateMachineId();
        this.deviceModel = getDeviceModel();
    }

    /**
     * 创建一个 Qoder OAuth 提供者实例，使用指定的设备 ID。
     *
     * @param deviceId 设备唯一标识，为空时自动生成
     */
    public QoderOAuth(String deviceId) {
        this.deviceId = (deviceId != null && !deviceId.trim().isEmpty())
                ? deviceId.trim()
                : generateMachineId();
        this.deviceModel = getDeviceModel();
    }

    // ---------------------------------------------------------------
    // OAuthProvider 抽象方法实现
    // ---------------------------------------------------------------

    /**
     * 启动设备授权流程。
     * <p>
     * 生成 PKCE 码对和随机 nonce，构建用户验证 URL。
     * 返回的 URL 需要由用户在浏览器中打开以完成授权。
     *
     * @return 用户验证 URI（verification_uri_complete），用户应在浏览器中打开此 URL
     * @throws RuntimeException 如果设备码请求失败
     */
    public String startAuth() {
        try {
            DeviceFlowRequest request = initiateDeviceFlow();
            long expiresAt = System.currentTimeMillis() + MAX_POLL_DURATION_MS;

            String state = generateRandomState();

            DeviceFlowSession session = new DeviceFlowSession(
                    state,
                    request.codeVerifier,
                    request.nonce,
                    request.machineId,
                    request.verificationUriComplete,
                    expiresAt,
                    DEFAULT_POLL_INTERVAL_MS
            );
            activeSessions.put(state, session);

            log("Qoder device auth flow started, state=" + state);
            return request.verificationUriComplete;
        } catch (Exception e) {
            logError("Qoder OAuth: failed to start device auth flow", e);
            throw new RuntimeException("Qoder OAuth: failed to start device auth flow", e);
        }
    }

    /**
     * 轮询授权状态。
     * <p>
     * 向 Qoder 令牌端点发起一次设备码交换请求，检查用户是否已完成授权。
     * 如果授权完成，内部会缓存令牌结果，后续调用 {@link #handleCallback} 可返回该结果。
     *
     * @param state 授权状态标识（由 {@link #startAuth()} 生成）
     * @return true 如果用户已完成授权且令牌已就绪，false 表示仍需等待
     */
    public boolean pollAuthStatus(String state) {
        DeviceFlowSession session = activeSessions.get(state);
        if (session == null) {
            log("Qoder OAuth: no session found for state=" + state);
            return false;
        }

        if (session.isExpired()) {
            log("Qoder OAuth: session expired for state=" + state);
            activeSessions.remove(state);
            return false;
        }

        if (session.tokenResult != null) {
            return true;
        }

        try {
            QoderTokenData tokenData = pollForToken(session.nonce, session.codeVerifier);
            if (tokenData != null) {
                session.tokenResult = tokenData;
                log("Qoder OAuth: token received for state=" + state);
                return true;
            }
        } catch (AuthorizationPendingException e) {
            // 用户尚未授权，继续轮询
            return false;
        } catch (IOException e) {
            // 网络错误，由调用方决定重试策略
            log("Qoder OAuth: poll error for state=" + state + ": " + e.getMessage());
            return false;
        }

        return false;
    }

    /**
     * 处理授权回调并返回认证结果。
     * <p>
     * 在设备流中，此方法从 {@link #pollAuthStatus} 缓存的结果中提取令牌，
     * 构造 {@link AuthResult} 并清理会话状态。
     *
     * @param code  授权码（设备流中可传空字符串）
     * @param state 状态参数（由 {@link #startAuth()} 生成，用于 CSRF 验证）
     * @return 认证结果，如果会话无效或令牌未就绪则返回 null
     */
    public AuthResult handleCallback(String code, String state) {
        DeviceFlowSession session = activeSessions.remove(state);
        if (session == null || session.tokenResult == null) {
            log("Qoder OAuth: handleCallback failed - no session or token for state=" + state);
            return null;
        }

        if (!session.state.equals(state)) {
            log("Qoder OAuth: state mismatch");
            return null;
        }

        QoderTokenData token = session.tokenResult;

        // 计算过期时间
        long expireAt = token.expiresAt > 0 ? token.expiresAt : 0L;

        // 尝试获取用户信息
        String email = "";
        String accountId = token.userId;
        if (token.accessToken != null && !token.accessToken.isEmpty()) {
            try {
                String[] userInfo = fetchUserInfo(token.accessToken);
                if (userInfo != null) {
                    if (userInfo[0] != null && !userInfo[0].isEmpty()) {
                        accountId = userInfo[0];
                    }
                    email = userInfo[1] != null ? userInfo[1] : "";
                }
            } catch (Exception e) {
                logError("Qoder OAuth: failed to fetch user info", e);
            }
        }

        TokenData tokenData = new TokenData();
        tokenData.idToken = "";
        tokenData.accessToken = token.accessToken;
        tokenData.refreshToken = token.refreshToken != null ? token.refreshToken : "";
        tokenData.accountId = accountId;
        tokenData.email = email;
        tokenData.expiresIn = expireAt > 0 ? (int) ((expireAt - System.currentTimeMillis()) / 1000L) : 0;
        tokenData.expireAt = expireAt;

        log("Qoder OAuth: authentication completed for account=" + accountId);
        return new AuthResult(tokenData);
    }

    /**
     * 刷新 Access Token。
     * <p>
     * 使用刷新令牌获取新的访问令牌，无需用户重新授权。
     *
     * @param refreshToken 刷新令牌
     * @return 新的 Token 数据
     * @throws OAuthException 如果刷新请求失败
     */
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new OAuthException("refresh_token_required",
                    "Qoder OAuth: refresh token is required");
        }

        try {
            QoderTokenData tokenData = refreshTokenInternal(refreshToken);

            long expireAt = tokenData.expiresAt > 0 ? tokenData.expiresAt : 0L;

            // 获取当前 access token 用于用户信息查询（如果返回了新的 access token）
            String currentAccessToken = tokenData.accessToken;

            TokenData result = new TokenData();
            result.idToken = "";
            result.accessToken = tokenData.accessToken;
            result.refreshToken = tokenData.refreshToken != null ? tokenData.refreshToken : refreshToken;
            result.accountId = tokenData.userId;
            result.expiresIn = expireAt > 0 ? (int) ((expireAt - System.currentTimeMillis()) / 1000L) : 0;
            result.expireAt = expireAt;

            return result;
        } catch (IOException e) {
            logError("Qoder OAuth: token refresh failed", e);
            throw new OAuthException("refresh_failed",
                    "Qoder OAuth: token refresh failed: " + e.getMessage(), e);
        }
    }

    // ---------------------------------------------------------------
    // 设备流核心方法
    // ---------------------------------------------------------------

    /**
     * 发起设备流。
     * <p>
     * Qoder 使用简化的设备流：本地生成 PKCE 码对，构建登录 URL。
     * 不需要向服务器发送设备码请求。
     *
     * @return 设备流请求信息，包含 PKCE 码、nonce 和验证 URL
     */
    private DeviceFlowRequest initiateDeviceFlow() {
        PKCECodes pkceCodes = generatePKCECodes();
        String nonce = UUID.randomUUID().toString();
        String machineId = generateMachineId();

        String verificationUriComplete = QODER_LOGIN_URL
                + "?challenge=" + encodeParam(pkceCodes.codeChallenge)
                + "&challenge_method=S256"
                + "&machine_id=" + encodeParam(machineId)
                + "&nonce=" + encodeParam(nonce);

        return new DeviceFlowRequest(
                pkceCodes.codeVerifier,
                pkceCodes.codeChallenge,
                nonce,
                machineId,
                verificationUriComplete
        );
    }

    /**
     * 轮询令牌端点。
     * <p>
     * 向 Qoder 设备令牌轮询端点发送 GET 请求，检查用户是否已完成授权。
     * 返回 200 表示授权完成，202/404 表示用户尚未授权。
     *
     * @param nonce       随机 nonce
     * @param codeVerifier PKCE code verifier
     * @return 令牌数据，如果用户尚未授权则抛出 AuthorizationPendingException
     * @throws IOException                   如果请求失败
     * @throws AuthorizationPendingException 如果用户尚未授权（应继续轮询）
     */
    private QoderTokenData pollForToken(String nonce, String codeVerifier)
            throws IOException, AuthorizationPendingException {

        String pollUrl = QODER_DEVICE_TOKEN_POLL_URL
                + "?nonce=" + encodeParam(nonce)
                + "&verifier=" + encodeParam(codeVerifier)
                + "&challenge_method=S256";

        URL url = new URL(pollUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            // 202 Accepted - 用户尚未授权，继续轮询
            if (responseCode == HttpURLConnection.HTTP_ACCEPTED) {
                throw new AuthorizationPendingException("User has not yet authorized (202)");
            }

            // 404 Not Found - 令牌尚未创建，用户尚未完成认证
            if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
                throw new AuthorizationPendingException("Token not created yet (404)");
            }

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Qoder OAuth: poll failed with status " + responseCode
                        + ": " + responseBody);
            }

            return parsePollTokenResponse(responseBody);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 刷新令牌。
     * <p>
     * 向 Qoder 刷新令牌端点发送 POST 请求。
     *
     * @param refreshToken 刷新令牌
     * @return 新的令牌数据
     * @throws IOException 如果请求失败
     */
    private QoderTokenData refreshTokenInternal(String refreshToken) throws IOException {
        // 先获取当前 access token 用于认证
        // 在刷新流程中，我们需要用旧的 access token 来认证刷新请求
        // 但 Qoder 的刷新端点可能只需要 refreshToken 在请求体中
        // 我们从会话中获取 access token 作为 Bearer 认证

        String accessToken = findAccessTokenForRefresh();

        JSONObject bodyJson = new JSONObject();
        try {
            bodyJson.put("refreshToken", refreshToken);
        } catch (JSONException e) {
            throw new IOException("Qoder OAuth: failed to build refresh request body", e);
        }
        byte[] postData = bodyJson.toString().getBytes(StandardCharsets.UTF_8);

        URL url = new URL(QODER_REFRESH_TOKEN_URL);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            if (accessToken != null && !accessToken.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            }
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Qoder OAuth: refresh failed with status " + responseCode
                        + ": " + responseBody);
            }

            return parsePollTokenResponse(responseBody);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 从活跃会话中查找用于刷新认证的 access token。
     */
    private String findAccessTokenForRefresh() {
        for (DeviceFlowSession session : activeSessions.values()) {
            if (session.tokenResult != null && session.tokenResult.accessToken != null
                    && !session.tokenResult.accessToken.isEmpty()) {
                return session.tokenResult.accessToken;
            }
        }
        return null;
    }

    // ---------------------------------------------------------------
    // 用户信息
    // ---------------------------------------------------------------

    /**
     * 获取用户信息。
     *
     * @param accessToken 访问令牌
     * @return [userId, email] 数组，失败时返回 null
     */
    private String[] fetchUserInfo(String accessToken) {
        try {
            URL url = new URL(QODER_USER_INFO_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            try {
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Accept", "application/json");
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);
                conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
                conn.setConnectTimeout(15000);
                conn.setReadTimeout(15000);

                int responseCode = conn.getResponseCode();
                String responseBody = readResponse(conn, responseCode);

                if (responseCode != HttpURLConnection.HTTP_OK) {
                    log("Qoder OAuth: user info request failed with status " + responseCode);
                    return null;
                }

                return parseUserInfoResponse(responseBody);
            } finally {
                conn.disconnect();
            }
        } catch (IOException e) {
            logError("Qoder OAuth: failed to fetch user info", e);
            return null;
        }
    }

    // ---------------------------------------------------------------
    // HTTP 工具
    // ---------------------------------------------------------------

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
     * 解析设备令牌轮询响应 JSON。
     * <p>
     * Qoder 的轮询成功响应格式：
     * <pre>
     * {
     *   "id": "019e34c9-...",
     *   "token": "dt-xwVyvraeJKzjDfLbM6ANNy9d",
     *   "user_id": "019cbc72-...",
     *   "code_challenge": "...",
     *   "expires_at": "2026-06-16T07:15:04Z",
     *   "refresh_token": "drt-AQHr26ttbx1nAZrKit4g7dns",
     *   "expires_in": 2591999998,
     *   "refresh_token_expires_in": 31103999999,
     *   "refresh_token_expires_at": "2027-05-12T07:15:04Z"
     * }
     * </pre>
     */
    private QoderTokenData parsePollTokenResponse(String json) throws IOException {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查是否有错误信息
            if (obj.has("error")) {
                String error = obj.optString("error", "");
                String errorDesc = obj.optString("error_description", "");
                if (!error.isEmpty()) {
                    throw new IOException("Qoder OAuth: error - " + error + ": " + errorDesc);
                }
            }

            String token = obj.optString("token", "");
            if (token.isEmpty()) {
                // 检查是否有 access_token 字段（刷新端点可能使用此字段名）
                token = obj.optString("access_token", "");
            }
            if (token.isEmpty()) {
                throw new IOException("Qoder OAuth: empty token in response");
            }

            QoderTokenData data = new QoderTokenData();
            data.accessToken = token;
            data.refreshToken = obj.optString("refresh_token", "");
            data.userId = obj.optString("user_id", "");

            // 解析过期时间
            String expiresAtStr = obj.optString("expires_at", "");
            long expiresIn = obj.optLong("expires_in", 0);
            data.expiresAt = parseExpiresAt(expiresAtStr, expiresIn);

            return data;
        } catch (JSONException e) {
            throw new IOException("Qoder OAuth: failed to parse token response", e);
        }
    }

    /**
     * 解析用户信息响应 JSON。
     * <p>
     * Qoder 用户信息端点返回格式：
     * <pre>
     * {
     *   "id": "019cbc72-...",
     *   "name": "...",
     *   "username": "...",
     *   "email": "user@example.com",
     *   "organization_id": "..."
     * }
     * </pre>
     *
     * @return [userId, email] 数组
     */
    private String[] parseUserInfoResponse(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            String userId = obj.optString("id", "");
            String name = obj.optString("name", "");
            String username = obj.optString("username", "");
            String email = obj.optString("email", "");

            if (name.isEmpty()) {
                name = username;
            }

            return new String[]{userId, email};
        } catch (JSONException e) {
            logError("Qoder OAuth: failed to parse user info response", e);
            return null;
        }
    }

    // ---------------------------------------------------------------
    // 工具方法
    // ---------------------------------------------------------------

    /**
     * 生成随机 state 参数。
     */
    private String generateRandomState() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * 生成设备唯一标识。
     */
    private static String generateMachineId() {
        return UUID.randomUUID().toString();
    }

    /**
     * 获取设备型号字符串。
     */
    private static String getDeviceModel() {
        try {
            String manufacturer = android.os.Build.MANUFACTURER != null
                    ? android.os.Build.MANUFACTURER : "unknown";
            String model = android.os.Build.MODEL != null
                    ? android.os.Build.MODEL : "unknown";
            return manufacturer + " " + model;
        } catch (Exception e) {
            return "Android unknown";
        }
    }

    /**
     * URL 编码参数值。
     */
    private static String encodeParam(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return value;
        }
    }

    /**
     * 解析过期时间。
     * <p>
     * Qoder 的过期时间可以是 RFC3339 时间戳字符串，也可以是秒数。
     * 优先使用 RFC3339 字符串，其次使用 expiresIn 秒数，最后使用默认值。
     *
     * @param expiresAtStr RFC3339 时间戳字符串
     * @param expiresIn    从当前时间开始的过期秒数
     * @return 过期时间戳（毫秒），0 表示未知
     */
    private static long parseExpiresAt(String expiresAtStr, long expiresIn) {
        if (expiresAtStr != null && !expiresAtStr.trim().isEmpty()) {
            try {
                TemporalAccessor parsed = DateTimeFormatter.ISO_DATE_TIME.parse(expiresAtStr.trim());
                Instant instant = Instant.from(parsed);
                return instant.toEpochMilli();
            } catch (Exception e) {
                // 尝试解析为数字毫秒时间戳
                try {
                    long ms = Long.parseLong(expiresAtStr.trim());
                    if (ms > 0) {
                        return ms;
                    }
                } catch (NumberFormatException ignored) {
                    // 忽略
                }
            }
        }

        if (expiresIn > 0) {
            return System.currentTimeMillis() + (expiresIn * 1000L);
        }

        // 默认 30 天
        return System.currentTimeMillis() + (30L * 24L * 60L * 60L * 1000L);
    }

    // ---------------------------------------------------------------
    // Getter
    // ---------------------------------------------------------------

    /**
     * 获取设备唯一标识。
     */
    public String getDeviceId() {
        return deviceId;
    }

    /**
     * 获取设备型号。
     */
    private static class DeviceFlowRequest {
        final String codeVerifier;
        final String codeChallenge;
        final String nonce;
        final String machineId;
        final String verificationUriComplete;

        DeviceFlowRequest(String codeVerifier, String codeChallenge,
                          String nonce, String machineId,
                          String verificationUriComplete) {
            this.codeVerifier = codeVerifier;
            this.codeChallenge = codeChallenge;
            this.nonce = nonce;
            this.machineId = machineId;
            this.verificationUriComplete = verificationUriComplete;
        }
    }

    /**
     * 令牌数据，对应 Go 中的 QoderTokenData。
     */
    public static class QoderTokenData {
        public String accessToken;
        public String refreshToken;
        public String userId;
        public long expiresAt; // 毫秒时间戳

        /**
         * 检查令牌是否已过期。
         *
         * @return true 如果当前时间已超过过期时间
         */
        public boolean isExpired() {
            return expiresAt > 0 && System.currentTimeMillis() >= expiresAt;
        }

        /**
         * 获取剩余有效时间（毫秒）。
         *
         * @return 剩余毫秒数，如果已过期或未设置过期时间则返回 0
         */
        public long getRemainingMs() {
            if (expiresAt <= 0) return 0;
            long remaining = expiresAt - System.currentTimeMillis();
            return Math.max(remaining, 0);
        }
    }

    /**
     * 设备流会话状态，跟踪一次完整的设备授权流程。
     */
    private static class DeviceFlowSession {
        final String state;
        final String codeVerifier;
        final String nonce;
        final String machineId;
        final String verificationUriComplete;
        final long expiresAt;       // 毫秒时间戳
        final long pollIntervalMs;  // 推荐轮询间隔
        volatile QoderTokenData tokenResult;

        DeviceFlowSession(String state, String codeVerifier, String nonce,
                          String machineId, String verificationUriComplete,
                          long expiresAt, long pollIntervalMs) {
            this.state = state;
            this.codeVerifier = codeVerifier;
            this.nonce = nonce;
            this.machineId = machineId;
            this.verificationUriComplete = verificationUriComplete;
            this.expiresAt = expiresAt;
            this.pollIntervalMs = pollIntervalMs;
        }

        boolean isExpired() {
            return System.currentTimeMillis() >= expiresAt;
        }
    }

    /**
     * 授权待定异常，表示用户尚未完成授权，应继续轮询。
     */
    private static class AuthorizationPendingException extends Exception {
        AuthorizationPendingException(String message) {
            super(message);
        }
    }
}