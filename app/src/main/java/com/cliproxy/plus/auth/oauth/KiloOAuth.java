package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KiloOAuth - Kilo AI OAuth Provider
 * <p>
 * 实现 Kilo AI 的 OAuth 2.0 Device Authorization Grant 流程 (RFC 8628)。
 * 设备码流程与 GitHub Copilot 类似，使用 Kilo AI 专用认证端点。
 * <p>
 * 流程说明:
 * 1. 调用 startAuth() 向 Kilo 请求设备码，返回用户需要访问的验证 URL
 * 2. 用户在浏览器中打开该 URL，输入用户码完成授权
 * 3. 调用 pollAuthStatus() 轮询令牌端点，检查用户是否已完成授权
 * 4. 调用 handleCallback() 完成令牌交换，获取最终的 AuthResult
 * <p>
 * 对应原版 CLIProxyAPIPlus/internal/auth/kilo/ 中的 Go 实现。
 */
public class KiloOAuth extends OAuthProvider {

    private static final String TAG = "KiloOAuth";

    // ---- 常量 ----

    /** Kilo AI OAuth 客户端 ID */
    private static final String KILO_CLIENT_ID = "kilo_android_client";

    /** Kilo AI OAuth 主机地址 */
    private static final String KILO_OAUTH_HOST = "https://auth.kilo.app";

    /** 设备授权端点 */
    private static final String KILO_DEVICE_CODE_URL = KILO_OAUTH_HOST + "/oauth/device/code";

    /** 令牌端点 */
    private static final String KILO_TOKEN_URL = KILO_OAUTH_HOST + "/oauth/token";

    /** 默认轮询间隔（毫秒） */
    private static final long DEFAULT_POLL_INTERVAL_MS = 5000L;

    /** 最大轮询持续时间（毫秒） */
    private static final long MAX_POLL_DURATION_MS = 15 * 60 * 1000L;

    /** 授权作用域 */
    private static final String SCOPE = "openid email profile offline_access";

    // ---- 设备流状态 ----

    /** 活跃的设备流会话，按 state 参数索引 */
    private final ConcurrentHashMap<String, DeviceFlowSession> activeSessions = new ConcurrentHashMap<>();

    // ---- 认证状态 ----

    /** 当前认证状态标识 */
    private volatile String currentState;

    // ---------------------------------------------------------------
    // 构造
    // ---------------------------------------------------------------

    /**
     * 创建一个 Kilo AI OAuth 提供者实例。
     */
    public KiloOAuth() {
        super("kilo", KILO_DEVICE_CODE_URL, KILO_TOKEN_URL, KILO_CLIENT_ID, "");
    }

    // ---------------------------------------------------------------
    // OAuthProvider 抽象方法实现
    // ---------------------------------------------------------------

    /**
     * 启动设备授权流程。
     * <p>
     * 向 Kilo AI 设备授权端点发起请求，获取设备码和用户验证 URI。
     * 返回的 URL 需要由用户在浏览器中打开以完成授权。
     * 此方法阻塞直到用户完成授权或超时，内部进行轮询。
     *
     * @return 包含 Token 数据的 AuthResult
     * @throws OAuthException 如果设备码请求失败或用户授权超时
     */
    @Override
    public AuthResult startAuth() throws OAuthException {
        try {
            // 1. 请求设备码
            DeviceCodeResponse deviceCode = requestDeviceCode();
            long expiresAt = System.currentTimeMillis() + (deviceCode.expiresIn * 1000L);
            String state = generateState();

            DeviceFlowSession session = new DeviceFlowSession(
                    state,
                    deviceCode.deviceCode,
                    deviceCode.userCode,
                    deviceCode.verificationUriComplete,
                    expiresAt,
                    deviceCode.interval > 0 ? deviceCode.interval * 1000L : DEFAULT_POLL_INTERVAL_MS
            );
            activeSessions.put(state, session);
            currentState = state;

            log("Kilo OAuth: device code obtained, user code: " + deviceCode.userCode);
            log("Kilo OAuth: verification URL: " + deviceCode.verificationUriComplete);

            // 2. 轮询等待用户授权
            long deadline = Math.min(expiresAt, System.currentTimeMillis() + MAX_POLL_DURATION_MS);
            long pollInterval = session.pollIntervalMs;

            while (System.currentTimeMillis() < deadline) {
                try {
                    Thread.sleep(pollInterval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    activeSessions.remove(state);
                    throw new OAuthException("poll_interrupted",
                            "Kilo OAuth: device auth polling interrupted", e);
                }

                try {
                    KiloTokenData tokenData = exchangeDeviceCode(deviceCode.deviceCode);
                    if (tokenData != null) {
                        // 授权成功，构造返回值
                        session.tokenResult = tokenData;
                        String authId = "kilo-" + deviceCode.deviceCode.substring(
                                0, Math.min(8, deviceCode.deviceCode.length()));

                        TokenData td = new TokenData();
                        td.accessToken = tokenData.accessToken;
                        td.refreshToken = tokenData.refreshToken;
                        td.idToken = tokenData.idToken;
                        td.expiresIn = tokenData.expiresIn;
                        td.expireAt = System.currentTimeMillis() + (tokenData.expiresIn * 1000L);

                        // 从 ID Token 提取用户信息
                        if (tokenData.idToken != null && !tokenData.idToken.isEmpty()) {
                            try {
                                JWTClaims claims = parseJWT(tokenData.idToken);
                                if (claims != null) {
                                    td.accountId = claims.accountId;
                                    td.email = claims.email;
                                }
                            } catch (Exception e) {
                                logError("Kilo OAuth: failed to parse ID token", e);
                            }
                        }

                        return new AuthResult(td);
                    }
                } catch (AuthorizationPendingException e) {
                    // 用户尚未授权，继续轮询
                    continue;
                } catch (SlowDownException e) {
                    // 服务器要求减慢轮询速度
                    pollInterval = Math.min(pollInterval + 1000, 10000);
                    continue;
                } catch (IOException e) {
                    String msg = e.getMessage();
                    if (msg != null) {
                        if (msg.contains("access_denied")) {
                            throw new OAuthException("access_denied",
                                    "Kilo OAuth: access denied by user");
                        }
                        if (msg.contains("expired_token")) {
                            throw new OAuthException("expired_token",
                                    "Kilo OAuth: device code has expired. Please start again.");
                        }
                    }
                    // 网络错误，继续轮询
                    logError("Kilo OAuth: poll error", e);
                }
            }

            activeSessions.remove(state);
            throw new OAuthException("poll_timeout",
                    "Kilo OAuth: device authorization timed out");
        } catch (OAuthException e) {
            throw e;
        } catch (IOException e) {
            throw new OAuthException("device_auth_failed",
                    "Kilo OAuth: failed to start device auth flow", e);
        }
    }

    /**
     * 刷新 Access Token。
     * <p>
     * 使用刷新令牌获取新的访问令牌，无需用户重新授权。
     *
     * @param refreshToken 刷新令牌
     * @return 新的 Token 数据
     * @throws OAuthException 如果刷新失败
     */
    @Override
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new OAuthException("refresh_token_required",
                    "Kilo OAuth: refresh token is required");
        }

        try {
            String body = "client_id=" + encodeParam(KILO_CLIENT_ID)
                    + "&grant_type=" + encodeParam("refresh_token")
                    + "&refresh_token=" + encodeParam(refreshToken.trim())
                    + "&scope=" + encodeParam(SCOPE);

            HttpURLConnection conn = createPostConnection(KILO_TOKEN_URL, body);
            try {
                int responseCode = conn.getResponseCode();
                String responseBody = readResponse(conn, responseCode);

                if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED
                        || responseCode == HttpURLConnection.HTTP_FORBIDDEN) {
                    throw new IOException("Kilo OAuth: refresh token rejected (status " + responseCode + ")");
                }

                if (responseCode != HttpURLConnection.HTTP_OK) {
                    throw new IOException("Kilo OAuth: refresh failed with status " + responseCode
                            + ": " + responseBody);
                }

                return parseRefreshTokenResponse(responseBody, refreshToken.trim());
            } finally {
                conn.disconnect();
            }
        } catch (IOException e) {
            logError("Kilo OAuth: token refresh failed", e);
            throw new OAuthException("refresh_failed",
                    "Kilo OAuth: token refresh request failed: " + e.getMessage(), e);
        }
    }

    /**
     * 轮询授权状态。
     * <p>
     * 向 Kilo AI 令牌端点发起一次设备码交换请求，检查用户是否已完成授权。
     * 如果授权完成，内部会缓存令牌结果，后续调用 {@link #handleCallback} 可返回该结果。
     *
     * @param state 授权状态标识（由 {@link #startAuth()} 生成）
     * @return true 如果用户已完成授权且令牌已就绪，false 表示仍需等待
     */
    public boolean pollAuthStatus(String state) {
        DeviceFlowSession session = activeSessions.get(state);
        if (session == null) {
            return false;
        }

        if (session.isExpired()) {
            activeSessions.remove(state);
            return false;
        }

        if (session.tokenResult != null) {
            return true;
        }

        try {
            KiloTokenData tokenData = exchangeDeviceCode(session.deviceCode);
            if (tokenData != null) {
                session.tokenResult = tokenData;
                return true;
            }
        } catch (AuthorizationPendingException e) {
            // 用户尚未授权，继续轮询
            return false;
        } catch (SlowDownException e) {
            // 服务器要求减慢速度
            return false;
        } catch (IOException e) {
            // 网络错误，由调用方决定重试策略
            return false;
        }

        return false;
    }

    /**
     * 处理授权回调并返回认证结果。
     * <p>
     * 在设备流中，此方法从 {@link #pollAuthStatus} 缓存的结果中提取令牌，
     * 构造 {@link AuthResult} 并清理会话状态。
     * 参数 code 在设备流中可传空字符串。
     *
     * @param code  授权码（设备流中可传空字符串）
     * @param state 状态参数（由 {@link #startAuth()} 生成，用于 CSRF 验证）
     * @return 认证结果，如果会话无效或令牌未就绪则返回 null
     */
    public AuthResult handleCallback(String code, String state) {
        DeviceFlowSession session = activeSessions.remove(state);
        if (session == null || session.tokenResult == null) {
            return null;
        }

        // 验证 state 匹配
        if (!this.currentState.equals(state)) {
            return null;
        }

        KiloTokenData token = session.tokenResult;

        TokenData tokenData = new TokenData();
        tokenData.accessToken = token.accessToken;
        tokenData.refreshToken = token.refreshToken;
        tokenData.idToken = token.idToken;
        tokenData.expiresIn = token.expiresIn;
        tokenData.expireAt = System.currentTimeMillis() + (token.expiresIn * 1000L);

        // 从 ID Token 提取用户信息
        if (token.idToken != null && !token.idToken.isEmpty()) {
            try {
                JWTClaims claims = parseJWT(token.idToken);
                if (claims != null) {
                    tokenData.accountId = claims.accountId;
                    tokenData.email = claims.email;
                }
            } catch (Exception e) {
                logError("Kilo OAuth: failed to parse ID token", e);
            }
        }

        String authId = "kilo-" + session.deviceCode.substring(
                0, Math.min(8, session.deviceCode.length()));
        return new AuthResult(tokenData);
    }

    // ---------------------------------------------------------------
    // 设备流 API 请求
    // ---------------------------------------------------------------

    /**
     * 向 Kilo AI 设备授权端点请求设备码。
     *
     * @return 设备码响应
     * @throws IOException 如果请求失败
     */
    private DeviceCodeResponse requestDeviceCode() throws IOException {
        String body = "client_id=" + encodeParam(KILO_CLIENT_ID)
                + "&scope=" + encodeParam(SCOPE);

        HttpURLConnection conn = createPostConnection(KILO_DEVICE_CODE_URL, body);
        try {
            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Kilo OAuth: device code request failed with status " + responseCode
                        + ": " + responseBody);
            }

            return parseDeviceCodeResponse(responseBody);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 向 Kilo AI 令牌端点发起设备码交换请求。
     *
     * @param deviceCode 设备码
     * @return 令牌数据，如果用户尚未授权则抛出 AuthorizationPendingException
     * @throws IOException                   如果请求失败
     * @throws AuthorizationPendingException 如果用户尚未授权（应继续轮询）
     * @throws SlowDownException            如果服务器要求减慢轮询速度
     */
    private KiloTokenData exchangeDeviceCode(String deviceCode)
            throws IOException, AuthorizationPendingException, SlowDownException {
        String body = "client_id=" + encodeParam(KILO_CLIENT_ID)
                + "&device_code=" + encodeParam(deviceCode)
                + "&grant_type=" + encodeParam("urn:ietf:params:oauth:grant-type:device_code");

        HttpURLConnection conn = createPostConnection(KILO_TOKEN_URL, body);
        try {
            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            return parseTokenResponse(responseBody);
        } finally {
            conn.disconnect();
        }
    }

    // ---------------------------------------------------------------
    // HTTP 工具
    // ---------------------------------------------------------------

    /**
     * 创建 POST 请求连接并设置 Kilo AI 专用请求头。
     */
    private HttpURLConnection createPostConnection(String urlStr, String body) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
        conn.setDoOutput(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(30000);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = body.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
            os.flush();
        }

        return conn;
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
     * 解析设备码响应 JSON。
     */
    private DeviceCodeResponse parseDeviceCodeResponse(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            DeviceCodeResponse resp = new DeviceCodeResponse();
            resp.deviceCode = obj.optString("device_code", "");
            resp.userCode = obj.optString("user_code", "");
            resp.verificationUri = obj.optString("verification_uri", "");
            resp.verificationUriComplete = obj.optString("verification_uri_complete", "");
            resp.expiresIn = obj.optInt("expires_in", 900);
            resp.interval = obj.optInt("interval", 5);
            return resp;
        } catch (org.json.JSONException e) {
            throw new RuntimeException("Kilo OAuth: failed to parse device code response", e);
        }
    }

    /**
     * 解析令牌响应 JSON。
     * <p>
     * Kilo AI 对 pending 状态也返回 200，因此需要检查 error 字段。
     *
     * @throws AuthorizationPendingException 如果用户尚未授权
     * @throws SlowDownException            如果服务器要求减慢轮询速度
     */
    private KiloTokenData parseTokenResponse(String json)
            throws IOException, AuthorizationPendingException, SlowDownException {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查 OAuth 错误
            String error = obj.optString("error", "");
            if (!error.isEmpty()) {
                String errorDesc = obj.optString("error_description", "");
                switch (error) {
                    case "authorization_pending":
                        throw new AuthorizationPendingException("User has not yet authorized");
                    case "slow_down":
                        throw new SlowDownException("Polling too fast, slow down");
                    case "expired_token":
                        throw new IOException("Kilo OAuth: device code expired");
                    case "access_denied":
                        throw new IOException("Kilo OAuth: access denied by user");
                    default:
                        throw new IOException("Kilo OAuth: error - " + error + ": " + errorDesc);
                }
            }

            String accessToken = obj.optString("access_token", "");
            if (accessToken.isEmpty()) {
                throw new IOException("Kilo OAuth: empty access token in response");
            }

            KiloTokenData token = new KiloTokenData();
            token.accessToken = accessToken;
            token.refreshToken = obj.optString("refresh_token", "");
            token.idToken = obj.optString("id_token", "");
            token.tokenType = obj.optString("token_type", "Bearer");
            token.scope = obj.optString("scope", "");

            double expiresIn = obj.optDouble("expires_in", 0);
            token.expiresIn = (int) expiresIn;
            if (expiresIn > 0) {
                token.expiresAt = System.currentTimeMillis() / 1000L + (long) expiresIn;
            }

            return token;
        } catch (org.json.JSONException e) {
            throw new IOException("Kilo OAuth: failed to parse token response", e);
        }
    }

    /**
     * 解析刷新令牌响应 JSON。
     * <p>
     * 刷新令牌响应与授权响应格式类似，但可能不返回新的 refresh_token。
     * 如果响应中没有新的 refresh_token，则使用已有的。
     */
    private TokenData parseRefreshTokenResponse(String json, String existingRefreshToken) throws IOException {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查错误
            String error = obj.optString("error", "");
            if (!error.isEmpty()) {
                String errorDesc = obj.optString("error_description", "");
                if ("invalid_grant".equals(error)) {
                    throw new IOException("Kilo OAuth: refresh token invalid or revoked");
                }
                throw new IOException("Kilo OAuth: refresh error - " + error + ": " + errorDesc);
            }

            String accessToken = obj.optString("access_token", "");
            if (accessToken.isEmpty()) {
                throw new IOException("Kilo OAuth: empty access token in refresh response");
            }

            TokenData tokenData = new TokenData();
            tokenData.accessToken = accessToken;
            // 刷新响应可能返回新的 refresh_token，也可能返回原有的
            String newRefreshToken = obj.optString("refresh_token", "");
            tokenData.refreshToken = !newRefreshToken.isEmpty() ? newRefreshToken : existingRefreshToken;
            tokenData.idToken = obj.optString("id_token", "");
            tokenData.expiresIn = obj.optInt("expires_in", 3600);
            tokenData.expireAt = System.currentTimeMillis() + (tokenData.expiresIn * 1000L);

            // 从 ID Token 提取用户信息
            if (tokenData.idToken != null && !tokenData.idToken.isEmpty()) {
                try {
                    JWTClaims claims = parseJWT(tokenData.idToken);
                    if (claims != null) {
                        tokenData.accountId = claims.accountId;
                        tokenData.email = claims.email;
                    }
                } catch (Exception e) {
                    logError("Kilo OAuth: failed to parse ID token in refresh", e);
                }
            }

            return tokenData;
        } catch (org.json.JSONException e) {
            throw new IOException("Kilo OAuth: failed to parse refresh token response", e);
        }
    }

    // ---------------------------------------------------------------
    // JWT 解析
    // ---------------------------------------------------------------

    /**
     * 解析 JWT Token 的 claims 部分（不验证签名）。
     *
     * @param token JWT 格式的 ID Token
     * @return 解析后的 claims，解析失败时返回 null
     */
    public JWTClaims parseJWT(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                logError("Kilo OAuth: invalid JWT format: expected 3 parts, got " + parts.length, null);
                return null;
            }

            byte[] claimsData = java.util.Base64.getUrlDecoder().decode(padBase64(parts[1]));
            String json = new String(claimsData, StandardCharsets.UTF_8);
            return new JWTClaims(json);
        } catch (Exception e) {
            logError("Kilo OAuth: failed to parse JWT", e);
            return null;
        }
    }

    /**
     * 对 Base64 URL-safe 字符串进行填充，使其长度满足 Base64 解码要求。
     */
    private String padBase64(String input) {
        int remainder = input.length() % 4;
        if (remainder == 2) return input + "==";
        if (remainder == 3) return input + "=";
        return input;
    }

    /**
     * JWT Claims 解析结果。
     * <p>
     * 包含 Kilo AI ID Token 中的标准声明。
     */
    public static class JWTClaims {
        public final String email;
        public final String sub;
        public final String accountId;
        public final String rawJson;

        JWTClaims(String json) throws org.json.JSONException {
            this.rawJson = json;
            JSONObject obj = new JSONObject(json);
            this.email = obj.optString("email", "");
            this.sub = obj.optString("sub", "");

            // 尝试从标准 sub 和自定义 claims 中提取账户 ID
            String accountIdValue = obj.optString("kilo_account_id", "");
            if (accountIdValue.isEmpty()) {
                accountIdValue = obj.optString("sub", "");
            }
            this.accountId = accountIdValue;
        }

        public String getAccountId() {
            return accountId;
        }

        public String getEmail() {
            return email;
        }
    }

    // ---------------------------------------------------------------
    // 工具方法
    // ---------------------------------------------------------------

    /**
     * 生成随机状态标识。
     */
    private String generateState() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * URL 编码参数值。
     */
    private static String encodeParam(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    // ---------------------------------------------------------------
    // 内部类型
    // ---------------------------------------------------------------

    /**
     * 设备码响应，对应 Go 中的 DeviceCodeResponse。
     */
    private static class DeviceCodeResponse {
        String deviceCode;
        String userCode;
        String verificationUri;
        String verificationUriComplete;
        int expiresIn;
        int interval;
    }

    /**
     * 令牌数据，对应 Go 中的 KiloTokenData。
     */
    public static class KiloTokenData {
        public String accessToken;
        public String refreshToken;
        public String idToken;
        public String tokenType;
        public long expiresAt;   // Unix 时间戳（秒）
        public int expiresIn;    // 过期时间（秒）
        public String scope;

        /**
         * 检查令牌是否已过期。
         *
         * @return true 如果当前时间已超过过期时间
         */
        public boolean isExpired() {
            return expiresAt > 0 && System.currentTimeMillis() / 1000L >= expiresAt;
        }

        /**
         * 获取剩余有效时间（秒）。
         *
         * @return 剩余秒数，如果已过期或未设置过期时间则返回 0
         */
        public long getRemainingSeconds() {
            if (expiresAt <= 0) return 0;
            long remaining = expiresAt - System.currentTimeMillis() / 1000L;
            return Math.max(remaining, 0);
        }
    }

    /**
     * 设备流会话状态，跟踪一次完整的设备授权流程。
     */
    private static class DeviceFlowSession {
        final String state;
        final String deviceCode;
        final String userCode;
        final String verificationUriComplete;
        final long expiresAt;       // 毫秒时间戳
        final long pollIntervalMs;  // 推荐轮询间隔
        volatile KiloTokenData tokenResult;

        DeviceFlowSession(String state, String deviceCode, String userCode,
                          String verificationUriComplete, long expiresAt, long pollIntervalMs) {
            this.state = state;
            this.deviceCode = deviceCode;
            this.userCode = userCode;
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

    /**
     * 减慢速度异常，表示服务器要求减慢轮询频率。
     */
    private static class SlowDownException extends Exception {
        SlowDownException(String message) {
            super(message);
        }
    }

    // ---------------------------------------------------------------
    // Getter
    // ---------------------------------------------------------------

    /**
     * 获取当前认证状态标识。
     *
     * @return 当前 state 字符串，如果未启动认证则返回 null
     */
    public String getCurrentState() {
        return currentState;
    }

    /**
     * 检查是否有活跃的设备流会话。
     *
     * @return true 如果存在至少一个未过期的会话
     */
    public boolean hasActiveSession() {
        long now = System.currentTimeMillis();
        for (DeviceFlowSession session : activeSessions.values()) {
            if (!session.isExpired()) {
                return true;
            }
        }
        return false;
    }
}