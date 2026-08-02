package com.cliproxy.plus.auth.oauth;

import android.os.Build;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * KimiOAuth - Moonshot Kimi OAuth Provider
 * <p>
 * 实现 Kimi (Moonshot AI) 的 OAuth 2.0 Device Authorization Grant 流程 (RFC 8628)。
 * 对应原版 CLIProxyAPIPlus/internal/auth/kimi/ 中的 Go 实现。
 * <p>
 * 流程说明:
 * 1. 调用 startAuth() 向 Kimi 请求设备码，返回用户需要访问的验证 URL
 * 2. 用户在浏览器中打开该 URL，输入用户码完成授权
 * 3. 调用 pollAuthStatus() 轮询令牌端点，检查用户是否已完成授权
 * 4. 调用 handleCallback() 完成令牌交换，获取最终的 AuthResult
 */
public class KimiOAuth extends OAuthProvider {

    private static final String TAG = "KimiOAuth";

    // ---- 常量 ----

    /** Kimi OAuth 客户端 ID */
    private static final String KIMI_CLIENT_ID = "17e5f671-d194-4dfb-9706-5516cb48c098";

    /** Kimi OAuth 主机地址 */
    private static final String KIMI_OAUTH_HOST = "https://auth.kimi.com";

    /** 设备授权端点 */
    private static final String KIMI_DEVICE_CODE_URL = KIMI_OAUTH_HOST + "/api/oauth/device_authorization";

    /** 令牌端点 */
    private static final String KIMI_TOKEN_URL = KIMI_OAUTH_HOST + "/api/oauth/token";

    /** 默认轮询间隔（毫秒） */
    private static final long DEFAULT_POLL_INTERVAL_MS = 5000L;

    /** 最大轮询持续时间（毫秒） */
    private static final long MAX_POLL_DURATION_MS = 15 * 60 * 1000L;

    /** 平台标识 */
    private static final String PLATFORM = "CLIProxyPlus";

    /** 版本号 */
    private static final String VERSION = "1.0.0";

    /** 重定向 URI（设备流中不使用，但 OAuthProvider 基类需要） */
    private static final String REDIRECT_URI = "https://auth.kimi.com/callback";

    // ---- 设备流状态 ----

    /** 活跃的设备流会话，按 state 参数索引 */
    private final ConcurrentHashMap<String, DeviceFlowSession> activeSessions = new ConcurrentHashMap<>();

    // ---- 设备信息 ----

    /** 设备唯一标识 */
    private final String deviceId;

    /** 设备名称 */
    private final String deviceName;

    /** 设备型号 */
    private final String deviceModel;

    // ---------------------------------------------------------------
    // 构造
    // ---------------------------------------------------------------

    /**
     * 创建一个 Kimi OAuth 提供者实例。
     */
    public KimiOAuth() {
        super("kimi", KIMI_DEVICE_CODE_URL, KIMI_TOKEN_URL, KIMI_CLIENT_ID, REDIRECT_URI);
        this.deviceId = UUID.randomUUID().toString().replace("-", "");
        this.deviceName = getDeviceName();
        this.deviceModel = getDeviceModel();
    }

    /**
     * 创建一个 Kimi OAuth 提供者实例，使用指定的设备 ID。
     *
     * @param deviceId 设备唯一标识，为空时自动生成
     */
    public KimiOAuth(String deviceId) {
        super("kimi", KIMI_DEVICE_CODE_URL, KIMI_TOKEN_URL, KIMI_CLIENT_ID, REDIRECT_URI);
        this.deviceId = (deviceId != null && !deviceId.trim().isEmpty())
                ? deviceId.trim()
                : UUID.randomUUID().toString().replace("-", "");
        this.deviceName = getDeviceName();
        this.deviceModel = getDeviceModel();
    }

    // ---------------------------------------------------------------
    // OAuthProvider 抽象方法实现
    // ---------------------------------------------------------------

    /**
     * 启动设备授权流程。
     * <p>
     * 向 Kimi 设备授权端点发起请求，获取设备码和用户验证 URI。
     * 返回的 URL 需要由用户在浏览器中打开以完成授权。
     *
     * @return 用户验证 URI（verification_uri_complete），用户应在浏览器中打开此 URL
     * @throws RuntimeException 如果设备码请求失败
     */
    @Override
    public String startAuth() {
        try {
            DeviceCodeResponse deviceCode = requestDeviceCode();
            long expiresAt = System.currentTimeMillis() + (deviceCode.expiresIn * 1000L);

            DeviceFlowSession session = new DeviceFlowSession(
                    state,
                    deviceCode.deviceCode,
                    deviceCode.userCode,
                    deviceCode.verificationUriComplete,
                    expiresAt,
                    deviceCode.interval > 0 ? deviceCode.interval * 1000L : DEFAULT_POLL_INTERVAL_MS
            );
            activeSessions.put(state, session);

            return deviceCode.verificationUriComplete;
        } catch (IOException e) {
            throw new RuntimeException("Kimi OAuth: failed to start device auth flow", e);
        }
    }

    /**
     * 轮询授权状态。
     * <p>
     * 向 Kimi 令牌端点发起一次设备码交换请求，检查用户是否已完成授权。
     * 如果授权完成，内部会缓存令牌结果，后续调用 {@link #handleCallback} 可返回该结果。
     *
     * @param state 授权状态标识（由 {@link #startAuth()} 生成）
     * @return true 如果用户已完成授权且令牌已就绪，false 表示仍需等待
     */
    @Override
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
            KimiTokenData tokenData = exchangeDeviceCode(session.deviceCode);
            if (tokenData != null) {
                session.tokenResult = tokenData;
                return true;
            }
        } catch (AuthorizationPendingException e) {
            // 用户尚未授权，继续轮询
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
     * 参数 code 和 state 在标准授权码流中由回调携带，在设备流中 code 可传空字符串。
     *
     * @param code  授权码（设备流中可传空字符串）
     * @param state 状态参数（由 {@link #startAuth()} 生成，用于 CSRF 验证）
     * @return 认证结果，如果会话无效或令牌未就绪则返回 null
     */
    @Override
    public AuthResult handleCallback(String code, String state) {
        DeviceFlowSession session = activeSessions.remove(state);
        if (session == null || session.tokenResult == null) {
            return null;
        }

        // 验证 state 匹配
        if (!this.state.equals(state)) {
            return null;
        }

        KimiTokenData token = session.tokenResult;

        // 从过期时间戳计算 expiresAt
        long expiresAt = token.expiresAt > 0 ? token.expiresAt * 1000L : 0L;

        String authId = "kimi-" + deviceId.substring(0, 8);
        return new AuthResult(authId, token.accessToken, "", expiresAt);
    }

    // ---------------------------------------------------------------
    // 设备流 API 请求
    // ---------------------------------------------------------------

    /**
     * 向 Kimi 设备授权端点请求设备码。
     *
     * @return 设备码响应
     * @throws IOException 如果请求失败
     */
    private DeviceCodeResponse requestDeviceCode() throws IOException {
        String body = "client_id=" + encodeParam(KIMI_CLIENT_ID);

        HttpURLConnection conn = createPostConnection(KIMI_DEVICE_CODE_URL, body);
        try {
            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Kimi OAuth: device code request failed with status " + responseCode
                        + ": " + responseBody);
            }

            return parseDeviceCodeResponse(responseBody);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 向 Kimi 令牌端点发起设备码交换请求。
     *
     * @param deviceCode 设备码
     * @return 令牌数据，如果用户尚未授权则抛出 AuthorizationPendingException
     * @throws IOException                    如果请求失败
     * @throws AuthorizationPendingException  如果用户尚未授权（应继续轮询）
     */
    private KimiTokenData exchangeDeviceCode(String deviceCode) throws IOException, AuthorizationPendingException {
        String body = "client_id=" + encodeParam(KIMI_CLIENT_ID)
                + "&device_code=" + encodeParam(deviceCode)
                + "&grant_type=" + encodeParam("urn:ietf:params:oauth:grant-type:device_code");

        HttpURLConnection conn = createPostConnection(KIMI_TOKEN_URL, body);
        try {
            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            return parseTokenResponse(responseBody);
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 刷新访问令牌。
     * <p>
     * 使用刷新令牌获取新的访问令牌，无需用户重新授权。
     *
     * @param refreshToken 刷新令牌
     * @return 新的令牌数据
     * @throws IOException 如果刷新请求失败
     */
    public KimiTokenData refreshToken(String refreshToken) throws IOException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new IllegalArgumentException("Kimi OAuth: refresh token is required");
        }

        String body = "client_id=" + encodeParam(KIMI_CLIENT_ID)
                + "&grant_type=" + encodeParam("refresh_token")
                + "&refresh_token=" + encodeParam(refreshToken.trim());

        HttpURLConnection conn = createPostConnection(KIMI_TOKEN_URL, body);
        try {
            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED
                    || responseCode == HttpURLConnection.HTTP_FORBIDDEN) {
                throw new IOException("Kimi OAuth: refresh token rejected (status " + responseCode + ")");
            }

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new IOException("Kimi OAuth: refresh failed with status " + responseCode
                        + ": " + responseBody);
            }

            return parseTokenResponse(responseBody);
        } finally {
            conn.disconnect();
        }
    }

    // ---------------------------------------------------------------
    // HTTP 工具
    // ---------------------------------------------------------------

    /**
     * 创建 POST 请求连接并设置 Kimi 专用请求头。
     */
    private HttpURLConnection createPostConnection(String urlStr, String body) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
        conn.setRequestProperty("Accept", "application/json");
        conn.setRequestProperty("X-Msh-Platform", PLATFORM);
        conn.setRequestProperty("X-Msh-Version", VERSION);
        conn.setRequestProperty("X-Msh-Device-Name", deviceName);
        conn.setRequestProperty("X-Msh-Device-Model", deviceModel);
        conn.setRequestProperty("X-Msh-Device-Id", deviceId);
        conn.setDoOutput(true);
        conn.setConnectTimeout(30000);
        conn.setReadTimeout(30000);

        try (OutputStream os = conn.getOutputStream()) {
            byte[] input = body.getBytes(StandardCharsets.UTF_8);
            os.write(input, 0, input.length);
        }

        return conn;
    }

    /**
     * 读取 HTTP 响应体。
     */
    private String readResponse(HttpURLConnection conn, int responseCode) throws IOException {
        BufferedReader reader;
        if (responseCode >= HttpURLConnection.HTTP_BAD_REQUEST) {
            reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8));
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
            org.json.JSONObject obj = new org.json.JSONObject(json);
            DeviceCodeResponse resp = new DeviceCodeResponse();
            resp.deviceCode = obj.optString("device_code", "");
            resp.userCode = obj.optString("user_code", "");
            resp.verificationUri = obj.optString("verification_uri", "");
            resp.verificationUriComplete = obj.optString("verification_uri_complete", "");
            resp.expiresIn = obj.optInt("expires_in", 0);
            resp.interval = obj.optInt("interval", 5);
            return resp;
        } catch (org.json.JSONException e) {
            throw new RuntimeException("Kimi OAuth: failed to parse device code response", e);
        }
    }

    /**
     * 解析令牌响应 JSON。
     * <p>
     * Kimi 对 pending 状态也返回 200，因此需要检查 error 字段。
     *
     * @throws AuthorizationPendingException 如果用户尚未授权
     */
    private KimiTokenData parseTokenResponse(String json) throws IOException, AuthorizationPendingException {
        try {
            org.json.JSONObject obj = new org.json.JSONObject(json);

            // 检查 OAuth 错误
            String error = obj.optString("error", "");
            if (!error.isEmpty()) {
                String errorDesc = obj.optString("error_description", "");
                switch (error) {
                    case "authorization_pending":
                        throw new AuthorizationPendingException("User has not yet authorized");
                    case "slow_down":
                        throw new AuthorizationPendingException("Polling too fast, slow down");
                    case "expired_token":
                        throw new IOException("Kimi OAuth: device code expired");
                    case "access_denied":
                        throw new IOException("Kimi OAuth: access denied by user");
                    default:
                        throw new IOException("Kimi OAuth: error - " + error + ": " + errorDesc);
                }
            }

            String accessToken = obj.optString("access_token", "");
            if (accessToken.isEmpty()) {
                throw new IOException("Kimi OAuth: empty access token in response");
            }

            KimiTokenData token = new KimiTokenData();
            token.accessToken = accessToken;
            token.refreshToken = obj.optString("refresh_token", "");
            token.tokenType = obj.optString("token_type", "Bearer");
            token.scope = obj.optString("scope", "");

            double expiresIn = obj.optDouble("expires_in", 0);
            if (expiresIn > 0) {
                token.expiresAt = System.currentTimeMillis() / 1000L + (long) expiresIn;
            }

            return token;
        } catch (org.json.JSONException e) {
            throw new IOException("Kimi OAuth: failed to parse token response", e);
        }
    }

    // ---------------------------------------------------------------
    // 设备信息获取
    // ---------------------------------------------------------------

    /**
     * 获取设备名称。
     */
    private static String getDeviceName() {
        try {
            return Build.MODEL != null ? Build.MODEL : "unknown";
        } catch (Exception e) {
            return "unknown";
        }
    }

    /**
     * 获取设备型号字符串。
     */
    private static String getDeviceModel() {
        try {
            String manufacturer = Build.MANUFACTURER != null ? Build.MANUFACTURER : "unknown";
            String model = Build.MODEL != null ? Build.MODEL : "unknown";
            String device = Build.DEVICE != null ? Build.DEVICE : "unknown";
            return manufacturer + " " + model + " (" + device + ")";
        } catch (Exception e) {
            return "Android unknown";
        }
    }

    // ---------------------------------------------------------------
    // 工具方法
    // ---------------------------------------------------------------

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
     * 令牌数据，对应 Go 中的 KimiTokenData。
     */
    public static class KimiTokenData {
        public String accessToken;
        public String refreshToken;
        public String tokenType;
        public long expiresAt;   // Unix 时间戳（秒）
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
        volatile KimiTokenData tokenResult;

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
     * 获取设备名称。
     */
    public String getDeviceName() {
        return deviceName;
    }

    /**
     * 获取设备型号。
     */
    public String getDeviceModel() {
        return deviceModel;
    }
}