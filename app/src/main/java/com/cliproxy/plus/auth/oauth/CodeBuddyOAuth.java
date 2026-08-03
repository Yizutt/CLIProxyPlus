package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;
import org.json.JSONException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * CodeBuddy OAuth2 认证实现。
 * <p>
 * 处理 CodeBuddy AI 服务的自定义 OAuth2 认证流程，包括获取认证状态、轮询令牌和刷新令牌。
 * 使用自定义 HTTP 请求头进行认证，不使用标准 OAuth2 授权码流程。
 * <p>
 * 1:1 从 CLIProxyAPIPlus/internal/auth/codebuddy/ 移植的 Go 代码。
 */
public class CodeBuddyOAuth {

    private static final String TAG = "CodeBuddyOAuth";

    // ========================================================================
    // OAuth Configuration Constants (1:1 port of Go constants)
    // ========================================================================

    /** CodeBuddy API 基础 URL。 */
    public static final String BASE_URL = "https://copilot.tencent.com";

    /** 默认域名。 */
    public static final String DEFAULT_DOMAIN = "www.codebuddy.cn";

    /** User-Agent 头。 */
    public static final String USER_AGENT = "CLI/2.63.2 CodeBuddy/2.63.2";

    /** 获取认证状态的路径。 */
    private static final String CODE_BUDDY_STATE_PATH = "/v2/plugin/auth/state";

    /** 获取令牌的路径。 */
    private static final String CODE_BUDDY_TOKEN_PATH = "/v2/plugin/auth/token";

    /** 刷新令牌的路径。 */
    private static final String CODE_BUDDY_REFRESH_PATH = "/v2/plugin/auth/token/refresh";

    /** 轮询间隔（5 秒）。 */
    private static final long POLL_INTERVAL_MS = 5000L;

    /** 最大轮询持续时间（5 分钟）。 */
    private static final long MAX_POLL_DURATION_MS = 5 * 60 * 1000L;

    /** 登录待处理状态码。 */
    private static final int CODE_LOGIN_PENDING = 11217;

    /** 成功状态码。 */
    private static final int CODE_SUCCESS = 0;

    /** HTTP 连接超时（30 秒）。 */
    private static final int CONNECT_TIMEOUT = 30000;

    /** HTTP 读取超时（30 秒）。 */
    private static final int READ_TIMEOUT = 30000;

    // ========================================================================
    // Data Classes (1:1 port of Go structs)
    // ========================================================================

    /**
     * AuthState 保存认证状态 API 返回的状态和认证 URL。
     * 1:1 移植 Go AuthState 结构体。
     */
    public static class AuthState {
        /** OAuth 状态值。 */
        public final String state;
        /** 用户登录 URL。 */
        public final String authUrl;

        AuthState(String state, String authUrl) {
            this.state = state;
            this.authUrl = authUrl;
        }
    }

    /**
     * CodeBuddyTokenStorage 存储 CodeBuddy API 认证的 OAuth 令牌信息。
     * 保持与现有认证系统的兼容性，同时添加 CodeBuddy 特定字段用于管理访问令牌和用户账户信息。
     * <p>
     * 1:1 移植 Go CodeBuddyTokenStorage 结构体。
     */
    public static class CodeBuddyTokenStorage {
        /** OAuth2 访问令牌，用于 API 请求的认证。 */
        public String accessToken;
        /** OAuth2 刷新令牌，用于获取新的访问令牌。 */
        public String refreshToken;
        /** 访问令牌的过期时间（秒）。 */
        public long expiresIn;
        /** 刷新令牌的过期时间（秒）。 */
        public long refreshExpiresIn;
        /** 令牌类型，通常为 "bearer"。 */
        public String tokenType;
        /** CodeBuddy 服务域名/区域。 */
        public String domain;
        /** 与此令牌关联的用户 ID。 */
        public String userId;
        /** 认证提供商类型，始终为 "codebuddy"。 */
        public String type;

        public CodeBuddyTokenStorage() {
            this.type = "codebuddy";
        }
    }

    // ========================================================================
    // Inner response holder (1:1 port of Go pollResponse struct)
    // ========================================================================

    /**
     * 轮询认证令牌的响应数据结构。
     * 1:1 移植 Go pollResponse 结构体。
     */
    private static class PollResponseData {
        String accessToken;
        String refreshToken;
        long expiresIn;
        String tokenType;
        String domain;

        static PollResponseData fromJson(JSONObject json) {
            PollResponseData data = new PollResponseData();
            data.accessToken = json.optString("accessToken", "");
            data.refreshToken = json.optString("refreshToken", "");
            data.expiresIn = json.optLong("expiresIn", 0);
            data.tokenType = json.optString("tokenType", "");
            data.domain = json.optString("domain", "");
            return data;
        }
    }

    // ========================================================================
    // Fields
    // ========================================================================

    private final String baseURL;

    /**
     * 创建一个新的 CodeBuddyOAuth 实例，使用默认基础 URL。
     * 1:1 移植 Go NewCodeBuddyAuth()。
     */
    public CodeBuddyOAuth() {
        this.baseURL = BASE_URL;
    }

    /**
     * 创建一个新的 CodeBuddyOAuth 实例并指定基础 URL。
     *
     * @param baseURL 自定义基础 URL；如果为 null 或空则使用默认值
     */
    public CodeBuddyOAuth(String baseURL) {
        this.baseURL = (baseURL != null && !baseURL.isEmpty()) ? baseURL : BASE_URL;
    }

    // ========================================================================
    // FetchAuthState (1:1 port of Go FetchAuthState)
    // ========================================================================

    /**
     * 调用 POST /v2/plugin/auth/state?platform=CLI 获取认证状态和登录 URL。
     * <p>
     * 请求体为 JSON 对象 {}，携带自定义请求头（Accept、Content-Type、X-Requested-With、
     * X-Domain、X-No-Authorization、X-No-User-Id、X-No-Enterprise-Id、X-No-Department-Info、
     * X-Product、User-Agent、X-Request-ID）。
     * <p>
     * 响应格式：{"code":0, "data":{"state":"...", "authUrl":"..."}}
     * <p>
     * 1:1 移植 Go FetchAuthState()。
     *
     * @return 包含 state 和 authUrl 的 AuthState 对象
     * @throws IOException 如果请求失败、状态码非 200、响应 code 非 0，或缺少必要字段
     */
    public AuthState fetchAuthState() throws IOException {
        String stateURL = baseURL + CODE_BUDDY_STATE_PATH + "?platform=CLI";
        String requestId = UUID.randomUUID().toString();

        Log.d(TAG, "Fetching auth state from: " + stateURL);

        byte[] postData = "{}".getBytes(StandardCharsets.UTF_8);
        HttpURLConnection conn = (HttpURLConnection) new URL(stateURL).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Accept", "application/json, text/plain, */*");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-Requested-With", "XMLHttpRequest");
            conn.setRequestProperty("X-Domain", "copilot.tencent.com");
            conn.setRequestProperty("X-No-Authorization", "true");
            conn.setRequestProperty("X-No-User-Id", "true");
            conn.setRequestProperty("X-No-Enterprise-Id", "true");
            conn.setRequestProperty("X-No-Department-Info", "true");
            conn.setRequestProperty("X-Product", "SaaS");
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.setRequestProperty("X-Request-ID", requestId);
            conn.setDoOutput(true);
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, responseCode);

            if (responseCode != HttpURLConnection.HTTP_OK) {
                String errorMsg = "codebuddy: auth state request returned status "
                        + responseCode + ": " + responseBody;
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            JSONObject json = parseJson(responseBody);
            int code = json.optInt("code", -1);
            if (code != CODE_SUCCESS) {
                String msg = json.optString("msg", "");
                String errorMsg = "codebuddy: auth state request failed with code "
                        + code + ": " + msg;
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            JSONObject data = json.optJSONObject("data");
            if (data == null) {
                String errorMsg = "codebuddy: auth state response missing data";
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            String state = data.optString("state", "");
            String authUrl = data.optString("authUrl", "");
            if (state.isEmpty() || authUrl.isEmpty()) {
                String errorMsg = "codebuddy: auth state response missing state or authUrl";
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            Log.d(TAG, "Auth state fetched successfully, state=" + state);
            return new AuthState(state, authUrl);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("codebuddy: failed to parse auth state response: "
                    + e.getMessage(), e);
        } finally {
            conn.disconnect();
        }
    }

    // ========================================================================
    // PollForToken (1:1 port of Go PollForToken)
    // ========================================================================

    /**
     * 轮询令牌端点，直到用户完成浏览器授权，返回认证数据。
     * <p>
     * 使用 GET /v2/plugin/auth/token?state={state} 进行轮询，间隔 5 秒，最长 5 分钟。
     * 携带自定义请求头（Accept、User-Agent、X-Requested-With、X-No-Authorization、
     * X-No-User-Id、X-No-Enterprise-Id、X-No-Department-Info、X-Product）。
     * <p>
     * 待处理状态码 (11217) 时继续轮询，成功状态码 (0) 时返回令牌数据。
     * <p>
     * 1:1 移植 Go PollForToken()。
     *
     * @param state 从 fetchAuthState() 获取的状态值
     * @return 包含令牌信息的 CodeBuddyTokenStorage 对象
     * @throws IOException 如果轮询超时、令牌获取失败，或线程被中断
     * @throws InterruptedException 如果线程在轮询休眠期间被中断
     */
    public CodeBuddyTokenStorage pollForToken(String state)
            throws IOException, InterruptedException {
        if (state == null || state.trim().isEmpty()) {
            throw new IOException("codebuddy: state is required for polling");
        }

        String pollURL = baseURL + CODE_BUDDY_TOKEN_PATH + "?state="
                + URLEncoder.encode(state, "UTF-8");
        long deadline = System.currentTimeMillis() + MAX_POLL_DURATION_MS;

        Log.d(TAG, "Starting token poll for state=" + state);

        while (true) {
            // Check for cancellation (1:1 port of Go ctx.Done())
            if (Thread.currentThread().isInterrupted()) {
                throw new InterruptedException("codebuddy: polling cancelled");
            }

            // Sleep before next poll (1:1 port of Go time.After(pollInterval))
            Thread.sleep(POLL_INTERVAL_MS);

            // Check deadline (1:1 port of Go time.Now().Before(deadline))
            if (System.currentTimeMillis() > deadline) {
                String errorMsg = "codebuddy: polling timeout, user did not authorize in time";
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            // Perform a single poll request
            PollResult result = doPollRequest(pollURL);
            if (result.token != null) {
                return result.token;
            }
            if (!result.shouldContinue) {
                throw result.error;
            }
            // Continue polling (codeLoginPending case)
        }
    }

    /**
     * PollResult 保存单次轮询的结果。
     * 1:1 移植 Go 的 (token, error, shouldContinue) 三元组返回。
     */
    private static class PollResult {
        final CodeBuddyTokenStorage token;
        final IOException error;
        final boolean shouldContinue;

        PollResult(CodeBuddyTokenStorage token, IOException error, boolean shouldContinue) {
            this.token = token;
            this.error = error;
            this.shouldContinue = shouldContinue;
        }
    }

    /**
     * 执行单次轮询请求，解析响应并根据状态码决定下一步操作。
     * <p>
     * 1:1 移植 Go doPollRequest() 和 PollForToken() 中的 switch 逻辑。
     *
     * @param pollURL 完整的轮询 URL
     * @return PollResult 包含令牌数据、错误或继续轮询标志
     */
    private PollResult doPollRequest(String pollURL) {
        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(pollURL).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json, text/plain, */*");
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.setRequestProperty("X-Requested-With", "XMLHttpRequest");
            conn.setRequestProperty("X-No-Authorization", "true");
            conn.setRequestProperty("X-No-User-Id", "true");
            conn.setRequestProperty("X-No-Enterprise-Id", "true");
            conn.setRequestProperty("X-No-Department-Info", "true");
            conn.setRequestProperty("X-Product", "SaaS");
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);

            int responseCode = conn.getResponseCode();
            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.d(TAG, "codebuddy poll: unexpected status " + responseCode);
                return new PollResult(null, null, true);
            }

            String responseBody = readResponseBody(conn, responseCode);
            JSONObject json = parseJson(responseBody);
            int code = json.optInt("code", -1);

            switch (code) {
                case CODE_SUCCESS: {
                    JSONObject data = json.optJSONObject("data");
                    if (data == null) {
                        return new PollResult(null,
                                new IOException("codebuddy: empty data in response"), false);
                    }

                    String accessToken = data.optString("accessToken", "");
                    String userId = decodeUserID(accessToken);

                    CodeBuddyTokenStorage token = new CodeBuddyTokenStorage();
                    token.accessToken = accessToken;
                    token.refreshToken = data.optString("refreshToken", "");
                    token.expiresIn = data.optLong("expiresIn", 0);
                    token.tokenType = data.optString("tokenType", "");
                    token.domain = data.optString("domain", "");
                    token.userId = userId;
                    token.type = "codebuddy";

                    Log.d(TAG, "Token poll succeeded, userId=" + userId);
                    return new PollResult(token, null, false);
                }
                case CODE_LOGIN_PENDING:
                    // Continue polling (1:1 port of Go case)
                    Log.d(TAG, "Token poll: login pending, continuing...");
                    return new PollResult(null, null, true);
                default: {
                    String msg = json.optString("msg", "");
                    String errorMsg = "codebuddy: server returned code " + code + ": " + msg;
                    Log.e(TAG, errorMsg);
                    return new PollResult(null,
                            new IOException(errorMsg), false);
                }
            }

        } catch (Exception e) {
            Log.d(TAG, "codebuddy poll: request error: " + e.getMessage());
            return new PollResult(null, null, true);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // RefreshToken (1:1 port of Go RefreshToken)
    // ========================================================================

    /**
     * 使用刷新令牌获取新的访问令牌。
     * <p>
     * 调用 POST /v2/plugin/auth/token/refresh 并携带所需请求头：
     * Accept、Content-Type、X-Requested-With、X-Domain、X-Refresh-Token、
     * X-Auth-Refresh-Source、X-Request-ID、Authorization、X-User-Id、X-Product、User-Agent。
     * <p>
     * 1:1 移植 Go RefreshToken()。
     *
     * @param accessToken  当前的访问令牌（用于 Authorization 头）
     * @param refreshToken 刷新令牌（用于 X-Refresh-Token 头）
     * @param userId       用户 ID（用于 X-User-Id 头）
     * @param domain       服务域名（用于 X-Domain 头）；如果为空则使用默认域名
     * @return 包含新令牌信息的 CodeBuddyTokenStorage 对象
     * @throws IOException 如果刷新令牌为空、请求失败、响应无效或令牌被拒绝
     */
    public CodeBuddyTokenStorage refreshToken(String accessToken, String refreshToken,
                                               String userId, String domain) throws IOException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new IOException("codebuddy: refresh token is required");
        }

        String resolvedDomain = (domain != null && !domain.isEmpty()) ? domain : DEFAULT_DOMAIN;
        String refreshURL = baseURL + CODE_BUDDY_REFRESH_PATH;
        String requestId = UUID.randomUUID().toString().replace("-", "");

        Log.d(TAG, "Refreshing token at: " + refreshURL);

        byte[] postData = "{}".getBytes(StandardCharsets.UTF_8);
        HttpURLConnection conn = (HttpURLConnection) new URL(refreshURL).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Accept", "application/json, text/plain, */*");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-Requested-With", "XMLHttpRequest");
            conn.setRequestProperty("X-Domain", resolvedDomain);
            conn.setRequestProperty("X-Refresh-Token", refreshToken);
            conn.setRequestProperty("X-Auth-Refresh-Source", "plugin");
            conn.setRequestProperty("X-Request-ID", requestId);
            if (accessToken != null && !accessToken.isEmpty()) {
                conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            }
            if (userId != null && !userId.isEmpty()) {
                conn.setRequestProperty("X-User-Id", userId);
            }
            conn.setRequestProperty("X-Product", "SaaS");
            conn.setRequestProperty("User-Agent", USER_AGENT);
            conn.setDoOutput(true);
            conn.setConnectTimeout(CONNECT_TIMEOUT);
            conn.setReadTimeout(READ_TIMEOUT);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, responseCode);

            // Check for auth rejection (1:1 port of Go status check)
            if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED
                    || responseCode == HttpURLConnection.HTTP_FORBIDDEN) {
                String errorMsg = "codebuddy: refresh token rejected (status " + responseCode + ")";
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            if (responseCode != HttpURLConnection.HTTP_OK) {
                String errorMsg = "codebuddy: refresh failed with status "
                        + responseCode + ": " + responseBody;
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            JSONObject json = parseJson(responseBody);
            int code = json.optInt("code", -1);
            if (code != CODE_SUCCESS) {
                String msg = json.optString("msg", "");
                String errorMsg = "codebuddy: refresh failed with code "
                        + code + ": " + msg;
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            JSONObject data = json.optJSONObject("data");
            if (data == null) {
                String errorMsg = "codebuddy: empty data in refresh response";
                Log.e(TAG, errorMsg);
                throw new IOException(errorMsg);
            }

            // Decode user ID from new access token (1:1 port of Go)
            String newAccessToken = data.optString("accessToken", "");
            String newUserId = decodeUserID(newAccessToken);
            if (newUserId == null || newUserId.isEmpty()) {
                newUserId = userId;
            }

            // Resolve domain (1:1 port of Go)
            String tokenDomain = data.optString("domain", "");
            if (tokenDomain == null || tokenDomain.isEmpty()) {
                tokenDomain = resolvedDomain;
            }

            CodeBuddyTokenStorage token = new CodeBuddyTokenStorage();
            token.accessToken = newAccessToken;
            token.refreshToken = data.optString("refreshToken", "");
            token.expiresIn = data.optLong("expiresIn", 0);
            token.refreshExpiresIn = data.optLong("refreshExpiresIn", 0);
            token.tokenType = data.optString("tokenType", "");
            token.domain = tokenDomain;
            token.userId = newUserId;
            token.type = "codebuddy";

            Log.d(TAG, "Token refreshed successfully, userId=" + newUserId);
            return token;

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("codebuddy: failed to parse refresh response: "
                    + e.getMessage(), e);
        } finally {
            conn.disconnect();
        }
    }

    // ========================================================================
    // DecodeUserID (1:1 port of Go DecodeUserID)
    // ========================================================================

    /**
     * 从 JWT 访问令牌的 sub 字段解码用户 ID。
     * <p>
     * 将 JWT 的第二部分（payload）使用 Base64 URL 安全解码，解析 JSON 后提取 sub 字段。
     * <p>
     * 1:1 移植 Go DecodeUserID()。
     *
     * @param accessToken JWT 格式的访问令牌（header.payload.signature）
     * @return 解码后的用户 ID（sub 字段值），如果解码失败则返回空字符串
     */
    public static String decodeUserID(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) {
            return "";
        }
        String[] parts = accessToken.split("\\.");
        if (parts.length < 2) {
            Log.e(TAG, "codebuddy: failed to decode JWT token: not enough parts");
            return "";
        }
        try {
            byte[] payload = android.util.Base64.decode(parts[1],
                    android.util.Base64.URL_SAFE);
            String jsonStr = new String(payload, StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(jsonStr);
            String sub = json.optString("sub", "");
            if (sub.isEmpty()) {
                Log.e(TAG, "codebuddy: sub claim is empty in JWT");
                return "";
            }
            return sub;
        } catch (Exception e) {
            Log.e(TAG, "codebuddy: failed to decode JWT token: " + e.getMessage());
            return "";
        }
    }

    // ========================================================================
    // Error helpers (1:1 port of Go errors.go)
    // ========================================================================

    /**
     * 根据错误内容获取用户友好的错误消息。
     * <p>
     * 1:1 移植 Go GetUserFriendlyMessage()。
     *
     * @param error 错误对象；可以为 null
     * @return 用户友好的错误描述字符串
     */
    public static String getUserFriendlyMessage(Throwable error) {
        if (error == null) {
            return "Authentication failed: unknown error";
        }
        String msg = error.getMessage();
        if (msg == null) {
            return "Authentication failed: unknown error";
        }
        if (msg.contains("polling timeout")) {
            return "Authentication timed out. Please try again.";
        }
        if (msg.contains("access denied") || msg.contains("Access denied")) {
            return "Access denied. Please try again and approve the login request.";
        }
        if (msg.contains("failed to decode JWT") || msg.contains("JWT")) {
            return "Failed to decode token. Please try logging in again.";
        }
        if (msg.contains("failed to fetch token") || msg.contains("token")) {
            return "Failed to fetch token from server. Please try again.";
        }
        return "Authentication failed: " + msg;
    }

    // ========================================================================
    // Utility methods
    // ========================================================================

    /**
     * 从 HttpURLConnection 读取响应体。
     * <p>
     * 根据响应状态码自动选择输入流（成功时使用 getInputStream()，失败时使用 getErrorStream()）。
     *
     * @param conn         HTTP 连接对象
     * @param responseCode HTTP 响应状态码
     * @return 响应体字符串（UTF-8 编码）
     * @throws IOException 如果读取失败
     */
    private static String readResponseBody(HttpURLConnection conn, int responseCode)
            throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        try (java.io.InputStream is = (responseCode >= 200 && responseCode < 300)
                ? conn.getInputStream() : conn.getErrorStream()) {
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
        }
        return baos.toString("UTF-8");
    }

    /**
     * 解析 JSON 字符串为 JSONObject。
     *
     * @param body JSON 格式的字符串
     * @return 解析后的 JSONObject 对象
     * @throws IOException 如果 JSON 解析失败
     */
    private static JSONObject parseJson(String body) throws IOException {
        try {
            return new JSONObject(body);
        } catch (JSONException e) {
            throw new IOException("codebuddy: failed to parse JSON response", e);
        }
    }
}