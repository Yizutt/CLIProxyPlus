package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpCookie;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * IFlowOAuth - iFlow OAuth 认证实现（支持 Cookie 会话管理）
 * <p>
 * 实现 iFlow AI 平台的 OAuth 2.0 Authorization Code flow with PKCE，
 * 并扩展了完整的 Cookie 支持，用于维持登录会话和自动续期。
 * <p>
 * OAuth 流程：
 * 1. 生成 PKCE 码对 → 2. 构建授权 URL → 3. 启动本地回调服务器
 * 4. 用户在浏览器中完成认证 → 5. 回调服务器接收授权码
 * 6. 交换授权码为 Token → 7. 携带 Cookie 维持会话
 * <p>
 * Cookie 支持：
 * - CookieJar 管理：自动存储和发送 Cookie
 * - 持久化 Cookie 存储，支持序列化/反序列化
 * - Cookie 过期自动清理
 * - 会话 Cookie 与应用 Cookie 分离管理
 * - 支持 Cookie 注入（用于已存在的登录会话）
 * <p>
 * 对应原版 CLIProxyAPIPlus/internal/auth/iflow/ 中的 Go 实现。
 */
public class IFlowOAuth extends OAuthProvider {

    private static final String TAG = "IFlowOAuth";

    // ================================================================
    //  OAuth 端点常量
    // ================================================================

    /** iFlow OAuth 授权端点 */
    private static final String AUTH_URL = "https://auth.iflow.ai/oauth/authorize";

    /** iFlow OAuth 令牌端点 */
    private static final String TOKEN_URL = "https://auth.iflow.ai/oauth/token";

    /** iFlow OAuth 吊销端点 */
    private static final String REVOKE_URL = "https://auth.iflow.ai/oauth/revoke";

    /** iFlow 用户信息端点 */
    private static final String USER_INFO_URL = "https://api.iflow.ai/v1/user/me";

    /** iFlow 客户端 ID */
    private static final String CLIENT_ID = "iflow_android_client";

    /** 重定向 URI（本地回调） */
    private static final String REDIRECT_URI = "http://localhost:1460/auth/callback";

    /** 本地回调服务器默认端口 */
    private static final int DEFAULT_CALLBACK_PORT = 1460;

    /** 回调等待超时时间（秒） */
    private static final int CALLBACK_TIMEOUT_SECONDS = 300;

    /** 默认轮询间隔（毫秒） */
    private static final int POLL_INTERVAL_MS = 2000;

    /** 请求超时（毫秒） */
    private static final int REQUEST_TIMEOUT_MS = 15000;

    /** Cookie 最大数量 */
    private static final int MAX_COOKIES = 256;

    /** 最大重试次数 */
    private static final int MAX_RETRIES = 3;

    // ================================================================
    //  实例状态
    // ================================================================

    /** CookieJar 实例，统一管理所有 Cookie */
    private final CookieJar cookieJar;

    /** 是否启用 Cookie 自动管理 */
    private volatile boolean cookieEnabled;

    /** 是否在 OAuth 请求中自动携带 Cookie */
    private volatile boolean autoSendCookies;

    /** 代理 URL（可选） */
    private final String proxyUrl;

    // ================================================================
    //  构造
    // ================================================================

    /**
     * 创建一个 iFlow OAuth 提供者实例，使用默认配置。
     */
    public IFlowOAuth() {
        this.cookieJar = new CookieJar();
        this.cookieEnabled = true;
        this.autoSendCookies = true;
        this.proxyUrl = "";
        log("IFlowOAuth initialized");
    }

    /**
     * 创建一个 iFlow OAuth 提供者实例，使用指定的代理 URL。
     *
     * @param proxyUrl 代理 URL，为空则不使用代理
     */
    public IFlowOAuth(String proxyUrl) {
        this.cookieJar = new CookieJar();
        this.cookieEnabled = true;
        this.autoSendCookies = true;
        this.proxyUrl = proxyUrl != null ? proxyUrl : "";
        log("IFlowOAuth initialized with proxy: " + (this.proxyUrl.isEmpty() ? "none" : this.proxyUrl));
    }

    /**
     * 创建一个 iFlow OAuth 提供者实例，使用指定的代理 URL 和 Cookie 配置。
     *
     * @param proxyUrl      代理 URL，为空则不使用代理
     * @param cookieEnabled 是否启用 Cookie 管理
     */
    public IFlowOAuth(String proxyUrl, boolean cookieEnabled) {
        this.cookieJar = new CookieJar();
        this.cookieEnabled = cookieEnabled;
        this.autoSendCookies = cookieEnabled;
        this.proxyUrl = proxyUrl != null ? proxyUrl : "";
        log("IFlowOAuth initialized (cookieEnabled=" + cookieEnabled + ")");
    }

    // ================================================================
    //  OAuth Authorization Code Flow（PKCE）
    // ================================================================

    /**
     * 启动标准 OAuth Authorization Code 流程（PKCE）。
     * <p>
     * 1. 生成 PKCE 码对
     * 2. 生成随机 state 参数
     * 3. 构建授权 URL
     * 4. 启动本地 HTTP 回调服务器
     * 5. 返回包含授权 URL 和 CompletableFuture 的 OAuthFlow 对象
     * 6. 调用方应在浏览器中打开授权 URL
     * 7. 后台等待回调并交换 Token
     *
     * @return 包含授权 URL 和 CompletableFuture 的 OAuthFlow 对象
     * @throws OAuthException 如果启动流程失败
     */
    public OAuthFlow startAuth() throws OAuthException {
        PKCECodes pkceCodes = generatePKCECodes();
        String state = generateRandomState();

        // 构建授权 URL
        String authUrl = buildAuthorizationUrl(state, pkceCodes);

        // 启动本地回调服务器
        CallbackServer server = new CallbackServer(DEFAULT_CALLBACK_PORT);

        // 创建 Future 用于异步等待认证结果
        CompletableFuture<AuthResult> future = CompletableFuture.supplyAsync(() -> {
            try {
                // 启动服务器
                server.start();

                // 等待回调
                OAuthCallbackResult callback = server.waitForCallback(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                if (callback.error != null) {
                    throw new OAuthException("callback_error", "OAuth callback error: " + callback.error);
                }
                if (!state.equals(callback.state)) {
                    throw new OAuthException("invalid_state", "State parameter mismatch");
                }

                // 交换授权码为 Token
                log("Authorization code received, exchanging for tokens...");
                AuthResult result = exchangeCodeForTokens(callback.code, pkceCodes);
                log("Token exchange successful");

                // 尝试获取用户信息并更新 Cookie
                if (cookieEnabled && result != null && result.tokenData != null) {
                    try {
                        fetchAndStoreUserInfo(result.tokenData.accessToken);
                    } catch (Exception e) {
                        logError("Failed to fetch user info after auth", e);
                    }
                }

                return result;
            } catch (OAuthException e) {
                throw new RuntimeException(e);
            } finally {
                server.stop();
            }
        });

        return new OAuthFlow(authUrl, state, "iflow", future);
    }

    /**
     * 构建 OAuth 授权 URL。
     */
    private String buildAuthorizationUrl(String state, PKCECodes pkceCodes) {
        StringBuilder sb = new StringBuilder(AUTH_URL);
        sb.append("?client_id=").append(encodeParam(CLIENT_ID));
        sb.append("&response_type=code");
        sb.append("&redirect_uri=").append(encodeParam(REDIRECT_URI));
        sb.append("&scope=").append(encodeParam("openid email profile offline_access"));
        sb.append("&state=").append(encodeParam(state));
        sb.append("&code_challenge=").append(encodeParam(pkceCodes.codeChallenge));
        sb.append("&code_challenge_method=S256");
        sb.append("&prompt=login");
        sb.append("&audience=").append(encodeParam("https://api.iflow.ai"));
        return sb.toString();
    }

    /**
     * 交换授权码为 Token。
     *
     * @param code      授权码
     * @param pkceCodes PKCE 码对
     * @return 认证结果
     * @throws OAuthException 如果交换失败
     */
    public AuthResult exchangeCodeForTokens(String code, PKCECodes pkceCodes) throws OAuthException {
        return exchangeCodeForTokens(code, REDIRECT_URI, pkceCodes);
    }

    /**
     * 使用自定义 redirect URI 交换授权码为 Token。
     *
     * @param code        授权码
     * @param redirectUri 自定义重定向 URI
     * @param pkceCodes   PKCE 码对
     * @return 认证结果
     * @throws OAuthException 如果交换失败
     */
    public AuthResult exchangeCodeForTokens(String code, String redirectUri, PKCECodes pkceCodes)
            throws OAuthException {
        if (pkceCodes == null) {
            throw new OAuthException("pkce_required", "PKCE codes are required for token exchange");
        }
        if (redirectUri == null || redirectUri.trim().isEmpty()) {
            throw new OAuthException("redirect_uri_required", "Redirect URI is required for token exchange");
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "authorization_code");
            params.put("client_id", CLIENT_ID);
            params.put("code", code);
            params.put("redirect_uri", redirectUri.trim());
            params.put("code_verifier", pkceCodes.codeVerifier);

            String responseBody = postFormWithCookies(TOKEN_URL, params);
            return parseTokenResponse(responseBody);
        } catch (IOException e) {
            logError("Token exchange failed", e);
            throw new OAuthException("exchange_failed", "Token exchange request failed: " + e.getMessage(), e);
        }
    }

    // ================================================================
    //  Token Refresh
    // ================================================================

    /**
     * 刷新 Access Token。
     * <p>
     * 使用刷新令牌获取新的访问令牌。如果启用了 Cookie 管理，
     * 刷新成功后会自动更新 Cookie 中的会话信息。
     *
     * @param refreshToken 刷新令牌
     * @return 新的 Token 数据
     * @throws OAuthException 如果刷新失败
     */
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new OAuthException("refresh_token_required", "Refresh token is required");
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_id", CLIENT_ID);
            params.put("grant_type", "refresh_token");
            params.put("refresh_token", refreshToken);
            params.put("scope", "openid profile email offline_access");

            String responseBody = postFormWithCookies(TOKEN_URL, params);
            AuthResult result = parseTokenResponse(responseBody);

            // 更新 Cookie 中的会话信息
            if (cookieEnabled && result != null && result.tokenData != null) {
                try {
                    fetchAndStoreUserInfo(result.tokenData.accessToken);
                } catch (Exception e) {
                    logError("Failed to fetch user info after token refresh", e);
                }
            }

            return result != null ? result.tokenData : null;
        } catch (OAuthException e) {
            throw e;
        } catch (IOException e) {
            logError("Token refresh failed", e);
            throw new OAuthException("refresh_failed", "Token refresh request failed: " + e.getMessage(), e);
        }
    }

    /**
     * 带重试机制的 Token 刷新。
     *
     * @param refreshToken 刷新令牌
     * @param maxRetries   最大重试次数
     * @return 新的 Token 数据
     * @throws OAuthException 如果所有重试均失败
     */
    public TokenData refreshTokensWithRetry(String refreshToken, int maxRetries) throws OAuthException {
        OAuthException lastError = null;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            if (attempt > 0) {
                try {
                    Thread.sleep(attempt * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new OAuthException("retry_interrupted", "Token refresh retry interrupted", e);
                }
            }

            try {
                return refreshTokens(refreshToken);
            } catch (OAuthException e) {
                if (isNonRetryableRefreshError(e)) {
                    log("Non-retryable refresh error on attempt " + (attempt + 1) + ": " + e.getMessage());
                    throw e;
                }
                lastError = e;
                log("Token refresh attempt " + (attempt + 1) + " failed: " + e.getMessage());
            }
        }

        throw new OAuthException("refresh_failed_after_retries",
                "Token refresh failed after " + maxRetries + " attempts", lastError);
    }

    /**
     * 判断 Token 刷新错误是否为不可重试类型。
     */
    private boolean isNonRetryableRefreshError(OAuthException e) {
        String msg = e.getMessage();
        if (msg == null) return false;
        String lower = msg.toLowerCase();
        return lower.contains("refresh_token_reused")
                || lower.contains("invalid_grant")
                || lower.contains("invalid_token");
    }

    // ================================================================
    //  Token Revocation
    // ================================================================

    /**
     * 吊销 Token。
     * <p>
     * 通知 iFlow 认证服务器使指定的令牌失效。
     * 吊销完成后，关联的 Cookie 也会被清除。
     *
     * @param accessToken  待吊销的访问令牌（可为空）
     * @param refreshToken 待吊销的刷新令牌（可为空）
     * @return true 如果吊销成功（或无需吊销）
     */
    public boolean revokeTokens(String accessToken, String refreshToken) {
        boolean revoked = false;

        try {
            if (refreshToken != null && !refreshToken.trim().isEmpty()) {
                Map<String, String> params = new HashMap<>();
                params.put("client_id", CLIENT_ID);
                params.put("token", refreshToken.trim());
                params.put("token_type_hint", "refresh_token");

                try {
                    postFormWithCookies(REVOKE_URL, params);
                    log("Refresh token revoked successfully");
                    revoked = true;
                } catch (IOException e) {
                    logError("Failed to revoke refresh token", e);
                }
            }

            if (accessToken != null && !accessToken.trim().isEmpty()) {
                Map<String, String> params = new HashMap<>();
                params.put("client_id", CLIENT_ID);
                params.put("token", accessToken.trim());
                params.put("token_type_hint", "access_token");

                try {
                    postFormWithCookies(REVOKE_URL, params);
                    log("Access token revoked successfully");
                    revoked = true;
                } catch (IOException e) {
                    logError("Failed to revoke access token", e);
                }
            }
        } finally {
            // 清除所有 Cookie
            if (cookieEnabled) {
                cookieJar.clear();
                log("Cookies cleared after token revocation");
            }
        }

        return revoked;
    }

    // ================================================================
    //  用户信息
    // ================================================================

    /**
     * 获取当前登录用户的个人信息。
     * <p>
     * 使用访问令牌和 Cookie 向 iFlow 用户信息端点发起请求。
     *
     * @param accessToken 访问令牌
     * @return 用户信息对象，如果获取失败则返回 null
     */
    public UserInfo fetchUserInfo(String accessToken) {
        if (accessToken == null || accessToken.trim().isEmpty()) {
            log("Cannot fetch user info: no access token");
            return null;
        }

        try {
            String responseBody = getWithCookies(USER_INFO_URL, accessToken);
            if (responseBody == null || responseBody.isEmpty()) {
                return null;
            }
            return parseUserInfoResponse(responseBody);
        } catch (IOException e) {
            logError("Failed to fetch user info", e);
            return null;
        }
    }

    /**
     * 获取用户信息并更新 Cookie 存储中的会话数据。
     */
    private void fetchAndStoreUserInfo(String accessToken) {
        UserInfo info = fetchUserInfo(accessToken);
        if (info != null && info.userId != null && !info.userId.isEmpty()) {
            // 在 Cookie 中标记用户身份
            cookieJar.addSessionInfo("user_id", info.userId);
            cookieJar.addSessionInfo("email", info.email);
            cookieJar.addSessionInfo("display_name", info.displayName);
            log("User info stored in cookie session: " + info.email);
        }
    }

    /**
     * 解析用户信息响应 JSON。
     * <p>
     * iFlow 用户信息端点返回格式：
     * <pre>
     * {
     *   "id": "usr_xxx",
     *   "email": "user@example.com",
     *   "display_name": "User Name",
     *   "avatar_url": "https://...",
     *   "created_at": "2024-01-01T00:00:00Z",
     *   "subscription": { "plan": "pro", "expires_at": "..." }
     * }
     * </pre>
     */
    private UserInfo parseUserInfoResponse(String json) {
        try {
            JSONObject obj = new JSONObject(json);
            UserInfo info = new UserInfo();
            info.userId = obj.optString("id", "");
            info.email = obj.optString("email", "");
            info.displayName = obj.optString("display_name", "");
            info.avatarUrl = obj.optString("avatar_url", "");
            info.createdAt = obj.optString("created_at", "");

            // 解析订阅信息
            JSONObject sub = obj.optJSONObject("subscription");
            if (sub != null) {
                info.subscriptionPlan = sub.optString("plan", "");
                info.subscriptionExpiresAt = sub.optString("expires_at", "");
            }

            info.fetchedAt = System.currentTimeMillis();
            return info;
        } catch (org.json.JSONException e) {
            logError("Failed to parse user info response", e);
            return null;
        }
    }

    // ================================================================
    //  Cookie 管理
    // ================================================================

    /**
     * 启用或禁用 Cookie 管理。
     *
     * @param enabled true 启用 Cookie 管理
     */
    public void setCookieEnabled(boolean enabled) {
        this.cookieEnabled = enabled;
        this.autoSendCookies = enabled;
        log("Cookie management " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * 检查 Cookie 管理是否已启用。
     *
     * @return true 如果 Cookie 管理已启用
     */
    public boolean isCookieEnabled() {
        return cookieEnabled;
    }

    /**
     * 设置是否在 OAuth 请求中自动携带 Cookie。
     *
     * @param autoSend true 自动携带 Cookie
     */
    public void setAutoSendCookies(boolean autoSend) {
        this.autoSendCookies = autoSend;
    }

    /**
     * 检查是否自动携带 Cookie。
     *
     * @return true 如果自动携带 Cookie
     */
    public boolean isAutoSendCookies() {
        return autoSendCookies;
    }

    /**
     * 获取 CookieJar 实例，用于直接操作 Cookie 存储。
     *
     * @return CookieJar 实例
     */
    public CookieJar getCookieJar() {
        return cookieJar;
    }

    /**
     * 从 Cookie 字符串导入 Cookie 到 CookieJar。
     * <p>
     * 支持标准的 "key=value; key2=value2" 格式。
     *
     * @param cookieString Cookie 字符串
     * @param domain       Cookie 所属域名
     * @param path         Cookie 路径
     */
    public void importCookies(String cookieString, String domain, String path) {
        if (cookieString == null || cookieString.trim().isEmpty()) {
            return;
        }

        String[] parts = cookieString.split(";");
        for (String part : parts) {
            String trimmed = part.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                String name = trimmed.substring(0, eq).trim();
                String value = trimmed.substring(eq + 1).trim();
                if (!name.isEmpty()) {
                    HttpCookie cookie = new HttpCookie(name, value);
                    cookie.setDomain(domain != null ? domain : "auth.iflow.ai");
                    cookie.setPath(path != null ? path : "/");
                    cookie.setSecure(true);
                    cookie.setHttpOnly(true);
                    cookie.setVersion(0);
                    cookieJar.addCookie(cookie);
                }
            }
        }
        log("Imported " + parts.length + " cookies for domain: " + domain);
    }

    /**
     * 导出所有非会话 Cookie 为字符串格式。
     *
     * @return Cookie 字符串，格式为 "key1=value1; key2=value2"
     */
    public String exportCookies() {
        List<HttpCookie> allCookies = cookieJar.getAllCookies();
        StringBuilder sb = new StringBuilder();
        for (HttpCookie cookie : allCookies) {
            if (cookie.hasExpired()) continue;
            if (sb.length() > 0) sb.append("; ");
            sb.append(cookie.getName()).append("=").append(cookie.getValue());
        }
        return sb.toString();
    }

    /**
     * 清除所有 Cookie。
     */
    public void clearCookies() {
        cookieJar.clear();
        log("All cookies cleared");
    }

    // ================================================================
    //  HTTP 请求（带 Cookie 支持）
    // ================================================================

    /**
     * 发送带 Cookie 的 POST 表单请求。
     * <p>
     * 在 {@link #postForm(String, Map)} 的基础上增加了 Cookie 的
     * 自动发送和响应 Cookie 的存储。
     */
    protected String postFormWithCookies(String urlStr, Map<String, String> params) throws IOException {
        StringBuilder body = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (body.length() > 0) body.append("&");
            body.append(URLEncoder.encode(entry.getKey(), "UTF-8"))
                    .append("=")
                    .append(URLEncoder.encode(entry.getValue(), "UTF-8"));
        }

        byte[] postData = body.toString().getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
            conn.setDoOutput(true);
            conn.setConnectTimeout(REQUEST_TIMEOUT_MS);
            conn.setReadTimeout(REQUEST_TIMEOUT_MS);

            // 自动携带 Cookie
            if (cookieEnabled && autoSendCookies) {
                attachCookies(conn, urlStr);
            }

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();

            // 存储响应 Cookie
            if (cookieEnabled) {
                storeResponseCookies(conn, urlStr);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            try (InputStream is = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream()
                    : conn.getErrorStream()) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            String responseBody = baos.toString("UTF-8");

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("HTTP " + responseCode + ": " + responseBody);
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 发送带 Cookie 的 GET 请求。
     */
    protected String getWithCookies(String urlStr, String accessToken) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
            conn.setConnectTimeout(REQUEST_TIMEOUT_MS);
            conn.setReadTimeout(REQUEST_TIMEOUT_MS);

            // 自动携带 Cookie
            if (cookieEnabled && autoSendCookies) {
                attachCookies(conn, urlStr);
            }

            int responseCode = conn.getResponseCode();

            // 存储响应 Cookie
            if (cookieEnabled) {
                storeResponseCookies(conn, urlStr);
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            try (InputStream is = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream()
                    : conn.getErrorStream()) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            String responseBody = baos.toString("UTF-8");

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("HTTP " + responseCode + ": " + responseBody);
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * 将 CookieJar 中的 Cookie 附加到 HTTP 请求的 Cookie 头中。
     */
    private void attachCookies(HttpURLConnection conn, String urlStr) {
        try {
            URI uri = new URI(urlStr);
            List<HttpCookie> cookies = cookieJar.getCookiesForUri(uri);
            if (cookies.isEmpty()) return;

            StringBuilder cookieHeader = new StringBuilder();
            for (HttpCookie cookie : cookies) {
                if (cookie.hasExpired()) {
                    cookieJar.removeCookie(cookie);
                    continue;
                }
                if (cookieHeader.length() > 0) cookieHeader.append("; ");
                cookieHeader.append(cookie.getName()).append("=").append(cookie.getValue());
            }

            if (cookieHeader.length() > 0) {
                conn.setRequestProperty("Cookie", cookieHeader.toString());
                log("Attached " + cookies.size() + " cookies to request: " + urlStr);
            }
        } catch (URISyntaxException e) {
            logError("Invalid URI for cookie attachment: " + urlStr, e);
        }
    }

    /**
     * 从 HTTP 响应中提取并存储 Cookie。
     */
    private void storeResponseCookies(HttpURLConnection conn, String urlStr) {
        try {
            URI uri = new URI(urlStr);
            Map<String, List<String>> headerFields = conn.getHeaderFields();
            if (headerFields == null) return;

            List<String> setCookieHeaders = headerFields.get("Set-Cookie");
            if (setCookieHeaders == null || setCookieHeaders.isEmpty()) {
                setCookieHeaders = headerFields.get("set-cookie");
            }
            if (setCookieHeaders == null || setCookieHeaders.isEmpty()) return;

            for (String headerValue : setCookieHeaders) {
                if (headerValue == null || headerValue.trim().isEmpty()) continue;
                try {
                    List<HttpCookie> parsed = HttpCookie.parse(headerValue);
                    for (HttpCookie cookie : parsed) {
                        // 如果域名未设置，使用请求 URI 的域名
                        if (cookie.getDomain() == null || cookie.getDomain().isEmpty()) {
                            cookie.setDomain(uri.getHost());
                        }
                        cookieJar.addCookie(cookie);
                    }
                } catch (IllegalArgumentException e) {
                    logError("Failed to parse Set-Cookie header: " + headerValue, e);
                }
            }

            log("Stored " + setCookieHeaders.size() + " Set-Cookie headers from: " + urlStr);
        } catch (URISyntaxException e) {
            logError("Invalid URI for cookie storage: " + urlStr, e);
        }
    }

    // ================================================================
    //  JSON 解析
    // ================================================================

    /**
     * 解析 Token 响应 JSON。
     * <p>
     * iFlow 令牌端点返回标准 OAuth 2.0 响应格式：
     * <pre>
     * {
     *   "access_token": "eyJ...",
     *   "refresh_token": "ifr_...",
     *   "id_token": "eyJ...",
     *   "token_type": "Bearer",
     *   "expires_in": 86400,
     *   "scope": "openid email profile offline_access"
     * }
     * </pre>
     */
    private AuthResult parseTokenResponse(String json) throws OAuthException {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查 OAuth 错误
            String error = obj.optString("error", "");
            if (!error.isEmpty()) {
                String errorDesc = obj.optString("error_description", "");
                throw new OAuthException("token_error", "iFlow OAuth error: " + error + " - " + errorDesc);
            }

            String accessToken = obj.optString("access_token", "");
            if (accessToken.isEmpty()) {
                throw new OAuthException("access_token_missing", "Access token not found in response");
            }

            String refreshToken = obj.optString("refresh_token", "");
            String idToken = obj.optString("id_token", "");
            int expiresIn = obj.optInt("expires_in", 0);

            // 从 ID Token 中提取用户信息
            String accountId = "";
            String email = "";
            if (idToken != null && !idToken.isEmpty()) {
                try {
                    JWTClaims claims = parseJWT(idToken);
                    if (claims != null) {
                        accountId = claims.getAccountId();
                        email = claims.email;
                    }
                } catch (Exception e) {
                    logError("Failed to parse ID token", e);
                }
            }

            TokenData tokenData = new TokenData();
            tokenData.idToken = idToken;
            tokenData.accessToken = accessToken;
            tokenData.refreshToken = refreshToken;
            tokenData.accountId = accountId;
            tokenData.email = email;
            tokenData.expiresIn = expiresIn;
            tokenData.expireAt = System.currentTimeMillis() + (expiresIn * 1000L);

            return new AuthResult(tokenData);
        } catch (org.json.JSONException e) {
            logError("Failed to parse token response", e);
            throw new OAuthException("parse_failed", "Failed to parse token response: " + e.getMessage(), e);
        }
    }

    // ================================================================
    //  JWT 解析
    // ================================================================

    /**
     * 解析 JWT Token 的 claims 部分（不验证签名）。
     *
     * @param token JWT 字符串
     * @return 解析后的 claims，解析失败返回 null
     */
    public JWTClaims parseJWT(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                logError("Invalid JWT format: expected 3 parts, got " + parts.length, null);
                return null;
            }

            byte[] claimsData = Base64.getUrlDecoder().decode(padBase64(parts[1]));
            String json = new String(claimsData, StandardCharsets.UTF_8);
            return new JWTClaims(json);
        } catch (Exception e) {
            logError("Failed to parse JWT", e);
            return null;
        }
    }

    private String padBase64(String input) {
        int remainder = input.length() % 4;
        if (remainder == 2) return input + "==";
        if (remainder == 3) return input + "=";
        return input;
    }

    /**
     * JWT Claims 解析结果。
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

            // 解析 iFlow 自定义 claims
            JSONObject iflowAuth = obj.optJSONObject("https://iflow.ai/auth");
            if (iflowAuth != null) {
                this.accountId = iflowAuth.optString("account_id", "");
            } else {
                this.accountId = obj.optString("sub", "");
            }
        }

        public String getAccountId() {
            return accountId;
        }

        public String getEmail() {
            return email;
        }
    }

    // ================================================================
    //  辅助方法
    // ================================================================

    private String generateRandomState() {
        byte[] bytes = new byte[32];
        new java.security.SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String encodeParam(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return value;
        }
    }

    // ================================================================
    //  内部类：OAuthFlow
    // ================================================================

    /**
     * OAuth 流程信息，包含授权 URL 和用于等待结果的 Future。
     */
    public static class OAuthFlow {
        public final String authUrl;
        public final String state;
        public final String provider;
        public final CompletableFuture<AuthResult> future;

        public OAuthFlow(String authUrl, String state, String provider,
                         CompletableFuture<AuthResult> future) {
            this.authUrl = authUrl;
            this.state = state;
            this.provider = provider;
            this.future = future;
        }

        /**
         * 同步等待认证完成。
         *
         * @return 认证结果
         * @throws OAuthException 如果等待超时或认证失败
         */
        public AuthResult waitForResult() throws OAuthException {
            try {
                return future.get(CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (java.util.concurrent.TimeoutException e) {
                future.cancel(true);
                throw new OAuthException("callback_timeout",
                        "Timeout waiting for OAuth callback", e);
            } catch (java.util.concurrent.ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof OAuthException) {
                    throw (OAuthException) cause;
                }
                throw new OAuthException("auth_failed",
                        "Authentication failed: " + cause.getMessage(), cause);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OAuthException("auth_interrupted", "Authentication was interrupted", e);
            }
        }
    }

    // ================================================================
    //  内部类：CookieJar（线程安全的 Cookie 存储）
    // ================================================================

    /**
     * 线程安全的 Cookie 存储管理器。
     * <p>
     * 负责存储、检索和管理 HTTP Cookie，支持：
     * - 按域名和路径匹配 Cookie
     * - 自动过期清理
     * - 会话信息附加存储
     * - 线程安全的读写访问
     */
    public static class CookieJar {

        /** Cookie 存储，按域名分组 */
        private final ConcurrentHashMap<String, List<CookieEntry>> cookieStore;

        /** 会话信息存储（不与 HTTP Cookie 混淆） */
        private final ConcurrentHashMap<String, String> sessionInfo;

        /** 读写锁，用于批量操作 */
        private final ReentrantReadWriteLock rwLock;

        CookieJar() {
            this.cookieStore = new ConcurrentHashMap<>();
            this.sessionInfo = new ConcurrentHashMap<>();
            this.rwLock = new ReentrantReadWriteLock();
        }

        /**
         * 添加一个 Cookie。
         *
         * @param cookie 要添加的 Cookie
         */
        public void addCookie(HttpCookie cookie) {
            if (cookie == null) return;

            String domain = normalizeDomain(cookie.getDomain());
            String path = normalizePath(cookie.getPath());

            CookieEntry entry = new CookieEntry(cookie, domain, path);

            rwLock.writeLock().lock();
            try {
                List<CookieEntry> entries = cookieStore.get(domain);
                if (entries == null) {
                    entries = new ArrayList<>();
                    cookieStore.put(domain, entries);
                }

                // 替换同名同路径的已有 Cookie
                entries.removeIf(e -> e.cookie.getName().equals(cookie.getName())
                        && e.path.equals(path));
                entries.add(entry);

                // 限制 Cookie 总数，超出则移除最旧的
                if (entries.size() > MAX_COOKIES) {
                    entries.sort((a, b) -> Long.compare(a.addedAt, b.addedAt));
                    while (entries.size() > MAX_COOKIES) {
                        entries.remove(0);
                    }
                }
            } finally {
                rwLock.writeLock().unlock();
            }
        }

        /**
         * 获取指定 URI 匹配的 Cookie 列表。
         *
         * @param uri 请求 URI
         * @return 匹配的 Cookie 列表
         */
        public List<HttpCookie> getCookiesForUri(URI uri) {
            if (uri == null) return Collections.emptyList();

            String host = uri.getHost();
            String path = uri.getPath();
            if (host == null) return Collections.emptyList();

            List<HttpCookie> result = new ArrayList<>();
            long now = System.currentTimeMillis();

            rwLock.readLock().lock();
            try {
                for (Map.Entry<String, List<CookieEntry>> domainEntry : cookieStore.entrySet()) {
                    String cookieDomain = domainEntry.getKey();
                    if (!domainMatches(host, cookieDomain)) continue;

                    List<CookieEntry> entries = domainEntry.getValue();
                    if (entries == null) continue;

                    for (CookieEntry entry : entries) {
                        // 检查过期
                        if (entry.cookie.hasExpired()) continue;

                        // 检查路径匹配
                        if (!pathMatches(path, entry.path)) continue;

                        // 检查 Secure 标志：仅 HTTPS 请求发送 Secure Cookie
                        if (entry.cookie.getSecure() && !"https".equalsIgnoreCase(uri.getScheme())) {
                            continue;
                        }

                        // 检查 HttpOnly 标志：此处仅用于存储，不限制应用层访问
                        result.add(entry.cookie);
                    }
                }
            } finally {
                rwLock.readLock().unlock();
            }

            return result;
        }

        /**
         * 移除指定的 Cookie。
         *
         * @param cookie 要移除的 Cookie
         */
        public void removeCookie(HttpCookie cookie) {
            if (cookie == null) return;

            String domain = normalizeDomain(cookie.getDomain());
            String path = normalizePath(cookie.getPath());

            rwLock.writeLock().lock();
            try {
                List<CookieEntry> entries = cookieStore.get(domain);
                if (entries != null) {
                    entries.removeIf(e -> e.cookie.getName().equals(cookie.getName())
                            && e.path.equals(path));
                    if (entries.isEmpty()) {
                        cookieStore.remove(domain);
                    }
                }
            } finally {
                rwLock.writeLock().unlock();
            }
        }

        /**
         * 获取所有非过期 Cookie。
         *
         * @return 所有 Cookie 的列表
         */
        public List<HttpCookie> getAllCookies() {
            List<HttpCookie> result = new ArrayList<>();

            rwLock.readLock().lock();
            try {
                // 收集过期 Cookie 的键以便清理
                List<String> expiredDomains = new ArrayList<>();
                List<CookieEntry> allEntries = new ArrayList<>();

                for (Map.Entry<String, List<CookieEntry>> entry : cookieStore.entrySet()) {
                    List<CookieEntry> entries = entry.getValue();
                    if (entries == null || entries.isEmpty()) {
                        expiredDomains.add(entry.getKey());
                        continue;
                    }

                    boolean hasValid = false;
                    for (CookieEntry ce : entries) {
                        if (!ce.cookie.hasExpired()) {
                            result.add(ce.cookie);
                            hasValid = true;
                        }
                    }
                    if (!hasValid) {
                        expiredDomains.add(entry.getKey());
                    }
                }

                // 清理完全过期的域名条目（在写锁下进行）
                if (!expiredDomains.isEmpty()) {
                    rwLock.readLock().unlock();
                    rwLock.writeLock().lock();
                    try {
                        for (String domain : expiredDomains) {
                            List<CookieEntry> entries = cookieStore.get(domain);
                            if (entries != null) {
                                entries.removeIf(ce -> ce.cookie.hasExpired());
                                if (entries.isEmpty()) {
                                    cookieStore.remove(domain);
                                }
                            }
                        }
                    } finally {
                        rwLock.writeLock().unlock();
                        rwLock.readLock().lock();
                    }
                }
            } finally {
                rwLock.readLock().unlock();
            }

            return result;
        }

        /**
         * 获取指定域名的 Cookie 数量。
         *
         * @param domain 域名
         * @return Cookie 数量
         */
        public int getCookieCount(String domain) {
            String normalized = normalizeDomain(domain);
            rwLock.readLock().lock();
            try {
                List<CookieEntry> entries = cookieStore.get(normalized);
                if (entries == null) return 0;
                return (int) entries.stream().filter(e -> !e.cookie.hasExpired()).count();
            } finally {
                rwLock.readLock().unlock();
            }
        }

        /**
         * 获取所有 Cookie 的总数。
         *
         * @return Cookie 总数
         */
        public int getTotalCookieCount() {
            rwLock.readLock().lock();
            try {
                int count = 0;
                for (List<CookieEntry> entries : cookieStore.values()) {
                    if (entries != null) {
                        count += entries.stream().filter(e -> !e.cookie.hasExpired()).count();
                    }
                }
                return count;
            } finally {
                rwLock.readLock().unlock();
            }
        }

        /**
         * 添加一条会话信息（不参与 HTTP Cookie 传输）。
         *
         * @param key   信息键
         * @param value 信息值
         */
        public void addSessionInfo(String key, String value) {
            if (key != null && value != null) {
                sessionInfo.put(key, value);
            }
        }

        /**
         * 获取会话信息。
         *
         * @param key 信息键
         * @return 信息值，不存在则返回 null
         */
        public String getSessionInfo(String key) {
            return key != null ? sessionInfo.get(key) : null;
        }

        /**
         * 清除所有 Cookie 和会话信息。
         */
        public void clear() {
            rwLock.writeLock().lock();
            try {
                cookieStore.clear();
                sessionInfo.clear();
            } finally {
                rwLock.writeLock().unlock();
            }
        }

        /**
         * 清除过期 Cookie。
         *
         * @return 清除的 Cookie 数量
         */
        public int purgeExpiredCookies() {
            int removed = 0;
            rwLock.writeLock().lock();
            try {
                List<String> emptyDomains = new ArrayList<>();
                for (Map.Entry<String, List<CookieEntry>> entry : cookieStore.entrySet()) {
                    List<CookieEntry> entries = entry.getValue();
                    if (entries == null) continue;
                    int before = entries.size();
                    entries.removeIf(ce -> ce.cookie.hasExpired());
                    removed += (before - entries.size());
                    if (entries.isEmpty()) {
                        emptyDomains.add(entry.getKey());
                    }
                }
                for (String domain : emptyDomains) {
                    cookieStore.remove(domain);
                }
            } finally {
                rwLock.writeLock().unlock();
            }
            return removed;
        }

        /**
         * 检查指定域名是否包含有效的 Cookie。
         *
         * @param domain 域名
         * @return true 如果存在有效 Cookie
         */
        public boolean hasCookies(String domain) {
            return getCookieCount(domain) > 0;
        }

        /**
         * 检查 CookieJar 是否包含任何有效 Cookie。
         *
         * @return true 如果至少有一个有效 Cookie
         */
        public boolean hasAnyCookies() {
            return getTotalCookieCount() > 0;
        }

        // ---------------------------------------------------------------
        //  域名和路径匹配
        // ---------------------------------------------------------------

        /**
         * 检查请求域名是否匹配 Cookie 域名。
         * <p>
         * 遵循 RFC 6265 的域名匹配规则：
         * - 完全匹配
         * - 请求域名是 Cookie 域名的子域名
         * - Cookie 域名必须以 "." 开头（表示可匹配子域名）
         */
        private boolean domainMatches(String requestHost, String cookieDomain) {
            if (requestHost == null || cookieDomain == null) return false;

            String req = requestHost.toLowerCase();
            String cd = cookieDomain.toLowerCase();

            // 完全匹配
            if (req.equals(cd)) return true;

            // Cookie 域名以 "." 开头，匹配子域名
            if (cd.startsWith(".")) {
                return req.endsWith(cd) || req.equals(cd.substring(1));
            }

            // 请求域名是 Cookie 域名的子域名
            return req.endsWith("." + cd);
        }

        /**
         * 检查请求路径是否匹配 Cookie 路径。
         * <p>
         * 遵循 RFC 6265 的路径匹配规则：
         * - 完全匹配
         * - Cookie 路径是请求路径的前缀
         */
        private boolean pathMatches(String requestPath, String cookiePath) {
            if (requestPath == null) return false;
            if (cookiePath == null || cookiePath.isEmpty()) return true;

            // 标准化路径
            String rp = requestPath.endsWith("/") ? requestPath : requestPath + "/";
            String cp = cookiePath.endsWith("/") ? cookiePath : cookiePath + "/";

            return rp.startsWith(cp) || cp.startsWith(rp);
        }

        /**
         * 标准化域名：去除尾部句点，统一为小写。
         */
        private String normalizeDomain(String domain) {
            if (domain == null) return "";
            String d = domain.trim().toLowerCase();
            // 去除尾部句点
            while (d.endsWith(".")) {
                d = d.substring(0, d.length() - 1).trim();
            }
            return d;
        }

        /**
         * 标准化路径：确保以 "/" 开头。
         */
        private String normalizePath(String path) {
            if (path == null || path.trim().isEmpty()) return "/";
            String p = path.trim();
            return p.startsWith("/") ? p : "/" + p;
        }

        /**
         * Cookie 内部存储条目。
         */
        private static class CookieEntry {
            final HttpCookie cookie;
            final String domain;
            final String path;
            final long addedAt;

            CookieEntry(HttpCookie cookie, String domain, String path) {
                this.cookie = cookie;
                this.domain = domain;
                this.path = path;
                this.addedAt = System.currentTimeMillis();
            }
        }
    }

    // ================================================================
    //  内部类：CallbackServer（轻量级 HTTP 回调服务器）
    // ================================================================

    /**
     * 轻量级本地 HTTP 服务器，用于接收 OAuth 回调。
     */
    public static class CallbackServer {
        private final int port;
        private ServerSocket serverSocket;
        private volatile boolean running;

        public CallbackServer(int port) {
            this.port = port;
        }

        /**
         * 启动服务器（在独立线程中运行）。
         *
         * @throws OAuthException 如果启动失败
         */
        public void start() throws OAuthException {
            if (running) {
                return;
            }
            try {
                serverSocket = new ServerSocket();
                serverSocket.setReuseAddress(true);
                serverSocket.bind(new InetSocketAddress("localhost", port));
                running = true;
                Log.d(TAG, "OAuth callback server started on port " + port);
            } catch (IOException e) {
                throw new OAuthException("server_start_failed",
                        "Failed to start OAuth callback server on port " + port
                                + ": " + e.getMessage(), e);
            }
        }

        /**
         * 等待 OAuth 回调，超时后返回。
         *
         * @param timeout 超时时间
         * @param unit    时间单位
         * @return 回调结果
         * @throws OAuthException 如果超时或处理失败
         */
        public OAuthCallbackResult waitForCallback(long timeout, TimeUnit unit) throws OAuthException {
            long deadline = System.currentTimeMillis() + unit.toMillis(timeout);

            while (running && System.currentTimeMillis() < deadline) {
                try {
                    serverSocket.setSoTimeout((int) Math.min(500,
                            deadline - System.currentTimeMillis()));
                    try (Socket client = serverSocket.accept()) {
                        return handleRequest(client);
                    }
                } catch (java.net.SocketTimeoutException e) {
                    // 超时，继续循环检查 deadline
                    continue;
                } catch (IOException e) {
                    if (running) {
                        Log.e(TAG, "Callback server accept error", e);
                    }
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }

            if (running) {
                throw new OAuthException("callback_timeout",
                        "Timeout waiting for OAuth callback after "
                                + unit.toSeconds(timeout) + " seconds");
            }
            throw new OAuthException("server_stopped", "Callback server was stopped");
        }

        /**
         * 处理 HTTP 请求，解析 OAuth 回调参数。
         */
        private OAuthCallbackResult handleRequest(Socket client) throws IOException {
            InputStream in = client.getInputStream();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;

            // 读取请求行 + 头部
            int contentLength = 0;
            StringBuilder requestLine = new StringBuilder();
            boolean headersDone = false;

            while ((n = in.read(buf)) != -1) {
                baos.write(buf, 0, n);
                String data = new String(baos.toByteArray(), StandardCharsets.UTF_8);

                if (!headersDone) {
                    int headerEnd = data.indexOf("\r\n\r\n");
                    if (headerEnd >= 0) {
                        String headerSection = data.substring(0, headerEnd);
                        // 解析 Content-Length
                        for (String line : headerSection.split("\r\n")) {
                            if (line.toLowerCase().startsWith("content-length:")) {
                                contentLength = Integer.parseInt(line.substring(15).trim());
                            }
                        }
                        if (headerSection.contains("\r\n")) {
                            requestLine = new StringBuilder(
                                    headerSection.substring(0, headerSection.indexOf("\r\n")));
                        } else {
                            requestLine = new StringBuilder(headerSection);
                        }
                        headersDone = true;

                        // 如果还有 body 数据需要读取
                        int bodyStart = headerEnd + 4;
                        int bodyLen = data.length() - bodyStart;
                        if (bodyLen < contentLength) {
                            continue;
                        }
                    }
                } else {
                    int headerEnd = data.indexOf("\r\n\r\n");
                    int bodyStart = headerEnd + 4;
                    int bodyLen = data.length() - bodyStart;
                    if (bodyLen >= contentLength) {
                        break;
                    }
                }
                if (headersDone) break;
            }

            String rawRequest = baos.toString("UTF-8");
            Log.d(TAG, "Received callback request: " + requestLine);

            // 解析请求行: GET /auth/callback?code=xxx&state=yyy HTTP/1.1
            String[] parts = requestLine.toString().split(" ");
            OAuthCallbackResult result = new OAuthCallbackResult();

            if (parts.length >= 2) {
                String path = parts[1];
                int queryStart = path.indexOf('?');
                if (queryStart >= 0) {
                    String query = path.substring(queryStart + 1);
                    Map<String, String> queryParams = parseQueryString(query);

                    result.code = queryParams.get("code");
                    result.state = queryParams.get("state");
                    result.error = queryParams.get("error");
                }
            }

            // 发送响应
            String responseBody;
            if (result.error != null) {
                responseBody = buildErrorPage(result.error);
            } else {
                responseBody = buildSuccessPage();
            }

            String httpResponse = "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/html; charset=utf-8\r\n" +
                    "Content-Length: " + responseBody.getBytes(StandardCharsets.UTF_8).length + "\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    responseBody;

            OutputStream out = client.getOutputStream();
            out.write(httpResponse.getBytes(StandardCharsets.UTF_8));
            out.flush();

            return result;
        }

        private Map<String, String> parseQueryString(String query) {
            Map<String, String> params = new HashMap<>();
            if (query == null || query.isEmpty()) return params;
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    String key = java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                    String value = java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                    params.put(key, value);
                }
            }
            return params;
        }

        /**
         * 停止服务器。
         */
        public void stop() {
            running = false;
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException e) {
                    Log.e(TAG, "Error closing callback server", e);
                }
            }
            Log.d(TAG, "OAuth callback server stopped");
        }

        public boolean isRunning() {
            return running;
        }

        private String buildSuccessPage() {
            return "<!DOCTYPE html>" +
                    "<html lang=\"en\">" +
                    "<head><meta charset=\"UTF-8\">" +
                    "<title>Authentication Successful - iFlow</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#10b981;" +
                    "border-radius:50%;display:flex;align-items:center;justify-content:center;" +
                    "color:white;font-size:2rem;font-weight:bold;}" +
                    "h1{color:#1f2937;margin-bottom:1rem;}" +
                    "p{color:#6b7280;margin-bottom:1.5rem;}" +
                    ".countdown{color:#9ca3af;font-size:0.75rem;margin-top:1rem;}" +
                    "</style></head>" +
                    "<body><div class=\"container\">" +
                    "<div class=\"icon\">&#10003;</div>" +
                    "<h1>Authentication Successful!</h1>" +
                    "<p>You have successfully authenticated with iFlow. " +
                    "You can now close this window and return to your terminal.</p>" +
                    "<div class=\"countdown\">This window will close automatically in " +
                    "<span id=\"countdown\">5</span> seconds</div>" +
                    "</div>" +
                    "<script>" +
                    "let c=5;const e=document.getElementById('countdown');" +
                    "setInterval(()=>{c--;e.textContent=c;if(c<=0)window.close();},1000);" +
                    "</script></body></html>";
        }

        private String buildErrorPage(String error) {
            return "<!DOCTYPE html>" +
                    "<html lang=\"en\">" +
                    "<head><meta charset=\"UTF-8\">" +
                    "<title>Authentication Failed - iFlow</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#f87171 0%,#dc2626 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#ef4444;" +
                    "border-radius:50%;display:flex;align-items:center;justify-content:center;" +
                    "color:white;font-size:2rem;font-weight:bold;}" +
                    "h1{color:#1f2937;margin-bottom:1rem;}" +
                    "p{color:#6b7280;margin-bottom:1.5rem;}" +
                    "</style></head>" +
                    "<body><div class=\"container\">" +
                    "<div class=\"icon\">&#10007;</div>" +
                    "<h1>Authentication Failed</h1>" +
                    "<p>Error: " + error + "</p>" +
                    "</div></body></html>";
        }
    }

    // ================================================================
    //  内部类：UserInfo
    // ================================================================

    /**
     * iFlow 用户信息。
     */
    public static class UserInfo {
        /** 用户唯一标识 */
        public String userId;

        /** 邮箱地址 */
        public String email;

        /** 显示名称 */
        public String displayName;

        /** 头像 URL */
        public String avatarUrl;

        /** 账户创建时间 */
        public String createdAt;

        /** 订阅计划名称 */
        public String subscriptionPlan;

        /** 订阅过期时间 */
        public String subscriptionExpiresAt;

        /** 信息获取时间戳 */
        public long fetchedAt;

        UserInfo() {
            this.userId = "";
            this.email = "";
            this.displayName = "";
            this.avatarUrl = "";
            this.createdAt = "";
            this.subscriptionPlan = "";
            this.subscriptionExpiresAt = "";
            this.fetchedAt = 0L;
        }

        /**
         * 检查用户信息是否有效（至少包含 userId）。
         *
         * @return true 如果用户信息有效
         */
        public boolean isValid() {
            return userId != null && !userId.trim().isEmpty();
        }

        /**
         * 检查订阅是否有效（未过期）。
         *
         * @return true 如果订阅有效或无需订阅
         */
        public boolean hasValidSubscription() {
            if (subscriptionPlan == null || subscriptionPlan.isEmpty()) {
                return true; // 无需订阅
            }
            if (subscriptionExpiresAt == null || subscriptionExpiresAt.isEmpty()) {
                return true; // 无过期时间，视为永久有效
            }
            try {
                // 尝试解析 ISO 8601 时间
                java.time.Instant expires = java.time.Instant.parse(subscriptionExpiresAt);
                return !java.time.Instant.now().isAfter(expires);
            } catch (Exception e) {
                // 无法解析，视为有效
                return true;
            }
        }
    }
}