package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * GitLabOAuth - GitLab Duo OAuth + PAT 认证实现
 * <p>
 * 支持 GitLab OAuth 2.0 Authorization Code flow（PKCE）和
 * Personal Access Token (PAT) 直接认证两种方式。
 * <p>
 * GitLab Duo 是 GitLab 的 AI 功能套件，使用 GitLab 的标准 OAuth 2.0
 * 基础设施进行身份认证。同时支持使用 GitLab Personal Access Token
 * 直接访问 GitLab API。
 * <p>
 * OAuth 流程：
 * 1. 生成 PKCE 码对 → 2. 构建授权 URL → 3. 启动本地回调服务器
 * 4. 用户在浏览器中完成 GitLab 认证 → 5. 回调服务器接收授权码
 * 6. 交换授权码为 Token → 7. 刷新 Token 等
 * <p>
 * PAT 流程：
 * 1. 用户提供 GitLab Personal Access Token
 * 2. 验证 PAT 对 GitLab API 的访问权限
 * 3. 返回认证结果
 * <p>
 * 端点参考: https://docs.gitlab.com/ee/api/oauth2.html
 */
public class GitLabOAuth extends OAuthProvider {

    private static final String TAG = "GitLabOAuth";

    // === OAuth 端点常量 ===

    /** GitLab OAuth 授权端点 */
    private static final String AUTH_URL = "https://gitlab.com/oauth/authorize";

    /** GitLab OAuth 令牌端点 */
    private static final String TOKEN_URL = "https://gitlab.com/oauth/token";

    /** GitLab OAuth 撤销端点 */
    private static final String REVOKE_URL = "https://gitlab.com/oauth/revoke";

    /** GitLab API 基础地址 */
    private static final String GITLAB_API_BASE = "https://gitlab.com/api/v4";

    /** GitLab API 当前用户端点（用于 PAT 验证） */
    private static final String GITLAB_USER_URL = GITLAB_API_BASE + "/user";

    /** GitLab 应用客户端 ID（占位，实际应由用户配置） */
    private static final String DEFAULT_CLIENT_ID = "gitlab-duo-android-client";

    /** 本地回调 URI */
    private static final String REDIRECT_URI = "http://localhost:1478/auth/callback";

    /** 本地回调服务器端口 */
    private static final int DEFAULT_CALLBACK_PORT = 1478;

    /** 回调等待超时（秒） */
    private static final int CALLBACK_TIMEOUT_SECONDS = 300;

    /** GitLab OAuth 作用域 */
    private static final String GITLAB_SCOPE = "openid profile email api read_api";

    /** 请求超时（毫秒） */
    private static final int REQUEST_TIMEOUT_MS = 15000;

    /** 最大重试次数 */
    private static final int MAX_RETRIES = 3;

    /** 重试基础等待时间（毫秒） */
    private static final long RETRY_BASE_DELAY_MS = 1000L;

    /** 默认 PAT 过期时间（毫秒），默认 30 天 */
    private static final long DEFAULT_PAT_TTL_MS = 30L * 24 * 60 * 60 * 1000L;

    // === 实例状态 ===

    /** 可选的代理 URL */
    private final String proxyUrl;

    /** OAuth 客户端 ID */
    private final String clientId;

    /** GitLab 实例基础 URL（支持自托管 GitLab） */
    private final String gitlabBaseUrl;

    /** 缓存的 PAT */
    private volatile String cachedPat;

    /** PAT 上次验证时间 */
    private volatile long lastPatValidationTime;

    /** PAT 验证冷却时间（毫秒） */
    private volatile long patValidationCooldownMs = 60_000L;

    // ============================================================
    //  构造
    // ============================================================

    /**
     * 构造默认的 GitLabOAuth 实例，使用 GitLab SaaS 端点。
     */
    public GitLabOAuth() {
        this("", DEFAULT_CLIENT_ID, "https://gitlab.com");
    }

    /**
     * 构造 GitLabOAuth 实例，使用指定的代理 URL。
     *
     * @param proxyUrl 可选代理 URL，为空时不使用代理
     */
    public GitLabOAuth(String proxyUrl) {
        this(proxyUrl, DEFAULT_CLIENT_ID, "https://gitlab.com");
    }

    /**
     * 构造 GitLabOAuth 实例，使用指定的客户端 ID 和 GitLab 实例 URL。
     *
     * @param proxyUrl     可选代理 URL，为空时不使用代理
     * @param clientId     GitLab OAuth 应用客户端 ID
     * @param gitlabBaseUrl GitLab 实例基础 URL（支持自托管）
     */
    public GitLabOAuth(String proxyUrl, String clientId, String gitlabBaseUrl) {
        this.proxyUrl = proxyUrl != null ? proxyUrl : "";
        this.clientId = (clientId != null && !clientId.trim().isEmpty())
                ? clientId.trim() : DEFAULT_CLIENT_ID;
        this.gitlabBaseUrl = (gitlabBaseUrl != null && !gitlabBaseUrl.trim().isEmpty())
                ? gitlabBaseUrl.trim().replaceAll("/+$", "")
                : "https://gitlab.com";
    }

    // ============================================================
    //  OAuthProvider 抽象方法实现
    // ============================================================

    /**
     * 启动 GitLab OAuth Authorization Code 流程（PKCE）。
     * <p>
     * 1. 生成 PKCE 码对
     * 2. 生成随机 state 参数用于 CSRF 防护
     * 3. 构建 GitLab 授权 URL
     * 4. 启动本地 HTTP 回调服务器
     * 5. 返回授权 URL，调用方应在浏览器中打开
     * 6. 在后台等待回调并交换 Token
     * <p>
     * 如果已配置 PAT，则直接使用 PAT 进行认证，无需启动 OAuth 流程。
     *
     * @return 包含 Token 数据的 AuthResult
     * @throws OAuthException 如果启动流程或令牌交换失败
     */
    public AuthResult startAuth() throws OAuthException {
        // 如果已配置 PAT，优先使用 PAT 直接认证
        if (cachedPat != null && !cachedPat.trim().isEmpty()) {
            log("GitLab PAT configured, using PAT authentication");
            return authenticateWithPat(cachedPat);
        }

        log("Starting GitLab OAuth flow (Authorization Code + PKCE)");

        PKCECodes pkceCodes = generatePKCECodes();
        String state = generateRandomState();

        // 构建授权 URL
        String authUrl = buildAuthorizationUrl(state, pkceCodes);

        // 启动本地回调服务器
        CallbackServer server = new CallbackServer(DEFAULT_CALLBACK_PORT);

        try {
            server.start();

            log("GitLab OAuth: waiting for callback on port " + DEFAULT_CALLBACK_PORT);
            Log.d(TAG, "Open this URL in a browser:\n" + authUrl);

            // 等待回调
            OAuthCallbackResult callback = server.waitForCallback(
                    CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (callback.error != null) {
                throw new OAuthException("callback_error",
                        "GitLab OAuth callback error: " + callback.error);
            }
            if (callback.code == null || callback.code.isEmpty()) {
                throw new OAuthException("code_missing",
                        "Authorization code not found in callback");
            }
            if (!state.equals(callback.state)) {
                throw new OAuthException("invalid_state",
                        "State parameter mismatch: possible CSRF attack");
            }

            // 交换授权码为 Token
            log("Authorization code received, exchanging for tokens...");
            AuthResult result = exchangeCodeForTokens(callback.code, pkceCodes);
            log("Token exchange successful");

            return result;
        } catch (OAuthException e) {
            throw e;
        } catch (Exception e) {
            logError("GitLab OAuth callback failed", e);
            throw new OAuthException("auth_failed",
                    "Authentication failed: " + e.getMessage(), e);
        } finally {
            server.stop();
        }
    }

    /**
     * 刷新 Access Token。
     * <p>
     * 使用 GitLab OAuth 的 refresh_token grant type 获取新的 access token。
     * GitLab 的 refresh token 不会过期，但会在以下情况下失效：
     * 用户撤销应用授权、密码更改、令牌被手动撤销等。
     * <p>
     * 如果使用 PAT 模式，则重新验证 PAT 的有效性。
     *
     * @param refreshToken 刷新令牌（OAuth 模式）或空字符串（PAT 模式）
     * @return 新的 Token 数据
     * @throws OAuthException 如果刷新失败
     */
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        // 如果使用 PAT 模式
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            if (cachedPat != null && !cachedPat.trim().isEmpty()) {
                log("GitLab PAT mode: re-validating PAT");
                AuthResult result = authenticateWithPat(cachedPat);
                return result.tokenData;
            }
            throw new OAuthException("refresh_token_required",
                    "Refresh token or PAT is required for token refresh");
        }

        // OAuth 模式：使用 refresh_token 刷新
        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_id", clientId);
            params.put("grant_type", "refresh_token");
            params.put("refresh_token", refreshToken.trim());

            String responseBody = postForm(TOKEN_URL, params);
            return parseTokenResponse(responseBody, refreshToken.trim());
        } catch (IOException e) {
            logError("Token refresh failed", e);
            throw new OAuthException("refresh_failed",
                    "Token refresh request failed: " + e.getMessage(), e);
        }
    }

    // ============================================================
    //  PAT 认证
    // ============================================================

    /**
     * 使用 GitLab Personal Access Token 进行认证。
     * <p>
     * 向 GitLab API /user 端点发送请求，验证 PAT 的有效性，
     * 并获取当前用户信息。
     *
     * @param pat GitLab Personal Access Token
     * @return 认证结果
     * @throws OAuthException 如果 PAT 无效或验证失败
     */
    public AuthResult authenticateWithPat(String pat) throws OAuthException {
        if (pat == null || pat.trim().isEmpty()) {
            throw new OAuthException("pat_required",
                    "GitLab Personal Access Token is required");
        }

        // 验证 PAT 并获取用户信息
        GitLabUserInfo userInfo = validatePatInternal(pat.trim());
        if (userInfo == null) {
            throw new OAuthException("pat_invalid",
                    "GitLab PAT validation failed. Please check your token.");
        }

        // 缓存 PAT
        this.cachedPat = pat.trim();

        TokenData tokenData = new TokenData();
        tokenData.accessToken = pat.trim();
        tokenData.refreshToken = ""; // PAT 模式无 refresh token
        tokenData.expiresIn = (int) (DEFAULT_PAT_TTL_MS / 1000L);
        tokenData.expireAt = System.currentTimeMillis() + DEFAULT_PAT_TTL_MS;
        tokenData.accountId = String.valueOf(userInfo.id);
        tokenData.email = userInfo.email;

        return new AuthResult(tokenData, pat.trim());
    }

    /**
     * 设置 GitLab Personal Access Token。
     *
     * @param pat GitLab PAT
     */
    public void setPat(String pat) {
        this.cachedPat = (pat != null) ? pat.trim() : null;
        this.lastPatValidationTime = 0;
        log("GitLab PAT set" + (this.cachedPat != null && !this.cachedPat.isEmpty()
                ? " (" + maskToken(this.cachedPat) + ")" : " (empty)"));
    }

    /**
     * 获取当前配置的 PAT（已掩码）。
     *
     * @return 掩码后的 PAT，如 "glpat-...abcd"
     */
    public String getMaskedPat() {
        if (cachedPat == null || cachedPat.isEmpty()) {
            return "";
        }
        return maskToken(cachedPat);
    }

    /**
     * 获取原始 PAT。
     *
     * @return 原始 PAT 字符串
     */
    public String getRawPat() {
        return cachedPat;
    }

    /**
     * 检查是否已配置 PAT。
     *
     * @return true 如果已设置非空 PAT
     */
    public boolean hasPat() {
        return cachedPat != null && !cachedPat.trim().isEmpty();
    }

    /**
     * 清除缓存的 PAT。
     */
    public void clearPat() {
        this.cachedPat = null;
        this.lastPatValidationTime = 0;
        log("GitLab PAT cleared");
    }

    /**
     * 验证当前 PAT 是否有效。
     * <p>
     * 使用缓存机制避免频繁调用 GitLab API。验证结果在冷却时间内有效。
     *
     * @return true 如果 PAT 有效
     */
    public boolean validatePat() {
        if (!hasPat()) {
            return false;
        }

        // 检查冷却时间
        long now = System.currentTimeMillis();
        if (lastPatValidationTime > 0
                && (now - lastPatValidationTime) < patValidationCooldownMs) {
            return true; // 缓存有效
        }

        try {
            GitLabUserInfo userInfo = validatePatInternal(cachedPat);
            lastPatValidationTime = now;
            return userInfo != null;
        } catch (Exception e) {
            logError("PAT validation failed", e);
            return false;
        }
    }

    /**
     * 设置 PAT 验证冷却时间。
     *
     * @param cooldownMs 冷却时间（毫秒），最小 1000ms
     */
    public void setPatValidationCooldownMs(long cooldownMs) {
        this.patValidationCooldownMs = Math.max(cooldownMs, 1000L);
    }

    // ============================================================
    //  授权 URL 构建
    // ============================================================

    /**
     * 构建 GitLab OAuth 授权 URL。
     * <p>
     * GitLab 的 OAuth 授权端点支持标准 OAuth 2.0 参数。
     * 使用 PKCE 增强安全性，无需客户端密钥。
     *
     * @param state     随机 state 参数（CSRF 防护）
     * @param pkceCodes PKCE 码对
     * @return 完整的授权 URL
     */
    private String buildAuthorizationUrl(String state, PKCECodes pkceCodes) {
        String authEndpoint = getAuthEndpoint();
        StringBuilder sb = new StringBuilder(authEndpoint);
        sb.append("?client_id=").append(encodeParam(clientId));
        sb.append("&response_type=code");
        sb.append("&redirect_uri=").append(encodeParam(REDIRECT_URI));
        sb.append("&scope=").append(encodeParam(GITLAB_SCOPE));
        sb.append("&state=").append(encodeParam(state));
        sb.append("&code_challenge=").append(encodeParam(pkceCodes.codeChallenge));
        sb.append("&code_challenge_method=S256");
        return sb.toString();
    }

    // ============================================================
    //  令牌交换
    // ============================================================

    /**
     * 使用授权码交换 Token。
     * <p>
     * 向 GitLab 令牌端点发送 POST 请求，交换授权码为访问令牌和刷新令牌。
     *
     * @param code      授权码
     * @param pkceCodes PKCE 码对（包含 code_verifier）
     * @return 认证结果
     * @throws OAuthException 如果令牌交换失败
     */
    public AuthResult exchangeCodeForTokens(String code, PKCECodes pkceCodes)
            throws OAuthException {
        if (pkceCodes == null) {
            throw new OAuthException("pkce_required",
                    "PKCE codes are required for token exchange");
        }
        if (code == null || code.trim().isEmpty()) {
            throw new OAuthException("code_required",
                    "Authorization code is required for token exchange");
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "authorization_code");
            params.put("client_id", clientId);
            params.put("code", code.trim());
            params.put("redirect_uri", REDIRECT_URI);
            params.put("code_verifier", pkceCodes.codeVerifier);

            String responseBody = postForm(TOKEN_URL, params);
            return parseTokenResponse(responseBody, null);
        } catch (IOException e) {
            logError("Token exchange failed", e);
            throw new OAuthException("exchange_failed",
                    "Token exchange request failed: " + e.getMessage(), e);
        }
    }

    // ============================================================
    //  令牌撤销
    // ============================================================

    /**
     * 撤销给定的 Access Token 或 Refresh Token。
     * <p>
     * 调用 GitLab 的撤销端点，使令牌立即失效。
     * 适用于用户登出或令牌不再需要时。
     *
     * @param token 要撤销的 access token 或 refresh token
     * @throws OAuthException 如果撤销请求失败
     */
    public void revokeToken(String token) throws OAuthException {
        if (token == null || token.trim().isEmpty()) {
            throw new OAuthException("token_required",
                    "Token is required for revocation");
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_id", clientId);
            params.put("token", token.trim());

            String responseBody = postForm(REVOKE_URL, params);
            log("Token revoked successfully");
        } catch (IOException e) {
            logError("Token revocation failed", e);
            throw new OAuthException("revoke_failed",
                    "Token revocation request failed: " + e.getMessage(), e);
        }
    }

    // ============================================================
    //  PAT 内部验证
    // ============================================================

    /**
     * 验证 PAT 并返回用户信息。
     * <p>
     * 向 GitLab API /user 端点发送 GET 请求，使用 PRIVATE-TOKEN 头进行认证。
     * 如果返回 200，则 PAT 有效；否则返回 null。
     *
     * @param pat GitLab Personal Access Token
     * @return 用户信息，如果 PAT 无效则返回 null
     */
    private GitLabUserInfo validatePatInternal(String pat) {
        if (pat == null || pat.trim().isEmpty()) {
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
                String responseBody = getWithPat(GITLAB_USER_URL, pat);
                if (responseBody == null || responseBody.isEmpty()) {
                    log("PAT validation returned empty response (attempt "
                            + (attempt + 1) + ")");
                    continue;
                }
                return parseUserInfoResponse(responseBody);
            } catch (IOException e) {
                lastError = e;
                String msg = e.getMessage();
                // 401/403 表示 PAT 无效，不重试
                if (msg != null && (msg.contains("HTTP 401")
                        || msg.contains("HTTP 403"))) {
                    log("PAT rejected (HTTP 4xx), not retrying");
                    return null;
                }
                logError("PAT validation attempt " + (attempt + 1) + " failed", e);
            }
        }

        if (lastError != null) {
            logError("PAT validation failed after " + MAX_RETRIES + " attempts",
                    lastError);
        }
        return null;
    }

    // ============================================================
    //  HTTP 请求
    // ============================================================

    /**
     * 发送带 PRIVATE-TOKEN 认证的 GET 请求。
     * <p>
     * GitLab 支持两种认证方式：PRIVATE-TOKEN 头和 Authorization: Bearer。
     * 这里使用 PRIVATE-TOKEN 头，这是 GitLab PAT 的推荐方式。
     *
     * @param urlStr 请求 URL
     * @param pat    GitLab Personal Access Token
     * @return 响应体字符串
     * @throws IOException 如果请求失败
     */
    private String getWithPat(String urlStr, String pat) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("PRIVATE-TOKEN", pat);
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
     * 发送带 Bearer Token 认证的 GET 请求（用于 OAuth access token）。
     *
     * @param urlStr     请求 URL
     * @param accessToken OAuth access token
     * @return 响应体字符串
     * @throws IOException 如果请求失败
     */
    public String getWithOAuthToken(String urlStr, String accessToken) throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
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
     * 读取 HTTP 响应体。
     */
    private String readResponse(HttpURLConnection conn, int responseCode)
            throws IOException {
        java.io.InputStream inputStream;
        if (responseCode >= HttpURLConnection.HTTP_BAD_REQUEST) {
            inputStream = conn.getErrorStream();
            if (inputStream == null) {
                return "";
            }
        } else {
            inputStream = conn.getInputStream();
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = inputStream.read(buf)) != -1) {
            baos.write(buf, 0, n);
        }
        inputStream.close();
        return baos.toString("UTF-8");
    }

    // ============================================================
    //  响应解析
    // ============================================================

    /**
     * 解析 GitLab OAuth 令牌响应 JSON。
     * <p>
     * GitLab 的令牌响应包含 access_token、refresh_token（首次授权）、
     * id_token、expires_in 等字段。
     * <p>
     * 令牌响应格式：
     * <pre>
     * {
     *   "access_token": "glpat-xxx",
     *   "token_type": "Bearer",
     *   "expires_in": 7200,
     *   "refresh_token": "glrt-xxx",
     *   "id_token": "eyJ...",
     *   "scope": "openid profile email api read_api"
     * }
     * </pre>
     *
     * @param json            原始 JSON 响应
     * @param existingRefresh 已有的 refresh_token（刷新流程中使用），
     *                        如果为空则从响应中提取
     * @return 认证结果
     * @throws OAuthException 如果解析失败
     */
    private AuthResult parseTokenResponse(String json, String existingRefresh)
            throws OAuthException {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查错误响应
            String error = obj.optString("error", "");
            if (!error.isEmpty()) {
                String errorDesc = obj.optString("error_description", "");
                throw new OAuthException("token_error",
                        "GitLab OAuth error: " + error + " - " + errorDesc);
            }

            String accessToken = obj.optString("access_token", "");
            if (accessToken.isEmpty()) {
                throw new OAuthException("access_token_missing",
                        "Access token not found in response");
            }

            // 刷新流程可能不返回新的 refresh_token，此时使用已有的
            String refreshToken = obj.optString("refresh_token", "");
            if (refreshToken.isEmpty() && existingRefresh != null) {
                refreshToken = existingRefresh;
            }

            String idToken = obj.optString("id_token", "");
            int expiresIn = obj.optInt("expires_in", 7200);

            // 从 ID Token 中提取用户信息
            String accountId = "";
            String email = "";
            if (idToken != null && !idToken.isEmpty()) {
                try {
                    JWTClaims claims = parseJWT(idToken);
                    if (claims != null) {
                        accountId = claims.sub;
                        email = claims.email;
                    }
                } catch (Exception e) {
                    logError("Failed to parse ID token", e);
                }
            }

            // 如果 ID Token 中没有用户信息，尝试从 GitLab API 获取
            if (accountId.isEmpty() && !accessToken.isEmpty()) {
                try {
                    String userResponse = getWithOAuthToken(
                            GITLAB_USER_URL, accessToken);
                    JSONObject userObj = new JSONObject(userResponse);
                    accountId = userObj.optString("id", "");
                    if (email.isEmpty()) {
                        email = userObj.optString("email", "");
                    }
                } catch (Exception e) {
                    logError("Failed to fetch user info from GitLab API", e);
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
            throw new OAuthException("parse_failed",
                    "Failed to parse token response: " + e.getMessage(), e);
        }
    }

    /**
     * 解析 GitLab API /user 响应 JSON。
     * <p>
     * GitLab 用户信息格式：
     * <pre>
     * {
     *   "id": 12345,
     *   "username": "johndoe",
     *   "email": "john@example.com",
     *   "name": "John Doe",
     *   "state": "active",
     *   "avatar_url": "https://gitlab.com/uploads/...",
     *   "web_url": "https://gitlab.com/johndoe"
     * }
     * </pre>
     *
     * @param json 原始 JSON 响应
     * @return 用户信息对象，解析失败时返回 null
     */
    private GitLabUserInfo parseUserInfoResponse(String json) {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查错误响应
            String message = obj.optString("message", "");
            if (!message.isEmpty()) {
                log("GitLab API returned error: " + message);
                return null;
            }

            GitLabUserInfo info = new GitLabUserInfo();
            info.id = obj.optLong("id", 0);
            info.username = obj.optString("username", "");
            info.email = obj.optString("email", "");
            info.name = obj.optString("name", "");
            info.state = obj.optString("state", "");
            info.avatarUrl = obj.optString("avatar_url", "");
            info.webUrl = obj.optString("web_url", "");

            if (info.id == 0) {
                log("GitLab API returned user without valid id");
                return null;
            }

            info.valid = true;
            return info;
        } catch (org.json.JSONException e) {
            logError("Failed to parse user info response", e);
            return null;
        }
    }

    // ============================================================
    //  JWT 解析
    // ============================================================

    /**
     * 解析 JWT Token 的 claims 部分（不验证签名）。
     * <p>
     * 从 GitLab 返回的 id_token 中提取用户信息，
     * 包括 sub（GitLab 用户 ID）、email、name 等。
     *
     * @param token JWT 格式的 ID Token
     * @return 解析后的 claims，解析失败时返回 null
     */
    public JWTClaims parseJWT(String token) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                logError("Invalid JWT format: expected 3 parts, got "
                        + parts.length, null);
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
     * 包含 GitLab ID Token 中的标准声明：
     * - sub: GitLab 用户唯一标识符
     * - email: 用户的邮箱地址
     * - email_verified: 邮箱是否已验证
     * - name: 用户显示名称
     * - preferred_username: GitLab 用户名
     */
    public static class JWTClaims {
        public final String email;
        public final boolean emailVerified;
        public final String sub;
        public final String name;
        public final String preferredUsername;
        public final String rawJson;

        JWTClaims(String json) throws org.json.JSONException {
            this.rawJson = json;
            JSONObject obj = new JSONObject(json);
            this.email = obj.optString("email", "");
            this.emailVerified = obj.optBoolean("email_verified", false);
            this.sub = obj.optString("sub", "");
            this.name = obj.optString("name", "");
            this.preferredUsername = obj.optString("preferred_username", "");
        }

        public String getAccountId() {
            return sub;
        }

        public String getEmail() {
            return email;
        }
    }

    // ============================================================
    //  辅助方法
    // ============================================================

    /**
     * 生成随机的 state 参数用于 CSRF 防护。
     */
    private String generateRandomState() {
        byte[] bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * URL 编码参数值。
     */
    private String encodeParam(String value) {
        try {
            return URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            return value;
        }
    }

    /**
     * 掩码 Token，仅显示前 5 位和后 4 位字符。
     * <p>
     * GitLab PAT 格式：glpat-xxxxxxxxxxxxxxxx
     * 例如 "glpat-xxxxxxxxxxxxxxxxabcd" → "glpat-...abcd"
     */
    private static String maskToken(String token) {
        if (token == null || token.isEmpty()) {
            return "";
        }
        int len = token.length();
        if (len <= 8) {
            return token.substring(0, Math.min(3, len)) + "...";
        }
        return token.substring(0, Math.min(5, len)) + "..." + token.substring(len - 4);
    }

    /**
     * 检查 Token 是否为有效的 GitLab PAT 格式。
     * <p>
     * GitLab PAT 通常以 "glpat-" 开头。
     *
     * @param token Token 字符串
     * @return true 如果格式看起来有效
     */
    public static boolean isValidPatFormat(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }
        String trimmed = token.trim();
        return trimmed.startsWith("glpat-");
    }

    /**
     * 获取 GitLab OAuth 授权端点 URL。
     * <p>
     * 支持自托管 GitLab 实例，返回对应的端点 URL。
     *
     * @return 授权端点 URL
     */
    public String getAuthEndpoint() {
        return gitlabBaseUrl + "/oauth/authorize";
    }

    /**
     * 获取 GitLab OAuth 令牌端点 URL。
     *
     * @return 令牌端点 URL
     */
    public String getTokenEndpoint() {
        return gitlabBaseUrl + "/oauth/token";
    }

    /**
     * 获取 GitLab 实例基础 URL。
     *
     * @return GitLab 实例基础 URL
     */
    public String getGitlabBaseUrl() {
        return gitlabBaseUrl;
    }

    /**
     * 获取当前使用的客户端 ID。
     *
     * @return 客户端 ID
     */
    public String getClientId() {
        return clientId;
    }

    // ============================================================
    //  内部类：CallbackServer（轻量级 HTTP 回调服务器）
    // ============================================================

    /**
     * 轻量级本地 HTTP 服务器，用于接收 GitLab OAuth 回调。
     * <p>
     * 在本地端口上监听，等待 GitLab 在用户完成授权后重定向浏览器，
     * 从回调 URL 中提取授权码和 state 参数。
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
         * @throws OAuthException 如果端口被占用或启动失败
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
                Log.d(TAG, "GitLab OAuth callback server started on port " + port);
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
         * @return 解析后的回调结果（包含 code 和 state）
         * @throws OAuthException 如果超时或服务器错误
         */
        public OAuthCallbackResult waitForCallback(long timeout, TimeUnit unit)
                throws OAuthException {
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
                    // 尝试继续等待
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
            throw new OAuthException("server_stopped",
                    "Callback server was stopped");
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
                                contentLength = Integer.parseInt(
                                        line.substring(15).trim());
                            }
                        }
                        if (headerSection.contains("\r\n")) {
                            requestLine = new StringBuilder(
                                    headerSection.substring(0,
                                            headerSection.indexOf("\r\n")));
                        } else {
                            requestLine = new StringBuilder(headerSection);
                        }
                        headersDone = true;

                        // 如果还有 body 数据需要读取
                        int bodyStart = headerEnd + 4;
                        int bodyLen = data.length() - bodyStart;
                        if (bodyLen < contentLength) {
                            continue; // body 尚未完全读取
                        }
                    }
                } else {
                    // 检查 body 是否完整
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

            // 发送响应页面
            String responseBody;
            if (result.error != null) {
                responseBody = buildErrorPage(result.error);
            } else {
                responseBody = buildSuccessPage();
            }

            String httpResponse = "HTTP/1.1 200 OK\r\n" +
                    "Content-Type: text/html; charset=utf-8\r\n" +
                    "Content-Length: "
                    + responseBody.getBytes(StandardCharsets.UTF_8).length + "\r\n" +
                    "Connection: close\r\n" +
                    "\r\n" +
                    responseBody;

            OutputStream out = client.getOutputStream();
            out.write(httpResponse.getBytes(StandardCharsets.UTF_8));
            out.flush();

            return result;
        }

        /**
         * 解析 URL 查询字符串为键值映射。
         */
        private Map<String, String> parseQueryString(String query) {
            Map<String, String> params = new HashMap<>();
            if (query == null || query.isEmpty()) return params;
            for (String pair : query.split("&")) {
                int eq = pair.indexOf('=');
                if (eq > 0) {
                    String key = java.net.URLDecoder.decode(
                            pair.substring(0, eq), StandardCharsets.UTF_8);
                    String value = java.net.URLDecoder.decode(
                            pair.substring(eq + 1), StandardCharsets.UTF_8);
                    params.put(key, value);
                }
            }
            return params;
        }

        /**
         * 停止服务器并释放端口。
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
            Log.d(TAG, "GitLab OAuth callback server stopped");
        }

        public boolean isRunning() {
            return running;
        }

        /**
         * 构建授权成功页面（HTML）。
         */
        private String buildSuccessPage() {
            return "<!DOCTYPE html>" +
                    "<html lang=\"en\">" +
                    "<head><meta charset=\"UTF-8\">" +
                    "<title>Authentication Successful - GitLab Duo</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#FC6D26 0%,#E24329 50%,#FCA326 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#E24329;" +
                    "border-radius:50%;display:flex;align-items:center;justify-content:center;" +
                    "color:white;font-size:2rem;font-weight:bold;}" +
                    "h1{color:#1f2937;margin-bottom:1rem;}" +
                    "p{color:#6b7280;margin-bottom:1.5rem;}" +
                    ".countdown{color:#9ca3af;font-size:0.75rem;margin-top:1rem;}" +
                    "</style></head>" +
                    "<body><div class=\"container\">" +
                    "<div class=\"icon\">&#10003;</div>" +
                    "<h1>Authentication Successful!</h1>" +
                    "<p>You have successfully authenticated with GitLab Duo.<br>" +
                    "You can now close this window and return to your terminal.</p>" +
                    "<div class=\"countdown\">This window will close automatically in " +
                    "<span id=\"countdown\">5</span> seconds</div>" +
                    "</div>" +
                    "<script>" +
                    "let c=5;const e=document.getElementById('countdown');" +
                    "setInterval(()=>{c--;e.textContent=c;if(c<=0)window.close();},1000);" +
                    "</script></body></html>";
        }

        /**
         * 构建授权失败页面（HTML）。
         */
        private String buildErrorPage(String error) {
            return "<!DOCTYPE html>" +
                    "<html lang=\"en\">" +
                    "<head><meta charset=\"UTF-8\">" +
                    "<title>Authentication Failed - GitLab Duo</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#FC6D26 0%,#E24329 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#E24329;" +
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

    // ============================================================
    //  内部类：GitLabUserInfo
    // ============================================================

    /**
     * GitLab 用户信息。
     * <p>
     * 包含从 GitLab API /user 端点返回的用户元数据。
     */
    public static class GitLabUserInfo {
        /** GitLab 用户 ID */
        public long id;

        /** GitLab 用户名 */
        public String username;

        /** 用户邮箱地址 */
        public String email;

        /** 用户显示名称 */
        public String name;

        /** 用户状态（active / blocked / etc） */
        public String state;

        /** 用户头像 URL */
        public String avatarUrl;

        /** 用户 GitLab 主页 URL */
        public String webUrl;

        /** 是否有效 */
        public boolean valid;

        GitLabUserInfo() {
            this.id = 0;
            this.username = "";
            this.email = "";
            this.name = "";
            this.state = "";
            this.avatarUrl = "";
            this.webUrl = "";
            this.valid = false;
        }
    }
}