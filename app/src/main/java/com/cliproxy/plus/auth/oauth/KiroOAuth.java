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
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * KiroOAuth - AWS Kiro (CodeWhisperer) OAuth 认证实现
 * <p>
 * 支持三种认证流程：
 * 1. Google OAuth (Authorization Code flow with PKCE) - Google SSO 登录
 * 2. AWS Builder ID (Device Code flow) - AWS Builder ID 设备码登录
 * 3. IAM Identity Center (IDC) - IAM 身份中心认证
 * <p>
 * AWS Kiro 是 Amazon CodeWhisperer 的底层认证服务，提供多种身份认证方式。
 * 每个流程封装为独立的内部类，提供完整的认证生命周期管理。
 * <p>
 * 对应原版 CLIProxyAPIPlus/internal/auth/kiro/ 中的 Go 实现。
 */
public class KiroOAuth extends OAuthProvider {

    private static final String TAG = "KiroOAuth";

    // ================================================================
    //  AWS Kiro OAuth 端点常量
    // ================================================================

    /** AWS Kiro OAuth 授权端点 */
    private static final String AUTH_URL = "https://view.awsapps.com/auth/oauth/authorize";

    /** AWS Kiro OAuth 令牌端点 */
    private static final String TOKEN_URL = "https://view.awsapps.com/auth/oauth/token";

    /** AWS Kiro 设备授权端点 */
    private static final String DEVICE_AUTH_URL = "https://view.awsapps.com/auth/oauth/device/code";

    /** AWS Kiro 客户端 ID */
    private static final String CLIENT_ID = "amzn-aws-kiro-android-client";

    /** 重定向 URI（本地回调） */
    private static final String REDIRECT_URI = "http://localhost:1479/auth/callback";

    /** 本地回调服务器默认端口 */
    private static final int DEFAULT_CALLBACK_PORT = 1479;

    /** 回调等待超时时间（秒） */
    private static final int CALLBACK_TIMEOUT_SECONDS = 300;

    /** 设备流轮询间隔（毫秒） */
    private static final int POLL_INTERVAL_MS = 2000;

    /** 请求超时（毫秒） */
    private static final int REQUEST_TIMEOUT_MS = 15000;

    /** 最大重试次数 */
    private static final int MAX_RETRIES = 3;

    // ================================================================
    //  实例状态
    // ================================================================

    /** 当前活跃的设备流会话，按 state 参数索引 */
    private final Map<String, AwsBuilderIdFlow> activeDeviceSessions = new HashMap<>();

    /** 当前活跃的 IDC 会话，按 state 参数索引 */
    private final Map<String, IdentityCenterFlow> activeIdcSessions = new HashMap<>();

    // ================================================================
    //  构造
    // ================================================================

    /**
     * 创建一个 Kiro OAuth 提供者实例。
     */
    public KiroOAuth() {
        log("KiroOAuth initialized");
    }

    // ================================================================
    //  OAuthProvider 抽象方法实现
    // ================================================================

    /**
     * 启动 Kiro OAuth 认证流程。
     * <p>
     * KiroOAuth 支持多种认证方式，此方法默认使用 Google OAuth
     * Authorization Code flow with PKCE。调用方可通过其他方法
     * 启动 Builder ID 或 IDC 流程。
     *
     * @return 包含授权 URL 和 CompletableFuture 的 OAuthFlow 对象
     * @throws OAuthException 如果启动流程失败
     */
    @Override
    public AuthResult startAuth() throws OAuthException {
        log("Starting Kiro OAuth flow (Google OAuth default)");
        try {
            GoogleOAuthFlow flow = new GoogleOAuthFlow();
            OAuthFlow oauthFlow = flow.start();
            return oauthFlow.waitForResult();
        } catch (Exception e) {
            logError("Kiro OAuth start failed", e);
            throw new OAuthException("auth_start_failed",
                    "Failed to start Kiro OAuth: " + e.getMessage(), e);
        }
    }

    /**
     * 刷新 Access Token。
     * <p>
     * 使用刷新令牌获取新的访问令牌。Kiro 令牌刷新使用标准 OAuth 2.0
     * refresh_token grant type。
     *
     * @param refreshToken 刷新令牌
     * @return 新的 Token 数据
     * @throws OAuthException 如果刷新失败
     */
    @Override
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new OAuthException("refresh_token_required", "Refresh token is required");
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "refresh_token");
            params.put("client_id", CLIENT_ID);
            params.put("refresh_token", refreshToken.trim());
            params.put("scope", "openid email profile");

            String responseBody = postForm(TOKEN_URL, params);
            return parseTokenResponse(responseBody);
        } catch (IOException e) {
            logError("Token refresh failed", e);
            throw new OAuthException("refresh_failed",
                    "Token refresh request failed: " + e.getMessage(), e);
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
                    throw new OAuthException("retry_interrupted",
                            "Token refresh retry interrupted", e);
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
        return lower.contains("invalid_grant")
                || lower.contains("invalid_token")
                || lower.contains("invalid_client")
                || lower.contains("refresh_token_reused");
    }

    // ================================================================
    //  Google OAuth Flow
    // ================================================================

    /**
     * 启动 Google OAuth Authorization Code 流程（PKCE）。
     * <p>
     * 使用 Google 作为身份提供商（IdP）进行 AWS Kiro 认证。
     * 流程：生成 PKCE 码对 → 构建授权 URL → 启动本地回调服务器 →
     * 用户在浏览器中完成 Google 登录 → 回调服务器接收授权码 →
     * 交换授权码为 Token。
     *
     * @return OAuthFlow 对象，包含授权 URL 和用于等待结果的 Future
     * @throws OAuthException 如果启动流程失败
     */
    public GoogleOAuthFlow startGoogleOAuth() throws OAuthException {
        log("Starting Google OAuth flow for Kiro");
        return new GoogleOAuthFlow();
    }

    // ================================================================
    //  AWS Builder ID (Device Code) Flow
    // ================================================================

    /**
     * 启动 AWS Builder ID Device Code 流程。
     * <p>
     * 设备流程不需要启动本地服务器。用户通过设备码在另一台设备上完成认证。
     * 此方法返回设备认证信息，调用方应展示给用户并轮询等待完成。
     *
     * @return AwsBuilderIdFlow 对象，包含设备码、用户码和验证 URL
     * @throws OAuthException 如果请求设备码失败
     */
    public AwsBuilderIdFlow startAwsBuilderIdFlow() throws OAuthException {
        log("Starting AWS Builder ID device code flow");
        return new AwsBuilderIdFlow();
    }

    // ================================================================
    //  IAM Identity Center (IDC) Flow
    // ================================================================

    /**
     * 启动 IAM Identity Center 认证流程。
     * <p>
     * IAM Identity Center (IDC) 允许用户使用 AWS IAM 身份中心进行认证。
     * 流程：启动本地回调服务器 → 构建 IDC 授权 URL → 用户在浏览器中
     * 完成认证 → 回调服务器接收授权码 → 交换授权码为 Token。
     *
     * @param idcRegion     IAM Identity Center 区域，如 "us-east-1"
     * @param idcStartUrl   IAM Identity Center 起始 URL
     * @return IdentityCenterFlow 对象
     * @throws OAuthException 如果启动流程失败
     */
    public IdentityCenterFlow startIdentityCenterFlow(String idcRegion, String idcStartUrl)
            throws OAuthException {
        log("Starting IAM Identity Center flow for region: " + idcRegion);
        return new IdentityCenterFlow(idcRegion, idcStartUrl);
    }

    // ================================================================
    //  内部 Token 响应解析
    // ================================================================

    /**
     * 解析 Token 响应 JSON。
     * <p>
     * AWS Kiro 令牌端点返回标准 OAuth 2.0 响应格式：
     * <pre>
     * {
     *   "access_token": "eyJ...",
     *   "refresh_token": "kiro_rt_...",
     *   "id_token": "eyJ...",
     *   "token_type": "Bearer",
     *   "expires_in": 3600,
     *   "scope": "openid email profile"
     * }
     * </pre>
     */
    private TokenData parseTokenResponse(String json) throws OAuthException {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查 OAuth 错误
            String error = obj.optString("error", "");
            if (!error.isEmpty()) {
                String errorDesc = obj.optString("error_description", "");
                throw new OAuthException("token_error",
                        "Kiro OAuth error: " + error + " - " + errorDesc);
            }

            String accessToken = obj.optString("access_token", "");
            if (accessToken.isEmpty()) {
                throw new OAuthException("access_token_missing",
                        "Access token not found in response");
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

            return tokenData;
        } catch (org.json.JSONException e) {
            logError("Failed to parse token response", e);
            throw new OAuthException("parse_failed",
                    "Failed to parse token response: " + e.getMessage(), e);
        }
    }

    /**
     * 从 Token 响应 JSON 构造 AuthResult。
     */
    private AuthResult parseTokenResponseToAuthResult(String json) throws OAuthException {
        TokenData tokenData = parseTokenResponse(json);
        return new AuthResult(tokenData);
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

            // 解析 AWS Kiro 自定义 claims
            JSONObject kiroAuth = obj.optJSONObject("https://aws.amazon.com/kiro/auth");
            if (kiroAuth != null) {
                this.accountId = kiroAuth.optString("account_id", "");
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
                throw new OAuthException("auth_interrupted",
                        "Authentication was interrupted", e);
            }
        }
    }

    // ================================================================
    //  内部类：GoogleOAuthFlow
    // ================================================================

    /**
     * Google OAuth 认证流程。
     * <p>
     * 使用 Google 作为身份提供商，通过标准 OAuth 2.0 Authorization Code
     * flow with PKCE 进行认证。启动本地回调服务器接收授权码，
     * 然后交换为 AWS Kiro 令牌。
     * <p>
     * 流程：
     * 1. 生成 PKCE 码对
     * 2. 生成随机 state 参数
     * 3. 构建带有 Google SSO 提示的授权 URL
     * 4. 启动本地 HTTP 回调服务器监听 1479 端口
     * 5. 返回授权 URL，调用方应在浏览器中打开
     * 6. 后台等待回调并交换 Token
     */
    public class GoogleOAuthFlow {

        private final String authUrl;
        private final String state;
        private final PKCECodes pkceCodes;
        private final CallbackServer callbackServer;
        private final CompletableFuture<AuthResult> future;

        /**
         * 创建并启动 Google OAuth 流程。
         *
         * @throws OAuthException 如果启动流程失败
         */
        GoogleOAuthFlow() throws OAuthException {
            this.pkceCodes = generatePKCECodes();
            this.state = generateRandomState();
            this.authUrl = buildGoogleAuthUrl();
            this.callbackServer = new CallbackServer(DEFAULT_CALLBACK_PORT);
            this.future = startAsyncFlow();
            log("GoogleOAuthFlow created with auth URL");
        }

        /**
         * 构建 Google SSO 授权 URL。
         */
        private String buildGoogleAuthUrl() {
            StringBuilder sb = new StringBuilder(AUTH_URL);
            sb.append("?client_id=").append(encodeParam(CLIENT_ID));
            sb.append("&response_type=code");
            sb.append("&redirect_uri=").append(encodeParam(REDIRECT_URI));
            sb.append("&scope=").append(encodeParam("openid email profile offline_access"));
            sb.append("&state=").append(encodeParam(state));
            sb.append("&code_challenge=").append(encodeParam(pkceCodes.codeChallenge));
            sb.append("&code_challenge_method=S256");
            sb.append("&prompt=login");
            sb.append("&identity_provider=Google");
            sb.append("&idp_identifier=accounts.google.com");
            return sb.toString();
        }

        /**
         * 启动异步认证流程。
         */
        private CompletableFuture<AuthResult> startAsyncFlow() {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    callbackServer.start();

                    OAuthCallbackResult callback = callbackServer.waitForCallback(
                            CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    if (callback.error != null) {
                        throw new OAuthException("callback_error",
                                "OAuth callback error: " + callback.error);
                    }
                    if (!state.equals(callback.state)) {
                        throw new OAuthException("invalid_state", "State parameter mismatch");
                    }

                    log("Google OAuth authorization code received, exchanging for tokens...");
                    AuthResult result = exchangeGoogleCodeForTokens(callback.code);
                    log("Google OAuth token exchange successful");
                    return result;
                } catch (OAuthException e) {
                    throw new RuntimeException(e);
                } finally {
                    callbackServer.stop();
                }
            });
        }

        /**
         * 交换 Google OAuth 授权码为 Token。
         */
        private AuthResult exchangeGoogleCodeForTokens(String code) throws OAuthException {
            try {
                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "authorization_code");
                params.put("client_id", CLIENT_ID);
                params.put("code", code);
                params.put("redirect_uri", REDIRECT_URI);
                params.put("code_verifier", pkceCodes.codeVerifier);

                String responseBody = postForm(TOKEN_URL, params);
                return parseTokenResponseToAuthResult(responseBody);
            } catch (IOException e) {
                logError("Google OAuth token exchange failed", e);
                throw new OAuthException("exchange_failed",
                        "Google OAuth token exchange failed: " + e.getMessage(), e);
            }
        }

        /**
         * 获取授权 URL，调用方应在浏览器中打开此 URL。
         *
         * @return Google OAuth 授权 URL
         */
        public String getAuthUrl() {
            return authUrl;
        }

        /**
         * 获取 state 参数，用于 CSRF 验证。
         *
         * @return state 字符串
         */
        public String getState() {
            return state;
        }

        /**
         * 获取用于等待认证结果的 Future。
         *
         * @return CompletableFuture，完成时返回 AuthResult
         */
        public CompletableFuture<AuthResult> getFuture() {
            return future;
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
                        "Google OAuth callback timeout after "
                                + CALLBACK_TIMEOUT_SECONDS + " seconds", e);
            } catch (java.util.concurrent.ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof OAuthException) {
                    throw (OAuthException) cause;
                }
                throw new OAuthException("auth_failed",
                        "Google OAuth failed: " + cause.getMessage(), cause);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OAuthException("auth_interrupted",
                        "Google OAuth was interrupted", e);
            }
        }

        /**
         * 取消认证流程。
         */
        public void cancel() {
            future.cancel(true);
            callbackServer.stop();
            log("Google OAuth flow cancelled");
        }
    }

    // ================================================================
    //  内部类：AwsBuilderIdFlow
    // ================================================================

    /**
     * AWS Builder ID 设备码认证流程。
     * <p>
     * 使用 AWS Builder ID 通过 OAuth 2.0 Device Authorization Grant (RFC 8628)
     * 进行认证。此流程不需要本地回调服务器，用户通过设备码在浏览器中
     * 完成授权，然后通过轮询获取令牌。
     * <p>
     * 流程：
     * 1. 向设备授权端点请求设备码
     * 2. 返回用户验证 URL 和用户码，调用方应展示给用户
     * 3. 用户访问验证 URL 并输入用户码完成授权
     * 4. 轮询令牌端点直到用户完成认证或超时
     */
    public class AwsBuilderIdFlow {

        private final String deviceCode;
        private final String userCode;
        private final String verificationUri;
        private final String verificationUriComplete;
        private final int expiresIn;
        private final int interval;
        private volatile boolean completed;
        private volatile AuthResult authResult;
        private volatile OAuthException authError;

        /**
         * 创建并启动 AWS Builder ID 设备码流程。
         *
         * @throws OAuthException 如果请求设备码失败
         */
        AwsBuilderIdFlow() throws OAuthException {
            try {
                Map<String, String> params = new HashMap<>();
                params.put("client_id", CLIENT_ID);
                params.put("scope", "openid email profile offline_access");
                params.put("identity_provider", "AwsBuilderId");

                String responseBody = postForm(DEVICE_AUTH_URL, params);
                JSONObject obj = new JSONObject(responseBody);

                this.deviceCode = obj.optString("device_code", "");
                this.userCode = obj.optString("user_code", "");
                this.verificationUri = obj.optString("verification_uri", "");
                this.verificationUriComplete = obj.optString("verification_uri_complete", "");
                this.expiresIn = obj.optInt("expires_in", 900);
                this.interval = obj.optInt("interval", 5);
                this.completed = false;

                if (deviceCode.isEmpty()) {
                    throw new OAuthException("device_code_missing",
                            "Device code not found in AWS Builder ID response");
                }

                log("AwsBuilderIdFlow created: user_code=" + userCode
                        + ", verification_uri=" + verificationUri);
            } catch (org.json.JSONException e) {
                logError("Failed to parse device code response", e);
                throw new OAuthException("parse_failed",
                        "Failed to parse AWS Builder ID device code response: " + e.getMessage(), e);
            } catch (IOException e) {
                logError("Failed to start AWS Builder ID device auth", e);
                throw new OAuthException("device_auth_start_failed",
                        "Failed to start AWS Builder ID authorization: " + e.getMessage(), e);
            }
        }

        /**
         * 获取设备码。
         *
         * @return 设备码字符串
         */
        public String getDeviceCode() {
            return deviceCode;
        }

        /**
         * 获取用户码，用户需要在验证页面输入此码。
         *
         * @return 用户码字符串
         */
        public String getUserCode() {
            return userCode;
        }

        /**
         * 获取验证 URI。
         *
         * @return 验证页面 URL
         */
        public String getVerificationUri() {
            return verificationUri;
        }

        /**
         * 获取包含用户码的完整验证 URI（可直接打开）。
         *
         * @return 完整验证 URL
         */
        public String getVerificationUriComplete() {
            return verificationUriComplete;
        }

        /**
         * 获取用户友好的显示 URL。
         *
         * @return 用户应在浏览器中打开此 URL
         */
        public String getDisplayUrl() {
            return verificationUriComplete != null && !verificationUriComplete.isEmpty()
                    ? verificationUriComplete
                    : verificationUri;
        }

        /**
         * 获取设备码过期时间（秒）。
         *
         * @return 过期时间（秒）
         */
        public int getExpiresIn() {
            return expiresIn;
        }

        /**
         * 获取推荐的轮询间隔（秒）。
         *
         * @return 轮询间隔（秒）
         */
        public int getInterval() {
            return interval;
        }

        /**
         * 检查认证是否已完成。
         *
         * @return true 如果认证已完成（成功或失败）
         */
        public boolean isCompleted() {
            return completed;
        }

        /**
         * 检查认证是否已成功。
         *
         * @return true 如果认证成功
         */
        public boolean isSuccess() {
            return completed && authResult != null;
        }

        /**
         * 轮询等待用户完成授权。
         * <p>
         * 在用户于浏览器中完成授权后，获取 Token。
         * 此方法会阻塞直到认证完成或超时。
         *
         * @return 认证结果
         * @throws OAuthException 如果轮询超时或失败
         */
        public AuthResult pollForCompletion() throws OAuthException {
            if (completed) {
                if (authResult != null) return authResult;
                if (authError != null) throw authError;
            }

            long deadline = System.currentTimeMillis() + (expiresIn * 1000L);
            int currentInterval = Math.max(interval, 2) * 1000;

            while (System.currentTimeMillis() < deadline) {
                try {
                    Thread.sleep(currentInterval);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    completed = true;
                    authError = new OAuthException("poll_interrupted",
                            "AWS Builder ID polling interrupted", e);
                    throw authError;
                }

                try {
                    Map<String, String> params = new HashMap<>();
                    params.put("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
                    params.put("device_code", deviceCode);
                    params.put("client_id", CLIENT_ID);

                    String responseBody = postForm(TOKEN_URL, params);
                    authResult = parseTokenResponseToAuthResult(responseBody);
                    completed = true;
                    log("AWS Builder ID device auth completed successfully");
                    return authResult;
                } catch (IOException e) {
                    String msg = e.getMessage();
                    if (msg != null) {
                        if (msg.contains("authorization_pending")) {
                            continue;
                        }
                        if (msg.contains("slow_down")) {
                            currentInterval += 1000;
                            continue;
                        }
                        if (msg.contains("access_denied")) {
                            completed = true;
                            authError = new OAuthException("access_denied",
                                    "User denied the AWS Builder ID authorization request");
                            throw authError;
                        }
                        if (msg.contains("expired_token")) {
                            completed = true;
                            authError = new OAuthException("expired_token",
                                    "AWS Builder ID device code has expired. Please start again.");
                            throw authError;
                        }
                    }
                    logError("AWS Builder ID poll error", e);
                }
            }

            completed = true;
            authError = new OAuthException("poll_timeout",
                    "AWS Builder ID authorization timed out after " + expiresIn + " seconds");
            throw authError;
        }

        /**
         * 异步轮询等待认证完成。
         *
         * @return CompletableFuture，完成时返回 AuthResult
         */
        public CompletableFuture<AuthResult> pollAsync() {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return pollForCompletion();
                } catch (OAuthException e) {
                    throw new RuntimeException(e);
                }
            });
        }

        /**
         * 取消认证流程。
         */
        public void cancel() {
            completed = true;
            authError = new OAuthException("cancelled", "AWS Builder ID flow cancelled by user");
            log("AWS Builder ID flow cancelled");
        }
    }

    // ================================================================
    //  内部类：IdentityCenterFlow
    // ================================================================

    /**
     * IAM Identity Center (IDC) 认证流程。
     * <p>
     * 使用 AWS IAM Identity Center 进行认证，适用于企业用户。
     * 通过标准 OAuth 2.0 Authorization Code flow with PKCE 进行认证，
     * 使用本地回调服务器接收授权码。
     * <p>
     * 流程：
     * 1. 生成 PKCE 码对
     * 2. 生成随机 state 参数
     * 3. 构建带有 IDC 区域和起始 URL 的授权 URL
     * 4. 启动本地 HTTP 回调服务器
     * 5. 返回授权 URL，调用方应在浏览器中打开
     * 6. 后台等待回调并交换 Token
     */
    public class IdentityCenterFlow {

        private final String idcRegion;
        private final String idcStartUrl;
        private final String authUrl;
        private final String state;
        private final PKCECodes pkceCodes;
        private final CallbackServer callbackServer;
        private final CompletableFuture<AuthResult> future;

        /**
         * 创建并启动 IAM Identity Center 认证流程。
         *
         * @param idcRegion   IAM Identity Center 区域，如 "us-east-1"
         * @param idcStartUrl IAM Identity Center 起始 URL
         * @throws OAuthException 如果启动流程失败
         */
        IdentityCenterFlow(String idcRegion, String idcStartUrl) throws OAuthException {
            if (idcRegion == null || idcRegion.trim().isEmpty()) {
                throw new OAuthException("idc_region_required",
                        "IAM Identity Center region is required");
            }
            if (idcStartUrl == null || idcStartUrl.trim().isEmpty()) {
                throw new OAuthException("idc_start_url_required",
                        "IAM Identity Center start URL is required");
            }

            this.idcRegion = idcRegion.trim();
            this.idcStartUrl = idcStartUrl.trim();
            this.pkceCodes = generatePKCECodes();
            this.state = generateRandomState();
            this.authUrl = buildIdcAuthUrl();
            this.callbackServer = new CallbackServer(DEFAULT_CALLBACK_PORT);
            this.future = startAsyncFlow();
            log("IdentityCenterFlow created for region: " + idcRegion);
        }

        /**
         * 构建 IAM Identity Center 授权 URL。
         */
        private String buildIdcAuthUrl() {
            StringBuilder sb = new StringBuilder(AUTH_URL);
            sb.append("?client_id=").append(encodeParam(CLIENT_ID));
            sb.append("&response_type=code");
            sb.append("&redirect_uri=").append(encodeParam(REDIRECT_URI));
            sb.append("&scope=").append(encodeParam("openid email profile offline_access"));
            sb.append("&state=").append(encodeParam(state));
            sb.append("&code_challenge=").append(encodeParam(pkceCodes.codeChallenge));
            sb.append("&code_challenge_method=S256");
            sb.append("&prompt=login");
            sb.append("&identity_provider=AWSSSO");
            sb.append("&idp_identifier=").append(encodeParam(idcStartUrl));
            sb.append("&idc_region=").append(encodeParam(idcRegion));
            return sb.toString();
        }

        /**
         * 启动异步认证流程。
         */
        private CompletableFuture<AuthResult> startAsyncFlow() {
            return CompletableFuture.supplyAsync(() -> {
                try {
                    callbackServer.start();

                    OAuthCallbackResult callback = callbackServer.waitForCallback(
                            CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
                    if (callback.error != null) {
                        throw new OAuthException("callback_error",
                                "IDC OAuth callback error: " + callback.error);
                    }
                    if (!state.equals(callback.state)) {
                        throw new OAuthException("invalid_state", "State parameter mismatch");
                    }

                    log("IDC authorization code received, exchanging for tokens...");
                    AuthResult result = exchangeIdcCodeForTokens(callback.code);
                    log("IDC token exchange successful");
                    return result;
                } catch (OAuthException e) {
                    throw new RuntimeException(e);
                } finally {
                    callbackServer.stop();
                }
            });
        }

        /**
         * 交换 IDC 授权码为 Token。
         */
        private AuthResult exchangeIdcCodeForTokens(String code) throws OAuthException {
            try {
                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "authorization_code");
                params.put("client_id", CLIENT_ID);
                params.put("code", code);
                params.put("redirect_uri", REDIRECT_URI);
                params.put("code_verifier", pkceCodes.codeVerifier);
                params.put("idc_region", idcRegion);

                String responseBody = postForm(TOKEN_URL, params);
                return parseTokenResponseToAuthResult(responseBody);
            } catch (IOException e) {
                logError("IDC token exchange failed", e);
                throw new OAuthException("exchange_failed",
                        "IAM Identity Center token exchange failed: " + e.getMessage(), e);
            }
        }

        /**
         * 获取 IAM Identity Center 区域。
         *
         * @return 区域字符串
         */
        public String getIdcRegion() {
            return idcRegion;
        }

        /**
         * 获取 IAM Identity Center 起始 URL。
         *
         * @return 起始 URL 字符串
         */
        public String getIdcStartUrl() {
            return idcStartUrl;
        }

        /**
         * 获取授权 URL，调用方应在浏览器中打开此 URL。
         *
         * @return IDC 授权 URL
         */
        public String getAuthUrl() {
            return authUrl;
        }

        /**
         * 获取 state 参数，用于 CSRF 验证。
         *
         * @return state 字符串
         */
        public String getState() {
            return state;
        }

        /**
         * 获取用于等待认证结果的 Future。
         *
         * @return CompletableFuture，完成时返回 AuthResult
         */
        public CompletableFuture<AuthResult> getFuture() {
            return future;
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
                        "IAM Identity Center callback timeout after "
                                + CALLBACK_TIMEOUT_SECONDS + " seconds", e);
            } catch (java.util.concurrent.ExecutionException e) {
                Throwable cause = e.getCause();
                if (cause instanceof OAuthException) {
                    throw (OAuthException) cause;
                }
                throw new OAuthException("auth_failed",
                        "IAM Identity Center auth failed: " + cause.getMessage(), cause);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OAuthException("auth_interrupted",
                        "IAM Identity Center auth was interrupted", e);
            }
        }

        /**
         * 取消认证流程。
         */
        public void cancel() {
            future.cancel(true);
            callbackServer.stop();
            log("IdentityCenterFlow cancelled for region: " + idcRegion);
        }
    }

    // ================================================================
    //  内部类：CallbackServer（轻量级 HTTP 回调服务器）
    // ================================================================

    /**
     * 轻量级本地 HTTP 服务器，用于接收 OAuth 回调。
     * <p>
     * 监听 localhost 的指定端口，解析 OAuth 授权码回调请求。
     * 支持标准 OAuth 2.0 Authorization Code 流的回调参数解析。
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
                log("Kiro callback server started on port " + port);
            } catch (IOException e) {
                throw new OAuthException("server_start_failed",
                        "Failed to start callback server on port " + port
                                + ": " + e.getMessage(), e);
            }
        }

        /**
         * 等待 OAuth 回调，超时后返回。
         *
         * @param timeout 超时时间
         * @param unit    时间单位
         * @return 回调结果
         * @throws OAuthException 如果等待超时或服务器停止
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
                    continue;
                } catch (IOException e) {
                    if (running) {
                        logError("Callback server accept error", e);
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

            log("Received callback request: " + requestLine);

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
                    String key = java.net.URLDecoder.decode(pair.substring(0, eq),
                            StandardCharsets.UTF_8);
                    String value = java.net.URLDecoder.decode(pair.substring(eq + 1),
                            StandardCharsets.UTF_8);
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
                    logError("Error closing callback server", e);
                }
            }
            log("Kiro callback server stopped");
        }

        public boolean isRunning() {
            return running;
        }

        private String buildSuccessPage() {
            return "<!DOCTYPE html>" +
                    "<html lang=\"en\">" +
                    "<head><meta charset=\"UTF-8\">" +
                    "<title>Authentication Successful - AWS Kiro</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#FF9900 0%,#232F3E 100%);}" +
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
                    "<p>You have successfully authenticated with AWS Kiro. " +
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
                    "<title>Authentication Failed - AWS Kiro</title>" +
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
}