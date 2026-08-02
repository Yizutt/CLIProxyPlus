package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * CodexOAuth - OpenAI Codex OAuth 认证实现
 * <p>
 * 支持标准 OAuth Authorization Code flow（PKCE）和 Device Code flow。
 * 使用 OpenAI 认证端点（auth.openai.com）进行用户认证。
 * <p>
 * OAuth 流程：
 * 1. 生成 PKCE 码对 → 2. 构建授权 URL → 3. 启动本地回调服务器
 * 4. 用户在浏览器中完成认证 → 5. 回调服务器接收授权码
 * 6. 交换授权码为 Token → 7. 刷新 Token 等
 * <p>
 * Device Code 流程：
 * 1. 向设备端点请求设备码 → 2. 返回用户验证 URL 和用户码
 * 3. 轮询 Token 端点直到用户完成认证
 */
public class CodexOAuth extends OAuthProvider {

    private static final String TAG = "CodexOAuth";

    // === OAuth 端点常量 ===
    private static final String AUTH_URL = "https://auth.openai.com/oauth/authorize";
    private static final String TOKEN_URL = "https://auth.openai.com/oauth/token";
    private static final String DEVICE_AUTH_URL = "https://auth.openai.com/oauth/device/code";
    private static final String CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
    private static final String REDIRECT_URI = "http://localhost:1455/auth/callback";
    private static final int DEFAULT_CALLBACK_PORT = 1455;
    private static final int CALLBACK_TIMEOUT_SECONDS = 300;
    private static final int POLL_INTERVAL_MS = 2000;

    // 配置文件中的代理 URL（可选）
    private final String proxyUrl;

    /**
     * 构造 CodexOAuth 实例
     */
    public CodexOAuth() {
        this.proxyUrl = "";
    }

    /**
     * 构造 CodexOAuth 实例，使用指定的代理 URL
     */
    public CodexOAuth(String proxyUrl) {
        this.proxyUrl = proxyUrl != null ? proxyUrl : "";
    }

    // ============================================================
    //  OAuth Authorization Code Flow（PKCE）
    // ============================================================

    /**
     * 启动标准 OAuth Authorization Code 流程（PKCE）
     * <p>
     * 1. 生成 PKCE 码对
     * 2. 生成随机 state 参数
     * 3. 构建授权 URL
     * 4. 启动本地 HTTP 回调服务器
     * 5. 返回授权 URL，调用方应在浏览器中打开
     * 6. 在后台等待回调并交换 Token
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

                return result;
            } catch (OAuthException e) {
                throw new RuntimeException(e);
            } finally {
                server.stop();
            }
        });

        return new OAuthFlow(authUrl, state, "codex", future);
    }

    /**
     * 构建 OAuth 授权 URL
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
        sb.append("&id_token_add_organizations=true");
        sb.append("&codex_cli_simplified_flow=true");
        return sb.toString();
    }

    /**
     * 交换授权码为 Token
     */
    public AuthResult exchangeCodeForTokens(String code, PKCECodes pkceCodes) throws OAuthException {
        return exchangeCodeForTokens(code, REDIRECT_URI, pkceCodes);
    }

    /**
     * 使用自定义 redirect URI 交换授权码为 Token
     * 支持设备登录等替代流程
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

            String responseBody = postForm(TOKEN_URL, params);
            return parseTokenResponse(responseBody);
        } catch (IOException e) {
            logError("Token exchange failed", e);
            throw new OAuthException("exchange_failed", "Token exchange request failed: " + e.getMessage(), e);
        }
    }

    /**
     * 解析 Token 响应 JSON
     */
    private AuthResult parseTokenResponse(String json) throws OAuthException {
        try {
            JSONObject obj = new JSONObject(json);

            String accessToken = obj.optString("access_token", "");
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

    // ============================================================
    //  Device Code Flow
    // ============================================================

    /**
     * 启动 Device Code 流程
     * <p>
     * 设备流程不需要启动本地服务器。用户通过设备码在另一台设备上完成认证。
     * 此方法返回设备认证信息，调用方应展示给用户并轮询等待完成。
     *
     * @return DeviceFlow 对象，包含设备码、用户码和验证 URL
     * @throws OAuthException 如果请求设备码失败
     */
    public DeviceFlow startDeviceAuth() throws OAuthException {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_id", CLIENT_ID);
            params.put("scope", "openid email profile offline_access");

            String responseBody = postForm(DEVICE_AUTH_URL, params);
            return parseDeviceFlowResponse(responseBody);
        } catch (IOException e) {
            logError("Failed to start device auth", e);
            throw new OAuthException("device_auth_start_failed",
                    "Failed to start device authorization: " + e.getMessage(), e);
        }
    }

    /**
     * 解析 Device Code 响应
     */
    private DeviceFlow parseDeviceFlowResponse(String json) throws OAuthException {
        try {
            JSONObject obj = new JSONObject(json);

            String deviceCode = obj.optString("device_code", "");
            String userCode = obj.optString("user_code", "");
            String verificationUri = obj.optString("verification_uri", "");
            String verificationUriComplete = obj.optString("verification_uri_complete", "");
            int expiresIn = obj.optInt("expires_in", 900);
            int interval = obj.optInt("interval", 5);

            if (deviceCode.isEmpty()) {
                throw new OAuthException("device_code_missing",
                        "Device code not found in response");
            }

            return new DeviceFlow(deviceCode, userCode, verificationUri,
                    verificationUriComplete, expiresIn, interval);
        } catch (org.json.JSONException e) {
            logError("Failed to parse device flow response", e);
            throw new OAuthException("parse_failed",
                    "Failed to parse device flow response: " + e.getMessage(), e);
        }
    }

    /**
     * 轮询等待设备码授权完成
     * <p>
     * 在用户于浏览器中完成授权后，获取 Token。
     *
     * @param deviceFlow 设备认证流信息
     * @return 认证结果
     * @throws OAuthException 如果轮询超时或失败
     */
    public AuthResult pollDeviceAuthorization(DeviceFlow deviceFlow) throws OAuthException {
        long deadline = System.currentTimeMillis() + (deviceFlow.expiresIn * 1000L);
        int interval = Math.max(deviceFlow.interval, 2) * 1000;

        while (System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(interval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OAuthException("poll_interrupted", "Device auth polling interrupted", e);
            }

            try {
                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
                params.put("device_code", deviceFlow.deviceCode);
                params.put("client_id", CLIENT_ID);

                String responseBody = postForm(TOKEN_URL, params);
                // 成功
                return parseTokenResponse(responseBody);
            } catch (IOException e) {
                String msg = e.getMessage();
                if (msg != null) {
                    // 检查是否包含 authorization_pending - 用户尚未完成授权
                    if (msg.contains("authorization_pending") || msg.contains("slow_down")) {
                        if (msg.contains("slow_down")) {
                            interval += 1000; // 服务器要求减慢轮询速度
                        }
                        continue;
                    }
                    // 检查是否包含 access_denied - 用户拒绝授权
                    if (msg.contains("access_denied")) {
                        throw new OAuthException("access_denied",
                                "User denied the authorization request");
                    }
                    // 检查是否包含 expired_token - 设备码已过期
                    if (msg.contains("expired_token")) {
                        throw new OAuthException("expired_token",
                                "Device code has expired. Please start again.");
                    }
                }
                // 其他错误，继续轮询
                logError("Device auth poll error", e);
            } catch (OAuthException e) {
                throw e;
            }
        }

        throw new OAuthException("poll_timeout",
                "Device authorization timed out after " + deviceFlow.expiresIn + " seconds");
    }

    // ============================================================
    //  Token Refresh
    // ============================================================

    /**
     * 刷新 Access Token
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
            params.put("client_id", CLIENT_ID);
            params.put("grant_type", "refresh_token");
            params.put("refresh_token", refreshToken);
            params.put("scope", "openid profile email");

            String responseBody = postForm(TOKEN_URL, params);
            AuthResult result = parseTokenResponse(responseBody);
            return result.tokenData;
        } catch (OAuthException e) {
            // 检查是否由于 refresh_token_reused 导致失败
            if (e.getMessage() != null && e.getMessage().contains("refresh_token_reused")) {
                log("Refresh token reused, treating as non-retryable");
            }
            throw e;
        } catch (IOException e) {
            logError("Token refresh failed", e);
            throw new OAuthException("refresh_failed", "Token refresh request failed: " + e.getMessage(), e);
        }
    }

    /**
     * 带重试机制的 Token 刷新
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
                // 检查是否是非可重试错误
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

    private boolean isNonRetryableRefreshError(OAuthException e) {
        String msg = e.getMessage();
        return msg != null && msg.toLowerCase().contains("refresh_token_reused");
    }

    // ============================================================
    //  JWT 解析
    // ============================================================

    /**
     * 解析 JWT Token 的 claims 部分（不验证签名）
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
     * JWT Claims 解析结果
     */
    public static class JWTClaims {
        public final String email;
        public final String sub;
        public final String accountId;
        public final String planType;
        public final String rawJson;

        JWTClaims(String json) throws org.json.JSONException {
            this.rawJson = json;
            JSONObject obj = new JSONObject(json);
            this.email = obj.optString("email", "");
            this.sub = obj.optString("sub", "");

            // 解析 OpenAI 自定义 claims
            JSONObject authInfo = obj.optJSONObject("https://api.openai.com/auth");
            if (authInfo != null) {
                this.accountId = authInfo.optString("chatgpt_account_id", "");
                this.planType = authInfo.optString("chatgpt_plan_type", "");
            } else {
                this.accountId = "";
                this.planType = "";
            }
        }

        public String getAccountId() {
            return accountId;
        }

        public String getEmail() {
            return email;
        }
    }

    // ============================================================
    //  辅助方法
    // ============================================================

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

    // ============================================================
    //  内部类：OAuthFlow
    // ============================================================

    /**
     * OAuth 流程信息，包含授权 URL 和用于等待结果的 Future
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
         * 同步等待认证完成
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

    // ============================================================
    //  内部类：DeviceFlow
    // ============================================================

    /**
     * Device Code 流程信息
     */
    public static class DeviceFlow {
        public final String deviceCode;
        public final String userCode;
        public final String verificationUri;
        public final String verificationUriComplete;
        public final int expiresIn;
        public final int interval;

        public DeviceFlow(String deviceCode, String userCode,
                          String verificationUri, String verificationUriComplete,
                          int expiresIn, int interval) {
            this.deviceCode = deviceCode;
            this.userCode = userCode;
            this.verificationUri = verificationUri;
            this.verificationUriComplete = verificationUriComplete;
            this.expiresIn = expiresIn;
            this.interval = interval;
        }

        /**
         * 获取用户友好的验证 URL
         */
        public String getDisplayUrl() {
            return verificationUriComplete != null && !verificationUriComplete.isEmpty()
                    ? verificationUriComplete
                    : verificationUri;
        }
    }

    // ============================================================
    //  内部类：CallbackServer（轻量级 HTTP 回调服务器）
    // ============================================================

    /**
     * 轻量级本地 HTTP 服务器，用于接收 OAuth 回调
     */
    public static class CallbackServer {
        private final int port;
        private ServerSocket serverSocket;
        private volatile boolean running;

        public CallbackServer(int port) {
            this.port = port;
        }

        /**
         * 启动服务器（在独立线程中运行）
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
         * 等待 OAuth 回调，超时后返回
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
            throw new OAuthException("server_stopped", "Callback server was stopped");
        }

        /**
         * 处理 HTTP 请求，解析 OAuth 回调参数
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
         * 停止服务器
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
                    "<title>Authentication Successful - Codex</title>" +
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
                    "<p>You have successfully authenticated with Codex. " +
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
                    "<title>Authentication Failed - Codex</title>" +
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