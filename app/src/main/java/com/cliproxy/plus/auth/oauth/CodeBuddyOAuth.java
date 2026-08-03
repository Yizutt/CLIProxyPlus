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
 * CodeBuddyOAuth - CodeBuddy 浏览器 OAuth 认证实现
 * <p>
 * 实现 CodeBuddy 的 OAuth 2.0 Authorization Code flow with PKCE。
 * 通过启动本地 HTTP 回调服务器接收授权码，完成 OAuth 认证流程。
 * <p>
 * OAuth 流程：
 * 1. 生成 PKCE 码对 → 2. 构建授权 URL → 3. 启动本地回调服务器
 * 4. 用户在浏览器中完成认证 → 5. 回调服务器接收授权码
 * 6. 交换授权码为 Token → 7. 刷新 Token 等
 */
public class CodeBuddyOAuth extends OAuthProvider {

    private static final String TAG = "CodeBuddyOAuth";

    // === OAuth 端点常量 ===
    private static final String AUTH_URL = "https://codebuddy.ai/oauth/authorize";
    private static final String TOKEN_URL = "https://codebuddy.ai/oauth/token";
    private static final String CLIENT_ID = "codebuddy_android_client";
    private static final String REDIRECT_URI = "http://localhost:1456/auth/callback";
    private static final int DEFAULT_CALLBACK_PORT = 1456;
    private static final int CALLBACK_TIMEOUT_SECONDS = 300;
    private static final int POLL_INTERVAL_MS = 2000;

    // 配置文件中的代理 URL（可选）
    private final String proxyUrl;

    /**
     * 构造 CodeBuddyOAuth 实例
     */
    public CodeBuddyOAuth() {
        this.proxyUrl = "";
    }

    /**
     * 构造 CodeBuddyOAuth 实例，使用指定的代理 URL
     *
     * @param proxyUrl 代理 URL，为空则不使用代理
     */
    public CodeBuddyOAuth(String proxyUrl) {
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

                return result;
            } catch (OAuthException e) {
                throw new RuntimeException(e);
            } finally {
                server.stop();
            }
        });

        return new OAuthFlow(authUrl, state, "codebuddy", future);
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
        return sb.toString();
    }

    /**
     * 交换授权码为 Token
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
     * 使用自定义 redirect URI 交换授权码为 Token
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
    //  Token Refresh
    // ============================================================

    /**
     * 刷新 Access Token
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
            params.put("scope", "openid profile email");

            String responseBody = postForm(TOKEN_URL, params);
            AuthResult result = parseTokenResponse(responseBody);
            return result.tokenData;
        } catch (OAuthException e) {
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
     * JWT Claims 解析结果
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

            // 解析 CodeBuddy 自定义 claims
            this.accountId = obj.optString("account_id", "");
            if (accountId.isEmpty()) {
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
         * 等待 OAuth 回调，超时后返回
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
                    "<title>Authentication Successful - CodeBuddy</title>" +
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
                    "<p>You have successfully authenticated with CodeBuddy. " +
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
                    "<title>Authentication Failed - CodeBuddy</title>" +
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