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
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

/**
 * AntigravityOAuth - Google Antigravity OAuth 认证实现
 * <p>
 * 使用 Google OAuth 2.0 Authorization Code flow（PKCE）进行用户认证，
 * 支持 Google Cloud Platform 和 Antigravity API 的令牌获取与刷新。
 * Antigravity 是 Google 内部的高级 AI 推理平台，基于 Google Cloud 基础设施。
 * <p>
 * OAuth 流程：
 * 1. 生成 PKCE 码对 → 2. 构建授权 URL → 3. 启动本地回调服务器
 * 4. 用户在浏览器中完成 Google 认证 → 5. 回调服务器接收授权码
 * 6. 交换授权码为 Token → 7. 刷新 Token 等
 * <p>
 * 端点参考：
 * - 授权: https://accounts.google.com/o/oauth2/v2/auth
 * - 令牌: https://oauth2.googleapis.com/token
 * - 撤销: https://oauth2.googleapis.com/revoke
 */
public class AntigravityOAuth extends OAuthProvider {

    private static final String TAG = "AntigravityOAuth";

    // === OAuth 端点常量 ===
    private static final String AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
    private static final String TOKEN_URL = "https://oauth2.googleapis.com/token";
    private static final String REVOKE_URL = "https://oauth2.googleapis.com/revoke";

    /** Antigravity 客户端 ID（Google Cloud 项目） */
    private static final String CLIENT_ID = "94825173426-8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a.apps.googleusercontent.com";

    /** 本地回调 URI */
    private static final String REDIRECT_URI = "http://localhost:1478/auth/callback";

    /** 本地回调服务器端口 */
    private static final int DEFAULT_CALLBACK_PORT = 1478;

    /** 回调等待超时（秒） */
    private static final int CALLBACK_TIMEOUT_SECONDS = 300;

    /** Antigravity API 作用域（Google Cloud Platform） */
    private static final String ANTIGRAVITY_SCOPE =
            "openid email profile https://www.googleapis.com/auth/cloud-platform";

    // 配置文件中的代理 URL（可选）
    private final String proxyUrl;

    // ============================================================
    //  构造
    // ============================================================

    /**
     * 构造默认的 AntigravityOAuth 实例。
     */
    public AntigravityOAuth() {
        this.proxyUrl = "";
    }

    /**
     * 构造 AntigravityOAuth 实例，使用指定的代理 URL。
     *
     * @param proxyUrl 可选代理 URL，为空时不使用代理
     */
    public AntigravityOAuth(String proxyUrl) {
        this.proxyUrl = proxyUrl != null ? proxyUrl : "";
    }

    // ============================================================
    //  OAuthProvider 抽象方法实现
    // ============================================================

    /**
     * 启动 OAuth Authorization Code 流程（PKCE）。
     * <p>
     * 1. 生成 PKCE 码对
     * 2. 生成随机 state 参数用于 CSRF 防护
     * 3. 构建 Google 授权 URL
     * 4. 启动本地 HTTP 回调服务器
     * 5. 返回授权 URL，调用方应在浏览器中打开
     * 6. 在后台等待回调并交换 Token
     *
     * @return 包含 Token 数据的 AuthResult
     * @throws OAuthException 如果启动流程或令牌交换失败
     */
    @Override
    public AuthResult startAuth() throws OAuthException {
        PKCECodes pkceCodes = generatePKCECodes();
        String state = generateRandomState();

        // 构建授权 URL
        String authUrl = buildAuthorizationUrl(state, pkceCodes);

        // 启动本地回调服务器
        CallbackServer server = new CallbackServer(DEFAULT_CALLBACK_PORT);

        try {
            server.start();

            log("Antigravity OAuth: waiting for callback on port " + DEFAULT_CALLBACK_PORT);
            Log.d(TAG, "Open this URL in a browser:\n" + authUrl);

            // 等待回调
            OAuthCallbackResult callback = server.waitForCallback(
                    CALLBACK_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (callback.error != null) {
                throw new OAuthException("callback_error",
                        "Antigravity OAuth callback error: " + callback.error);
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
            logError("Antigravity OAuth callback failed", e);
            throw new OAuthException("auth_failed",
                    "Authentication failed: " + e.getMessage(), e);
        } finally {
            server.stop();
        }
    }

    /**
     * 刷新 Access Token。
     * <p>
     * 使用 Google 的 refresh_token grant type 获取新的 access token。
     * Google 的 refresh token 不会过期（除非用户撤销），
     * 但可能在以下情况下失效：密码更改、账户被撤销等。
     *
     * @param refreshToken 刷新令牌
     * @return 新的 Token 数据
     * @throws OAuthException 如果刷新失败
     */
    @Override
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new OAuthException("refresh_token_required",
                    "Refresh token is required for token refresh");
        }

        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_id", CLIENT_ID);
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
    //  授权 URL 构建
    // ============================================================

    /**
     * 构建 Google OAuth 授权 URL。
     *
     * @param state     随机 state 参数（CSRF 防护）
     * @param pkceCodes PKCE 码对
     * @return 完整的授权 URL
     */
    private String buildAuthorizationUrl(String state, PKCECodes pkceCodes) {
        StringBuilder sb = new StringBuilder(AUTH_URL);
        sb.append("?client_id=").append(encodeParam(CLIENT_ID));
        sb.append("&response_type=code");
        sb.append("&redirect_uri=").append(encodeParam(REDIRECT_URI));
        sb.append("&scope=").append(encodeParam(ANTIGRAVITY_SCOPE));
        sb.append("&state=").append(encodeParam(state));
        sb.append("&code_challenge=").append(encodeParam(pkceCodes.codeChallenge));
        sb.append("&code_challenge_method=S256");
        sb.append("&access_type=offline");
        sb.append("&prompt=consent");
        // 确保 Google 返回 refresh token
        sb.append("&include_granted_scopes=true");
        return sb.toString();
    }

    // ============================================================
    //  令牌交换
    // ============================================================

    /**
     * 使用授权码交换 Token。
     * <p>
     * 向 Google 令牌端点发送 POST 请求，交换授权码为访问令牌和刷新令牌。
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
            params.put("client_id", CLIENT_ID);
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
     * 调用 Google 的撤销端点，使令牌立即失效。
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
    //  响应解析
    // ============================================================

    /**
     * 解析 Google OAuth 令牌响应 JSON。
     * <p>
     * Google 的令牌响应包含 access_token、refresh_token（首次授权）、
     * id_token、expires_in 等字段。
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
                        "Antigravity OAuth error: " + error + " - " + errorDesc);
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
            int expiresIn = obj.optInt("expires_in", 3600);

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

    // ============================================================
    //  JWT 解析
    // ============================================================

    /**
     * 解析 JWT Token 的 claims 部分（不验证签名）。
     * <p>
     * 从 Google 返回的 id_token 中提取用户信息，
     * 包括 sub（Google 账户 ID）、email、name 等。
     *
     * @param token JWT 格式的 ID Token
     * @return 解析后的 claims，解析失败时返回 null
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
     * 包含 Google ID Token 中的标准声明：
     * - sub: Google 账户唯一标识符
     * - email: 用户的 Google 邮箱地址
     * - email_verified: 邮箱是否已验证
     * - name: 用户显示名称
     * - picture: 用户头像 URL
     */
    public static class JWTClaims {
        public final String email;
        public final boolean emailVerified;
        public final String sub;
        public final String name;
        public final String picture;
        public final String rawJson;

        JWTClaims(String json) throws org.json.JSONException {
            this.rawJson = json;
            JSONObject obj = new JSONObject(json);
            this.email = obj.optString("email", "");
            this.emailVerified = obj.optBoolean("email_verified", false);
            this.sub = obj.optString("sub", "");
            this.name = obj.optString("name", "");
            this.picture = obj.optString("picture", "");
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

    // ============================================================
    //  内部类：CallbackServer（轻量级 HTTP 回调服务器）
    // ============================================================

    /**
     * 轻量级本地 HTTP 服务器，用于接收 Google Antigravity OAuth 回调。
     * <p>
     * 在本地端口上监听，等待 Google 在用户完成授权后重定向浏览器，
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
                Log.d(TAG, "Antigravity OAuth callback server started on port " + port);
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
                    "Content-Length: " + responseBody.getBytes(StandardCharsets.UTF_8).length + "\r\n" +
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
            Log.d(TAG, "Antigravity OAuth callback server stopped");
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
                    "<title>Authentication Successful - Antigravity</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#4285F4 0%,#34A853 50%,#FBBC04 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#34A853;" +
                    "border-radius:50%;display:flex;align-items:center;justify-content:center;" +
                    "color:white;font-size:2rem;font-weight:bold;}" +
                    "h1{color:#1f2937;margin-bottom:1rem;}" +
                    "p{color:#6b7280;margin-bottom:1.5rem;}" +
                    ".countdown{color:#9ca3af;font-size:0.75rem;margin-top:1rem;}" +
                    "</style></head>" +
                    "<body><div class=\"container\">" +
                    "<div class=\"icon\">&#10003;</div>" +
                    "<h1>Authentication Successful!</h1>" +
                    "<p>You have successfully authenticated with Google Antigravity.<br>" +
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
                    "<title>Authentication Failed - Antigravity</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#EA4335 0%,#C5221F 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#EA4335;" +
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