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
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

/**
 * GitHubCopilotOAuth - GitHub Copilot OAuth 认证实现
 * <p>
 * 使用 GitHub OAuth Device Code flow 进行用户认证，
 * 支持 GitHub Copilot 的令牌获取与刷新。
 * <p>
 * Device Code 流程：
 * 1. 向 GitHub 设备端点请求设备码 → 2. 返回用户验证 URL 和用户码
 * 3. 用户在浏览器中输入用户码完成授权 → 4. 轮询 Token 端点获取令牌
 * 5. 使用令牌调用 Copilot 令牌端点获取最终 access_token
 * <p>
 * 端点参考：
 * - 设备授权: https://github.com/login/device/code
 * - 令牌: https://github.com/login/oauth/access_token
 * - Copilot 令牌: https://api.github.com/copilot_internal/v2/token
 */
public class GitHubCopilotOAuth extends OAuthProvider {

    private static final String TAG = "GitHubCopilotOAuth";

    // === OAuth 端点常量 ===
    private static final String DEVICE_AUTH_URL = "https://github.com/login/device/code";
    private static final String TOKEN_URL = "https://github.com/login/oauth/access_token";
    private static final String COPILOT_TOKEN_URL = "https://api.github.com/copilot_internal/v2/token";

    /** GitHub OAuth App 客户端 ID（Copilot） */
    private static final String CLIENT_ID = "Iv1.b6d1e3b8b7e3b8b7";

    /** OAuth 作用域 */
    private static final String SCOPES = "read:user";

    /** 设备认证轮询超时（秒） */
    private static final int DEVICE_POLL_TIMEOUT_SECONDS = 600;

    /** 设备认证轮询间隔（毫秒，初始值） */
    private static final int DEFAULT_POLL_INTERVAL_MS = 5000;

    // 配置文件中的代理 URL（可选）
    private final String proxyUrl;

    // ============================================================
    //  构造
    // ============================================================

    /**
     * 构造默认的 GitHubCopilotOAuth 实例。
     */
    public GitHubCopilotOAuth() {
        this.proxyUrl = "";
    }

    /**
     * 构造 GitHubCopilotOAuth 实例，使用指定的代理 URL。
     *
     * @param proxyUrl 可选代理 URL，为空时不使用代理
     */
    public GitHubCopilotOAuth(String proxyUrl) {
        this.proxyUrl = proxyUrl != null ? proxyUrl : "";
    }

    // ============================================================
    //  OAuthProvider 抽象方法实现
    // ============================================================

    /**
     * 启动 OAuth Device Code 流程。
     * <p>
     * GitHub Copilot 使用 Device Code 流程，不需要本地回调服务器。
     * 1. 请求设备码和用户码
     * 2. 返回 DeviceFlow 对象，包含用户需要在浏览器中打开的 URL 和输入的用户码
     * 3. 调用方应向用户展示设备码信息
     * 4. 轮询等待用户完成授权后获取令牌
     *
     * @return 包含 Token 数据的 AuthResult
     * @throws OAuthException 如果启动流程或令牌获取失败
     */
    @Override
    public AuthResult startAuth() throws OAuthException {
        // 1. 请求设备码
        DeviceFlow deviceFlow = startDeviceAuth();

        // 2. 轮询等待用户完成授权
        log("GitHub Copilot: waiting for device authorization...");
        AuthResult result = pollDeviceAuthorization(deviceFlow);

        // 3. 交换 GitHub access_token 为 Copilot 令牌
        log("GitHub access token obtained, exchanging for Copilot token...");
        return exchangeForCopilotToken(result.tokenData.accessToken);
    }

    /**
     * 刷新 Access Token。
     * <p>
     * GitHub Copilot 的 refresh_token 是 GitHub 颁发的。
     * 使用 refresh_token 获取新的 GitHub access_token，然后再交换为 Copilot 令牌。
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
            // 1. 刷新 GitHub access_token
            Map<String, String> params = new HashMap<>();
            params.put("client_id", CLIENT_ID);
            params.put("grant_type", "refresh_token");
            params.put("refresh_token", refreshToken.trim());

            String responseBody = postForm(TOKEN_URL, params);
            AuthResult gitHubResult = parseTokenResponse(responseBody, refreshToken.trim());

            // 2. 交换为 Copilot 令牌
            return exchangeForCopilotToken(gitHubResult.tokenData.accessToken).tokenData;
        } catch (IOException e) {
            logError("Token refresh failed", e);
            throw new OAuthException("refresh_failed",
                    "Token refresh request failed: " + e.getMessage(), e);
        }
    }

    // ============================================================
    //  Device Code Flow
    // ============================================================

    /**
     * 启动 Device Code 流程。
     * <p>
     * 向 GitHub 设备授权端点发送 POST 请求，获取 device_code、user_code 和
     * verification_uri。用户需在浏览器中打开验证 URI 并输入用户码完成授权。
     * <p>
     * 设备流程不需要启动本地服务器，适用于无浏览器环境或 CLI 工具。
     *
     * @return DeviceFlow 对象，包含设备码、用户码和验证 URL
     * @throws OAuthException 如果请求设备码失败
     */
    public DeviceFlow startDeviceAuth() throws OAuthException {
        try {
            Map<String, String> params = new HashMap<>();
            params.put("client_id", CLIENT_ID);
            params.put("scope", SCOPES);

            String responseBody = postForm(DEVICE_AUTH_URL, params);
            return parseDeviceFlowResponse(responseBody);
        } catch (IOException e) {
            logError("Failed to start device auth", e);
            throw new OAuthException("device_auth_start_failed",
                    "Failed to start device authorization: " + e.getMessage(), e);
        }
    }

    /**
     * 解析 Device Code 响应 JSON。
     * <p>
     * GitHub 返回的响应包含以下字段：
     * - device_code: 用于轮询的设备码
     * - user_code: 用户需要在验证页面输入的码
     * - verification_uri: 验证页面 URL
     * - expires_in: 设备码过期时间（秒）
     * - interval: 轮询间隔（秒）
     *
     * @param json 原始 JSON 响应
     * @return 解析后的 DeviceFlow 对象
     * @throws OAuthException 如果解析失败
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
                // 检查是否有错误
                String error = obj.optString("error", "");
                if (!error.isEmpty()) {
                    String errorDesc = obj.optString("error_description", error);
                    throw new OAuthException("device_auth_error",
                            "GitHub device authorization error: " + error + " - " + errorDesc);
                }
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
     * 轮询等待设备码授权完成。
     * <p>
     * 在用户于浏览器中完成授权后，轮询 GitHub 令牌端点获取 access_token。
     * 轮询过程中处理以下状态：
     * - authorization_pending: 用户尚未完成授权，继续轮询
     * - slow_down: 服务器要求减慢轮询速度
     * - access_denied: 用户拒绝授权
     * - expired_token: 设备码已过期
     *
     * @param deviceFlow 设备认证流信息
     * @return 认证结果（包含 GitHub access_token）
     * @throws OAuthException 如果轮询超时或失败
     */
    public AuthResult pollDeviceAuthorization(DeviceFlow deviceFlow) throws OAuthException {
        long deadline = System.currentTimeMillis() + (deviceFlow.expiresIn * 1000L);
        int interval = Math.max(deviceFlow.interval, 5) * 1000;

        while (System.currentTimeMillis() < deadline) {
            try {
                Thread.sleep(interval);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new OAuthException("poll_interrupted",
                        "Device auth polling interrupted", e);
            }

            try {
                Map<String, String> params = new HashMap<>();
                params.put("grant_type", "urn:ietf:params:oauth:grant-type:device_code");
                params.put("device_code", deviceFlow.deviceCode);
                params.put("client_id", CLIENT_ID);

                String responseBody = postForm(TOKEN_URL, params);
                // 成功获取到 access_token
                return parseTokenResponse(responseBody, null);
            } catch (IOException e) {
                String msg = e.getMessage();
                if (msg != null) {
                    // 用户尚未完成授权
                    if (msg.contains("authorization_pending")) {
                        continue;
                    }
                    // 服务器要求减慢轮询速度
                    if (msg.contains("slow_down")) {
                        interval += 5000; // 增加 5 秒间隔
                        Log.d(TAG, "GitHub requested slower polling, interval increased to " + interval + "ms");
                        continue;
                    }
                    // 用户拒绝授权
                    if (msg.contains("access_denied")) {
                        throw new OAuthException("access_denied",
                                "User denied the authorization request");
                    }
                    // 设备码已过期
                    if (msg.contains("expired_token")) {
                        throw new OAuthException("expired_token",
                                "Device code has expired. Please start the authorization process again.");
                    }
                }
                // 其他错误，记录并继续轮询
                logError("Device auth poll error", e);
            } catch (OAuthException e) {
                throw e;
            }
        }

        throw new OAuthException("poll_timeout",
                "Device authorization timed out after " + deviceFlow.expiresIn + " seconds. " +
                        "Please try again.");
    }

    // ============================================================
    //  Copilot 令牌交换
    // ============================================================

    /**
     * 使用 GitHub access_token 交换 Copilot 令牌。
     * <p>
     * 调用 GitHub Copilot 内部令牌端点，将 GitHub access_token 交换为
     * Copilot 专用的 access_token，同时获取过期时间和刷新令牌。
     *
     * @param gitHubToken GitHub access_token
     * @return 包含 Copilot 令牌数据的 AuthResult
     * @throws OAuthException 如果交换失败
     */
    public AuthResult exchangeForCopilotToken(String gitHubToken) throws OAuthException {
        if (gitHubToken == null || gitHubToken.trim().isEmpty()) {
            throw new OAuthException("github_token_required",
                    "GitHub access token is required for Copilot token exchange");
        }

        try {
            // 使用 GitHub access_token 作为 Bearer token 调用 Copilot 令牌端点
            String responseBody = getWithBearer(COPILOT_TOKEN_URL, gitHubToken);
            return parseCopilotTokenResponse(responseBody, gitHubToken);
        } catch (IOException e) {
            logError("Copilot token exchange failed", e);
            throw new OAuthException("copilot_token_exchange_failed",
                    "Failed to exchange GitHub token for Copilot token: " + e.getMessage(), e);
        }
    }

    /**
     * 发送 HTTP GET 请求，使用 Bearer token 认证。
     */
    private String getWithBearer(String urlStr, String token) throws IOException {
        java.net.HttpURLConnection conn = (java.net.HttpURLConnection) new java.net.URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setRequestProperty("User-Agent", "CLIProxyPlus/1.0");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            int responseCode = conn.getResponseCode();
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

    // ============================================================
    //  响应解析
    // ============================================================

    /**
     * 解析 GitHub OAuth 令牌响应 JSON。
     * <p>
     * GitHub 的令牌响应包含 access_token、token_type、scope 等字段。
     * 注意：GitHub 返回的是 application/x-www-form-urlencoded 格式，但
     * 也可以接受 application/json（通过 Accept 头）。
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
                String errorUri = obj.optString("error_uri", "");
                StringBuilder msg = new StringBuilder("GitHub OAuth error: ").append(error);
                if (!errorDesc.isEmpty()) {
                    msg.append(" - ").append(errorDesc);
                }
                throw new OAuthException("token_error", msg.toString());
            }

            String accessToken = obj.optString("access_token", "");
            if (accessToken.isEmpty()) {
                throw new OAuthException("access_token_missing",
                        "Access token not found in response");
            }

            // GitHub 的 refresh_token 是可选的（取决于 App 配置）
            String refreshToken = obj.optString("refresh_token", "");
            if (refreshToken.isEmpty() && existingRefresh != null) {
                refreshToken = existingRefresh;
            }

            // 解析 scope
            String scope = obj.optString("scope", "");
            int expiresIn = obj.optInt("expires_in", 28800); // 默认 8 小时

            TokenData tokenData = new TokenData();
            tokenData.accessToken = accessToken;
            tokenData.refreshToken = refreshToken;
            tokenData.expiresIn = expiresIn;
            tokenData.expireAt = System.currentTimeMillis() + (expiresIn * 1000L);
            tokenData.accountId = ""; // 后续通过 Copilot 令牌端点获取
            tokenData.email = "";

            return new AuthResult(tokenData);
        } catch (org.json.JSONException e) {
            logError("Failed to parse token response", e);
            throw new OAuthException("parse_failed",
                    "Failed to parse token response: " + e.getMessage(), e);
        }
    }

    /**
     * 解析 Copilot 令牌响应 JSON。
     * <p>
     * GitHub Copilot 内部令牌端点返回的 JSON 包含：
     * - token: Copilot access_token
     * - expires_at: 过期时间（Unix 时间戳，秒）
     * - refresh_in: 建议刷新时间（秒）
     * - subject: 用户标识（GitHub 用户 ID）
     * - github_com_id: GitHub 用户 ID
     * - github_com_login: GitHub 用户名
     *
     * @param json        原始 JSON 响应
     * @param gitHubToken 对应的 GitHub access_token（用于刷新）
     * @return 认证结果
     * @throws OAuthException 如果解析失败
     */
    private AuthResult parseCopilotTokenResponse(String json, String gitHubToken)
            throws OAuthException {
        try {
            JSONObject obj = new JSONObject(json);

            // 检查错误
            String message = obj.optString("message", "");
            if (!message.isEmpty()) {
                throw new OAuthException("copilot_api_error",
                        "GitHub Copilot API error: " + message);
            }

            String copilotToken = obj.optString("token", "");
            if (copilotToken.isEmpty()) {
                throw new OAuthException("copilot_token_missing",
                        "Copilot token not found in response");
            }

            // 过期时间（Unix 时间戳，秒）
            long expiresAt = obj.optLong("expires_at", 0);
            long refreshIn = obj.optLong("refresh_in", 1800);

            // 用户信息
            String accountId = obj.optString("subject", "");
            String githubLogin = obj.optString("github_com_login", "");
            String githubId = obj.optString("github_com_id", "");

            TokenData tokenData = new TokenData();
            tokenData.idToken = "";
            tokenData.accessToken = copilotToken;
            // 将 GitHub access_token 作为 refresh_token 存储，用于后续刷新
            tokenData.refreshToken = gitHubToken;
            tokenData.accountId = accountId;
            tokenData.email = githubLogin;

            // Copilot 的 expires_at 是绝对时间戳（秒）
            if (expiresAt > 0) {
                tokenData.expiresIn = (int) (expiresAt - (System.currentTimeMillis() / 1000));
                tokenData.expireAt = expiresAt * 1000L;
            } else {
                tokenData.expiresIn = (int) refreshIn;
                tokenData.expireAt = System.currentTimeMillis() + (refreshIn * 1000L);
            }

            return new AuthResult(tokenData);
        } catch (org.json.JSONException e) {
            logError("Failed to parse Copilot token response", e);
            throw new OAuthException("parse_failed",
                    "Failed to parse Copilot token response: " + e.getMessage(), e);
        }
    }

    // ============================================================
    //  辅助方法
    // ============================================================

    /**
     * 生成随机的 state 参数（保留以备 Authorization Code 流程扩展）。
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
    //  内部类：DeviceFlow
    // ============================================================

    /**
     * Device Code 流程信息。
     * <p>
     * 包含设备认证所需的全部信息，用于向用户展示验证码和 URL，
     * 以及在后台轮询授权状态。
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
         * 获取用户友好的验证 URL。
         * <p>
         * 优先返回包含用户码的完整 URL，如果不可用则返回基础验证 URL。
         * 调用方应向用户展示此 URL 和用户码。
         *
         * @return 显示给用户的验证 URL
         */
        public String getDisplayUrl() {
            return verificationUriComplete != null && !verificationUriComplete.isEmpty()
                    ? verificationUriComplete
                    : verificationUri;
        }
    }

    // ============================================================
    //  内部类：OAuthFlow（Authorization Code 流程，备选）
    // ============================================================

    /**
     * OAuth 流程信息，包含授权 URL 和用于等待结果的 Future。
     * <p>
     * 主要用于 GitHub 的标准 OAuth Authorization Code 流程（备选方案）。
     * 当前实现以 Device Code 流程为主。
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
                return future.get(DEVICE_POLL_TIMEOUT_SECONDS, TimeUnit.SECONDS);
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
    //  内部类：CallbackServer（轻量级 HTTP 回调服务器，备选）
    // ============================================================

    /**
     * 轻量级本地 HTTP 服务器，用于接收 OAuth 回调。
     * <p>
     * 主要用于 GitHub 的标准 OAuth Authorization Code 流程（备选方案）。
     * 当前主流程使用 Device Code，不需要本地服务器。
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
                Log.d(TAG, "GitHub Copilot OAuth callback server started on port " + port);
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
            Log.d(TAG, "GitHub Copilot OAuth callback server stopped");
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
                    "<title>Authentication Successful - GitHub Copilot</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#24292e 0%,#6e5494 50%,#2b3137 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#2ea44f;" +
                    "border-radius:50%;display:flex;align-items:center;justify-content:center;" +
                    "color:white;font-size:2rem;font-weight:bold;}" +
                    "h1{color:#1f2937;margin-bottom:1rem;}" +
                    "p{color:#6b7280;margin-bottom:1.5rem;}" +
                    ".countdown{color:#9ca3af;font-size:0.75rem;margin-top:1rem;}" +
                    "</style></head>" +
                    "<body><div class=\"container\">" +
                    "<div class=\"icon\">&#10003;</div>" +
                    "<h1>Authentication Successful!</h1>" +
                    "<p>You have successfully authenticated with GitHub Copilot.<br>" +
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
                    "<title>Authentication Failed - GitHub Copilot</title>" +
                    "<style>" +
                    "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;" +
                    "display:flex;justify-content:center;align-items:center;min-height:100vh;margin:0;" +
                    "background:linear-gradient(135deg,#cb2431 0%,#a51a28 100%);}" +
                    ".container{text-align:center;background:white;padding:2.5rem;border-radius:12px;" +
                    "box-shadow:0 10px 25px rgba(0,0,0,0.1);max-width:480px;width:100%;}" +
                    ".icon{width:64px;height:64px;margin:0 auto 1.5rem;background:#cb2431;" +
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