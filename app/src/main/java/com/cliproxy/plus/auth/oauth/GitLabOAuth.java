package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * GitLab OAuth 认证客户端
 * <p>
 * 提供 GitLab OAuth 2.0 认证流程，包括 PKCE 授权码流程、令牌刷新、
 * 用户信息获取、个人访问令牌（PAT）查询以及直连访问（Direct Access）等功能。
 * 对应 CLIProxyAPIPlus 项目中 internal/auth/gitlab 包的 Go 代码的 1:1 Java 移植。
 */
public final class GitLabOAuth {

    private static final String TAG = "GitLabOAuth";

    // ============================================================
    // 常量
    // ============================================================

    /** 默认 GitLab 基础 URL */
    public static final String DEFAULT_BASE_URL = "https://gitlab.com";

    /** 默认 OAuth 回调端口 */
    public static final int DEFAULT_CALLBACK_PORT = 17171;

    /** 默认 OAuth 作用域 */
    public static final String DEFAULT_OAUTH_SCOPE = "api read_user";

    // ============================================================
    // PKCE 码
    // ============================================================

    /**
     * PKCE 码对，包含 code_verifier 和 code_challenge
     */
    public static final class PKCECodes {
        private final String codeVerifier;
        private final String codeChallenge;

        public PKCECodes(String codeVerifier, String codeChallenge) {
            this.codeVerifier = codeVerifier;
            this.codeChallenge = codeChallenge;
        }

        public String getCodeVerifier() {
            return codeVerifier;
        }

        public String getCodeChallenge() {
            return codeChallenge;
        }
    }

    // ============================================================
    // OAuth 回调结果
    // ============================================================

    /**
     * OAuth 回调结果，包含授权码、state 和可能的错误信息
     */
    public static final class OAuthResult {
        private final String code;
        private final String state;
        private final String error;

        public OAuthResult(String code, String state, String error) {
            this.code = code;
            this.state = state;
            this.error = error;
        }

        public String getCode() {
            return code;
        }

        public String getState() {
            return state;
        }

        public String getError() {
            return error;
        }
    }

    // ============================================================
    // OAuth 服务器（本地回调 HTTP 服务器）
    // ============================================================

    /**
     * 本地 OAuth 回调服务器，用于接收 GitLab 授权码回调
     */
    public static final class OAuthServer {
        private final int port;
        private final BlockingQueue<OAuthResult> resultQueue;
        private final BlockingQueue<Exception> errorQueue;
        private final AtomicBoolean running = new AtomicBoolean(false);
        private ServerSocket serverSocket;
        private Thread acceptThread;
        private final Object lock = new Object();

        public OAuthServer(int port) {
            this.port = port;
            this.resultQueue = new LinkedBlockingQueue<>(1);
            this.errorQueue = new LinkedBlockingQueue<>(1);
        }

        /**
         * 启动本地回调服务器
         *
         * @throws IOException 如果端口被占用或启动失败
         */
        public void start() throws IOException {
            if (running.get()) {
                throw new IOException("GitLab OAuth 服务器已在运行");
            }
            if (!isPortAvailable()) {
                throw new IOException("端口 " + port + " 已被占用");
            }

            serverSocket = new ServerSocket();
            serverSocket.setReuseAddress(true);
            serverSocket.bind(new java.net.InetSocketAddress("localhost", port));
            running.set(true);

            acceptThread = new Thread(() -> {
                while (running.get() && !serverSocket.isClosed()) {
                    try {
                        java.net.Socket client = serverSocket.accept();
                        handleClient(client);
                    } catch (IOException e) {
                        if (running.get()) {
                            Log.e(TAG, "接受连接失败", e);
                            errorQueue.offer(e);
                        }
                        break;
                    }
                }
            }, "GitLabOAuth-Callback");
            acceptThread.setDaemon(true);
            acceptThread.start();

            Log.d(TAG, "GitLab OAuth 回调服务器已启动，端口: " + port);
        }

        /**
         * 处理客户端 HTTP 请求
         */
        private void handleClient(java.net.Socket client) {
            try {
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
                BufferedWriter writer = new BufferedWriter(
                        new OutputStreamWriter(client.getOutputStream(), StandardCharsets.UTF_8));

                // 读取请求行
                String requestLine = reader.readLine();
                if (requestLine == null) {
                    client.close();
                    return;
                }
                String[] parts = requestLine.split(" ", 3);
                if (parts.length < 3 || !"GET".equalsIgnoreCase(parts[0])) {
                    sendHttpResponse(writer, 405, "method not allowed");
                    client.close();
                    return;
                }

                // 解析请求路径和查询参数
                String requestPath = parts[1];
                String queryString = "";
                int queryIdx = requestPath.indexOf('?');
                if (queryIdx >= 0) {
                    queryString = requestPath.substring(queryIdx + 1);
                    requestPath = requestPath.substring(0, queryIdx);
                }

                // 读取剩余请求头直到空行
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    // 忽略请求头
                }

                // 仅处理 /auth/callback 路径
                if (!"/auth/callback".equals(requestPath)) {
                    sendHttpResponse(writer, 404, "not found");
                    client.close();
                    return;
                }

                // 解析查询参数
                Map<String, String> params = parseQueryParams(queryString);
                String errParam = params.getOrDefault("error", "");
                if (!errParam.isEmpty()) {
                    OAuthResult result = new OAuthResult(null, null, errParam);
                    sendResult(result);
                    sendHttpResponse(writer, 400, errParam);
                    client.close();
                    return;
                }
                String code = params.getOrDefault("code", "");
                String state = params.getOrDefault("state", "");
                if (code.isEmpty() || state.isEmpty()) {
                    OAuthResult result = new OAuthResult(null, null, "missing_code_or_state");
                    sendResult(result);
                    sendHttpResponse(writer, 400, "missing code or state");
                    client.close();
                    return;
                }
                OAuthResult result = new OAuthResult(code, state, null);
                sendResult(result);
                sendHttpResponse(writer, 200,
                        "GitLab authentication received. You can close this tab.");
                client.close();
            } catch (IOException e) {
                Log.e(TAG, "处理回调请求失败", e);
                errorQueue.offer(e);
            } finally {
                try {
                    client.close();
                } catch (IOException ignored) {
                }
            }
        }

        /**
         * 发送 HTTP 响应
         */
        private void sendHttpResponse(BufferedWriter writer, int statusCode, String body)
                throws IOException {
            String statusText;
            switch (statusCode) {
                case 200: statusText = "OK"; break;
                case 400: statusText = "Bad Request"; break;
                case 404: statusText = "Not Found"; break;
                case 405: statusText = "Method Not Allowed"; break;
                default:  statusText = "Unknown"; break;
            }
            byte[] bodyBytes = body.getBytes(StandardCharsets.UTF_8);
            writer.write("HTTP/1.1 " + statusCode + " " + statusText + "\r\n");
            writer.write("Content-Type: text/plain; charset=utf-8\r\n");
            writer.write("Content-Length: " + bodyBytes.length + "\r\n");
            writer.write("Connection: close\r\n");
            writer.write("\r\n");
            writer.write(body);
            writer.flush();
        }

        /**
         * 停止本地回调服务器
         */
        public void stop() {
            synchronized (lock) {
                running.set(false);
                if (serverSocket != null && !serverSocket.isClosed()) {
                    try {
                        serverSocket.close();
                    } catch (IOException e) {
                        Log.e(TAG, "关闭服务器套接字失败", e);
                    }
                    serverSocket = null;
                }
                if (acceptThread != null) {
                    acceptThread.interrupt();
                    acceptThread = null;
                }
                Log.d(TAG, "GitLab OAuth 回调服务器已停止");
            }
        }

        /**
         * 等待 OAuth 回调结果
         *
         * @param timeout 超时时间（毫秒）
         * @return OAuth 回调结果
         * @throws IOException 如果超时或发生错误
         */
        public OAuthResult waitForCallback(long timeout) throws IOException {
            long deadline = System.currentTimeMillis() + timeout;
            long remaining = timeout;

            // 先检查结果队列
            OAuthResult result = resultQueue.poll();
            if (result != null) {
                return result;
            }

            // 再检查错误队列
            Exception err = errorQueue.poll();
            if (err != null) {
                if (err instanceof IOException) {
                    throw (IOException) err;
                }
                throw new IOException("GitLab OAuth 回调错误", err);
            }

            // 阻塞等待
            while (remaining > 0) {
                try {
                    result = resultQueue.poll(remaining, TimeUnit.MILLISECONDS);
                    if (result != null) {
                        return result;
                    }
                    err = errorQueue.poll();
                    if (err != null) {
                        if (err instanceof IOException) {
                            throw (IOException) err;
                        }
                        throw new IOException("GitLab OAuth 回调错误", err);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("等待 OAuth 回调时被中断", e);
                }
                remaining = deadline - System.currentTimeMillis();
            }
            throw new IOException("等待 OAuth 回调超时");
        }

        private void sendResult(OAuthResult result) {
            if (!resultQueue.offer(result)) {
                Log.e(TAG, "GitLab OAuth 结果通道已满，丢弃回调结果");
            }
        }

        private boolean isPortAvailable() {
            try (ServerSocket ss = new ServerSocket()) {
                ss.setReuseAddress(true);
                ss.bind(new java.net.InetSocketAddress("localhost", port));
                return true;
            } catch (IOException e) {
                return false;
            }
        }

        private static Map<String, String> parseQueryParams(String query) {
            Map<String, String> params = new HashMap<>();
            if (query == null || query.isEmpty()) {
                return params;
            }
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int idx = pair.indexOf('=');
                if (idx > 0) {
                    String key = decodeUrl(pair.substring(0, idx));
                    String value = decodeUrl(pair.substring(idx + 1));
                    params.put(key, value);
                }
            }
            return params;
        }

        private static String decodeUrl(String encoded) {
            try {
                return java.net.URLDecoder.decode(encoded, "UTF-8");
            } catch (Exception e) {
                return encoded;
            }
        }
    }

    // ============================================================
    // 令牌响应
    // ============================================================

    /**
     * OAuth 令牌响应
     */
    public static final class TokenResponse {
        private final String accessToken;
        private final String tokenType;
        private final String refreshToken;
        private final String scope;
        private final long createdAt;
        private final int expiresIn;

        public TokenResponse(String accessToken, String tokenType, String refreshToken,
                             String scope, long createdAt, int expiresIn) {
            this.accessToken = accessToken;
            this.tokenType = tokenType;
            this.refreshToken = refreshToken;
            this.scope = scope;
            this.createdAt = createdAt;
            this.expiresIn = expiresIn;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public String getTokenType() {
            return tokenType;
        }

        public String getRefreshToken() {
            return refreshToken;
        }

        public String getScope() {
            return scope;
        }

        public long getCreatedAt() {
            return createdAt;
        }

        public int getExpiresIn() {
            return expiresIn;
        }
    }

    // ============================================================
    // GitLab 用户
    // ============================================================

    /**
     * GitLab 用户信息
     */
    public static final class User {
        private final long id;
        private final String username;
        private final String name;
        private final String email;
        private final String publicEmail;

        public User(long id, String username, String name, String email, String publicEmail) {
            this.id = id;
            this.username = username;
            this.name = name;
            this.email = email;
            this.publicEmail = publicEmail;
        }

        public long getId() {
            return id;
        }

        public String getUsername() {
            return username;
        }

        public String getName() {
            return name;
        }

        public String getEmail() {
            return email;
        }

        public String getPublicEmail() {
            return publicEmail;
        }
    }

    // ============================================================
    // 个人访问令牌（PAT）自查询
    // ============================================================

    /**
     * 个人访问令牌自查询结果
     */
    public static final class PersonalAccessTokenSelf {
        private final long id;
        private final String name;
        private final List<String> scopes;
        private final long userId;

        public PersonalAccessTokenSelf(long id, String name, List<String> scopes, long userId) {
            this.id = id;
            this.name = name;
            this.scopes = scopes;
            this.userId = userId;
        }

        public long getId() {
            return id;
        }

        public String getName() {
            return name;
        }

        public List<String> getScopes() {
            return scopes;
        }

        public long getUserId() {
            return userId;
        }
    }

    // ============================================================
    // 模型详情
    // ============================================================

    /**
     * 模型提供者与模型名称详情
     */
    public static final class ModelDetails {
        private final String modelProvider;
        private final String modelName;

        public ModelDetails(String modelProvider, String modelName) {
            this.modelProvider = modelProvider;
            this.modelName = modelName;
        }

        public String getModelProvider() {
            return modelProvider;
        }

        public String getModelName() {
            return modelName;
        }
    }

    // ============================================================
    // 直连访问响应
    // ============================================================

    /**
     * 直连访问（Direct Access）响应
     */
    public static final class DirectAccessResponse {
        private final String baseUrl;
        private final String token;
        private final long expiresAt;
        private final Map<String, String> headers;
        private final ModelDetails modelDetails;

        public DirectAccessResponse(String baseUrl, String token, long expiresAt,
                                    Map<String, String> headers, ModelDetails modelDetails) {
            this.baseUrl = baseUrl;
            this.token = token;
            this.expiresAt = expiresAt;
            this.headers = headers != null ? headers : new HashMap<>();
            this.modelDetails = modelDetails;
        }

        public String getBaseUrl() {
            return baseUrl;
        }

        public String getToken() {
            return token;
        }

        public long getExpiresAt() {
            return expiresAt;
        }

        public Map<String, String> getHeaders() {
            return headers;
        }

        public ModelDetails getModelDetails() {
            return modelDetails;
        }
    }

    // ============================================================
    // 发现模型
    // ============================================================

    /**
     * 从元数据中发现的模型信息
     */
    public static final class DiscoveredModel {
        private final String modelProvider;
        private final String modelName;

        public DiscoveredModel(String modelProvider, String modelName) {
            this.modelProvider = modelProvider;
            this.modelName = modelName;
        }

        public String getModelProvider() {
            return modelProvider;
        }

        public String getModelName() {
            return modelName;
        }
    }

    // ============================================================
    // 认证客户端
    // ============================================================

    /**
     * GitLab 认证客户端，封装 HTTP 请求逻辑
     */
    public static final class AuthClient {
        private int connectTimeout = 15000;
        private int readTimeout = 15000;

        public AuthClient() {
            Log.d(TAG, "创建 AuthClient 实例");
        }

        /**
         * 设置连接超时时间（毫秒）
         */
        public void setConnectTimeout(int connectTimeout) {
            this.connectTimeout = connectTimeout;
        }

        /**
         * 设置读取超时时间（毫秒）
         */
        public void setReadTimeout(int readTimeout) {
            this.readTimeout = readTimeout;
        }

        // ============================================================
        // 工具方法
        // ============================================================

        /**
         * 规范化 GitLab 基础 URL
         *
         * @param raw 原始 URL 字符串
         * @return 规范化后的 URL
         */
        public static String normalizeBaseURL(String raw) {
            String value = raw != null ? raw.trim() : "";
            if (value.isEmpty()) {
                return DEFAULT_BASE_URL;
            }
            if (!value.contains("://")) {
                value = "https://" + value;
            }
            while (value.endsWith("/")) {
                value = value.substring(0, value.length() - 1);
            }
            return value;
        }

        /**
         * 计算令牌过期时间
         *
         * @param now   当前时间戳（毫秒）
         * @param token 令牌响应
         * @return 过期时间戳（毫秒），如果无法确定则返回 0
         */
        public static long tokenExpiry(long now, TokenResponse token) {
            if (token == null) {
                return 0;
            }
            if (token.getCreatedAt() > 0 && token.getExpiresIn() > 0) {
                return (token.getCreatedAt() + token.getExpiresIn()) * 1000L;
            }
            if (token.getExpiresIn() > 0) {
                return now + (long) token.getExpiresIn() * 1000L;
            }
            return 0;
        }

        /**
         * 生成 PKCE 码对（code_verifier 和 code_challenge）
         *
         * @return PKCE 码对
         * @throws IOException 如果生成失败
         */
        public static PKCECodes generatePKCECodes() throws IOException {
            try {
                SecureRandom random = new SecureRandom();
                byte[] verifierBytes = new byte[32];
                random.nextBytes(verifierBytes);
                String verifier = base64RawURLEncode(verifierBytes);

                MessageDigest digest = MessageDigest.getInstance("SHA-256");
                byte[] hash = digest.digest(verifier.getBytes(StandardCharsets.US_ASCII));
                String challenge = base64RawURLEncode(hash);

                Log.d(TAG, "PKCE 码对生成成功");
                return new PKCECodes(verifier, challenge);
            } catch (Exception e) {
                Log.e(TAG, "PKCE 码对生成失败", e);
                throw new IOException("GitLab PKCE 生成失败: " + e.getMessage(), e);
            }
        }

        /**
         * 生成 OAuth 回调重定向 URI
         *
         * @param port 回调端口
         * @return 重定向 URI
         */
        public static String redirectURL(int port) {
            return "http://localhost:" + port + "/auth/callback";
        }

        /**
         * 创建新的 AuthClient 实例
         */
        public static AuthClient newAuthClient() {
            return new AuthClient();
        }

        // ============================================================
        // 认证 URL 生成
        // ============================================================

        /**
         * 生成 OAuth 授权 URL
         *
         * @param baseURL     GitLab 基础 URL
         * @param clientID    客户端 ID
         * @param redirectURI 重定向 URI
         * @param state       CSRF state
         * @param pkce        PKCE 码对
         * @return 完整的授权 URL
         * @throws IOException 如果参数无效
         */
        public String generateAuthURL(String baseURL, String clientID,
                                       String redirectURI, String state,
                                       PKCECodes pkce) throws IOException {
            if (pkce == null) {
                throw new IOException("GitLab 授权 URL 生成失败: 需要 PKCE 码");
            }
            if (clientID == null || clientID.trim().isEmpty()) {
                throw new IOException("GitLab 授权 URL 生成失败: 需要客户端 ID");
            }
            String normalizedBase = normalizeBaseURL(baseURL);
            Map<String, String> params = new java.util.LinkedHashMap<>();
            params.put("client_id", clientID.trim());
            params.put("response_type", "code");
            params.put("redirect_uri", redirectURI != null ? redirectURI.trim() : "");
            params.put("scope", DEFAULT_OAUTH_SCOPE);
            params.put("state", state != null ? state.trim() : "");
            params.put("code_challenge", pkce.getCodeChallenge());
            params.put("code_challenge_method", "S256");

            return normalizedBase + "/oauth/authorize?" + encodeFormData(params);
        }

        // ============================================================
        // 授权码换令牌
        // ============================================================

        /**
         * 使用授权码交换访问令牌
         *
         * @param baseURL       GitLab 基础 URL
         * @param clientID      客户端 ID
         * @param clientSecret  客户端密钥（可选）
         * @param redirectURI   重定向 URI
         * @param code          授权码
         * @param codeVerifier  PKCE code_verifier
         * @return 令牌响应
         * @throws IOException 如果请求失败
         */
        public TokenResponse exchangeCodeForTokens(String baseURL, String clientID,
                                                    String clientSecret, String redirectURI,
                                                    String code, String codeVerifier) throws IOException {
            Map<String, String> form = new java.util.LinkedHashMap<>();
            form.put("grant_type", "authorization_code");
            form.put("client_id", clientID != null ? clientID.trim() : "");
            form.put("code", code != null ? code.trim() : "");
            form.put("redirect_uri", redirectURI != null ? redirectURI.trim() : "");
            form.put("code_verifier", codeVerifier != null ? codeVerifier.trim() : "");
            if (clientSecret != null && !clientSecret.trim().isEmpty()) {
                form.put("client_secret", clientSecret.trim());
            }
            String tokenURL = normalizeBaseURL(baseURL) + "/oauth/token";
            return postToken(tokenURL, form);
        }

        // ============================================================
        // 刷新令牌
        // ============================================================

        /**
         * 刷新访问令牌
         *
         * @param baseURL      GitLab 基础 URL
         * @param clientID     客户端 ID
         * @param clientSecret 客户端密钥（可选）
         * @param refreshToken 刷新令牌
         * @return 新的令牌响应
         * @throws IOException 如果请求失败
         */
        public TokenResponse refreshTokens(String baseURL, String clientID,
                                            String clientSecret, String refreshToken) throws IOException {
            Map<String, String> form = new java.util.LinkedHashMap<>();
            form.put("grant_type", "refresh_token");
            form.put("refresh_token", refreshToken != null ? refreshToken.trim() : "");
            if (clientID != null && !clientID.trim().isEmpty()) {
                form.put("client_id", clientID.trim());
            }
            if (clientSecret != null && !clientSecret.trim().isEmpty()) {
                form.put("client_secret", clientSecret.trim());
            }
            String tokenURL = normalizeBaseURL(baseURL) + "/oauth/token";
            return postToken(tokenURL, form);
        }

        // ============================================================
        // 通用令牌 POST 请求
        // ============================================================

        private TokenResponse postToken(String tokenURL, Map<String, String> form) throws IOException {
            Log.d(TAG, "发送令牌请求到: " + tokenURL);

            HttpURLConnection conn = null;
            try {
                URL url = new URI(tokenURL).toURL();
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setRequestProperty("Accept", "application/json");
                conn.setConnectTimeout(connectTimeout);
                conn.setReadTimeout(readTimeout);
                conn.setDoOutput(true);

                String body = encodeFormData(form);
                try (OutputStream os = conn.getOutputStream();
                     OutputStreamWriter writer = new OutputStreamWriter(os, StandardCharsets.UTF_8)) {
                    writer.write(body);
                    writer.flush();
                }

                int statusCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn);

                if (statusCode < 200 || statusCode >= 300) {
                    Log.e(TAG, "令牌请求失败，状态码: " + statusCode + ", 响应: " + responseBody);
                    throw new IOException("GitLab 令牌请求失败，状态码 " + statusCode + ": "
                            + (responseBody != null ? responseBody.trim() : ""));
                }

                return parseTokenResponse(responseBody);

            } catch (IOException e) {
                Log.e(TAG, "GitLab 令牌请求失败", e);
                throw e;
            } catch (Exception e) {
                Log.e(TAG, "GitLab 令牌请求异常", e);
                throw new IOException("GitLab 令牌请求失败: " + e.getMessage(), e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }

        // ============================================================
        // 获取当前用户
        // ============================================================

        /**
         * 获取当前 GitLab 用户信息
         *
         * @param baseURL GitLab 基础 URL
         * @param token   访问令牌
         * @return 用户信息
         * @throws IOException 如果请求失败
         */
        public User getCurrentUser(String baseURL, String token) throws IOException {
            String userURL = normalizeBaseURL(baseURL) + "/api/v4/user";
            Log.d(TAG, "获取当前用户信息: " + userURL);

            HttpURLConnection conn = null;
            try {
                URL url = new URI(userURL).toURL();
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Authorization", "Bearer " + (token != null ? token.trim() : ""));
                conn.setRequestProperty("Accept", "application/json");
                conn.setConnectTimeout(connectTimeout);
                conn.setReadTimeout(readTimeout);

                int statusCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn);

                if (statusCode < 200 || statusCode >= 300) {
                    Log.e(TAG, "用户信息请求失败，状态码: " + statusCode + ", 响应: " + responseBody);
                    throw new IOException("GitLab 用户请求失败，状态码 " + statusCode + ": "
                            + (responseBody != null ? responseBody.trim() : ""));
                }

                return parseUserResponse(responseBody);

            } catch (IOException e) {
                Log.e(TAG, "GitLab 用户请求失败", e);
                throw e;
            } catch (Exception e) {
                Log.e(TAG, "GitLab 用户请求异常", e);
                throw new IOException("GitLab 用户请求失败: " + e.getMessage(), e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }

        // ============================================================
        // 获取 PAT 自查询信息
        // ============================================================

        /**
         * 获取当前个人访问令牌（PAT）信息
         *
         * @param baseURL GitLab 基础 URL
         * @param token   访问令牌
         * @return PAT 自查询信息
         * @throws IOException 如果请求失败
         */
        public PersonalAccessTokenSelf getPersonalAccessTokenSelf(String baseURL, String token) throws IOException {
            String patURL = normalizeBaseURL(baseURL) + "/api/v4/personal_access_tokens/self";
            Log.d(TAG, "获取 PAT 自查询信息: " + patURL);

            HttpURLConnection conn = null;
            try {
                URL url = new URI(patURL).toURL();
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Authorization", "Bearer " + (token != null ? token.trim() : ""));
                conn.setRequestProperty("Accept", "application/json");
                conn.setConnectTimeout(connectTimeout);
                conn.setReadTimeout(readTimeout);

                int statusCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn);

                if (statusCode < 200 || statusCode >= 300) {
                    Log.e(TAG, "PAT 自查询请求失败，状态码: " + statusCode + ", 响应: " + responseBody);
                    throw new IOException("GitLab PAT 自查询请求失败，状态码 " + statusCode + ": "
                            + (responseBody != null ? responseBody.trim() : ""));
                }

                return parsePATSelfResponse(responseBody);

            } catch (IOException e) {
                Log.e(TAG, "GitLab PAT 自查询请求失败", e);
                throw e;
            } catch (Exception e) {
                Log.e(TAG, "GitLab PAT 自查询请求异常", e);
                throw new IOException("GitLab PAT 自查询请求失败: " + e.getMessage(), e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }

        // ============================================================
        // 直连访问（Direct Access）
        // ============================================================

        /**
         * 获取直连访问（Direct Access）信息
         * <p>
         * 使用 PRIVATE-TOKEN 头进行 PAT 认证，向 GitLab 的
         * /api/v4/code_suggestions/direct_access 端点发起 POST 请求。
         *
         * @param baseURL GitLab 基础 URL
         * @param token   个人访问令牌（PAT）
         * @return 直连访问响应
         * @throws IOException 如果请求失败
         */
        public DirectAccessResponse fetchDirectAccess(String baseURL, String token) throws IOException {
            String directURL = normalizeBaseURL(baseURL) + "/api/v4/code_suggestions/direct_access";
            Log.d(TAG, "获取直连访问信息: " + directURL);

            HttpURLConnection conn = null;
            try {
                URL url = new URI(directURL).toURL();
                conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setRequestProperty("PRIVATE-TOKEN", token != null ? token.trim() : "");
                conn.setRequestProperty("Accept", "application/json");
                conn.setConnectTimeout(connectTimeout);
                conn.setReadTimeout(readTimeout);

                int statusCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn);

                if (statusCode < 200 || statusCode >= 300) {
                    Log.e(TAG, "直连访问请求失败，状态码: " + statusCode + ", 响应: " + responseBody);
                    throw new IOException("GitLab 直连访问请求失败，状态码 " + statusCode + ": "
                            + (responseBody != null ? responseBody.trim() : ""));
                }

                return parseDirectAccessResponse(responseBody);

            } catch (IOException e) {
                Log.e(TAG, "GitLab 直连访问请求失败", e);
                throw e;
            } catch (Exception e) {
                Log.e(TAG, "GitLab 直连访问请求异常", e);
                throw new IOException("GitLab 直连访问请求失败: " + e.getMessage(), e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }

        // ============================================================
        // 提取发现的模型
        // ============================================================

        /**
         * 从元数据中提取发现的模型列表
         * <p>
         * 从 metadata 中查找 model_details、model_provider/model_name、
         * models、supported_models、discovered_models 等字段，提取唯一模型列表。
         *
         * @param metadata 元数据 Map
         * @return 发现的模型列表
         */
        public static List<DiscoveredModel> extractDiscoveredModels(Map<String, Object> metadata) {
            if (metadata == null || metadata.isEmpty()) {
                return new ArrayList<>();
            }

            List<DiscoveredModel> models = new ArrayList<>();
            Set<String> seen = new HashSet<>();

            // 从 model_details 中提取
            if (metadata.containsKey("model_details")) {
                appendDiscoveredModels(metadata.get("model_details"), (provider, name) -> {
                    String p = provider != null ? provider.trim() : "";
                    String n = name != null ? name.trim() : "";
                    if (n.isEmpty()) return;
                    String key = n.toLowerCase();
                    if (seen.contains(key)) return;
                    seen.add(key);
                    models.add(new DiscoveredModel(p, n));
                });
            }

            // 从 model_provider / model_name 顶层字段提取
            {
                String provider = stringValue(metadata.get("model_provider"));
                String name = stringValue(metadata.get("model_name"));
                String p = provider != null ? provider.trim() : "";
                String n = name != null ? name.trim() : "";
                if (!n.isEmpty()) {
                    String key = n.toLowerCase();
                    if (!seen.contains(key)) {
                        seen.add(key);
                        models.add(new DiscoveredModel(p, n));
                    }
                }
            }

            // 从 models / supported_models / discovered_models 字段提取
            String[] listKeys = {"models", "supported_models", "discovered_models"};
            for (String key : listKeys) {
                if (metadata.containsKey(key)) {
                    appendDiscoveredModels(metadata.get(key), (provider, name) -> {
                        String p = provider != null ? provider.trim() : "";
                        String n = name != null ? name.trim() : "";
                        if (n.isEmpty()) return;
                        String k = n.toLowerCase();
                        if (seen.contains(k)) return;
                        seen.add(k);
                        models.add(new DiscoveredModel(p, n));
                    });
                }
            }

            return models;
        }

        /**
         * 递归解析发现的模型，将结果传递给回调函数
         */
        @SuppressWarnings("unchecked")
        private static void appendDiscoveredModels(Object raw, ModelConsumer consumer) {
            if (raw instanceof Map) {
                Map<String, Object> typed = (Map<String, Object>) raw;
                String provider = stringValue(typed.get("model_provider"));
                String name = stringValue(typed.get("model_name"));
                consumer.accept(provider, name);

                String provider2 = stringValue(typed.get("provider"));
                String name2 = stringValue(typed.get("name"));
                consumer.accept(provider2, name2);

                if (typed.containsKey("models")) {
                    appendDiscoveredModels(typed.get("models"), consumer);
                }
            } else if (raw instanceof List) {
                List<Object> typed = (List<Object>) raw;
                for (Object item : typed) {
                    appendDiscoveredModels(item, consumer);
                }
            } else if (raw instanceof String) {
                consumer.accept("", (String) raw);
            } else if (raw instanceof JSONObject) {
                JSONObject obj = (JSONObject) raw;
                String provider = obj.optString("model_provider", "");
                String name = obj.optString("model_name", "");
                consumer.accept(provider, name);

                String provider2 = obj.optString("provider", "");
                String name2 = obj.optString("name", "");
                consumer.accept(provider2, name2);

                if (obj.has("models")) {
                    try {
                        appendDiscoveredModels(obj.get("models"), consumer);
                    } catch (JSONException e) {
                        Log.e(TAG, "解析 JSON models 失败", e);
                    }
                }
            } else if (raw instanceof JSONArray) {
                JSONArray arr = (JSONArray) raw;
                for (int i = 0; i < arr.length(); i++) {
                    try {
                        appendDiscoveredModels(arr.get(i), consumer);
                    } catch (JSONException e) {
                        Log.e(TAG, "解析 JSONArray 元素失败", e);
                    }
                }
            }
        }

        @FunctionalInterface
        private interface ModelConsumer {
            void accept(String provider, String name);
        }

        /**
         * 将任意类型的值转换为字符串
         */
        private static String stringValue(Object raw) {
            if (raw == null) {
                return "";
            }
            if (raw instanceof String) {
                return ((String) raw).trim();
            }
            if (raw instanceof Number) {
                if (raw instanceof Double || raw instanceof Float) {
                    return String.valueOf((long) ((Number) raw).doubleValue());
                }
                return String.valueOf(raw);
            }
            return "";
        }

        // ============================================================
        // HTTP 响应读取
        // ============================================================

        private static String readResponseBody(HttpURLConnection conn) {
            try {
                InputStream inputStream;
                int statusCode = conn.getResponseCode();
                if (statusCode >= 200 && statusCode < 300) {
                    inputStream = conn.getInputStream();
                } else {
                    inputStream = conn.getErrorStream();
                    if (inputStream == null) {
                        inputStream = conn.getInputStream();
                    }
                }
                if (inputStream == null) {
                    return "";
                }
                try (BufferedReader reader = new BufferedReader(
                        new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    StringBuilder sb = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        sb.append(line);
                    }
                    return sb.toString();
                }
            } catch (IOException e) {
                Log.e(TAG, "读取 HTTP 响应体失败", e);
                return "";
            }
        }

        // ============================================================
        // JSON 解析
        // ============================================================

        private static TokenResponse parseTokenResponse(String json) throws IOException {
            try {
                JSONObject obj = new JSONObject(json);
                String accessToken = obj.optString("access_token", "");
                String tokenType = obj.optString("token_type", "");
                String refreshToken = obj.optString("refresh_token", "");
                String scope = obj.optString("scope", "");
                long createdAt = obj.optLong("created_at", 0);
                int expiresIn = obj.optInt("expires_in", 0);
                return new TokenResponse(accessToken, tokenType, refreshToken, scope, createdAt, expiresIn);
            } catch (JSONException e) {
                Log.e(TAG, "解析令牌响应 JSON 失败: " + json, e);
                throw new IOException("GitLab 令牌响应解析失败: " + e.getMessage(), e);
            }
        }

        private static User parseUserResponse(String json) throws IOException {
            try {
                JSONObject obj = new JSONObject(json);
                long id = obj.optLong("id", 0);
                String username = obj.optString("username", "");
                String name = obj.optString("name", "");
                String email = obj.optString("email", "");
                String publicEmail = obj.optString("public_email", "");
                return new User(id, username, name, email, publicEmail);
            } catch (JSONException e) {
                Log.e(TAG, "解析用户信息 JSON 失败: " + json, e);
                throw new IOException("GitLab 用户响应解析失败: " + e.getMessage(), e);
            }
        }

        private static PersonalAccessTokenSelf parsePATSelfResponse(String json) throws IOException {
            try {
                JSONObject obj = new JSONObject(json);
                long id = obj.optLong("id", 0);
                String name = obj.optString("name", "");
                long userId = obj.optLong("user_id", 0);
                List<String> scopes = new ArrayList<>();
                JSONArray scopesArr = obj.optJSONArray("scopes");
                if (scopesArr != null) {
                    for (int i = 0; i < scopesArr.length(); i++) {
                        scopes.add(scopesArr.optString(i, ""));
                    }
                }
                return new PersonalAccessTokenSelf(id, name, scopes, userId);
            } catch (JSONException e) {
                Log.e(TAG, "解析 PAT 自查询 JSON 失败: " + json, e);
                throw new IOException("GitLab PAT 自查询响应解析失败: " + e.getMessage(), e);
            }
        }

        private static DirectAccessResponse parseDirectAccessResponse(String json) throws IOException {
            try {
                JSONObject obj = new JSONObject(json);
                String baseUrl = obj.optString("base_url", "");
                String token = obj.optString("token", "");
                long expiresAt = obj.optLong("expires_at", 0);

                Map<String, String> headers = new HashMap<>();
                JSONObject headersObj = obj.optJSONObject("headers");
                if (headersObj != null) {
                    Iterator<String> keys = headersObj.keys();
                    while (keys.hasNext()) {
                        String key = keys.next();
                        headers.put(key, headersObj.optString(key, ""));
                    }
                }

                ModelDetails modelDetails = null;
                JSONObject modelObj = obj.optJSONObject("model_details");
                if (modelObj != null) {
                    String modelProvider = modelObj.optString("model_provider", "");
                    String modelName = modelObj.optString("model_name", "");
                    if (!modelName.isEmpty()) {
                        modelDetails = new ModelDetails(modelProvider, modelName);
                    }
                }

                return new DirectAccessResponse(baseUrl, token, expiresAt, headers, modelDetails);
            } catch (JSONException e) {
                Log.e(TAG, "解析直连访问响应 JSON 失败: " + json, e);
                throw new IOException("GitLab 直连访问响应解析失败: " + e.getMessage(), e);
            }
        }
    }

    // ============================================================
    // 编码工具
    // ============================================================

    /**
     * Base64 URL 安全编码（无填充）
     */
    private static String base64RawURLEncode(byte[] data) {
        String encoded = android.util.Base64.encodeToString(data, android.util.Base64.NO_PADDING
                | android.util.Base64.NO_WRAP | android.util.Base64.URL_SAFE);
        // Base64.encodeToString with URL_SAFE already uses URL-safe chars,
        // but ensure no trailing padding
        return encoded;
    }

    /**
     * 将表单数据编码为 URL 编码字符串
     */
    private static String encodeFormData(Map<String, String> params) {
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (!first) {
                sb.append('&');
            }
            sb.append(encodeUrl(entry.getKey()));
            sb.append('=');
            sb.append(encodeUrl(entry.getValue() != null ? entry.getValue() : ""));
            first = false;
        }
        return sb.toString();
    }

    /**
     * URL 编码单个值
     */
    private static String encodeUrl(String value) {
        try {
            return java.net.URLEncoder.encode(value, "UTF-8");
        } catch (java.io.UnsupportedEncodingException e) {
            // UTF-8 始终支持
            return value;
        }
    }
}