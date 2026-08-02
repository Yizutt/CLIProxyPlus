package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

/**
 * OAuthProvider - OAuth 认证提供者抽象基类
 * <p>
 * 提供 OAuth 2.0 认证流程的通用基础设施，包括 PKCE 码生成、
 * HTTP 请求发送、Authorization Code 换取 Token 等核心能力。
 * 子类只需实现特定于提供商的端点 URL、客户端 ID 和认证流程。
 */
public abstract class OAuthProvider {

    protected static final String TAG = "OAuthProvider";

    // 提供商名称
    protected final String providerName;
    // OAuth 端点
    protected final String authUrl;
    protected final String tokenUrl;
    protected final String clientId;
    protected final String redirectUri;

    /**
     * 默认构造器
     */
    public OAuthProvider() {
        this.providerName = "";
        this.authUrl = "";
        this.tokenUrl = "";
        this.clientId = "";
        this.redirectUri = "";
    }

    /**
     * 5 参数构造器
     *
     * @param providerName 提供商名称
     * @param authUrl      授权端点 URL
     * @param tokenUrl     令牌端点 URL
     * @param clientId     客户端 ID
     * @param redirectUri  重定向 URI
     */
    public OAuthProvider(String providerName, String authUrl, String tokenUrl,
                         String clientId, String redirectUri) {
        this.providerName = providerName;
        this.authUrl = authUrl;
        this.tokenUrl = tokenUrl;
        this.clientId = clientId;
        this.redirectUri = redirectUri;
    }

    /**
     * PKCE 码对，包含 code_verifier 和 code_challenge（S256）
     */
    public static class PKCECodes {
        public final String codeVerifier;
        public final String codeChallenge;

        public PKCECodes(String codeVerifier, String codeChallenge) {
            this.codeVerifier = codeVerifier;
            this.codeChallenge = codeChallenge;
        }
    }

    /**
     * 生成 PKCE 码对（S256 方法）
     */
    public static PKCECodes generatePKCECodes() {
        try {
            SecureRandom secureRandom = new SecureRandom();
            byte[] randomBytes = new byte[96];
            secureRandom.nextBytes(randomBytes);
            String codeVerifier = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(randomBytes);

            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            String codeChallenge = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(hash);

            return new PKCECodes(codeVerifier, codeChallenge);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 发送 HTTP POST 表单请求并返回响应体字符串
     */
    protected String postForm(String urlStr, Map<String, String> params) throws IOException {
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
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            try (java.io.InputStream is = (responseCode >= 200 && responseCode < 300)
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
     * 发送 HTTP GET 请求并返回响应体字符串
     */
    protected String get(String urlStr) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            int responseCode = conn.getResponseCode();
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            try (java.io.InputStream is = (responseCode >= 200 && responseCode < 300)
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

    protected void log(String msg) {
        Log.d(TAG, msg);
    }

    protected void logError(String msg, Throwable t) {
        Log.e(TAG, msg, t);
    }

    /**
     * OAuth 认证异常
     */
    public static class OAuthException extends Exception {
        public final String type;
        public final int code;

        public OAuthException(String type, String message) {
            super(message);
            this.type = type;
            this.code = 0;
        }

        public OAuthException(String type, String message, int code) {
            super(message);
            this.type = type;
            this.code = code;
        }

        public OAuthException(String type, String message, Throwable cause) {
            super(message, cause);
            this.type = type;
            this.code = 0;
        }
    }

    /**
     * Token 数据
     */
    public static class TokenData {
        public String idToken;
        public String accessToken;
        public String refreshToken;
        public String accountId;
        public String email;
        public long expiresIn;
        public long expireAt; // epoch millis

        public boolean isExpired() {
            return System.currentTimeMillis() >= expireAt;
        }
    }

    /**
     * 认证结果
     */
    public static class AuthResult {
        public TokenData tokenData;
        public String lastRefresh;
        public String apiKey;

        public AuthResult(TokenData tokenData) {
            this.tokenData = tokenData;
            this.lastRefresh = java.time.Instant.now().toString();
        }

        public AuthResult(TokenData tokenData, String apiKey) {
            this.tokenData = tokenData;
            this.apiKey = apiKey;
            this.lastRefresh = java.time.Instant.now().toString();
        }
    }

    /**
     * OAuth 回调结果
     */
    public static class OAuthCallbackResult {
        public String code;
        public String state;
        public String error;
    }
}