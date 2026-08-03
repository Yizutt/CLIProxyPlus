package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Kiro OAuth 认证实现 — 1:1 移植自 CLIProxyAPIPlus/internal/auth/kiro/。
 * <p>
 * 提供四种认证方式：
 * <ol>
 *   <li><b>Builder ID (AWS SSO OIDC 设备码流程)</b> — 通过 {@code https://oidc.us-east-1.amazonaws.com}
 *       注册客户端、启动设备授权、轮询令牌。</li>
 *   <li><b>Social Auth (Google/GitHub)</b> — 通过 {@code https://prod.us-east-1.auth.desktop.kiro.dev}
 *       使用 PKCE 授权码流程，本地回调端口 9876。</li>
 *   <li><b>IDC (AWS IAM Identity Center)</b> — 同 Builder ID 但支持指定区域和 StartURL。</li>
 *   <li><b>Token Import</b> — 导入原始 Kiro IDE 令牌 JSON。</li>
 * </ol>
 *
 * <h3>令牌存储格式</h3>
 * <pre>
 * {
 *   "type": "kiro",
 *   "access_token": "...",
 *   "refresh_token": "...",
 *   "profile_arn": "...",
 *   "auth_method": "builder-id|idc|social",
 *   "provider": "AWS|Google|GitHub"
 * }
 * </pre>
 *
 * <p>所有请求使用 Content-Type: application/json 和 HttpURLConnection。
 * 轮询间隔 5 秒。</p>
 */
public class KiroOAuth extends OAuthProvider {

    private static final String TAG = "KiroOAuth";

    // ========================================================================
    // 常量 — 1:1 移植自 Go const 块
    // ========================================================================

    /** Kiro AuthService 端点。 */
    public static final String KIRO_AUTH_ENDPOINT = "https://prod.us-east-1.auth.desktop.kiro.dev";

    /** AWS SSO OIDC 端点 (us-east-1)。 */
    public static final String SSO_OIDC_ENDPOINT = "https://oidc.us-east-1.amazonaws.com";

    /** Builder ID 的 Start URL。 */
    public static final String BUILDER_ID_START_URL = "https://view.awsapps.com/start";

    /** IDC 默认区域。 */
    public static final String DEFAULT_IDC_REGION = "us-east-1";

    /** 默认回调端口。 */
    public static final int DEFAULT_CALLBACK_PORT = 9876;

    /** 授权码流程回调端口。 */
    public static final int AUTH_CODE_CALLBACK_PORT = 19877;

    /** 轮询间隔（5 秒）。 */
    public static final long POLL_INTERVAL_MS = 5000L;

    /** 认证超时（10 分钟）。 */
    public static final long AUTH_TIMEOUT_MS = 10 * 60 * 1000L;

    // ========================================================================
    // 错误常量
    // ========================================================================

    public static final String ERROR_AUTHORIZATION_PENDING = "authorization_pending";
    public static final String ERROR_SLOW_DOWN = "slow_down";

    // ========================================================================
    // 数据类 — 1:1 移植自 Go 结构体
    // ========================================================================

    /**
     * KiroTokenData 保存 OAuth 令牌信息。
     * 1:1 移植自 Go KiroTokenData 结构体 (aws.go)。
     */
    public static class KiroTokenData {
        public String accessToken;
        public String refreshToken;
        public String profileArn;
        public String expiresAt;
        public String authMethod;
        public String provider;
        public String clientId;
        public String clientSecret;
        public String clientIdHash;
        public String email;
        public String startUrl;
        public String region;

        /**
         * 从 JSONObject 解析。
         * @param json 原始 JSON
         * @return 解析后的实例
         */
        public static KiroTokenData fromJson(JSONObject json) {
            if (json == null) return null;
            KiroTokenData data = new KiroTokenData();
            data.accessToken = json.optString("accessToken", "");
            data.refreshToken = json.optString("refreshToken", "");
            data.profileArn = json.optString("profileArn", "");
            data.expiresAt = json.optString("expiresAt", "");
            data.authMethod = json.optString("authMethod", "");
            data.provider = json.optString("provider", "");
            data.clientId = json.optString("clientId", "");
            data.clientSecret = json.optString("clientSecret", "");
            data.clientIdHash = json.optString("clientIdHash", "");
            data.email = json.optString("email", "");
            data.startUrl = json.optString("startUrl", "");
            data.region = json.optString("region", "");
            return data;
        }

        /**
         * 转换为 JSONObject。
         * @return JSON 表示
         */
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            try {
                json.put("accessToken", accessToken != null ? accessToken : "");
                json.put("refreshToken", refreshToken != null ? refreshToken : "");
                json.put("profileArn", profileArn != null ? profileArn : "");
                json.put("expiresAt", expiresAt != null ? expiresAt : "");
                json.put("authMethod", authMethod != null ? authMethod : "");
                json.put("provider", provider != null ? provider : "");
                if (clientId != null && !clientId.isEmpty()) json.put("clientId", clientId);
                if (clientSecret != null && !clientSecret.isEmpty()) json.put("clientSecret", clientSecret);
                if (clientIdHash != null && !clientIdHash.isEmpty()) json.put("clientIdHash", clientIdHash);
                if (email != null && !email.isEmpty()) json.put("email", email);
                if (startUrl != null && !startUrl.isEmpty()) json.put("startUrl", startUrl);
                if (region != null && !region.isEmpty()) json.put("region", region);
            } catch (JSONException e) {
                Log.e(TAG, "Failed to serialize KiroTokenData", e);
            }
            return json;
        }
    }

    /**
     * KiroTokenStorage 保存持久化的令牌数据。
     * 1:1 移植自 Go KiroTokenStorage 结构体 (token.go)。
     */
    public static class KiroTokenStorage {
        /** 提供者类型（必须为 "kiro"）。 */
        public String type = "kiro";
        /** OAuth2 访问令牌。 */
        public String accessToken;
        /** 刷新令牌。 */
        public String refreshToken;
        /** AWS CodeWhisperer 配置文件 ARN。 */
        public String profileArn;
        /** 令牌过期时间戳。 */
        public String expiresAt;
        /** 认证方法（builder-id, idc, social）。 */
        public String authMethod;
        /** OAuth 提供者。 */
        public String provider;
        /** 上次刷新时间戳。 */
        public String lastRefresh;
        /** OAuth 客户端 ID。 */
        public String clientId;
        /** OAuth 客户端密钥。 */
        public String clientSecret;
        /** 客户端 ID 哈希（用于设备注册文件查找）。 */
        public String clientIdHash;
        /** OIDC 区域。 */
        public String region;
        /** IDC Start URL。 */
        public String startUrl;
        /** 用户邮箱。 */
        public String email;

        /**
         * 从 JSONObject 解析。
         * @param json 原始 JSON
         * @return 解析后的实例
         */
        public static KiroTokenStorage fromJson(JSONObject json) {
            if (json == null) return null;
            KiroTokenStorage s = new KiroTokenStorage();
            s.type = json.optString("type", "kiro");
            s.accessToken = json.optString("access_token", "");
            s.refreshToken = json.optString("refresh_token", "");
            s.profileArn = json.optString("profile_arn", "");
            s.expiresAt = json.optString("expires_at", "");
            s.authMethod = json.optString("auth_method", "");
            s.provider = json.optString("provider", "");
            s.lastRefresh = json.optString("last_refresh", "");
            s.clientId = json.optString("client_id", "");
            s.clientSecret = json.optString("client_secret", "");
            s.clientIdHash = json.optString("client_id_hash", "");
            s.region = json.optString("region", "");
            s.startUrl = json.optString("start_url", "");
            s.email = json.optString("email", "");
            return s;
        }

        /**
         * 转换为 JSONObject（存储格式）。
         * @return JSON 表示
         */
        public JSONObject toJson() {
            JSONObject json = new JSONObject();
            try {
                json.put("type", type != null ? type : "kiro");
                json.put("access_token", accessToken != null ? accessToken : "");
                json.put("refresh_token", refreshToken != null ? refreshToken : "");
                json.put("profile_arn", profileArn != null ? profileArn : "");
                json.put("expires_at", expiresAt != null ? expiresAt : "");
                json.put("auth_method", authMethod != null ? authMethod : "");
                json.put("provider", provider != null ? provider : "");
                if (lastRefresh != null && !lastRefresh.isEmpty()) json.put("last_refresh", lastRefresh);
                if (clientId != null && !clientId.isEmpty()) json.put("client_id", clientId);
                if (clientSecret != null && !clientSecret.isEmpty()) json.put("client_secret", clientSecret);
                if (clientIdHash != null && !clientIdHash.isEmpty()) json.put("client_id_hash", clientIdHash);
                if (region != null && !region.isEmpty()) json.put("region", region);
                if (startUrl != null && !startUrl.isEmpty()) json.put("start_url", startUrl);
                if (email != null && !email.isEmpty()) json.put("email", email);
            } catch (JSONException e) {
                Log.e(TAG, "Failed to serialize KiroTokenStorage", e);
            }
            return json;
        }

        /**
         * 转换为 KiroTokenData 用于 API 使用。
         * @return 令牌数据实例
         */
        public KiroTokenData toTokenData() {
            KiroTokenData data = new KiroTokenData();
            data.accessToken = this.accessToken;
            data.refreshToken = this.refreshToken;
            data.profileArn = this.profileArn;
            data.expiresAt = this.expiresAt;
            data.authMethod = this.authMethod;
            data.provider = this.provider;
            data.clientId = this.clientId;
            data.clientSecret = this.clientSecret;
            data.clientIdHash = this.clientIdHash;
            data.region = this.region;
            data.startUrl = this.startUrl;
            data.email = this.email;
            return data;
        }
    }

    /**
     * KiroTokenResponse 表示 Kiro /oauth/token 端点的响应。
     * 1:1 移植自 Go KiroTokenResponse (oauth.go)。
     */
    public static class KiroTokenResponse {
        public String accessToken;
        public String refreshToken;
        public String profileArn;
        public int expiresIn;

        static KiroTokenResponse fromJson(JSONObject json) {
            if (json == null) return null;
            KiroTokenResponse r = new KiroTokenResponse();
            r.accessToken = json.optString("accessToken", "");
            r.refreshToken = json.optString("refreshToken", "");
            r.profileArn = json.optString("profileArn", "");
            r.expiresIn = json.optInt("expiresIn", 0);
            return r;
        }
    }

    /**
     * SocialTokenResponse 表示社交登录的令牌响应。
     * 1:1 移植自 Go SocialTokenResponse (social_auth.go)。
     */
    public static class SocialTokenResponse {
        public String accessToken;
        public String refreshToken;
        public String profileArn;
        public int expiresIn;

        static SocialTokenResponse fromJson(JSONObject json) {
            if (json == null) return null;
            SocialTokenResponse r = new SocialTokenResponse();
            r.accessToken = json.optString("accessToken", "");
            r.refreshToken = json.optString("refreshToken", "");
            r.profileArn = json.optString("profileArn", "");
            r.expiresIn = json.optInt("expiresIn", 0);
            return r;
        }
    }

    /**
     * CreateTokenRequest 发送到 Kiro 的 /oauth/token 端点。
     * 1:1 移植自 Go CreateTokenRequest (social_auth.go)。
     */
    public static class CreateTokenRequest {
        public String code;
        public String codeVerifier;
        public String redirectUri;
        public String invitationCode;

        JSONObject toJson() {
            JSONObject json = new JSONObject();
            try {
                json.put("code", code != null ? code : "");
                json.put("code_verifier", codeVerifier != null ? codeVerifier : "");
                json.put("redirect_uri", redirectUri != null ? redirectUri : "");
                if (invitationCode != null && !invitationCode.isEmpty()) {
                    json.put("invitation_code", invitationCode);
                }
            } catch (JSONException e) {
                Log.e(TAG, "Failed to serialize CreateTokenRequest", e);
            }
            return json;
        }
    }

    /**
     * RegisterClientResponse 来自 AWS SSO OIDC。
     * 1:1 移植自 Go RegisterClientResponse (sso_oidc.go)。
     */
    public static class RegisterClientResponse {
        public String clientId;
        public String clientSecret;
        public long clientIdIssuedAt;
        public long clientSecretExpiresAt;

        static RegisterClientResponse fromJson(JSONObject json) {
            if (json == null) return null;
            RegisterClientResponse r = new RegisterClientResponse();
            r.clientId = json.optString("clientId", "");
            r.clientSecret = json.optString("clientSecret", "");
            r.clientIdIssuedAt = json.optLong("clientIdIssuedAt", 0);
            r.clientSecretExpiresAt = json.optLong("clientSecretExpiresAt", 0);
            return r;
        }
    }

    /**
     * StartDeviceAuthResponse 来自 AWS SSO OIDC 设备授权。
     * 1:1 移植自 Go StartDeviceAuthResponse (sso_oidc.go)。
     */
    public static class StartDeviceAuthResponse {
        public String deviceCode;
        public String userCode;
        public String verificationUri;
        public String verificationUriComplete;
        public int expiresIn;
        public int interval;

        static StartDeviceAuthResponse fromJson(JSONObject json) {
            if (json == null) return null;
            StartDeviceAuthResponse r = new StartDeviceAuthResponse();
            r.deviceCode = json.optString("deviceCode", "");
            r.userCode = json.optString("userCode", "");
            r.verificationUri = json.optString("verificationUri", "");
            r.verificationUriComplete = json.optString("verificationUriComplete", "");
            r.expiresIn = json.optInt("expiresIn", 0);
            r.interval = json.optInt("interval", 0);
            return r;
        }
    }

    /**
     * CreateTokenResponse 来自 AWS SSO OIDC 令牌端点。
     * 1:1 移植自 Go CreateTokenResponse (sso_oidc.go)。
     */
    public static class CreateTokenResponse {
        public String accessToken;
        public String tokenType;
        public int expiresIn;
        public String refreshToken;

        static CreateTokenResponse fromJson(JSONObject json) {
            if (json == null) return null;
            CreateTokenResponse r = new CreateTokenResponse();
            r.accessToken = json.optString("accessToken", "");
            r.tokenType = json.optString("tokenType", "");
            r.expiresIn = json.optInt("expiresIn", 0);
            r.refreshToken = json.optString("refreshToken", "");
            return r;
        }
    }

    /**
     * AuthResult 包含来自回调的授权码和状态。
     * 1:1 移植自 Go AuthResult (oauth.go)。
     */
    public static class AuthResult {
        public String code;
        public String state;
        public String error;
    }

    /**
     * WebCallbackResult 包含来自 HTTP 服务器的 OAuth 回调结果。
     * 1:1 移植自 Go WebCallbackResult (social_auth.go)。
     */
    public static class WebCallbackResult {
        public String code;
        public String state;
        public String error;
    }

    /**
     * AuthCodeCallbackResult 包含授权码流程的结果。
     * 1:1 移植自 Go AuthCodeCallbackResult (sso_oidc.go)。
     */
    public static class AuthCodeCallbackResult {
        public String code;
        public String state;
        public String error;
    }

    /**
     * ImportTokenRequest 令牌导入请求。
     * 1:1 移植自 Go ImportTokenRequest (oauth_web.go)。
     */
    public static class ImportTokenRequest {
        public String refreshToken;
    }

    /**
     * ProfileARN 表示解析后的 AWS CodeWhisperer 配置文件 ARN。
     * 1:1 移植自 Go ProfileARN (aws.go)。
     * ARN 格式: arn:partition:service:region:account-id:resource-type/resource-id
     */
    public static class ProfileARN {
        public String raw;
        public String partition;
        public String service;
        public String region;
        public String accountId;
        public String resourceType;
        public String resourceId;
    }

    /**
     * IDCLoginOptions IDC 登录的可选参数。
     * 1:1 移植自 Go IDCLoginOptions (sso_oidc.go)。
     */
    public static class IDCLoginOptions {
        public String startUrl;
        public String region;
        public boolean useDeviceCode;
    }

    /**
     * PKCECodes 保存 PKCE 验证码和挑战码。
     * 1:1 移植自 Go PKCECodes (aws.go)。
     */
    public static class PKCECodes {
        public final String codeVerifier;
        public final String codeChallenge;

        public PKCECodes(String codeVerifier, String codeChallenge) {
            this.codeVerifier = codeVerifier;
            this.codeChallenge = codeChallenge;
        }
    }

    // ========================================================================
    // 实例字段
    // ========================================================================

    private final String machineID;
    private final String kiroVersion;
    private final int connectTimeout;
    private final int readTimeout;

    // ========================================================================
    // 构造方法
    // ========================================================================

    /**
     * 创建 KiroOAuth 实例。
     */
    public KiroOAuth() {
        super("Kiro", "", "", "", "");
        this.machineID = generateMachineID();
        this.kiroVersion = "0.10.32";
        this.connectTimeout = 30000;
        this.readTimeout = 30000;
        Log.d(TAG, "KiroOAuth initialized, machineID=" + machineID + ", kiroVersion=" + kiroVersion);
    }

    /**
     * 创建 KiroOAuth 实例，使用指定的超时值。
     * @param connectTimeout 连接超时（毫秒）
     * @param readTimeout 读取超时（毫秒）
     */
    public KiroOAuth(int connectTimeout, int readTimeout) {
        super("Kiro", "", "", "", "");
        this.machineID = generateMachineID();
        this.kiroVersion = "0.10.32";
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    /**
     * 创建 KiroOAuth 实例，使用指定的 machineID 和 kiroVersion。
     * @param machineID 机器标识
     * @param kiroVersion Kiro IDE 版本
     */
    public KiroOAuth(String machineID, String kiroVersion) {
        super("Kiro", "", "", "", "");
        this.machineID = machineID;
        this.kiroVersion = kiroVersion;
        this.connectTimeout = 30000;
        this.readTimeout = 30000;
    }

    // ========================================================================
    // PKCE 工具方法 — 1:1 移植自 Go PKCE 函数
    // ========================================================================

    /**
     * 生成随机的 code_verifier（32 字节，base64url 编码）。
     * @return code_verifier 字符串
     */
    public static String generateCodeVerifier() {
        try {
            SecureRandom sr = new SecureRandom();
            byte[] bytes = new byte[32];
            sr.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate code verifier", e);
            throw new RuntimeException("Failed to generate code verifier", e);
        }
    }

    /**
     * 从 verifier 生成 code_challenge（SHA-256 哈希，base64url 编码）。
     * @param verifier code_verifier
     * @return code_challenge 字符串
     */
    public static String generateCodeChallenge(String verifier) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "SHA-256 not available", e);
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    /**
     * 生成随机的 state 参数（16 字节，base64url 编码）。
     * @return state 字符串
     */
    public static String generateState() {
        try {
            SecureRandom sr = new SecureRandom();
            byte[] bytes = new byte[16];
            sr.nextBytes(bytes);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate state", e);
            throw new RuntimeException("Failed to generate state", e);
        }
    }

    /**
     * 生成 PKCE 码对（verifier + challenge）。
     * @return PKCECodes 实例
     */
    public static PKCECodes generatePKCE() {
        String verifier = generateCodeVerifier();
        String challenge = generateCodeChallenge(verifier);
        return new PKCECodes(verifier, challenge);
    }

    // ========================================================================
    // HTTP 工具方法
    // ========================================================================

    /**
     * 发送 HTTP POST 请求，JSON body。
     * @param urlStr 请求 URL
     * @param jsonBody JSON body
     * @param headers 额外的请求头
     * @return 响应体字符串
     * @throws IOException 网络错误或非 2xx 响应
     */
    private String httpPostJson(String urlStr, String jsonBody, Map<String, String> headers) throws IOException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json, text/plain, */*");
            if (headers != null) {
                for (Map.Entry<String, String> h : headers.entrySet()) {
                    conn.setRequestProperty(h.getKey(), h.getValue());
                }
            }
            conn.setDoOutput(true);
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);

            if (jsonBody != null && !jsonBody.isEmpty()) {
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                }
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readStream(responseCode >= 200 && responseCode < 300
                    ? conn.getInputStream() : conn.getErrorStream());

            Log.d(TAG, "POST " + urlStr + " -> " + responseCode);

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("HTTP " + responseCode + ": " + responseBody);
            }
            return responseBody;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * 发送 HTTP POST 请求，JSON body，无额外头。
     */
    private String httpPostJson(String urlStr, String jsonBody) throws IOException {
        return httpPostJson(urlStr, jsonBody, null);
    }

    /**
     * 发送 HTTP GET 请求。
     * @param urlStr 请求 URL
     * @param headers 额外的请求头
     * @return 响应体字符串
     * @throws IOException 网络错误或非 2xx 响应
     */
    private String httpGet(String urlStr, Map<String, String> headers) throws IOException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            if (headers != null) {
                for (Map.Entry<String, String> h : headers.entrySet()) {
                    conn.setRequestProperty(h.getKey(), h.getValue());
                }
            }
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);

            int responseCode = conn.getResponseCode();
            String responseBody = readStream(responseCode >= 200 && responseCode < 300
                    ? conn.getInputStream() : conn.getErrorStream());

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("HTTP " + responseCode + ": " + responseBody);
            }
            return responseBody;
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * 读取 InputStream 为字符串。
     */
    private static String readStream(InputStream is) throws IOException {
        if (is == null) return "";
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = is.read(buf)) != -1) {
            baos.write(buf, 0, n);
        }
        return baos.toString("UTF-8");
    }

    // ========================================================================
    // OIDC 请求头 — 1:1 移植自 Go SetOIDCHeaders (fingerprint.go)
    // ========================================================================

    /**
     * 设置 AWS SSO OIDC 请求头。
     * 1:1 移植自 Go SetOIDCHeaders (fingerprint.go)。
     * @param headers 请求头映射
     */
    public static void setOIDCHeaders(Map<String, String> headers) {
        headers.put("Content-Type", "application/json");
        headers.put("x-amz-user-agent", "aws-sdk-js/3.980.0 KiroIDE");
        headers.put("User-Agent", "aws-sdk-js/3.980.0 ua/2.1 os/android#12 lang/js md/nodejs#22.21.1 api/sso-oidc#3.980.0 m/E KiroIDE");
        headers.put("amz-sdk-invocation-id", UUID.randomUUID().toString());
        headers.put("amz-sdk-request", "attempt=1; max=4");
    }

    // ========================================================================
    // 回调服务器 — 1:1 移植自 Go startCallbackServer (oauth.go)
    // ========================================================================

    /**
     * 启动本地 HTTP 回调服务器接收 OAuth 授权码。
     * 1:1 移植自 Go (o *KiroOAuth) startCallbackServer (oauth.go)。
     *
     * @param expectedState 期望的 state 值，用于 CSRF 校验
     * @param timeoutMs 超时时间（毫秒）
     * @return AuthResult 包含授权码或错误
     */
    public AuthResult startCallbackServer(String expectedState, long timeoutMs) {
        ServerSocket serverSocket = null;
        try {
            // 尝试默认端口
            try {
                serverSocket = new ServerSocket(DEFAULT_CALLBACK_PORT, 50, java.net.InetAddress.getByName("localhost"));
            } catch (IOException e) {
                Log.w(TAG, "Default port " + DEFAULT_CALLBACK_PORT + " is busy, falling back to dynamic port");
                serverSocket = new ServerSocket(0, 50, java.net.InetAddress.getByName("localhost"));
            }

            int port = serverSocket.getLocalPort();
            String redirectURI = "http://localhost:" + port + "/oauth/callback";
            Log.d(TAG, "Callback server started at " + redirectURI);

            serverSocket.setSoTimeout((int) timeoutMs);

            AuthResult result = new AuthResult();
            try (Socket clientSocket = serverSocket.accept()) {
                InputStream in = clientSocket.getInputStream();
                ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) != -1) {
                    requestBytes.write(buf, 0, n);
                    if (n < buf.length) break;
                }

                String request = requestBytes.toString("UTF-8");
                Log.d(TAG, "Callback request: " + request.substring(0, Math.min(request.length(), 200)));

                // 解析请求行: GET /oauth/callback?code=...&state=... HTTP/1.1
                String[] lines = request.split("\r\n");
                if (lines.length > 0) {
                    String requestLine = lines[0];
                    String[] parts = requestLine.split(" ");
                    if (parts.length >= 2 && parts[1].contains("?")) {
                        String query = parts[1].substring(parts[1].indexOf('?') + 1);
                        Map<String, String> params = parseQueryString(query);
                        String code = params.get("code");
                        String state = params.get("state");
                        String errorParam = params.get("error");

                        String responseBody;
                        int statusCode;

                        if (errorParam != null && !errorParam.isEmpty()) {
                            result.error = errorParam;
                            statusCode = 400;
                            responseBody = "<html><body><h1>Login Failed</h1><p>" + escapeHtml(errorParam)
                                    + "</p><p>You can close this window.</p></body></html>";
                        } else if (state == null || !state.equals(expectedState)) {
                            result.error = "state mismatch";
                            statusCode = 400;
                            responseBody = "<html><body><h1>Login Failed</h1><p>Invalid state parameter</p>"
                                    + "<p>You can close this window.</p></body></html>";
                        } else {
                            result.code = code;
                            result.state = state;
                            statusCode = 200;
                            responseBody = "<html><body><h1>Login Successful!</h1>"
                                    + "<p>You can close this window and return to the terminal.</p></body></html>";
                        }

                        byte[] responseBytes = buildHttpResponse(statusCode, responseBody);
                        OutputStream out = clientSocket.getOutputStream();
                        out.write(responseBytes);
                        out.flush();
                    }
                }
            }

            return result;
        } catch (java.net.SocketTimeoutException e) {
            AuthResult result = new AuthResult();
            result.error = "timeout";
            return result;
        } catch (IOException e) {
            Log.e(TAG, "Callback server error", e);
            AuthResult result = new AuthResult();
            result.error = "callback_server_error: " + e.getMessage();
            return result;
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * 启动社交登录 Web 回调服务器。
     * 1:1 移植自 Go startWebCallbackServer (social_auth.go)。
     *
     * @param expectedState 期望的 state 值
     * @param timeoutMs 超时时间（毫秒）
     * @return 包含 redirectURI 和回调结果的包装
     */
    public CallbackServerResult startWebCallbackServer(String expectedState, long timeoutMs) {
        ServerSocket serverSocket = null;
        try {
            try {
                serverSocket = new ServerSocket(DEFAULT_CALLBACK_PORT, 50, java.net.InetAddress.getByName("localhost"));
            } catch (IOException e) {
                Log.w(TAG, "Social auth default port " + DEFAULT_CALLBACK_PORT + " is busy, falling back to dynamic port");
                serverSocket = new ServerSocket(0, 50, java.net.InetAddress.getByName("localhost"));
            }

            int port = serverSocket.getLocalPort();
            String redirectURI = "http://localhost:" + port + "/oauth/callback";
            serverSocket.setSoTimeout((int) timeoutMs);

            Log.d(TAG, "Social auth callback server started at " + redirectURI);

            try (Socket clientSocket = serverSocket.accept()) {
                InputStream in = clientSocket.getInputStream();
                ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) != -1) {
                    requestBytes.write(buf, 0, n);
                    if (n < buf.length) break;
                }

                String request = requestBytes.toString("UTF-8");
                String[] lines = request.split("\r\n");

                WebCallbackResult callbackResult = new WebCallbackResult();
                String responseBody;
                int statusCode;

                if (lines.length > 0) {
                    String requestLine = lines[0];
                    String[] parts = requestLine.split(" ");
                    if (parts.length >= 2 && parts[1].contains("?")) {
                        String query = parts[1].substring(parts[1].indexOf('?') + 1);
                        Map<String, String> params = parseQueryString(query);
                        String code = params.get("code");
                        String state = params.get("state");
                        String errorParam = params.get("error");

                        if (errorParam != null && !errorParam.isEmpty()) {
                            callbackResult.error = errorParam;
                            statusCode = 400;
                            responseBody = "<!DOCTYPE html>\n<html><head><title>Login Failed</title></head>\n"
                                    + "<body><h1>Login Failed</h1><p>" + escapeHtml(errorParam)
                                    + "</p><p>You can close this window.</p></body></html>";
                        } else if (state == null || !state.equals(expectedState)) {
                            callbackResult.error = "state mismatch";
                            statusCode = 400;
                            responseBody = "<!DOCTYPE html>\n<html><head><title>Login Failed</title></head>\n"
                                    + "<body><h1>Login Failed</h1><p>Invalid state parameter</p>"
                                    + "<p>You can close this window.</p></body></html>";
                        } else {
                            callbackResult.code = code;
                            callbackResult.state = state;
                            statusCode = 200;
                            responseBody = "<!DOCTYPE html>\n<html><head><title>Login Successful</title></head>\n"
                                    + "<body><h1>Login Successful!</h1>"
                                    + "<p>You can close this window and return to the terminal.</p>\n"
                                    + "<script>window.close();</script></body></html>";
                        }
                    } else {
                        // 健康检查或根路径
                        callbackResult.error = "no_callback";
                        statusCode = 404;
                        responseBody = "<html><body><h1>Not Found</h1></body></html>";
                    }
                } else {
                    callbackResult.error = "empty_request";
                    statusCode = 400;
                    responseBody = "<html><body><h1>Bad Request</h1></body></html>";
                }

                byte[] responseBytes = buildHttpResponse(statusCode, responseBody);
                OutputStream out = clientSocket.getOutputStream();
                out.write(responseBytes);
                out.flush();

                return new CallbackServerResult(redirectURI, callbackResult);
            }
        } catch (java.net.SocketTimeoutException e) {
            WebCallbackResult r = new WebCallbackResult();
            r.error = "timeout";
            return new CallbackServerResult("", r);
        } catch (IOException e) {
            Log.e(TAG, "Social auth callback server error", e);
            WebCallbackResult r = new WebCallbackResult();
            r.error = "callback_server_error: " + e.getMessage();
            return new CallbackServerResult("", r);
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * 启动授权码流程回调服务器。
     * 1:1 移植自 Go startAuthCodeCallbackServer (sso_oidc.go)。
     *
     * @param expectedState 期望的 state 值
     * @param timeoutMs 超时时间（毫秒）
     * @return 包含 redirectURI 和回调结果的包装
     */
    public AuthCodeServerResult startAuthCodeCallbackServer(String expectedState, long timeoutMs) {
        ServerSocket serverSocket = null;
        try {
            try {
                serverSocket = new ServerSocket(AUTH_CODE_CALLBACK_PORT, 50, java.net.InetAddress.getByName("127.0.0.1"));
            } catch (IOException e) {
                Log.w(TAG, "Auth code callback port " + AUTH_CODE_CALLBACK_PORT + " is busy, falling back to dynamic port");
                serverSocket = new ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"));
            }

            int port = serverSocket.getLocalPort();
            String redirectURI = "http://127.0.0.1:" + port + "/oauth/callback";
            serverSocket.setSoTimeout((int) timeoutMs);

            Log.d(TAG, "Auth code callback server started at " + redirectURI);

            try (Socket clientSocket = serverSocket.accept()) {
                InputStream in = clientSocket.getInputStream();
                ByteArrayOutputStream requestBytes = new ByteArrayOutputStream();
                byte[] buf = new byte[4096];
                int n;
                while ((n = in.read(buf)) != -1) {
                    requestBytes.write(buf, 0, n);
                    if (n < buf.length) break;
                }

                String request = requestBytes.toString("UTF-8");
                String[] lines = request.split("\r\n");

                AuthCodeCallbackResult callbackResult = new AuthCodeCallbackResult();
                String responseBody;
                int statusCode;

                if (lines.length > 0) {
                    String requestLine = lines[0];
                    String[] parts = requestLine.split(" ");
                    if (parts.length >= 2 && parts[1].contains("?")) {
                        String query = parts[1].substring(parts[1].indexOf('?') + 1);
                        Map<String, String> params = parseQueryString(query);
                        String code = params.get("code");
                        String state = params.get("state");
                        String errorParam = params.get("error");

                        if (errorParam != null && !errorParam.isEmpty()) {
                            callbackResult.error = errorParam;
                            statusCode = 400;
                            responseBody = "<!DOCTYPE html>\n<html><head><title>Login Failed</title></head>\n"
                                    + "<body><h1>Login Failed</h1><p>Error: " + escapeHtml(errorParam)
                                    + "</p><p>You can close this window.</p></body></html>";
                        } else if (state == null || !state.equals(expectedState)) {
                            callbackResult.error = "state mismatch";
                            statusCode = 400;
                            responseBody = "<!DOCTYPE html>\n<html><head><title>Login Failed</title></head>\n"
                                    + "<body><h1>Login Failed</h1><p>Invalid state parameter</p>"
                                    + "<p>You can close this window.</p></body></html>";
                        } else {
                            callbackResult.code = code;
                            callbackResult.state = state;
                            statusCode = 200;
                            responseBody = "<!DOCTYPE html>\n<html><head><title>Login Successful</title></head>\n"
                                    + "<body><h1>Login Successful!</h1>"
                                    + "<p>You can close this window and return to the terminal.</p>\n"
                                    + "<script>window.close();</script></body></html>";
                        }
                    } else {
                        callbackResult.error = "no_callback";
                        statusCode = 404;
                        responseBody = "<html><body><h1>Not Found</h1></body></html>";
                    }
                } else {
                    callbackResult.error = "empty_request";
                    statusCode = 400;
                    responseBody = "<html><body><h1>Bad Request</h1></body></html>";
                }

                byte[] responseBytes = buildHttpResponse(statusCode, responseBody);
                OutputStream out = clientSocket.getOutputStream();
                out.write(responseBytes);
                out.flush();

                return new AuthCodeServerResult(redirectURI, callbackResult);
            }
        } catch (java.net.SocketTimeoutException e) {
            AuthCodeCallbackResult r = new AuthCodeCallbackResult();
            r.error = "timeout";
            return new AuthCodeServerResult("", r);
        } catch (IOException e) {
            Log.e(TAG, "Auth code callback server error", e);
            AuthCodeCallbackResult r = new AuthCodeCallbackResult();
            r.error = "callback_server_error: " + e.getMessage();
            return new AuthCodeServerResult("", r);
        } finally {
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * 构建 HTTP 响应字节数组。
     */
    private static byte[] buildHttpResponse(int statusCode, String body) {
        String statusText = (statusCode == 200) ? "OK" : (statusCode == 400) ? "Bad Request" : "Not Found";
        String header = "HTTP/1.1 " + statusCode + " " + statusText + "\r\n"
                + "Content-Type: text/html; charset=utf-8\r\n"
                + "Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                + "Connection: close\r\n"
                + "\r\n";
        return (header + body).getBytes(StandardCharsets.UTF_8);
    }

    /**
     * 解析查询字符串为 Map。
     */
    private static Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) return params;
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                try {
                    String key = URLDecoder.decode(pair.substring(0, eq), "UTF-8");
                    String value = URLDecoder.decode(pair.substring(eq + 1), "UTF-8");
                    params.put(key, value);
                } catch (Exception e) {
                    Log.w(TAG, "Failed to parse query param: " + pair, e);
                }
            }
        }
        return params;
    }

    /**
     * 转义 HTML 特殊字符。
     */
    private static String escapeHtml(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }

    // ========================================================================
    // 回调服务器结果包装类
    // ========================================================================

    /** 回调服务器结果包装。 */
    public static class CallbackServerResult {
        public final String redirectURI;
        public final WebCallbackResult callbackResult;

        public CallbackServerResult(String redirectURI, WebCallbackResult callbackResult) {
            this.redirectURI = redirectURI;
            this.callbackResult = callbackResult;
        }
    }

    /** 授权码回调服务器结果包装。 */
    public static class AuthCodeServerResult {
        public final String redirectURI;
        public final AuthCodeCallbackResult callbackResult;

        public AuthCodeServerResult(String redirectURI, AuthCodeCallbackResult callbackResult) {
            this.redirectURI = redirectURI;
            this.callbackResult = callbackResult;
        }
    }

    // ========================================================================
    // 1. Builder ID — AWS SSO OIDC 设备码流程
    // ========================================================================

    /**
     * 注册 OIDC 客户端。
     * 1:1 移植自 Go RegisterClient (sso_oidc.go)。
     * <p>POST /client/register — JSON body: clientName, clientType, scopes, grantTypes</p>
     *
     * @return 注册客户端响应
     * @throws IOException 网络错误或非 2xx 响应
     */
    public RegisterClientResponse registerClient() throws IOException {
        JSONObject payload = new JSONObject();
        try {
            payload.put("clientName", "Kiro IDE");
            payload.put("clientType", "public");
            JSONArray scopes = new JSONArray();
            scopes.put("codewhisperer:completions");
            scopes.put("codewhisperer:analysis");
            scopes.put("codewhisperer:conversations");
            scopes.put("codewhisperer:transformations");
            scopes.put("codewhisperer:taskassist");
            payload.put("scopes", scopes);
            JSONArray grantTypes = new JSONArray();
            grantTypes.put("urn:ietf:params:oauth:grant-type:device_code");
            grantTypes.put("refresh_token");
            payload.put("grantTypes", grantTypes);
        } catch (JSONException e) {
            throw new IOException("Failed to build register client payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        String response = httpPostJson(SSO_OIDC_ENDPOINT + "/client/register",
                payload.toString(), headers);
        Log.d(TAG, "Client registered successfully");

        try {
            return RegisterClientResponse.fromJson(new JSONObject(response));
        } catch (JSONException e) {
            throw new IOException("Failed to parse register client response", e);
        }
    }

    /**
     * 在指定区域注册 OIDC 客户端。
     * 1:1 移植自 Go RegisterClientWithRegion (sso_oidc.go)。
     *
     * @param region AWS 区域
     * @return 注册客户端响应
     * @throws IOException 网络错误或非 2xx 响应
     */
    public RegisterClientResponse registerClientWithRegion(String region) throws IOException {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }
        String endpoint = getOIDCEndpoint(region);

        JSONObject payload = new JSONObject();
        try {
            payload.put("clientName", "Kiro IDE");
            payload.put("clientType", "public");
            JSONArray scopes = new JSONArray();
            scopes.put("codewhisperer:completions");
            scopes.put("codewhisperer:analysis");
            scopes.put("codewhisperer:conversations");
            scopes.put("codewhisperer:transformations");
            scopes.put("codewhisperer:taskassist");
            payload.put("scopes", scopes);
            JSONArray grantTypes = new JSONArray();
            grantTypes.put("urn:ietf:params:oauth:grant-type:device_code");
            grantTypes.put("refresh_token");
            payload.put("grantTypes", grantTypes);
        } catch (JSONException e) {
            throw new IOException("Failed to build register client payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        String response = httpPostJson(endpoint + "/client/register",
                payload.toString(), headers);
        Log.d(TAG, "Client registered with region " + region);

        try {
            return RegisterClientResponse.fromJson(new JSONObject(response));
        } catch (JSONException e) {
            throw new IOException("Failed to parse register client response", e);
        }
    }

    /**
     * 启动设备授权流程。
     * 1:1 移植自 Go StartDeviceAuthorization (sso_oidc.go)。
     * <p>POST /device_authorization — JSON body: clientId, clientSecret, startUrl</p>
     *
     * @param clientId     注册的客户端 ID
     * @param clientSecret 注册的客户端密钥
     * @return 设备授权响应
     * @throws IOException 网络错误或非 2xx 响应
     */
    public StartDeviceAuthResponse startDeviceAuthorization(String clientId, String clientSecret) throws IOException {
        JSONObject payload = new JSONObject();
        try {
            payload.put("clientId", clientId);
            payload.put("clientSecret", clientSecret);
            payload.put("startUrl", BUILDER_ID_START_URL);
        } catch (JSONException e) {
            throw new IOException("Failed to build device auth payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        String response = httpPostJson(SSO_OIDC_ENDPOINT + "/device_authorization",
                payload.toString(), headers);
        Log.d(TAG, "Device authorization started");

        try {
            return StartDeviceAuthResponse.fromJson(new JSONObject(response));
        } catch (JSONException e) {
            throw new IOException("Failed to parse device auth response", e);
        }
    }

    /**
     * 使用指定区域启动设备授权（用于 IDC）。
     * 1:1 移植自 Go StartDeviceAuthorizationWithIDC (sso_oidc.go)。
     *
     * @param clientId     注册的客户端 ID
     * @param clientSecret 注册的客户端密钥
     * @param startUrl     IDC Start URL
     * @param region       AWS 区域
     * @return 设备授权响应
     * @throws IOException 网络错误或非 2xx 响应
     */
    public StartDeviceAuthResponse startDeviceAuthorizationWithIDC(String clientId, String clientSecret,
                                                                   String startUrl, String region) throws IOException {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }
        String endpoint = getOIDCEndpoint(region);

        JSONObject payload = new JSONObject();
        try {
            payload.put("clientId", clientId);
            payload.put("clientSecret", clientSecret);
            payload.put("startUrl", startUrl);
        } catch (JSONException e) {
            throw new IOException("Failed to build device auth payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        String response = httpPostJson(endpoint + "/device_authorization",
                payload.toString(), headers);
        Log.d(TAG, "Device authorization started with IDC region " + region);

        try {
            return StartDeviceAuthResponse.fromJson(new JSONObject(response));
        } catch (JSONException e) {
            throw new IOException("Failed to parse device auth response", e);
        }
    }

    /**
     * 轮询令牌端点。
     * 1:1 移植自 Go CreateToken (sso_oidc.go)。
     * <p>POST /token — JSON body: clientId, clientSecret, deviceCode, grantType</p>
     *
     * @param clientId     注册的客户端 ID
     * @param clientSecret 注册的客户端密钥
     * @param deviceCode   设备码
     * @return 令牌创建响应，如果授权待定返回 null
     * @throws IOException 网络错误或非 2xx 响应
     */
    public CreateTokenResponse createToken(String clientId, String clientSecret, String deviceCode) throws IOException {
        JSONObject payload = new JSONObject();
        try {
            payload.put("clientId", clientId);
            payload.put("clientSecret", clientSecret);
            payload.put("deviceCode", deviceCode);
            payload.put("grantType", "urn:ietf:params:oauth:grant-type:device_code");
        } catch (JSONException e) {
            throw new IOException("Failed to build create token payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        try {
            String response = httpPostJson(SSO_OIDC_ENDPOINT + "/token",
                    payload.toString(), headers);
            try {
                return CreateTokenResponse.fromJson(new JSONObject(response));
            } catch (JSONException e) {
                throw new IOException("Failed to parse token response", e);
            }
        } catch (IOException e) {
            String msg = e.getMessage();
            // 检查是否包含 authorization_pending 或 slow_down 错误
            if (msg != null) {
                if (msg.contains(ERROR_AUTHORIZATION_PENDING)) {
                    Log.d(TAG, "Authorization pending");
                    return null;
                }
                if (msg.contains(ERROR_SLOW_DOWN)) {
                    Log.d(TAG, "Slow down");
                    CreateTokenResponse slowDownResp = new CreateTokenResponse();
                    slowDownResp.tokenType = ERROR_SLOW_DOWN;
                    return slowDownResp;
                }
            }
            throw e;
        }
    }

    /**
     * 使用指定区域轮询令牌（用于 IDC）。
     * 1:1 移植自 Go CreateTokenWithRegion (sso_oidc.go)。
     *
     * @param clientId     注册的客户端 ID
     * @param clientSecret 注册的客户端密钥
     * @param deviceCode   设备码
     * @param region       AWS 区域
     * @return 令牌创建响应，如果授权待定返回 null
     * @throws IOException 网络错误或非 2xx 响应
     */
    public CreateTokenResponse createTokenWithRegion(String clientId, String clientSecret,
                                                     String deviceCode, String region) throws IOException {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }
        String endpoint = getOIDCEndpoint(region);

        JSONObject payload = new JSONObject();
        try {
            payload.put("clientId", clientId);
            payload.put("clientSecret", clientSecret);
            payload.put("deviceCode", deviceCode);
            payload.put("grantType", "urn:ietf:params:oauth:grant-type:device_code");
        } catch (JSONException e) {
            throw new IOException("Failed to build create token payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        try {
            String response = httpPostJson(endpoint + "/token",
                    payload.toString(), headers);
            try {
                return CreateTokenResponse.fromJson(new JSONObject(response));
            } catch (JSONException e) {
                throw new IOException("Failed to parse token response", e);
            }
        } catch (IOException e) {
            String msg = e.getMessage();
            if (msg != null) {
                if (msg.contains(ERROR_AUTHORIZATION_PENDING)) {
                    Log.d(TAG, "Authorization pending for region " + region);
                    return null;
                }
                if (msg.contains(ERROR_SLOW_DOWN)) {
                    Log.d(TAG, "Slow down for region " + region);
                    CreateTokenResponse slowDownResp = new CreateTokenResponse();
                    slowDownResp.tokenType = ERROR_SLOW_DOWN;
                    return slowDownResp;
                }
            }
            throw e;
        }
    }

    /**
     * 执行完整的 Builder ID 设备码流程。
     * 1:1 移植自 Go LoginWithBuilderID (sso_oidc.go)。
     * <p>
     * 步骤：
     * <ol>
     *   <li>注册客户端 (POST /client/register)</li>
     *   <li>启动设备授权 (POST /device_authorization)</li>
     *   <li>显示验证 URL 和用户码</li>
     *   <li>轮询令牌 (POST /token)，间隔 5 秒</li>
     * </ol>
     *
     * @param callback 用于通知用户验证 URL 和码的回调
     * @return 令牌数据
     * @throws IOException 网络错误或超时
     * @throws InterruptedException 线程中断
     */
    public KiroTokenData loginWithBuilderID(DeviceCodeCallback callback) throws IOException, InterruptedException {
        Log.d(TAG, "Starting Builder ID authentication");

        // Step 1: 注册客户端
        Log.d(TAG, "Registering client...");
        RegisterClientResponse regResp = registerClient();
        Log.d(TAG, "Client registered: " + regResp.clientId);

        // Step 2: 启动设备授权
        Log.d(TAG, "Starting device authorization...");
        StartDeviceAuthResponse authResp = startDeviceAuthorization(regResp.clientId, regResp.clientSecret);

        // Step 3: 通知用户验证 URL
        if (callback != null) {
            callback.onVerificationRequired(authResp.verificationUriComplete,
                    authResp.verificationUri, authResp.userCode);
        }

        // Step 4: 轮询令牌
        Log.d(TAG, "Waiting for authorization...");
        long interval = POLL_INTERVAL_MS;
        if (authResp.interval > 0) {
            interval = authResp.interval * 1000L;
        }

        long deadline = System.currentTimeMillis() + (authResp.expiresIn * 1000L);

        while (System.currentTimeMillis() < deadline) {
            CreateTokenResponse tokenResp = createToken(regResp.clientId, regResp.clientSecret, authResp.deviceCode);

            if (tokenResp == null) {
                // authorization_pending
                if (callback != null) callback.onPollingProgress();
                Thread.sleep(interval);
                continue;
            }

            if (ERROR_SLOW_DOWN.equals(tokenResp.tokenType)) {
                interval += 5000;
                continue;
            }

            Log.d(TAG, "Authorization successful!");

            // 构建令牌数据
            String expiresAt = Instant.now()
                    .plusSeconds(tokenResp.expiresIn > 0 ? tokenResp.expiresIn : 3600)
                    .atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);

            // 尝试从 JWT 提取邮箱
            String email = extractEmailFromJWT(tokenResp.accessToken);

            KiroTokenData data = new KiroTokenData();
            data.accessToken = tokenResp.accessToken;
            data.refreshToken = tokenResp.refreshToken;
            data.profileArn = "";
            data.expiresAt = expiresAt;
            data.authMethod = "builder-id";
            data.provider = "AWS";
            data.clientId = regResp.clientId;
            data.clientSecret = regResp.clientSecret;
            data.email = email;
            data.region = DEFAULT_IDC_REGION;

            return data;
        }

        throw new IOException("Authorization timed out");
    }

    /**
     * 执行完整的 IDC 设备码流程。
     * 1:1 移植自 Go LoginWithIDC (sso_oidc.go)。
     *
     * @param startUrl IDC Start URL
     * @param region   AWS 区域
     * @param callback 用于通知用户验证 URL 和码的回调
     * @return 令牌数据
     * @throws IOException 网络错误或超时
     * @throws InterruptedException 线程中断
     */
    public KiroTokenData loginWithIDC(String startUrl, String region, DeviceCodeCallback callback) throws IOException, InterruptedException {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }
        Log.d(TAG, "Starting IDC authentication with region " + region + " and startUrl " + startUrl);

        // Step 1: 注册客户端（指定区域）
        Log.d(TAG, "Registering client...");
        RegisterClientResponse regResp = registerClientWithRegion(region);
        Log.d(TAG, "Client registered: " + regResp.clientId);

        // Step 2: 启动设备授权
        Log.d(TAG, "Starting device authorization...");
        StartDeviceAuthResponse authResp = startDeviceAuthorizationWithIDC(
                regResp.clientId, regResp.clientSecret, startUrl, region);

        // Step 3: 通知用户
        if (callback != null) {
            callback.onVerificationRequired(authResp.verificationUriComplete,
                    authResp.verificationUri, authResp.userCode);
        }

        // Step 4: 轮询令牌
        Log.d(TAG, "Waiting for authorization...");
        long interval = POLL_INTERVAL_MS;
        if (authResp.interval > 0) {
            interval = authResp.interval * 1000L;
        }

        long deadline = System.currentTimeMillis() + (authResp.expiresIn * 1000L);

        while (System.currentTimeMillis() < deadline) {
            CreateTokenResponse tokenResp = createTokenWithRegion(
                    regResp.clientId, regResp.clientSecret, authResp.deviceCode, region);

            if (tokenResp == null) {
                if (callback != null) callback.onPollingProgress();
                Thread.sleep(interval);
                continue;
            }

            if (ERROR_SLOW_DOWN.equals(tokenResp.tokenType)) {
                interval += 5000;
                continue;
            }

            Log.d(TAG, "Authorization successful!");

            // 尝试获取邮箱
            String email = extractEmailFromJWT(tokenResp.accessToken);

            String expiresAt = Instant.now()
                    .plusSeconds(tokenResp.expiresIn > 0 ? tokenResp.expiresIn : 3600)
                    .atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);

            KiroTokenData data = new KiroTokenData();
            data.accessToken = tokenResp.accessToken;
            data.refreshToken = tokenResp.refreshToken;
            data.profileArn = "";
            data.expiresAt = expiresAt;
            data.authMethod = "idc";
            data.provider = "AWS";
            data.clientId = regResp.clientId;
            data.clientSecret = regResp.clientSecret;
            data.email = email;
            data.startUrl = startUrl;
            data.region = region;

            return data;
        }

        throw new IOException("Authorization timed out");
    }

    // ========================================================================
    // 2. Social Auth — Google/GitHub PKCE 授权码流程
    // ========================================================================

    /**
     * 构建社交登录 URL。
     * 1:1 移植自 Go buildLoginURL (social_auth.go)。
     *
     * @param provider      提供者名称（"Google" 或 "GitHub"）
     * @param redirectURI   重定向 URI
     * @param codeChallenge PKCE code_challenge
     * @param state         CSRF state
     * @return 完整的登录 URL
     */
    public String buildLoginURL(String provider, String redirectURI, String codeChallenge, String state) {
        return KIRO_AUTH_ENDPOINT + "/login?idp=" + provider
                + "&redirect_uri=" + URLEncoder.encode(redirectURI, StandardCharsets.UTF_8)
                + "&code_challenge=" + codeChallenge
                + "&code_challenge_method=S256"
                + "&state=" + state
                + "&prompt=select_account";
    }

    /**
     * 交换授权码获取令牌。
     * 1:1 移植自 Go exchangeCodeForToken (oauth.go) 和 CreateToken (social_auth.go)。
     * <p>POST /oauth/token — JSON body: code, code_verifier, redirect_uri</p>
     *
     * @param code         授权码
     * @param codeVerifier PKCE code_verifier
     * @param redirectURI  重定向 URI
     * @return 令牌数据
     * @throws IOException 网络错误或非 2xx 响应
     */
    public KiroTokenData exchangeCodeForToken(String code, String codeVerifier, String redirectURI) throws IOException {
        JSONObject payload = new JSONObject();
        try {
            payload.put("code", code);
            payload.put("code_verifier", codeVerifier);
            payload.put("redirect_uri", redirectURI);
        } catch (JSONException e) {
            throw new IOException("Failed to build token exchange payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "KiroIDE-" + kiroVersion + "-" + machineID);
        headers.put("Accept", "application/json, text/plain, */*");

        String response = httpPostJson(KIRO_AUTH_ENDPOINT + "/oauth/token",
                payload.toString(), headers);

        try {
            JSONObject json = new JSONObject(response);
            KiroTokenResponse tokenResp = KiroTokenResponse.fromJson(json);

            int expiresIn = tokenResp.expiresIn;
            if (expiresIn <= 0) expiresIn = 3600;
            String expiresAt = Instant.now().plusSeconds(expiresIn)
                    .atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);

            KiroTokenData data = new KiroTokenData();
            data.accessToken = tokenResp.accessToken;
            data.refreshToken = tokenResp.refreshToken;
            data.profileArn = tokenResp.profileArn;
            data.expiresAt = expiresAt;
            data.authMethod = "social";
            data.provider = "";
            data.region = DEFAULT_IDC_REGION;
            return data;
        } catch (JSONException e) {
            throw new IOException("Failed to parse token exchange response", e);
        }
    }

    /**
     * 刷新社交登录令牌。
     * 1:1 移植自 Go RefreshToken (oauth.go) 和 RefreshSocialToken (social_auth.go)。
     * <p>POST /refreshToken — JSON body: refreshToken</p>
     *
     * @param refreshToken 刷新令牌
     * @return 新的令牌数据
     * @throws IOException 网络错误或非 2xx 响应
     */
    public KiroTokenData refreshToken(String refreshToken) throws IOException {
        JSONObject payload = new JSONObject();
        try {
            payload.put("refreshToken", refreshToken);
        } catch (JSONException e) {
            throw new IOException("Failed to build refresh payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "KiroIDE-" + kiroVersion + "-" + machineID);
        headers.put("Accept", "application/json, text/plain, */*");

        String response = httpPostJson(KIRO_AUTH_ENDPOINT + "/refreshToken",
                payload.toString(), headers);

        try {
            JSONObject json = new JSONObject(response);
            KiroTokenResponse tokenResp = KiroTokenResponse.fromJson(json);

            int expiresIn = tokenResp.expiresIn;
            if (expiresIn <= 0) expiresIn = 3600;
            String expiresAt = Instant.now().plusSeconds(expiresIn)
                    .atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);

            KiroTokenData data = new KiroTokenData();
            data.accessToken = tokenResp.accessToken;
            data.refreshToken = tokenResp.refreshToken;
            data.profileArn = tokenResp.profileArn;
            data.expiresAt = expiresAt;
            data.authMethod = "social";
            data.provider = "";
            data.region = DEFAULT_IDC_REGION;
            return data;
        } catch (JSONException e) {
            throw new IOException("Failed to parse refresh response", e);
        }
    }

    /**
     * 使用 SSO OIDC 刷新 Builder ID 令牌。
     * 1:1 移植自 Go RefreshToken (sso_oidc.go)。
     * <p>POST /token — JSON body: clientId, clientSecret, refreshToken, grantType</p>
     *
     * @param clientId     客户端 ID
     * @param clientSecret 客户端密钥
     * @param refreshToken 刷新令牌
     * @return 新的令牌数据
     * @throws IOException 网络错误或非 2xx 响应
     */
    public KiroTokenData refreshBuilderIDToken(String clientId, String clientSecret, String refreshToken) throws IOException {
        JSONObject payload = new JSONObject();
        try {
            payload.put("clientId", clientId);
            payload.put("clientSecret", clientSecret);
            payload.put("refreshToken", refreshToken);
            payload.put("grantType", "refresh_token");
        } catch (JSONException e) {
            throw new IOException("Failed to build refresh payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        String response = httpPostJson(SSO_OIDC_ENDPOINT + "/token",
                payload.toString(), headers);

        try {
            JSONObject json = new JSONObject(response);
            CreateTokenResponse tokenResp = CreateTokenResponse.fromJson(json);

            String expiresAt = Instant.now().plusSeconds(tokenResp.expiresIn > 0 ? tokenResp.expiresIn : 3600)
                    .atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);

            KiroTokenData data = new KiroTokenData();
            data.accessToken = tokenResp.accessToken;
            data.refreshToken = tokenResp.refreshToken;
            data.expiresAt = expiresAt;
            data.authMethod = "builder-id";
            data.provider = "AWS";
            data.clientId = clientId;
            data.clientSecret = clientSecret;
            data.region = DEFAULT_IDC_REGION;
            return data;
        } catch (JSONException e) {
            throw new IOException("Failed to parse refresh response", e);
        }
    }

    /**
     * 使用指定区域刷新 IDC 令牌。
     * 1:1 移植自 Go RefreshTokenWithRegion (sso_oidc.go)。
     *
     * @param clientId     客户端 ID
     * @param clientSecret 客户端密钥
     * @param refreshToken 刷新令牌
     * @param region       AWS 区域
     * @param startUrl     IDC Start URL
     * @return 新的令牌数据
     * @throws IOException 网络错误或非 2xx 响应
     */
    public KiroTokenData refreshIDCToken(String clientId, String clientSecret, String refreshToken,
                                         String region, String startUrl) throws IOException {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }
        String endpoint = getOIDCEndpoint(region);

        JSONObject payload = new JSONObject();
        try {
            payload.put("clientId", clientId);
            payload.put("clientSecret", clientSecret);
            payload.put("refreshToken", refreshToken);
            payload.put("grantType", "refresh_token");
        } catch (JSONException e) {
            throw new IOException("Failed to build refresh payload", e);
        }

        Map<String, String> headers = new HashMap<>();
        setOIDCHeaders(headers);

        String response = httpPostJson(endpoint + "/token",
                payload.toString(), headers);

        try {
            JSONObject json = new JSONObject(response);
            CreateTokenResponse tokenResp = CreateTokenResponse.fromJson(json);

            String expiresAt = Instant.now().plusSeconds(tokenResp.expiresIn > 0 ? tokenResp.expiresIn : 3600)
                    .atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ISO_INSTANT);

            KiroTokenData data = new KiroTokenData();
            data.accessToken = tokenResp.accessToken;
            data.refreshToken = tokenResp.refreshToken;
            data.expiresAt = expiresAt;
            data.authMethod = "idc";
            data.provider = "AWS";
            data.clientId = clientId;
            data.clientSecret = clientSecret;
            data.startUrl = startUrl;
            data.region = region;
            return data;
        } catch (JSONException e) {
            throw new IOException("Failed to parse refresh response", e);
        }
    }

    /**
     * 执行 Google 社交登录（PKCE 授权码流程）。
     * 1:1 移植自 Go LoginWithGoogle (oauth.go) 和 LoginWithSocial (social_auth.go)。
     *
     * @param timeoutMs 认证超时（毫秒）
     * @return 令牌数据
     * @throws IOException 网络错误或认证失败
     * @throws InterruptedException 线程中断
     */
    public KiroTokenData loginWithGoogle(long timeoutMs) throws IOException, InterruptedException {
        return loginWithSocial("Google", timeoutMs);
    }

    /**
     * 执行 GitHub 社交登录（PKCE 授权码流程）。
     * 1:1 移植自 Go LoginWithGitHub (oauth.go) 和 LoginWithSocial (social_auth.go)。
     *
     * @param timeoutMs 认证超时（毫秒）
     * @return 令牌数据
     * @throws IOException 网络错误或认证失败
     * @throws InterruptedException 线程中断
     */
    public KiroTokenData loginWithGitHub(long timeoutMs) throws IOException, InterruptedException {
        return loginWithSocial("GitHub", timeoutMs);
    }

    /**
     * 执行社交登录（PKCE 授权码流程）。
     * 1:1 移植自 Go LoginWithSocial (social_auth.go)。
     * <p>
     * 步骤：
     * <ol>
     *   <li>生成 PKCE code_verifier 和 code_challenge</li>
     *   <li>生成 state 参数</li>
     *   <li>启动本地 HTTP 回调服务器</li>
     *   <li>构建登录 URL 并打开浏览器</li>
     *   <li>等待回调获取授权码</li>
     *   <li>交换授权码获取令牌</li>
     * </ol>
     *
     * @param providerName 提供者名称（"Google" 或 "GitHub"）
     * @param timeoutMs    认证超时（毫秒）
     * @return 令牌数据
     * @throws IOException 网络错误或认证失败
     * @throws InterruptedException 线程中断
     */
    public KiroTokenData loginWithSocial(String providerName, long timeoutMs) throws IOException, InterruptedException {
        Log.d(TAG, "Starting " + providerName + " authentication");

        // Step 1: 生成 PKCE
        PKCECodes pkce = generatePKCE();
        Log.d(TAG, "PKCE codes generated");

        // Step 2: 生成 state
        String state = generateState();
        Log.d(TAG, "State generated");

        // Step 3: 启动回调服务器
        CallbackServerResult serverResult = startWebCallbackServer(state, timeoutMs);
        if (serverResult.callbackResult.error != null && !serverResult.callbackResult.error.isEmpty()) {
            if ("timeout".equals(serverResult.callbackResult.error)) {
                throw new IOException("Authentication timed out");
            }
            throw new IOException("Callback server error: " + serverResult.callbackResult.error);
        }
        String redirectURI = serverResult.redirectURI;
        Log.d(TAG, "Callback server started at " + redirectURI);

        // Step 4: 构建登录 URL
        String authURL = buildLoginURL(providerName, redirectURI, pkce.codeChallenge, state);
        Log.d(TAG, "Auth URL: " + authURL);

        // Step 5: 等待回调结果
        WebCallbackResult callback = serverResult.callbackResult;
        if (callback.error != null && !callback.error.isEmpty()) {
            throw new IOException("Authentication error: " + callback.error);
        }
        if (callback.code == null || callback.code.isEmpty()) {
            throw new IOException("No authorization code received");
        }

        Log.d(TAG, "Authorization code received");

        // Step 6: 交换授权码获取令牌
        KiroTokenData tokenData = exchangeCodeForToken(callback.code, pkce.codeVerifier, redirectURI);

        // 设置提供者
        tokenData.provider = providerName;

        // 尝试从 JWT 提取邮箱
        String email = extractEmailFromJWT(tokenData.accessToken);
        tokenData.email = email;

        Log.d(TAG, providerName + " authentication successful");
        return tokenData;
    }

    // ========================================================================
    // 3. Token Import — 1:1 移植自 Go oauth_web_import.go
    // ========================================================================

    /**
     * 解析导入的令牌载荷。
     * 1:1 移植自 Go parseImportTokenPayload (oauth_web_import.go)。
     * <p>
     * 支持两种格式：
     * <ol>
     *   <li>原始 Kiro IDE 令牌 JSON</li>
     *   <li>结构化 ImportTokenRequest（仅包含 refreshToken）</li>
     * </ol>
     *
     * @param jsonBody JSON 字符串
     * @return 解析后的令牌数据
     * @throws IOException 解析失败
     */
    public KiroTokenData parseImportTokenPayload(String jsonBody) throws IOException {
        if (jsonBody == null || jsonBody.trim().isEmpty()) {
            throw new IOException("Invalid request body");
        }

        // 尝试解析为原始 Kiro IDE 令牌 JSON
        try {
            JSONObject json = new JSONObject(jsonBody);
            KiroTokenData rawResult = parseRawKiroIDETokenJSON(json);
            if (rawResult != null) {
                return rawResult;
            }
        } catch (JSONException ignored) {
            // 不是有效 JSON，继续尝试其他格式
        }

        // 尝试解析为结构化请求
        try {
            JSONObject json = new JSONObject(jsonBody);
            ImportTokenRequest req = new ImportTokenRequest();
            req.refreshToken = json.optString("refreshToken", "");

            String refreshToken = req.refreshToken.trim();
            if (refreshToken.startsWith("{")) {
                try {
                    KiroTokenData rawResult = parseRawKiroIDETokenJSON(new JSONObject(refreshToken));
                    if (rawResult != null) {
                        return rawResult;
                    }
                } catch (JSONException ignored) {
                }
            }

            // 返回仅含 refreshToken 的令牌数据
            KiroTokenData data = new KiroTokenData();
            data.refreshToken = refreshToken;
            return data;
        } catch (JSONException e) {
            throw new IOException("Invalid request body");
        }
    }

    /**
     * 解析原始 Kiro IDE 令牌 JSON。
     * 1:1 移植自 Go parseRawKiroIDETokenJSON (oauth_web_import.go)。
     *
     * @param json JSON 对象
     * @return 解析后的令牌数据，如果不是 Kiro IDE 格式返回 null
     * @throws IOException 解析失败或缺少必填字段
     */
    public KiroTokenData parseRawKiroIDETokenJSON(JSONObject json) throws IOException {
        if (json == null) return null;

        String accessToken = importStringField(json, "accessToken", "access_token");
        String refreshToken = importStringField(json, "refreshToken", "refresh_token");

        boolean hasKiroIDEField = (accessToken != null && !accessToken.isEmpty())
                || (importStringField(json, "profileArn", "profile_arn") != null
                && !importStringField(json, "profileArn", "profile_arn").isEmpty())
                || (importStringField(json, "clientIdHash", "client_id_hash") != null
                && !importStringField(json, "clientIdHash", "client_id_hash").isEmpty())
                || (importStringField(json, "startUrl", "start_url") != null
                && !importStringField(json, "startUrl", "start_url").isEmpty())
                || (importStringField(json, "authMethod", "auth_method") != null
                && !importStringField(json, "authMethod", "auth_method").isEmpty());

        if (!hasKiroIDEField) {
            return null;
        }

        if (accessToken == null || accessToken.isEmpty()) {
            throw new IOException("accessToken is required when importing raw Kiro IDE token JSON");
        }
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IOException("refreshToken is required when importing raw Kiro IDE token JSON");
        }

        String authMethod = normalizeImportedKiroAuthMethod(json);
        String region = importStringField(json, "region");
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }

        String email = importStringField(json, "email");
        if (email == null || email.isEmpty()) {
            email = extractEmailFromJWT(accessToken);
        }

        String provider = importStringField(json, "provider");
        if (provider == null || provider.isEmpty()) {
            provider = "imported";
        }

        KiroTokenData data = new KiroTokenData();
        data.accessToken = accessToken;
        data.refreshToken = refreshToken;
        data.profileArn = importStringField(json, "profileArn", "profile_arn");
        data.expiresAt = importStringField(json, "expiresAt", "expires_at");
        data.authMethod = authMethod;
        data.provider = provider;
        data.clientId = importStringField(json, "clientId", "client_id");
        data.clientSecret = importStringField(json, "clientSecret", "client_secret");
        data.clientIdHash = importStringField(json, "clientIdHash", "client_id_hash");
        data.email = email;
        data.startUrl = importStringField(json, "startUrl", "start_url");
        data.region = region;

        return data;
    }

    /**
     * 规范化导入的 Kiro 认证方法。
     * 1:1 移植自 Go normalizeImportedKiroAuthMethod (oauth_web_import.go)。
     */
    private static String normalizeImportedKiroAuthMethod(JSONObject json) {
        String authMethod = importStringField(json, "authMethod", "auth_method");
        if (authMethod == null) authMethod = "";
        authMethod = authMethod.toLowerCase().trim().replace("_", "-");

        switch (authMethod) {
            case "idc":
            case "builder-id":
            case "social":
            case "google":
            case "github":
            case "imported":
                return authMethod;
            case "builderid":
            case "aws":
                return "builder-id";
        }

        String clientIdHash = importStringField(json, "clientIdHash", "client_id_hash");
        String startUrl = importStringField(json, "startUrl", "start_url");
        if ((clientIdHash != null && !clientIdHash.isEmpty())
                || (startUrl != null && !startUrl.isEmpty())) {
            return "idc";
        }

        return "imported";
    }

    /**
     * 从 JSONObject 中按优先顺序获取字符串字段。
     * 1:1 移植自 Go importStringField (oauth_web_import.go)。
     */
    private static String importStringField(JSONObject json, String... names) {
        for (String name : names) {
            if (json.has(name)) {
                try {
                    Object val = json.get(name);
                    if (val != null && !JSONObject.NULL.equals(val)) {
                        return val.toString();
                    }
                } catch (JSONException ignored) {
                }
            }
        }
        return "";
    }

    // ========================================================================
    // 4. JWT 工具 — 1:1 移植自 Go ExtractEmailFromJWT (aws.go)
    // ========================================================================

    /**
     * 从 JWT 访问令牌中提取邮箱。
     * 1:1 移植自 Go ExtractEmailFromJWT (aws.go)。
     * <p>JWT 格式: header.payload.signature，payload 是 base64url 编码的 JSON。</p>
     *
     * @param accessToken JWT 访问令牌
     * @return 邮箱，如果无法提取则返回空字符串
     */
    public static String extractEmailFromJWT(String accessToken) {
        if (accessToken == null || accessToken.isEmpty()) {
            return "";
        }

        // JWT 格式: header.payload.signature
        String[] parts = accessToken.split("\\.");
        if (parts.length != 3) {
            return "";
        }

        // 解码 payload（第二部分）
        String payload = parts[1];
        try {
            // 添加填充
            int padding = 4 - (payload.length() % 4);
            if (padding != 4) {
                StringBuilder sb = new StringBuilder(payload);
                for (int i = 0; i < padding; i++) {
                    sb.append('=');
                }
                payload = sb.toString();
            }

            byte[] decoded = Base64.getUrlDecoder().decode(payload);
            String jsonStr = new String(decoded, StandardCharsets.UTF_8);

            JSONObject json = new JSONObject(jsonStr);
            // 优先使用 email
            if (json.has("email")) {
                String email = json.optString("email", "");
                if (!email.isEmpty()) return email;
            }

            // 备选: preferred_username
            if (json.has("preferred_username")) {
                String username = json.optString("preferred_username", "");
                if (username.contains("@")) return username;
            }

            // 备选: sub（如果看起来像邮箱）
            if (json.has("sub")) {
                String sub = json.optString("sub", "");
                if (sub.contains("@")) return sub;
            }
        } catch (Exception e) {
            Log.d(TAG, "Failed to extract email from JWT: " + e.getMessage());

            // 尝试无填充解码
            try {
                byte[] decoded = Base64.getUrlDecoder().withoutPadding().decode(parts[1]);
                String jsonStr = new String(decoded, StandardCharsets.UTF_8);
                JSONObject json = new JSONObject(jsonStr);
                if (json.has("email")) {
                    return json.optString("email", "");
                }
            } catch (Exception ignored) {
            }
        }

        return "";
    }

    // ========================================================================
    // 5. AWS 工具方法
    // ========================================================================

    /**
     * 获取指定区域的 OIDC 端点。
     * 1:1 移植自 Go getOIDCEndpoint (sso_oidc.go)。
     */
    public static String getOIDCEndpoint(String region) {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }
        return "https://oidc." + region + ".amazonaws.com";
    }

    /**
     * 解析 AWS ARN 字符串。
     * 1:1 移植自 Go ParseProfileARN (aws.go)。
     * <p>ARN 格式: arn:partition:service:region:account-id:resource-type/resource-id</p>
     *
     * @param arn ARN 字符串
     * @return 解析后的 ProfileARN，无效则返回 null
     */
    public static ProfileARN parseProfileARN(String arn) {
        if (arn == null || arn.isEmpty()) return null;

        String[] parts = arn.split(":");
        if (parts.length < 6) {
            Log.w(TAG, "Invalid ARN format: " + arn);
            return null;
        }

        if (!"arn".equals(parts[0])) return null;
        String partition = parts[1];
        if (partition.isEmpty()) return null;
        String service = parts[2];
        // 如果不是 codewhisperer，我们仍然解析但不拒绝
        String region = parts[3];
        if (region.isEmpty() || !region.contains("-")) return null;
        String accountId = parts[4];

        // 解析资源: resource-type/resource-id
        StringBuilder resourceBuilder = new StringBuilder();
        for (int i = 5; i < parts.length; i++) {
            if (i > 5) resourceBuilder.append(":");
            resourceBuilder.append(parts[i]);
        }
        String resource = resourceBuilder.toString();
        String resourceType = resource;
        String resourceId = "";

        int slashIdx = resource.indexOf('/');
        if (slashIdx > 0) {
            resourceType = resource.substring(0, slashIdx);
            resourceId = resource.substring(slashIdx + 1);
        }

        ProfileARN pa = new ProfileARN();
        pa.raw = arn;
        pa.partition = partition;
        pa.service = service;
        pa.region = region;
        pa.accountId = accountId;
        pa.resourceType = resourceType;
        pa.resourceId = resourceId;
        return pa;
    }

    /**
     * 从 ProfileARN 提取区域。
     * 1:1 移植自 Go ExtractRegionFromProfileArn (aws.go)。
     *
     * @param profileArn 配置文件 ARN
     * @return 区域，无法提取则返回空字符串
     */
    public static String extractRegionFromProfileArn(String profileArn) {
        ProfileARN parsed = parseProfileARN(profileArn);
        if (parsed == null) return "";
        return parsed.region;
    }

    /**
     * 获取指定区域的 Q API 端点。
     * 1:1 移植自 Go GetKiroAPIEndpoint (aws.go)。
     */
    public static String getKiroAPIEndpoint(String region) {
        if (region == null || region.isEmpty()) {
            region = DEFAULT_IDC_REGION;
        }
        return "https://q." + region + ".amazonaws.com";
    }

    /**
     * 从 ProfileARN 提取区域并返回 API 端点。
     * 1:1 移植自 Go GetKiroAPIEndpointFromProfileArn (aws.go)。
     */
    public static String getKiroAPIEndpointFromProfileArn(String profileArn) {
        String region = extractRegionFromProfileArn(profileArn);
        return getKiroAPIEndpoint(region);
    }

    /**
     * 从 IDC startUrl 提取唯一标识符。
     * 1:1 移植自 Go ExtractIDCIdentifier (aws.go)。
     * <p>示例:</p>
     * <ul>
     *   <li>"https://d-1234567890.awsapps.com/start" -> "d-1234567890"</li>
     *   <li>"https://my-company.awsapps.com/start" -> "my-company"</li>
     * </ul>
     */
    public static String extractIDCIdentifier(String startUrl) {
        if (startUrl == null || startUrl.isEmpty()) return "";

        String url = startUrl;
        if (url.startsWith("https://")) {
            url = url.substring(8);
        } else if (url.startsWith("http://")) {
            url = url.substring(7);
        }

        String[] parts = url.split("\\.");
        if (parts.length > 0 && !parts[0].isEmpty()) {
            String identifier = parts[0];
            identifier = identifier.replace("/", "_");
            identifier = identifier.replace("\\", "_");
            identifier = identifier.replace(":", "_");
            return identifier;
        }

        return "";
    }

    /**
     * 生成令牌文件名。
     * 1:1 移植自 Go GenerateTokenFileName (aws.go)。
     * <p>格式: kiro-{authMethod}-{identifier}[-{seq}].json</p>
     * <p>优先级: email > startUrl identifier (IDC) > authMethod only</p>
     */
    public static String generateTokenFileName(KiroTokenData tokenData) {
        if (tokenData == null) return "kiro-unknown.json";

        String authMethod = sanitizeTokenFileComponent(tokenData.authMethod, "unknown");

        // 优先级 1: 使用邮箱
        if (tokenData.email != null && !tokenData.email.isEmpty()) {
            String sanitizedEmail = sanitizeTokenFileComponent(tokenData.email, "account");
            return "kiro-" + authMethod + "-" + sanitizedEmail + ".json";
        }

        // 生成序列号
        long seq = System.nanoTime() % 100000;

        // 优先级 2: IDC 使用 startUrl 标识符
        if ("idc".equals(authMethod) && tokenData.startUrl != null && !tokenData.startUrl.isEmpty()) {
            String identifier = sanitizeTokenFileComponent(extractIDCIdentifier(tokenData.startUrl), "");
            if (!identifier.isEmpty()) {
                return String.format("kiro-%s-%s-%05d.json", authMethod, identifier, seq);
            }
        }

        // 优先级 3: 仅使用 authMethod
        return String.format("kiro-%s-%05d.json", authMethod, seq);
    }

    /**
     * 清理令牌文件路径组件。
     * 1:1 移植自 Go sanitizeTokenFileComponent (aws.go)。
     */
    private static String sanitizeTokenFileComponent(String value, String fallback) {
        if (value == null) value = "";
        value = value.trim();
        if (value.isEmpty()) {
            return fallback;
        }

        StringBuilder sb = new StringBuilder();
        boolean lastDash = false;
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '+') {
                sb.append(c);
                lastDash = false;
            } else {
                if (!lastDash) {
                    sb.append('-');
                    lastDash = true;
                }
            }
        }

        String safe = sb.toString().replaceAll("^[-_]+|[-_]+$", "");
        if (safe.isEmpty()) {
            return fallback;
        }
        return safe;
    }

    /**
     * 生成机器 ID。
     * @return SHA-256 哈希的十六进制字符串
     */
    private static String generateMachineID() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8));
            StringBuilder hex = new StringBuilder();
            for (byte b : hash) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (NoSuchAlgorithmException e) {
            Log.e(TAG, "SHA-256 not available", e);
            return UUID.randomUUID().toString().replace("-", "");
        }
    }

    // ========================================================================
    // 设备码回调接口
    // ========================================================================

    /**
     * 设备码流程回调接口。
     * 用于通知用户需要验证的 URL 和码。
     */
    public interface DeviceCodeCallback {
        /**
         * 用户需要打开浏览器验证。
         * @param verificationUriComplete 完整的验证 URL
         * @param verificationUri 验证 URI
         * @param userCode 用户码
         */
        void onVerificationRequired(String verificationUriComplete, String verificationUri, String userCode);

        /**
         * 轮询进度通知。
         */
        void onPollingProgress();
    }

    // ========================================================================
    // 令牌存储工具方法
    // ========================================================================

    /**
     * 将 KiroTokenData 转换为 KiroTokenStorage（存储格式）。
     *
     * @param data 令牌数据
     * @return 令牌存储实例
     */
    public static KiroTokenStorage toStorage(KiroTokenData data) {
        if (data == null) return null;
        KiroTokenStorage storage = new KiroTokenStorage();
        storage.accessToken = data.accessToken;
        storage.refreshToken = data.refreshToken;
        storage.profileArn = data.profileArn;
        storage.expiresAt = data.expiresAt;
        storage.authMethod = data.authMethod;
        storage.provider = data.provider;
        storage.clientId = data.clientId;
        storage.clientSecret = data.clientSecret;
        storage.clientIdHash = data.clientIdHash;
        storage.region = data.region;
        storage.startUrl = data.startUrl;
        storage.email = data.email;
        storage.lastRefresh = Instant.now().atZone(ZoneOffset.UTC).format(DateTimeFormatter.ISO_INSTANT);
        return storage;
    }

    /**
     * 将 KiroTokenStorage 转换为 KiroTokenData（API 格式）。
     *
     * @param storage 令牌存储
     * @return 令牌数据
     */
    public static KiroTokenData fromStorage(KiroTokenStorage storage) {
        if (storage == null) return null;
        return storage.toTokenData();
    }
}