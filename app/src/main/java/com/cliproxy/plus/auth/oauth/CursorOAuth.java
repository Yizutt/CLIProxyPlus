package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Cursor OAuth PKCE 认证与令牌刷新实现。
 * <p>
 * 实现 Cursor 的 PKCE (Proof Key for Code Exchange) 认证流程，
 * 包括登录参数生成、认证状态轮询、令牌刷新和 JWT 解析。
 * <p>
 * 1:1 移植自 CLIProxyAPIPlus/internal/auth/cursor/oauth.go 和 filename.go。
 */
public class CursorOAuth {

    private static final String TAG = "CursorOAuth";

    // =========================================================================
    // 配置常量（1:1 移植自 Go 常量）
    // =========================================================================

    /** Cursor 登录 URL。 */
    public static final String CURSOR_LOGIN_URL = "https://cursor.com/loginDeepControl";

    /** Cursor 认证轮询 URL。 */
    public static final String CURSOR_POLL_URL = "https://api2.cursor.sh/auth/poll";

    /** Cursor 令牌刷新 URL。 */
    public static final String CURSOR_REFRESH_URL = "https://api2.cursor.sh/auth/exchange_user_api_key";

    /** 最大轮询尝试次数。 */
    private static final int POLL_MAX_ATTEMPTS = 150;

    /** 轮询基础延迟（秒）。 */
    private static final long POLL_BASE_DELAY_MS = 1000L;

    /** 轮询最大延迟（秒）。 */
    private static final long POLL_MAX_DELAY_MS = 10000L;

    /** 轮询退避乘数。 */
    private static final double POLL_BACKOFF_MULTIPLY = 1.2;

    /** 最大连续错误次数。 */
    private static final int MAX_CONSECUTIVE_ERRORS = 10;

    /** HTTP 请求超时（秒）。 */
    private static final int HTTP_TIMEOUT_MS = 10000;

    // =========================================================================
    // 数据类（1:1 移植自 Go 结构体）
    // =========================================================================

    /**
     * AuthParams 包含 Cursor 登录所需的 PKCE 参数。
     * 1:1 移植自 Go AuthParams 结构体。
     */
    public static class AuthParams {
        /** PKCE 验证码。 */
        public final String verifier;
        /** PKCE 挑战码。 */
        public final String challenge;
        /** 唯一标识 UUID。 */
        public final String uuid;
        /** 完整登录 URL。 */
        public final String loginURL;

        public AuthParams(String verifier, String challenge, String uuid, String loginURL) {
            this.verifier = verifier;
            this.challenge = challenge;
            this.uuid = uuid;
            this.loginURL = loginURL;
        }
    }

    /**
     * TokenPair 包含 Cursor 的访问令牌和刷新令牌。
     * 1:1 移植自 Go TokenPair 结构体。
     */
    public static class TokenPair {
        /** 访问令牌。 */
        public String accessToken;
        /** 刷新令牌。 */
        public String refreshToken;

        public TokenPair() {
        }

        public TokenPair(String accessToken, String refreshToken) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
        }
    }

    // =========================================================================
    // PKCE 生成（1:1 移植自 Go GeneratePKCE）
    // =========================================================================

    /**
     * 生成 PKCE 验证码和挑战码对。
     * <p>
     * 验证码：96 字节随机数，RawURL 编码的 Base64 字符串。<br>
     * 挑战码：验证码的 SHA-256 哈希，RawURL 编码的 Base64 字符串。
     * <p>
     * 1:1 移植自 Go GeneratePKCE()。
     *
     * @return PKCECodes 包含验证码和挑战码
     * @throws OAuthException 如果生成失败
     */
    public static PKCECodes generatePKCE() throws OAuthException {
        try {
            // 96 字节随机验证码
            SecureRandom secureRandom = new SecureRandom();
            byte[] verifierBytes = new byte[96];
            secureRandom.nextBytes(verifierBytes);
            String verifier = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(verifierBytes);

            // SHA-256 哈希生成挑战码
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            String challenge = Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(hash);

            Log.d(TAG, "PKCE generated successfully");
            return new PKCECodes(verifier, challenge);
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate PKCE", e);
            throw new OAuthException("cursor: failed to generate PKCE verifier: " + e.getMessage(), e);
        }
    }

    /**
     * PKCECodes 包含 PKCE 验证码和挑战码。
     */
    public static class PKCECodes {
        public final String verifier;
        public final String challenge;

        public PKCECodes(String verifier, String challenge) {
            this.verifier = verifier;
            this.challenge = challenge;
        }
    }

    // =========================================================================
    // 认证参数生成（1:1 移植自 Go GenerateAuthParams）
    // =========================================================================

    /**
     * 生成完整的 Cursor 登录认证参数。
     * <p>
     * 包括 PKCE 验证码/挑战码、UUID（16字节格式化为 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx），
     * 以及完整的登录 URL（含 challenge、uuid、mode=login、redirectTarget=cli 参数）。
     * <p>
     * 1:1 移植自 Go GenerateAuthParams()。
     *
     * @return AuthParams 包含所有认证参数
     * @throws OAuthException 如果生成失败
     */
    public static AuthParams generateAuthParams() throws OAuthException {
        PKCECodes codes = generatePKCE();

        try {
            // 16 字节随机 UUID
            SecureRandom secureRandom = new SecureRandom();
            byte[] uuidBytes = new byte[16];
            secureRandom.nextBytes(uuidBytes);

            // 格式化为 xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
            String uuid = String.format("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                    uuidBytes[0] & 0xFF, uuidBytes[1] & 0xFF, uuidBytes[2] & 0xFF, uuidBytes[3] & 0xFF,
                    uuidBytes[4] & 0xFF, uuidBytes[5] & 0xFF, uuidBytes[6] & 0xFF, uuidBytes[7] & 0xFF,
                    uuidBytes[8] & 0xFF, uuidBytes[9] & 0xFF, uuidBytes[10] & 0xFF, uuidBytes[11] & 0xFF,
                    uuidBytes[12] & 0xFF, uuidBytes[13] & 0xFF, uuidBytes[14] & 0xFF, uuidBytes[15] & 0xFF);

            String loginURL = CURSOR_LOGIN_URL
                    + "?challenge=" + codes.challenge
                    + "&uuid=" + uuid
                    + "&mode=login"
                    + "&redirectTarget=cli";

            Log.d(TAG, "Auth params generated, UUID: " + uuid);
            return new AuthParams(codes.verifier, codes.challenge, uuid, loginURL);
        } catch (Exception e) {
            Log.e(TAG, "Failed to generate auth params", e);
            throw new OAuthException("cursor: failed to generate UUID: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // 认证轮询（1:1 移植自 Go PollForAuth）
    // =========================================================================

    /**
     * 轮询 Cursor 认证端点，等待用户完成登录。
     * <p>
     * 使用指数退避策略进行轮询：<br>
     * - 最大尝试次数：150 次<br>
     * - 基础延迟：1 秒<br>
     * - 退避乘数：1.2 倍<br>
     * - 最大延迟：10 秒<br>
     * - 最大连续错误：10 次<br>
     * <p>
     * HTTP 404 表示用户尚未授权（继续轮询），<br>
     * HTTP 200 表示成功（返回 accessToken 和 refreshToken）。
     * <p>
     * 1:1 移植自 Go PollForAuth()。
     *
     * @param uuid    认证 UUID
     * @param verifier PKCE 验证码
     * @return TokenPair 包含访问令牌和刷新令牌
     * @throws OAuthException 如果轮询超时或失败
     * @throws InterruptedException 如果线程被中断
     */
    public static TokenPair pollForAuth(String uuid, String verifier)
            throws OAuthException, InterruptedException {
        long delayMs = POLL_BASE_DELAY_MS;
        int consecutiveErrors = 0;

        for (int attempt = 0; attempt < POLL_MAX_ATTEMPTS; attempt++) {
            Log.d(TAG, "Poll attempt " + (attempt + 1) + "/" + POLL_MAX_ATTEMPTS
                    + ", delay=" + delayMs + "ms");

            // 等待延迟时间
            Thread.sleep(delayMs);

            try {
                String urlStr = CURSOR_POLL_URL + "?uuid=" + uuid + "&verifier=" + verifier;
                Log.d(TAG, "Polling URL: " + urlStr);

                URL url = new URL(urlStr);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                try {
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("Accept", "application/json");
                    conn.setConnectTimeout(HTTP_TIMEOUT_MS);
                    conn.setReadTimeout(HTTP_TIMEOUT_MS);

                    int responseCode = conn.getResponseCode();

                    if (responseCode == HttpURLConnection.HTTP_NOT_FOUND) {
                        // 404: 用户尚未授权，继续等待
                        Log.d(TAG, "Poll returned 404, user not yet authorized");
                        consecutiveErrors = 0;
                        delayMs = minDuration(
                                (long) (delayMs * POLL_BACKOFF_MULTIPLY),
                                POLL_MAX_DELAY_MS);
                        continue;
                    }

                    // 读取响应体
                    String responseBody = readResponseBody(conn, responseCode);

                    if (responseCode >= 200 && responseCode < 300) {
                        // 成功：解析令牌
                        Log.d(TAG, "Poll succeeded with status " + responseCode);
                        JSONObject json = new JSONObject(responseBody);
                        TokenPair tokens = new TokenPair();
                        tokens.accessToken = json.optString("accessToken", null);
                        tokens.refreshToken = json.optString("refreshToken", null);
                        return tokens;
                    }

                    // 其他状态码视为错误
                    throw new OAuthException("cursor: poll failed with status "
                            + responseCode + ": " + responseBody);
                } finally {
                    conn.disconnect();
                }
            } catch (OAuthException e) {
                throw e;
            } catch (Exception e) {
                // 网络错误
                consecutiveErrors++;
                Log.e(TAG, "Poll attempt " + (attempt + 1) + " failed: " + e.getMessage());

                if (consecutiveErrors >= MAX_CONSECUTIVE_ERRORS) {
                    throw new OAuthException("cursor: too many consecutive poll errors (last: "
                            + e.getMessage() + ")", e);
                }

                delayMs = minDuration(
                        (long) (delayMs * POLL_BACKOFF_MULTIPLY),
                        POLL_MAX_DELAY_MS);
            }
        }

        // 超时
        long estimatedWaitSeconds = (POLL_MAX_ATTEMPTS * POLL_MAX_DELAY_MS) / 2000;
        throw new OAuthException("cursor: authentication polling timeout (waited ~"
                + estimatedWaitSeconds + " seconds)");
    }

    // =========================================================================
    // 令牌刷新（1:1 移植自 Go RefreshToken）
    // =========================================================================

    /**
     * 使用刷新令牌刷新 Cursor 访问令牌。
     * <p>
     * 向刷新端点发送 POST 请求，Authorization 头为 "Bearer {refreshToken}"，
     * 请求体为空 JSON 对象 "{}"。
     * <p>
     * 如果响应中没有返回新的刷新令牌，则保留原始刷新令牌。
     * <p>
     * 1:1 移植自 Go RefreshToken()。
     *
     * @param refreshToken 刷新令牌
     * @return TokenPair 包含新的访问令牌和刷新令牌
     * @throws OAuthException 如果刷新失败
     */
    public static TokenPair refreshToken(String refreshToken) throws OAuthException {
        Log.d(TAG, "Refreshing token");

        try {
            URL url = new URL(CURSOR_REFRESH_URL);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            try {
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Authorization", "Bearer " + refreshToken);
                conn.setRequestProperty("Content-Type", "application/json");
                conn.setRequestProperty("Accept", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(HTTP_TIMEOUT_MS);
                conn.setReadTimeout(HTTP_TIMEOUT_MS);

                // 请求体：空 JSON 对象
                byte[] requestBody = "{}".getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(requestBody);
                    os.flush();
                }

                int responseCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn, responseCode);

                if (responseCode < 200 || responseCode >= 300) {
                    throw new OAuthException("cursor: token refresh failed (status "
                            + responseCode + "): " + responseBody);
                }

                JSONObject json = new JSONObject(responseBody);
                TokenPair tokens = new TokenPair();
                tokens.accessToken = json.optString("accessToken", null);

                // 如果响应中没有返回新的刷新令牌，保留原始刷新令牌
                String newRefreshToken = json.optString("refreshToken", null);
                if (newRefreshToken != null && !newRefreshToken.isEmpty()) {
                    tokens.refreshToken = newRefreshToken;
                } else {
                    tokens.refreshToken = refreshToken;
                }

                Log.d(TAG, "Token refreshed successfully");
                return tokens;
            } finally {
                conn.disconnect();
            }
        } catch (OAuthException e) {
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "Token refresh failed", e);
            throw new OAuthException("cursor: token refresh request failed: " + e.getMessage(), e);
        }
    }

    // =========================================================================
    // JWT 解析（1:1 移植自 Go ParseJWTSub / decodeJWTPayload / GetTokenExpiry）
    // =========================================================================

    /**
     * 从 Cursor JWT 访问令牌中提取 "sub" 声明。
     * <p>
     * Cursor JWT 的 "sub" 格式为 "auth0|user_XXXX"，用于唯一标识账户。
     * <p>
     * 1:1 移植自 Go ParseJWTSub()。
     *
     * @param token JWT 访问令牌
     * @return sub 声明值，解析失败返回空字符串
     */
    public static String parseJWTSub(String token) {
        byte[] decoded = decodeJWTPayload(token);
        if (decoded == null) {
            return "";
        }
        try {
            JSONObject json = new JSONObject(new String(decoded, StandardCharsets.UTF_8));
            return json.optString("sub", "");
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse JWT sub", e);
            return "";
        }
    }

    /**
     * 将 JWT sub 声明转换为短十六进制哈希，用于文件名标识。
     * <p>
     * 例如："auth0|user_2x..." → "a3f8b2c1"（8 个十六进制字符，即 SHA-256 的前 4 字节）。
     * <p>
     * 1:1 移植自 Go SubToShortHash()。
     *
     * @param sub JWT sub 声明值
     * @return 8 字符十六进制哈希，sub 为空时返回空字符串
     */
    public static String subToShortHash(String sub) {
        if (sub == null || sub.isEmpty()) {
            return "";
        }
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(sub.getBytes(StandardCharsets.UTF_8));
            // 前 4 字节 → 8 字符十六进制
            return String.format("%02x%02x%02x%02x",
                    hash[0] & 0xFF, hash[1] & 0xFF, hash[2] & 0xFF, hash[3] & 0xFF);
        } catch (Exception e) {
            Log.e(TAG, "Failed to hash sub", e);
            return "";
        }
    }

    /**
     * 解码 JWT 的载荷（中间）部分。
     * <p>
     * 处理 Base64 URL 安全编码到标准编码的转换，并填充补齐。
     * <p>
     * 1:1 移植自 Go decodeJWTPayload()。
     *
     * @param token JWT 令牌
     * @return 解码后的载荷字节数组，解析失败返回 null
     */
    private static byte[] decodeJWTPayload(String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            Log.e(TAG, "Invalid JWT: expected 3 parts, got " + parts.length);
            return null;
        }

        String payload = parts[1];
        // 处理 Base64 URL 安全字符
        payload = payload.replace("-", "+").replace("_", "/");
        // 填充补齐
        switch (payload.length() % 4) {
            case 2:
                payload += "==";
                break;
            case 3:
                payload += "=";
                break;
        }

        try {
            return Base64.getDecoder().decode(payload);
        } catch (Exception e) {
            Log.e(TAG, "Failed to decode JWT payload", e);
            return null;
        }
    }

    /**
     * 从访问令牌中提取 JWT 过期时间，并减去 5 分钟的安全余量。
     * <p>
     * 如果令牌无法解析，则返回当前时间 + 1 小时作为兜底。
     * <p>
     * 1:1 移植自 Go GetTokenExpiry()。
     *
     * @param token JWT 访问令牌
     * @return 过期时间戳（毫秒）
     */
    public static long getTokenExpiry(String token) {
        byte[] decoded = decodeJWTPayload(token);
        if (decoded == null) {
            return System.currentTimeMillis() + 3600_000L; // 1 小时
        }

        try {
            JSONObject json = new JSONObject(new String(decoded, StandardCharsets.UTF_8));
            if (!json.has("exp")) {
                return System.currentTimeMillis() + 3600_000L;
            }
            double exp = json.getDouble("exp");
            long expMillis = (long) (exp * 1000);
            // 减去 5 分钟安全余量
            return expMillis - 300_000L;
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse JWT expiry", e);
            return System.currentTimeMillis() + 3600_000L;
        }
    }

    // =========================================================================
    // 文件名与标签（1:1 移植自 Go filename.go）
    // =========================================================================

    /**
     * 返回用于持久化 Cursor 凭证的文件名。
     * <p>
     * 优先级：显式标签 > 自动生成的 JWT sub 哈希 > 默认 "cursor.json"。
     * <p>
     * 1:1 移植自 Go CredentialFileName()。
     *
     * @param label   用户自定义标签（可为空）
     * @param subHash JWT sub 哈希（可为空）
     * @return 凭证文件名
     */
    public static String credentialFileName(String label, String subHash) {
        String trimmedLabel = (label != null) ? label.trim() : "";
        String trimmedHash = (subHash != null) ? subHash.trim() : "";

        if (!trimmedLabel.isEmpty()) {
            return "cursor." + trimmedLabel + ".json";
        }
        if (!trimmedHash.isEmpty()) {
            return "cursor." + trimmedHash + ".json";
        }
        return "cursor.json";
    }

    /**
     * 返回 Cursor 账户的人类可读标签。
     * <p>
     * 优先级：显式标签 > JWT sub 哈希 > "Cursor User"。
     * <p>
     * 1:1 移植自 Go DisplayLabel()。
     *
     * @param label   用户自定义标签（可为空）
     * @param subHash JWT sub 哈希（可为空）
     * @return 显示标签
     */
    public static String displayLabel(String label, String subHash) {
        String trimmedLabel = (label != null) ? label.trim() : "";
        String trimmedHash = (subHash != null) ? subHash.trim() : "";

        if (!trimmedLabel.isEmpty()) {
            return "Cursor " + trimmedLabel;
        }
        if (!trimmedHash.isEmpty()) {
            return "Cursor " + trimmedHash;
        }
        return "Cursor User";
    }

    // =========================================================================
    // 内部工具方法
    // =========================================================================

    /**
     * 读取 HTTP 响应体。
     *
     * @param conn         HTTP 连接
     * @param responseCode HTTP 响应码
     * @return 响应体字符串
     * @throws java.io.IOException 如果读取失败
     */
    private static String readResponseBody(HttpURLConnection conn, int responseCode)
            throws java.io.IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        try (InputStream is = (responseCode >= 200 && responseCode < 300)
                ? conn.getInputStream() : conn.getErrorStream()) {
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
        }
        return baos.toString("UTF-8");
    }

    /**
     * 返回两个毫秒值中的较小值。
     *
     * @param a 第一个值
     * @param b 第二个值
     * @return 较小的值
     */
    private static long minDuration(long a, long b) {
        return (a < b) ? a : b;
    }

    // =========================================================================
    // 异常类
    // =========================================================================

    /**
     * Cursor OAuth 操作异常。
     */
    public static class OAuthException extends Exception {
        public OAuthException(String message) {
            super(message);
        }

        public OAuthException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}