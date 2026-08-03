package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;
import org.json.JSONException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * OAuth2 authentication implementation for Anthropic's Claude API.
 * <p>
 * Handles the complete OAuth2 flow with PKCE (Proof Key for Code Exchange)
 * for secure authentication with Claude API, including token exchange,
 * refresh, and storage. Uses JSON body for token requests (not form-encoded).
 */
public class ClaudeOAuth extends OAuthProvider {

    private static final String TAG = "ClaudeOAuth";

    // ====== OAuth Configuration Constants ======

    /** Claude OAuth authorization endpoint. */
    public static final String AUTH_URL = "https://claude.ai/oauth/authorize";

    /** Claude OAuth token endpoint. */
    public static final String TOKEN_URL = "https://api.anthropic.com/v1/oauth/token";

    /** Claude OAuth client ID. */
    public static final String CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e";

    /** Claude OAuth redirect URI. */
    public static final String REDIRECT_URI = "http://localhost:54545/callback";

    /** Minimum backoff duration for token refresh retries. */
    private static final long CLAUDE_REFRESH_MIN_BACKOFF_MS = 5000L; // 5 seconds

    /** Maximum backoff duration for token refresh retries. */
    private static final long CLAUDE_REFRESH_MAX_BACKOFF_MS = 300000L; // 5 minutes

    // ====== Token Response Structure ======

    /**
     * Represents the response structure from Anthropic's OAuth token endpoint.
     * Contains access token, refresh token, and associated user/organization information.
     */
    private static class TokenResponse {
        String accessToken;
        String refreshToken;
        String tokenType;
        int expiresIn;
        String organizationUuid;
        String organizationName;
        String accountUuid;
        String accountEmailAddress;

        static TokenResponse fromJson(JSONObject json) throws JSONException {
            TokenResponse resp = new TokenResponse();
            resp.accessToken = json.optString("access_token", "");
            resp.refreshToken = json.optString("refresh_token", "");
            resp.tokenType = json.optString("token_type", "");
            resp.expiresIn = json.optInt("expires_in", 0);

            JSONObject org = json.optJSONObject("organization");
            if (org != null) {
                resp.organizationUuid = org.optString("uuid", "");
                resp.organizationName = org.optString("name", "");
            }

            JSONObject account = json.optJSONObject("account");
            if (account != null) {
                resp.accountUuid = account.optString("uuid", "");
                resp.accountEmailAddress = account.optString("email_address", "");
            }

            return resp;
        }
    }

    // ====== Data Classes ======

    /**
     * Holds OAuth token information from Anthropic.
     */
    public static class ClaudeTokenData {
        /** OAuth2 access token for API access. */
        public String accessToken;
        /** Used to obtain new access tokens. */
        public String refreshToken;
        /** Anthropic account email. */
        public String email;
        /** Timestamp of token expiration. */
        public String expire;

        public ClaudeTokenData() {}

        public ClaudeTokenData(String accessToken, String refreshToken, String email, String expire) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.email = email;
            this.expire = expire;
        }
    }

    /**
     * Aggregates authentication data after OAuth flow completion.
     */
    public static class ClaudeAuthBundle {
        /** Anthropic API key obtained from token exchange. */
        public String apiKey;
        /** OAuth tokens from the authentication flow. */
        public ClaudeTokenData tokenData;
        /** Timestamp of the last token refresh. */
        public String lastRefresh;

        public ClaudeAuthBundle() {}

        public ClaudeAuthBundle(ClaudeTokenData tokenData, String lastRefresh) {
            this.tokenData = tokenData;
            this.lastRefresh = lastRefresh;
        }
    }

    /**
     * Stores OAuth2 token information for Anthropic Claude API authentication.
     * Maintains compatibility with the existing auth system while adding
     * Claude-specific fields for managing access tokens, refresh tokens,
     * and user account information.
     */
    public static class ClaudeTokenStorage {
        /** JWT ID token containing user claims and identity information. */
        public String idToken;
        /** OAuth2 access token used for authenticating API requests. */
        public String accessToken;
        /** Used to obtain new access tokens when the current one expires. */
        public String refreshToken;
        /** Timestamp of the last token refresh operation. */
        public String lastRefresh;
        /** Anthropic account email address associated with this token. */
        public String email;
        /** Indicates the authentication provider type, always "claude" for this storage. */
        public String type;
        /** Timestamp when the current access token expires. */
        public String expire;
        /** Holds arbitrary key-value pairs injected via hooks. */
        public Map<String, Object> metadata;

        public ClaudeTokenStorage() {
            this.type = "claude";
        }

        /**
         * Allows external callers to inject metadata into the storage before saving.
         */
        public void setMetadata(Map<String, Object> meta) {
            this.metadata = meta;
        }
    }

    // ====== Refresh Error ======

    /**
     * Internal error type for token refresh HTTP failures.
     */
    private static class RefreshHttpError extends Exception {
        final int status;
        final boolean retryable;

        RefreshHttpError(int status, String message, boolean retryable) {
            super(message);
            this.status = status;
            this.retryable = retryable;
        }

        boolean isRetryable() {
            return retryable;
        }
    }

    // ====== Singleflight Dedup State ======

    /** Singleflight group for deduplicating concurrent refresh calls per refresh token. */
    private static final ConcurrentHashMap<String, AtomicReference<RefreshResult>> refreshGroup = new ConcurrentHashMap<>();

    /** Per-token rate-limit block map. */
    private static final ConcurrentHashMap<String, Long> refreshBlock = new ConcurrentHashMap<>();

    /**
     * Holder for singleflight result.
     */
    private static class RefreshResult {
        final ClaudeTokenData tokenData;
        final Exception error;

        RefreshResult(ClaudeTokenData tokenData, Exception error) {
            this.tokenData = tokenData;
            this.error = error;
        }
    }

    // ====== Constructors ======

    public ClaudeOAuth() {
        super("claude", AUTH_URL, TOKEN_URL, CLIENT_ID, REDIRECT_URI);
    }

    public ClaudeOAuth(String providerName, String authUrl, String tokenUrl,
                       String clientId, String redirectUri) {
        super(providerName, authUrl, tokenUrl, clientId, redirectUri);
    }

    // ====== Static Helpers ======

    private static String nowRfc3339() {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    }

    private static String instantToRfc3339(long epochMillis) {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(epochMillis));
    }

    private static long rfc3339ToEpochMillis(String rfc3339) {
        if (rfc3339 == null || rfc3339.isEmpty()) return 0;
        try {
            return Instant.from(DateTimeFormatter.ISO_INSTANT.parse(rfc3339)).toEpochMilli();
        } catch (Exception e) {
            return 0;
        }
    }

    // ====== Backoff Helpers ======

    private static long clampClaudeRefreshBackoff(long ms) {
        if (ms < CLAUDE_REFRESH_MIN_BACKOFF_MS) return CLAUDE_REFRESH_MIN_BACKOFF_MS;
        if (ms > CLAUDE_REFRESH_MAX_BACKOFF_MS) return CLAUDE_REFRESH_MAX_BACKOFF_MS;
        return ms;
    }

    /**
     * Parses Retry-After headers from HTTP response headers.
     * Supports both "Retry-After" (seconds or HTTP-date) and
     * "Retry-After-Ms" (milliseconds) headers.
     */
    public static long parseClaudeRetryAfter(Map<String, String> headers) {
        if (headers == null) {
            return CLAUDE_REFRESH_MIN_BACKOFF_MS;
        }

        // Try Retry-After header (seconds or HTTP-date)
        String retryAfter = headers.get("Retry-After");
        if (retryAfter != null) {
            retryAfter = retryAfter.trim();
            if (!retryAfter.isEmpty()) {
                try {
                    long seconds = Long.parseLong(retryAfter);
                    return clampClaudeRefreshBackoff(seconds * 1000L);
                } catch (NumberFormatException ignored) {
                    // Not a seconds value, could be an HTTP-date
                }
                // Try to parse as HTTP-date
                // Simple HTTP-date parsing: try rfc1123
                java.text.SimpleDateFormat sdf = new java.text.SimpleDateFormat(
                        "EEE, dd MMM yyyy HH:mm:ss z", java.util.Locale.US);
                sdf.setTimeZone(java.util.TimeZone.getTimeZone("GMT"));
                try {
                    java.util.Date date = sdf.parse(retryAfter);
                    long delayMs = date.getTime() - System.currentTimeMillis();
                    return clampClaudeRefreshBackoff(delayMs);
                } catch (java.text.ParseException ignored2) {
                    // Not a valid HTTP-date either
                }
            }
        }

        // Try Retry-After-Ms header (milliseconds)
        String retryAfterMs = headers.get("Retry-After-Ms");
        if (retryAfterMs != null) {
            retryAfterMs = retryAfterMs.trim();
            if (!retryAfterMs.isEmpty()) {
                try {
                    long ms = Long.parseLong(retryAfterMs);
                    return clampClaudeRefreshBackoff(ms);
                } catch (NumberFormatException ignored) {
                }
            }
        }

        return CLAUDE_REFRESH_MIN_BACKOFF_MS;
    }

    // ====== Block Management ======

    private static long claudeRefreshBlockedUntil(String refreshToken) {
        Long until = refreshBlock.get(refreshToken);
        if (until == null) return 0;
        return until;
    }

    private static void setClaudeRefreshBlockedUntil(String refreshToken, long untilMs) {
        refreshBlock.put(refreshToken, untilMs);
    }

    private static void clearClaudeRefreshBlockedUntil(String refreshToken) {
        refreshBlock.remove(refreshToken);
    }

    public static void resetClaudeRefreshState() {
        refreshBlock.clear();
        refreshGroup.clear();
    }

    private static boolean isClaudeRefreshRetryable(Exception error) {
        if (error instanceof RefreshHttpError) {
            return ((RefreshHttpError) error).isRetryable();
        }
        return true;
    }

    // ====== JSON Body POST Helper ======

    /**
     * Performs an HTTP POST with a JSON body and returns the response body string.
     * Used for token exchange and refresh requests to Anthropic's OAuth token endpoint.
     */
    protected String postJson(String urlStr, JSONObject jsonBody) throws IOException {
        byte[] postData = jsonBody.toString().getBytes(StandardCharsets.UTF_8);
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
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
                    ? conn.getInputStream() : conn.getErrorStream()) {
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
     * Parses the code and state from the raw callback code parameter.
     * Handles the case where the code may contain additional fragments
     * separated by '#'.
     */
    public String[] parseCodeAndState(String code) {
        String[] result = new String[2];
        String[] splits = code.split("#", 2);
        result[0] = splits[0];
        if (splits.length > 1) {
            result[1] = splits[1];
        }
        return result;
    }

    // ====== Auth URL Generation ======

    /**
     * Creates the OAuth authorization URL with PKCE.
     * Generates a secure authorization URL including PKCE challenge codes
     * for the OAuth2 flow with Anthropic's API.
     *
     * @param state    A random state parameter for CSRF protection
     * @param pkceCodes The PKCE codes for secure code exchange
     * @return The complete authorization URL
     * @throws IllegalArgumentException if pkceCodes is null
     */
    public String generateAuthURL(String state, PKCECodes pkceCodes) {
        if (pkceCodes == null) {
            throw new IllegalArgumentException("PKCE codes are required");
        }

        try {
            StringBuilder sb = new StringBuilder();
            sb.append(AUTH_URL).append("?");
            sb.append("code=").append(URLEncoder.encode("true", "UTF-8"));
            sb.append("&client_id=").append(URLEncoder.encode(CLIENT_ID, "UTF-8"));
            sb.append("&response_type=").append(URLEncoder.encode("code", "UTF-8"));
            sb.append("&redirect_uri=").append(URLEncoder.encode(REDIRECT_URI, "UTF-8"));
            sb.append("&scope=").append(URLEncoder.encode(
                    "user:profile user:inference user:sessions:claude_code user:mcp_servers user:file_upload",
                    "UTF-8"));
            sb.append("&code_challenge=").append(URLEncoder.encode(pkceCodes.codeChallenge, "UTF-8"));
            sb.append("&code_challenge_method=").append(URLEncoder.encode("S256", "UTF-8"));
            sb.append("&state=").append(URLEncoder.encode(state, "UTF-8"));

            return sb.toString();
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode auth URL parameters", e);
        }
    }

    // ====== Token Exchange ======

    /**
     * Exchanges authorization code for access tokens.
     * Implements the OAuth2 token exchange flow using PKCE for security.
     * Sends the authorization code along with PKCE verifier to get access and refresh tokens.
     * Uses JSON body (not form-encoded) per Anthropic's token endpoint requirements.
     *
     * @param code     The authorization code received from OAuth callback
     * @param state    The state parameter for verification
     * @param pkceCodes The PKCE codes for secure verification
     * @return The complete authentication bundle with tokens
     * @throws IOException if the token exchange request fails
     * @throws JSONException if the response cannot be parsed
     */
    public ClaudeAuthBundle exchangeCodeForTokens(String code, String state, PKCECodes pkceCodes)
            throws IOException, JSONException {
        if (pkceCodes == null) {
            throw new IllegalArgumentException("PKCE codes are required for token exchange");
        }

        String[] parsed = parseCodeAndState(code);
        String newCode = parsed[0];
        String newState = parsed[1];

        // Build JSON request body
        JSONObject reqBody = new JSONObject();
        reqBody.put("code", newCode);
        reqBody.put("state", state);
        reqBody.put("grant_type", "authorization_code");
        reqBody.put("client_id", CLIENT_ID);
        reqBody.put("redirect_uri", REDIRECT_URI);
        reqBody.put("code_verifier", pkceCodes.codeVerifier);

        // Include parsed state if present
        if (newState != null && !newState.isEmpty()) {
            reqBody.put("state", newState);
        }

        log("Token exchange request: " + reqBody.toString());

        String responseBody = postJson(TOKEN_URL, reqBody);
        log("Token response: " + responseBody);

        JSONObject json = new JSONObject(responseBody);
        TokenResponse tokenResp = TokenResponse.fromJson(json);

        // Create token data
        String expire = instantToRfc3339(System.currentTimeMillis()
                + (tokenResp.expiresIn * 1000L));
        ClaudeTokenData tokenData = new ClaudeTokenData(
                tokenResp.accessToken,
                tokenResp.refreshToken,
                tokenResp.accountEmailAddress,
                expire
        );

        // Create auth bundle
        ClaudeAuthBundle bundle = new ClaudeAuthBundle(tokenData, nowRfc3339());

        return bundle;
    }

    // ====== Token Refresh ======

    /**
     * Refreshes the access token using the refresh token.
     * Exchanges a valid refresh token for a new access token,
     * extending the user's authenticated session.
     * Uses singleflight deduplication to prevent multiple concurrent
     * refresh requests for the same token.
     *
     * @param refreshToken The refresh token to use for getting a new access token
     * @return The new token data with updated access token
     * @throws IOException if the token refresh fails
     * @throws JSONException if the response cannot be parsed
     */
    public ClaudeTokenData refreshTokens(String refreshToken) throws IOException, JSONException {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("refresh token is required");
        }

        long blockedUntil = claudeRefreshBlockedUntil(refreshToken);
        if (blockedUntil > System.currentTimeMillis()) {
            throw new RefreshHttpError(429,
                    "refresh temporarily blocked until "
                            + instantToRfc3339(blockedUntil),
                    false);
        }

        // Singleflight dedup: if a refresh is already in-flight for this token,
        // share its result rather than making a duplicate request
        AtomicReference<RefreshResult> ref = new AtomicReference<>(null);
        AtomicReference<RefreshResult> existing = refreshGroup.putIfAbsent(refreshToken, ref);
        if (existing != null) {
            // Another thread is already refreshing; wait for its result
            synchronized (existing) {
                while (existing.get() == null) {
                    try {
                        existing.wait();
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("token refresh interrupted", e);
                    }
                }
            }
            RefreshResult result = existing.get();
            if (result.error != null) {
                if (result.error instanceof IOException) throw (IOException) result.error;
                if (result.error instanceof JSONException) throw (JSONException) result.error;
                if (result.error instanceof RuntimeException) throw (RuntimeException) result.error;
                throw new IOException("token refresh failed", result.error);
            }
            return result.tokenData;
        }

        // We are the designated refresher for this token
        try {
            ClaudeTokenData tokenData = refreshTokensSingleFlight(refreshToken);
            RefreshResult result = new RefreshResult(tokenData, null);
            ref.set(result);
            synchronized (ref) {
                ref.notifyAll();
            }
            return tokenData;
        } catch (Exception e) {
            RefreshResult result = new RefreshResult(null, e);
            ref.set(result);
            synchronized (ref) {
                ref.notifyAll();
            }
            if (e instanceof IOException) throw (IOException) e;
            if (e instanceof JSONException) throw (JSONException) e;
            if (e instanceof RuntimeException) throw (RuntimeException) e;
            throw new IOException("token refresh failed", e);
        } finally {
            refreshGroup.remove(refreshToken, ref);
        }
    }

    /**
     * Performs the actual HTTP request to refresh tokens.
     * This is the inner method called by the singleflight wrapper.
     */
    private ClaudeTokenData refreshTokensSingleFlight(String refreshToken)
            throws IOException, JSONException {
        long blockedUntil = claudeRefreshBlockedUntil(refreshToken);
        if (blockedUntil > System.currentTimeMillis()) {
            throw new RefreshHttpError(429,
                    "refresh temporarily blocked until "
                            + instantToRfc3339(blockedUntil),
                    false);
        }

        // Build JSON request body
        JSONObject reqBody = new JSONObject();
        reqBody.put("client_id", CLIENT_ID);
        reqBody.put("grant_type", "refresh_token");
        reqBody.put("refresh_token", refreshToken);

        HttpURLConnection conn = (HttpURLConnection) new URL(TOKEN_URL).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            byte[] postData = reqBody.toString().getBytes(StandardCharsets.UTF_8);
            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();

            // Read response body
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            try (java.io.InputStream is = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream() : conn.getErrorStream()) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            String responseBody = baos.toString("UTF-8");

            if (responseCode != HttpURLConnection.HTTP_OK) {
                // Extract response headers for Retry-After parsing
                Map<String, String> headers = new HashMap<>();
                String retryAfter = conn.getHeaderField("Retry-After");
                if (retryAfter != null) headers.put("Retry-After", retryAfter);
                String retryAfterMs = conn.getHeaderField("Retry-After-Ms");
                if (retryAfterMs != null) headers.put("Retry-After-Ms", retryAfterMs);

                if (responseCode == 429) {
                    long retryAfterDelay = parseClaudeRetryAfter(headers);
                    setClaudeRefreshBlockedUntil(refreshToken,
                            System.currentTimeMillis() + retryAfterDelay);
                    throw new RefreshHttpError(responseCode, responseBody, false);
                }
                throw new RefreshHttpError(responseCode, responseBody,
                        responseCode >= 500);
            }

            log("Token refresh response: " + responseBody);

            JSONObject json = new JSONObject(responseBody);
            TokenResponse tokenResp = TokenResponse.fromJson(json);

            // Clear the block on success
            clearClaudeRefreshBlockedUntil(refreshToken);

            // Create token data
            String expire = instantToRfc3339(System.currentTimeMillis()
                    + (tokenResp.expiresIn * 1000L));
            return new ClaudeTokenData(
                    tokenResp.accessToken,
                    tokenResp.refreshToken,
                    tokenResp.accountEmailAddress,
                    expire
            );
        } finally {
            conn.disconnect();
        }
    }

    // ====== Token Storage ======

    /**
     * Creates a new ClaudeTokenStorage from auth bundle and user info.
     * Converts the authentication bundle into a token storage structure
     * suitable for persistence and later use.
     *
     * @param bundle The authentication bundle containing token data
     * @return A new token storage instance
     */
    public ClaudeTokenStorage createTokenStorage(ClaudeAuthBundle bundle) {
        ClaudeTokenStorage storage = new ClaudeTokenStorage();
        if (bundle.tokenData != null) {
            storage.accessToken = bundle.tokenData.accessToken;
            storage.refreshToken = bundle.tokenData.refreshToken;
            storage.email = bundle.tokenData.email;
            storage.expire = bundle.tokenData.expire;
        }
        storage.lastRefresh = bundle.lastRefresh;
        storage.type = "claude";
        return storage;
    }

    /**
     * Updates an existing token storage with new token data.
     * Refreshes the token storage with newly obtained access and refresh tokens,
     * updating timestamps and expiration information.
     *
     * @param storage   The existing token storage to update
     * @param tokenData The new token data to apply
     */
    public void updateTokenStorage(ClaudeTokenStorage storage, ClaudeTokenData tokenData) {
        storage.accessToken = tokenData.accessToken;
        storage.refreshToken = tokenData.refreshToken;
        storage.lastRefresh = nowRfc3339();
        storage.email = tokenData.email;
        storage.expire = tokenData.expire;
    }

    // ====== Retry Logic ======

    /**
     * Refreshes tokens with automatic retry logic.
     * Implements exponential backoff retry logic for token refresh operations,
     * providing resilience against temporary network or service issues.
     *
     * @param refreshToken The refresh token to use
     * @param maxRetries   The maximum number of retry attempts
     * @return The refreshed token data
     * @throws IOException if all retry attempts fail
     */
    public ClaudeTokenData refreshTokensWithRetry(String refreshToken, int maxRetries)
            throws IOException, JSONException {
        Exception lastError = null;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            if (attempt > 0) {
                // Wait before retry with exponential backoff
                try {
                    Thread.sleep((attempt + 1) * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("token refresh retry interrupted", e);
                }
            }

            try {
                ClaudeTokenData tokenData = refreshTokens(refreshToken);
                if (tokenData != null) {
                    return tokenData;
                }
                lastError = new IOException("token refresh returned null");
            } catch (Exception e) {
                lastError = e;
                log("Token refresh attempt " + (attempt + 1) + " failed: " + e.getMessage());
                if (!isClaudeRefreshRetryable(e)) {
                    break;
                }
            }
        }

        throw new IOException(
                "token refresh failed after " + maxRetries + " attempts",
                lastError);
    }
}