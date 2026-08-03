package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * XAIOAuth handles xAI (Grok) OAuth2 authentication using the device authorization flow (RFC 8628).
 * <p>
 * 1:1 port of internal/auth/xai/ from CLIProxyAPIPlus.
 * <p>
 * Flow: OIDC discovery → device code request → poll for user authorization → token exchange.
 * Uses form-encoded POST requests throughout.
 * Token refresh uses singleflight deduplication.
 */
public class XAIOAuth {

    private static final String TAG = "XAIOAuth";

    // =========================================================================
    // OAuth Configuration Constants (1:1 port of types.go)
    // =========================================================================

    /** Default official xAI API base URL. */
    public static final String DEFAULT_API_BASE_URL = "https://api.x.ai/v1";

    /** Grok CLI chat-proxy base URL for non-image/video HTTP chat. */
    public static final String CLI_CHAT_PROXY_BASE_URL = "https://cli-chat-proxy.grok.com/v1";

    /** xAI OAuth issuer. */
    public static final String ISSUER = "https://auth.x.ai";

    /** OIDC discovery endpoint. */
    public static final String DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration";

    /** Public xAI Grok CLI OAuth client ID. */
    public static final String CLIENT_ID = "b1a00492-073a-47ea-816f-4c329264a828";

    /** OAuth scope set required for xAI API access. */
    public static final String SCOPE = "openid profile email offline_access grok-cli:access api:access";

    /** OAuth2 device authorization grant type (RFC 8628). */
    public static final String DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";

    /** Default poll interval (5s) when the device endpoint omits interval. */
    private static final long DEFAULT_POLL_INTERVAL_MS = 5000L;

    /** HTTP client timeout for credential-acquisition calls. */
    private static final int HTTP_CLIENT_TIMEOUT_MS = 30000;

    /** Maximum duration to wait for user authorization (30 minutes). */
    private static final long MAX_POLL_DURATION_MS = 30 * 60 * 1000L;

    /** Refresh lead time for proactive token refresh. */
    private static final long REFRESH_LEAD_MS = 5 * 60 * 1000L;

    // =========================================================================
    // Data Classes (1:1 port of types.go Discovery, DeviceCodeResponse, TokenData, AuthBundle)
    // =========================================================================

    /**
     * Discovery contains OAuth endpoints resolved from xAI OIDC discovery.
     * 1:1 port of Go Discovery struct.
     */
    public static class Discovery {
        public String deviceAuthorizationEndpoint;
        public String tokenEndpoint;

        public Discovery() {}

        public Discovery(String deviceAuthorizationEndpoint, String tokenEndpoint) {
            this.deviceAuthorizationEndpoint = deviceAuthorizationEndpoint;
            this.tokenEndpoint = tokenEndpoint;
        }
    }

    /**
     * DeviceCodeResponse represents xAI's device authorization response.
     * 1:1 port of Go DeviceCodeResponse struct.
     */
    public static class DeviceCodeResponse {
        public String deviceCode;
        public String userCode;
        public String verificationUri;
        public String verificationUriComplete;
        public int expiresIn;
        public int interval;
        public String tokenEndpoint;

        public DeviceCodeResponse() {}
    }

    /**
     * TokenData holds xAI OAuth token data.
     * 1:1 port of Go TokenData struct.
     */
    public static class TokenData {
        public String accessToken;
        public String refreshToken;
        public String idToken;
        public String tokenType;
        public int expiresIn;
        public String expire;
        public String email;
        public String subject;

        public TokenData() {}
    }

    /**
     * AuthBundle aggregates token data and OAuth metadata for persistence.
     * 1:1 port of Go AuthBundle struct.
     */
    public static class AuthBundle {
        public TokenData tokenData;
        public String lastRefresh;
        public String baseUrl;
        public String redirectUri;
        public String tokenEndpoint;

        public AuthBundle() {}

        public AuthBundle(TokenData tokenData, String lastRefresh, String baseUrl, String tokenEndpoint) {
            this.tokenData = tokenData;
            this.lastRefresh = lastRefresh;
            this.baseUrl = baseUrl;
            this.tokenEndpoint = tokenEndpoint;
        }
    }

    /**
     * TokenStorage stores xAI OAuth credentials for persistence.
     * 1:1 port of Go TokenStorage struct.
     */
    public static class TokenStorage {
        public String type;
        public String accessToken;
        public String refreshToken;
        public String idToken;
        public String tokenType;
        public int expiresIn;
        public String expire;
        public String lastRefresh;
        public String email;
        public String subject;
        public String baseUrl;
        public String redirectUri;
        public String tokenEndpoint;
        public String authKind;
        public Map<String, Object> metadata;

        public TokenStorage() {
            this.type = "xai";
            this.authKind = "oauth";
        }

        /**
         * SetMetadata allows external callers to inject metadata into the storage before saving.
         * 1:1 port of Go SetMetadata().
         */
        public void setMetadata(Map<String, Object> meta) {
            this.metadata = meta;
        }
    }

    // =========================================================================
    // Singleflight Dedup State (1:1 port of xaiRefreshGroup)
    // =========================================================================

    private static final ConcurrentHashMap<String, Object> refreshGroup = new ConcurrentHashMap<>();

    // =========================================================================
    // Instance State
    // =========================================================================

    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    // =========================================================================
    // Constructors (1:1 port of NewXAIAuth, NewXAIAuthWithProxyURL)
    // =========================================================================

    public XAIOAuth() {
        this(HTTP_CLIENT_TIMEOUT_MS);
    }

    public XAIOAuth(int timeoutMs) {
        this.connectTimeoutMs = timeoutMs;
        this.readTimeoutMs = timeoutMs;
    }

    // =========================================================================
    // Refresh Lead (1:1 port of RefreshLead())
    // =========================================================================

    public static long refreshLeadMs() {
        return REFRESH_LEAD_MS;
    }

    // =========================================================================
    // Endpoint Validation (1:1 port of ValidateOAuthEndpoint)
    // =========================================================================

    /**
     * ValidateOAuthEndpoint validates an endpoint returned by xAI discovery.
     * 1:1 port of Go ValidateOAuthEndpoint().
     */
    public static String validateOAuthEndpoint(String rawURL, String field)
            throws OAuthProvider.OAuthException {
        if (rawURL == null) {
            rawURL = "";
        }
        rawURL = rawURL.trim();
        if (rawURL.isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai discovery " + field + " is empty");
        }
        try {
            URL parsed = new URL(rawURL);
            if (!"https".equals(parsed.getProtocol())) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "xai discovery " + field + " must use https: \"" + rawURL + "\"");
            }
            String host = parsed.getHost();
            if (host == null) {
                host = "";
            }
            host = host.toLowerCase().trim();
            if (!"x.ai".equals(host) && !host.endsWith(".x.ai")) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "xai discovery " + field + " host \"" + host + "\" is not on x.ai");
            }
            return rawURL;
        } catch (java.net.MalformedURLException e) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai discovery " + field + " is invalid: " + e.getMessage());
        }
    }

    // =========================================================================
    // OIDC Discovery (1:1 port of Discover)
    // =========================================================================

    /**
     * Discover resolves xAI OAuth endpoints through OIDC discovery.
     * 1:1 port of Go XAIAuth.Discover().
     */
    public Discovery discover() throws IOException, OAuthProvider.OAuthException {
        String responseBody = doGet(DISCOVERY_URL);
        JSONObject json = new JSONObject(responseBody);

        String deviceAuthorizationEndpoint = json.optString("device_authorization_endpoint", "");
        String tokenEndpoint = json.optString("token_endpoint", "");

        deviceAuthorizationEndpoint = validateOAuthEndpoint(
                deviceAuthorizationEndpoint, "device_authorization_endpoint");
        tokenEndpoint = validateOAuthEndpoint(tokenEndpoint, "token_endpoint");

        return new Discovery(deviceAuthorizationEndpoint, tokenEndpoint);
    }

    // =========================================================================
    // Device Code Flow (1:1 port of StartDeviceFlow, RequestDeviceCode)
    // =========================================================================

    /**
     * StartDeviceFlow requests a device code from xAI by first discovering endpoints.
     * 1:1 port of Go XAIAuth.StartDeviceFlow().
     */
    public DeviceCodeResponse startDeviceFlow() throws IOException, OAuthProvider.OAuthException {
        Discovery discovery = discover();
        return requestDeviceCode(discovery.deviceAuthorizationEndpoint, discovery.tokenEndpoint);
    }

    /**
     * RequestDeviceCode requests a device authorization code from the given endpoint.
     * 1:1 port of Go XAIAuth.RequestDeviceCode().
     */
    public DeviceCodeResponse requestDeviceCode(String deviceAuthorizationEndpoint, String tokenEndpoint)
            throws IOException, OAuthProvider.OAuthException {
        if (deviceAuthorizationEndpoint == null) {
            deviceAuthorizationEndpoint = "";
        }
        deviceAuthorizationEndpoint = deviceAuthorizationEndpoint.trim();
        if (deviceAuthorizationEndpoint.isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai device code: device authorization endpoint is required");
        }

        Map<String, String> form = new HashMap<>();
        form.put("client_id", CLIENT_ID);
        form.put("scope", SCOPE);

        String responseBody = doPostForm(deviceAuthorizationEndpoint, form);
        JSONObject json = new JSONObject(responseBody);

        DeviceCodeResponse deviceCode = new DeviceCodeResponse();
        deviceCode.deviceCode = json.optString("device_code", "");
        deviceCode.userCode = json.optString("user_code", "");
        deviceCode.verificationUri = json.optString("verification_uri", "");
        deviceCode.verificationUriComplete = json.optString("verification_uri_complete", "");
        deviceCode.expiresIn = json.optInt("expires_in", 0);
        deviceCode.interval = json.optInt("interval", 0);

        if (deviceCode.deviceCode.trim().isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai device code: response missing device_code");
        }
        if (deviceCode.userCode.trim().isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai device code: response missing user_code");
        }
        if (deviceCode.verificationUri.trim().isEmpty()
                && deviceCode.verificationUriComplete.trim().isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai device code: response missing verification URI");
        }

        deviceCode.tokenEndpoint = (tokenEndpoint != null) ? tokenEndpoint.trim() : "";
        return deviceCode;
    }

    // =========================================================================
    // Poll for Authorization (1:1 port of WaitForAuthorization, PollForToken, exchangeDeviceCode)
    // =========================================================================

    /**
     * WaitForAuthorization polls until the user authorizes the device code and returns tokens.
     * 1:1 port of Go XAIAuth.WaitForAuthorization().
     */
    public AuthBundle waitForAuthorization(DeviceCodeResponse deviceCode)
            throws IOException, OAuthProvider.OAuthException, InterruptedException {
        TokenData tokenData = pollForToken(deviceCode);
        String tokenEndpoint = "";
        if (deviceCode != null) {
            tokenEndpoint = deviceCode.tokenEndpoint != null
                    ? deviceCode.tokenEndpoint.trim() : "";
        }
        return new AuthBundle(
                tokenData,
                Instant.now().toString(),
                DEFAULT_API_BASE_URL,
                tokenEndpoint
        );
    }

    /**
     * PollForToken polls the token endpoint until the user authorizes or the device code expires.
     * 1:1 port of Go XAIAuth.PollForToken().
     */
    public TokenData pollForToken(DeviceCodeResponse deviceCode)
            throws IOException, OAuthProvider.OAuthException, InterruptedException {
        if (deviceCode == null) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai device code: response is nil");
        }

        String tokenEndpoint = deviceCode.tokenEndpoint != null
                ? deviceCode.tokenEndpoint.trim() : "";
        if (tokenEndpoint.isEmpty()) {
            Discovery discovery = discover();
            tokenEndpoint = discovery.tokenEndpoint;
        }

        long intervalMs = (long) deviceCode.interval * 1000L;
        if (intervalMs < DEFAULT_POLL_INTERVAL_MS) {
            intervalMs = DEFAULT_POLL_INTERVAL_MS;
        }

        long deadline = System.currentTimeMillis() + MAX_POLL_DURATION_MS;
        if (deviceCode.expiresIn > 0) {
            long codeDeadline = System.currentTimeMillis()
                    + (long) deviceCode.expiresIn * 1000L;
            if (codeDeadline < deadline) {
                deadline = codeDeadline;
            }
        }

        // Poll immediately once, then wait between subsequent attempts.
        boolean firstAttempt = true;

        while (true) {
            if (!firstAttempt && System.currentTimeMillis() > deadline) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "xai device code expired");
            }
            firstAttempt = false;

            ExchangeResult result = exchangeDeviceCode(tokenEndpoint, deviceCode.deviceCode, intervalMs);
            if (result.token != null) {
                return result.token;
            }
            if (!result.shouldContinue) {
                if (result.error != null) {
                    throw result.error;
                }
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                        "xai device code: unexpected error");
            }
            intervalMs = result.nextIntervalMs;
            Thread.sleep(intervalMs);
        }
    }

    /**
     * Holds the result of a single device code exchange attempt.
     * 1:1 port of Go exchangeDeviceCode return values (token, error, nextInterval, shouldContinue).
     */
    private static class ExchangeResult {
        final TokenData token;
        final OAuthProvider.OAuthException error;
        final long nextIntervalMs;
        final boolean shouldContinue;

        ExchangeResult(TokenData token, OAuthProvider.OAuthException error,
                       long nextIntervalMs, boolean shouldContinue) {
            this.token = token;
            this.error = error;
            this.nextIntervalMs = nextIntervalMs;
            this.shouldContinue = shouldContinue;
        }
    }

    /**
     * exchangeDeviceCode attempts to exchange a device code for tokens.
     * Handles HTTP directly because the device code endpoint may return non-200
     * with JSON error fields (e.g. authorization_pending).
     * <p>
     * 1:1 port of Go XAIAuth.exchangeDeviceCode().
     */
    private ExchangeResult exchangeDeviceCode(String tokenEndpoint, String deviceCode, long intervalMs) {
        try {
            Map<String, String> form = new HashMap<>();
            form.put("grant_type", DEVICE_CODE_GRANT_TYPE);
            form.put("device_code", deviceCode != null ? deviceCode.trim() : "");
            form.put("client_id", CLIENT_ID);

            // Build form-encoded body
            StringBuilder bodyBuilder = new StringBuilder();
            for (Map.Entry<String, String> entry : form.entrySet()) {
                if (bodyBuilder.length() > 0) bodyBuilder.append("&");
                bodyBuilder.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                        .append("=")
                        .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            }
            byte[] postData = bodyBuilder.toString().getBytes(StandardCharsets.UTF_8);

            // Execute HTTP request
            HttpURLConnection conn = (HttpURLConnection)
                    new URL(tokenEndpoint != null ? tokenEndpoint.trim() : "").openConnection();
            try {
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setRequestProperty("Accept", "application/json");
                conn.setDoOutput(true);
                conn.setConnectTimeout(connectTimeoutMs);
                conn.setReadTimeout(readTimeoutMs);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(postData);
                    os.flush();
                }

                int responseCode = conn.getResponseCode();
                String responseBody = readResponse(conn, responseCode);

                JSONObject json = new JSONObject(responseBody);

                String errorStr = json.optString("error", "");
                String errorDescription = json.optString("error_description", "");

                if (!errorStr.isEmpty()) {
                    switch (errorStr) {
                        case "authorization_pending":
                            return new ExchangeResult(null, null, intervalMs, true);
                        case "slow_down":
                            long nextInterval = intervalMs + DEFAULT_POLL_INTERVAL_MS;
                            return new ExchangeResult(null, null, nextInterval, true);
                        case "expired_token":
                            return new ExchangeResult(null, null, intervalMs, false);
                        case "access_denied":
                            return new ExchangeResult(
                                    null,
                                    new OAuthProvider.OAuthException(
                                            OAuthProvider.OAuthException.TYPE_AUTH,
                                            "xai device authorization denied"),
                                    intervalMs,
                                    false);
                        default:
                            String desc = errorDescription != null
                                    ? errorDescription.trim() : "";
                            if (!desc.isEmpty()) {
                                return new ExchangeResult(
                                        null,
                                        new OAuthProvider.OAuthException(
                                                OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                                                "xai device token error: " + errorStr + ": " + desc),
                                        intervalMs,
                                        false);
                            }
                            return new ExchangeResult(
                                    null,
                                    new OAuthProvider.OAuthException(
                                            OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                                            "xai device token error: " + errorStr),
                                    intervalMs,
                                    false);
                    }
                }

                // Secondary status code check (1:1 port of Go: if resp.StatusCode != http.StatusOK)
                if (responseCode != HttpURLConnection.HTTP_OK) {
                    return new ExchangeResult(
                            null,
                            new OAuthProvider.OAuthException(
                                    OAuthProvider.OAuthException.TYPE_NETWORK,
                                    "xai device token request failed with status "
                                            + responseCode + ": " + responseBody.trim()),
                            intervalMs,
                            false);
                }

                String accessToken = json.optString("access_token", "");
                if (accessToken.trim().isEmpty()) {
                    return new ExchangeResult(
                            null,
                            new OAuthProvider.OAuthException(
                                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                                    "xai device token response missing access_token"),
                            intervalMs,
                            false);
                }

                String refreshToken = json.optString("refresh_token", "");
                String idToken = json.optString("id_token", "");
                String tokenType = json.optString("token_type", "");
                int expiresIn = json.optInt("expires_in", 0);

                String[] identity = parseJWTIdentity(idToken);
                String email = identity[0];
                String subject = identity[1];

                TokenData tokenData = buildTokenData(
                        accessToken, refreshToken, idToken, tokenType,
                        expiresIn, email, subject);
                return new ExchangeResult(tokenData, null, intervalMs, false);

            } finally {
                conn.disconnect();
            }

        } catch (Exception e) {
            return new ExchangeResult(
                    null,
                    new OAuthProvider.OAuthException(
                            OAuthProvider.OAuthException.TYPE_NETWORK,
                            "xai device token: " + e.getMessage()),
                    intervalMs,
                    false);
        }
    }

    // =========================================================================
    // Token Refresh (1:1 port of RefreshTokens, refreshTokensSingleFlight)
    // =========================================================================

    /**
     * RefreshTokens refreshes an xAI access token.
     * Uses singleflight deduplication for concurrent calls with the same refresh token.
     * <p>
     * 1:1 port of Go XAIAuth.RefreshTokens().
     */
    public TokenData refreshTokens(String refreshToken, String tokenEndpoint)
            throws IOException, OAuthProvider.OAuthException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_AUTH,
                    "xai token refresh: refresh token is required");
        }
        refreshToken = refreshToken.trim();

        String effectiveTokenEndpoint = (tokenEndpoint != null) ? tokenEndpoint.trim() : "";
        if (effectiveTokenEndpoint.isEmpty()) {
            Discovery discovery = discover();
            effectiveTokenEndpoint = discovery.tokenEndpoint;
        }
        effectiveTokenEndpoint = effectiveTokenEndpoint.trim();

        // Singleflight dedup: only one concurrent call per refresh token
        // 1:1 port of Go xaiRefreshGroup.Do(refreshToken, ...)
        Object lock = refreshGroup.computeIfAbsent(refreshToken, k -> new Object());
        synchronized (lock) {
            try {
                return refreshTokensSingleFlight(refreshToken, effectiveTokenEndpoint);
            } finally {
                refreshGroup.remove(refreshToken, lock);
            }
        }
    }

    /**
     * refreshTokensSingleFlight performs the actual token refresh HTTP request.
     * 1:1 port of Go XAIAuth.refreshTokensSingleFlight().
     */
    private TokenData refreshTokensSingleFlight(String refreshToken, String tokenEndpoint)
            throws IOException, OAuthProvider.OAuthException {
        Map<String, String> form = new HashMap<>();
        form.put("grant_type", "refresh_token");
        form.put("client_id", CLIENT_ID);
        form.put("refresh_token", refreshToken);
        return postTokenForm(tokenEndpoint, form);
    }

    // =========================================================================
    // Generic Form POST Helper (1:1 port of postTokenForm)
    // =========================================================================

    /**
     * postTokenForm performs a form-encoded POST to the token endpoint
     * and parses the token response.
     * <p>
     * 1:1 port of Go XAIAuth.postTokenForm().
     */
    private TokenData postTokenForm(String tokenEndpoint, Map<String, String> form)
            throws IOException, OAuthProvider.OAuthException {
        String responseBody = doPostForm(tokenEndpoint, form);
        JSONObject json = new JSONObject(responseBody);

        String accessToken = json.optString("access_token", "");
        String refreshToken = json.optString("refresh_token", "");
        String idToken = json.optString("id_token", "");
        String tokenType = json.optString("token_type", "");
        int expiresIn = json.optInt("expires_in", 0);

        if (accessToken.trim().isEmpty()) {
            throw new OAuthProvider.OAuthException(
                    OAuthProvider.OAuthException.TYPE_PROVIDER_ERROR,
                    "xai token response missing access_token");
        }

        String[] identity = parseJWTIdentity(idToken);
        String email = identity[0];
        String subject = identity[1];

        return buildTokenData(accessToken, refreshToken, idToken, tokenType,
                expiresIn, email, subject);
    }

    // =========================================================================
    // Token Storage (1:1 port of CreateTokenStorage)
    // =========================================================================

    /**
     * CreateTokenStorage converts an auth bundle into persistable storage.
     * <p>
     * 1:1 port of Go XAIAuth.CreateTokenStorage().
     */
    public TokenStorage createTokenStorage(AuthBundle bundle) {
        if (bundle == null) {
            return null;
        }
        TokenStorage storage = new TokenStorage();
        storage.type = "xai";
        if (bundle.tokenData != null) {
            storage.accessToken = bundle.tokenData.accessToken;
            storage.refreshToken = bundle.tokenData.refreshToken;
            storage.idToken = bundle.tokenData.idToken;
            storage.tokenType = bundle.tokenData.tokenType;
            storage.expiresIn = bundle.tokenData.expiresIn;
            storage.expire = bundle.tokenData.expire;
            storage.email = bundle.tokenData.email != null
                    ? bundle.tokenData.email.trim() : "";
            storage.subject = bundle.tokenData.subject;
        }
        storage.lastRefresh = bundle.lastRefresh;
        storage.baseUrl = firstNonEmpty(bundle.baseUrl, DEFAULT_API_BASE_URL);
        storage.redirectUri = bundle.redirectUri;
        storage.tokenEndpoint = bundle.tokenEndpoint;
        storage.authKind = "oauth";
        return storage;
    }

    // =========================================================================
    // Static Helpers (1:1 port of buildTokenData, parseJWTIdentity, firstNonEmpty)
    // =========================================================================

    /**
     * buildTokenData creates a TokenData from raw token fields.
     * <p>
     * 1:1 port of Go buildTokenData().
     */
    private static TokenData buildTokenData(String accessToken, String refreshToken,
                                            String idToken, String tokenType,
                                            int expiresIn, String email, String subject) {
        TokenData tokenData = new TokenData();
        tokenData.accessToken = accessToken != null ? accessToken.trim() : "";
        tokenData.refreshToken = refreshToken != null ? refreshToken.trim() : "";
        tokenData.idToken = idToken != null ? idToken.trim() : "";
        tokenData.tokenType = tokenType != null ? tokenType.trim() : "";
        tokenData.expiresIn = expiresIn;
        tokenData.email = email;
        tokenData.subject = subject;
        if (expiresIn > 0) {
            tokenData.expire = Instant.now().plusSeconds(expiresIn).toString();
        }
        return tokenData;
    }

    /**
     * parseJWTIdentity extracts email and subject from a JWT ID token
     * without signature verification.
     * <p>
     * 1:1 port of Go parseJWTIdentity().
     */
    static String[] parseJWTIdentity(String token) {
        String[] result = new String[]{"", ""};
        if (token == null || token.isEmpty()) {
            return result;
        }
        String[] parts = token.split("\\.");
        if (parts.length < 2) {
            return result;
        }
        String payload = parts[1];
        // Add Base64 URL-safe padding (1:1 port of Go padding logic)
        switch (payload.length() % 4) {
            case 2:
                payload += "==";
                break;
            case 3:
                payload += "=";
                break;
        }
        try {
            byte[] raw = Base64.getUrlDecoder().decode(payload);
            String jsonStr = new String(raw, StandardCharsets.UTF_8);
            JSONObject claims = new JSONObject(jsonStr);
            result[0] = claims.optString("email", "");
            result[1] = claims.optString("sub", "");
        } catch (Exception e) {
            Log.w(TAG, "parseJWTIdentity: failed to parse JWT claims: " + e.getMessage());
        }
        return result;
    }

    /**
     * firstNonEmpty returns the first non-empty (after trim) string value.
     * <p>
     * 1:1 port of Go firstNonEmpty().
     */
    private static String firstNonEmpty(String... values) {
        for (String value : values) {
            if (value != null && !value.trim().isEmpty()) {
                return value.trim();
            }
        }
        return "";
    }

    // =========================================================================
    // HTTP Helpers
    // =========================================================================

    /**
     * Performs an HTTP GET request and returns the response body.
     * Throws on non-200 status code.
     */
    private String doGet(String urlStr) throws IOException, OAuthProvider.OAuthException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(connectTimeoutMs);
            conn.setReadTimeout(readTimeoutMs);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_NETWORK,
                        "xai discovery failed with status "
                                + responseCode + ": " + responseBody.trim());
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Performs an HTTP POST with form-encoded body and returns the response body.
     * Throws on non-200 status code.
     */
    private String doPostForm(String urlStr, Map<String, String> params)
            throws IOException, OAuthProvider.OAuthException {
        StringBuilder bodyBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : params.entrySet()) {
            if (bodyBuilder.length() > 0) bodyBuilder.append("&");
            bodyBuilder.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                    .append("=")
                    .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
        }
        byte[] postData = bodyBuilder.toString().getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(connectTimeoutMs);
            conn.setReadTimeout(readTimeoutMs);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn, responseCode);

            if (responseCode != HttpURLConnection.HTTP_OK) {
                throw new OAuthProvider.OAuthException(
                        OAuthProvider.OAuthException.TYPE_NETWORK,
                        "xai request failed with status "
                                + responseCode + ": " + responseBody.trim());
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Reads the HTTP response body from the connection.
     */
    private String readResponse(HttpURLConnection conn, int responseCode) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        try (java.io.InputStream is = (responseCode >= 200 && responseCode < 300)
                ? conn.getInputStream() : conn.getErrorStream()) {
            if (is != null) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
        }
        return baos.toString("UTF-8");
    }

    // =========================================================================
    // Credential File Name (1:1 port of token.go CredentialFileName, sanitizeFileSegment)
    // =========================================================================

    /**
     * CredentialFileName returns the filename used for xAI credentials.
     * <p>
     * 1:1 port of Go CredentialFileName().
     */
    public static String credentialFileName(String email, String subject) {
        String sanitizedEmail = sanitizeFileSegment(email);
        if (!sanitizedEmail.isEmpty()) {
            return "xai-" + sanitizedEmail + ".json";
        }
        String sanitizedSubject = sanitizeFileSegment(subject);
        if (!sanitizedSubject.isEmpty()) {
            return "xai-" + sanitizedSubject + ".json";
        }
        return "xai-" + System.currentTimeMillis() + ".json";
    }

    /**
     * sanitizeFileSegment sanitizes a string for use as a filename segment.
     * <p>
     * 1:1 port of Go sanitizeFileSegment().
     */
    private static String sanitizeFileSegment(String value) {
        if (value == null) {
            return "";
        }
        value = value.trim();
        if (value.isEmpty()) {
            return "";
        }
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if ((c >= 'a' && c <= 'z')
                    || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9')
                    || c == '@' || c == '.' || c == '_' || c == '-') {
                b.append(c);
            } else {
                b.append('-');
            }
        }
        String result = b.toString();
        // Trim leading/trailing dashes (1:1 port of Go strings.Trim(b.String(), "-"))
        int start = 0;
        while (start < result.length() && result.charAt(start) == '-') {
            start++;
        }
        int end = result.length();
        while (end > start && result.charAt(end - 1) == '-') {
            end--;
        }
        return (start < end) ? result.substring(start, end) : "";
    }
    private static JSONObject parseJson(String body) throws IOException {
        try {
            return new JSONObject(body);
        } catch (org.json.JSONException e) {
            throw new IOException("xai: failed to parse JSON response", e);
        }
    }
}