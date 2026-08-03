package com.cliproxy.plus.auth.oauth;

import android.os.Build;
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
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * OAuth2 authentication implementation for Kimi (Moonshot AI) API.
 * <p>
 * Handles the RFC 8628 OAuth2 Device Authorization Grant flow for secure authentication,
 * including device code request, token polling, and token refresh with singleflight dedup.
 * <p>
 * 1:1 port of internal/auth/kimi/ from CLIProxyAPIPlus.
 */
public class KimiOAuth extends OAuthProvider {

    private static final String TAG = "KimiOAuth";

    // ========================================================================
    // OAuth Configuration Constants (1:1 port of Go constants)
    // ========================================================================

    /** Kimi Code's OAuth client ID. */
    public static final String KIMI_CLIENT_ID = "17e5f671-d194-4dfb-9706-5516cb48c098";

    /** OAuth server endpoint. */
    public static final String KIMI_OAUTH_HOST = "https://auth.kimi.com";

    /** Endpoint for requesting device codes. */
    public static final String KIMI_DEVICE_CODE_URL = KIMI_OAUTH_HOST + "/api/oauth/device_authorization";

    /** Endpoint for exchanging device codes for tokens. */
    public static final String KIMI_TOKEN_URL = KIMI_OAUTH_HOST + "/api/oauth/token";

    /** Base URL for Kimi API requests. */
    public static final String KIMI_API_BASE_URL = "https://api.kimi.com/coding";

    /** Default interval for polling token endpoint (5 seconds). */
    private static final long DEFAULT_POLL_INTERVAL_MS = 5000L;

    /** Maximum time to wait for user authorization (15 minutes). */
    private static final long MAX_POLL_DURATION_MS = 15 * 60 * 1000L;

    /** When to refresh token before expiry (5 minutes). */
    private static final int REFRESH_THRESHOLD_SECONDS = 300;

    // ========================================================================
    // Data Classes (1:1 port of token.go)
    // ========================================================================

    /**
     * DeviceCodeResponse represents Kimi's device code response.
     * 1:1 port of Go DeviceCodeResponse struct.
     */
    public static class DeviceCodeResponse {
        /** Device verification code. */
        public String deviceCode;
        /** Code the user must enter at the verification URI. */
        public String userCode;
        /** URL where the user should enter the code. */
        public String verificationUri;
        /** URL with the code pre-filled. */
        public String verificationUriComplete;
        /** Number of seconds until the device code expires. */
        public int expiresIn;
        /** Minimum number of seconds to wait between polling requests. */
        public int interval;

        static DeviceCodeResponse fromJson(JSONObject json) {
            DeviceCodeResponse resp = new DeviceCodeResponse();
            resp.deviceCode = json.optString("device_code", "");
            resp.userCode = json.optString("user_code", "");
            resp.verificationUri = json.optString("verification_uri", "");
            resp.verificationUriComplete = json.optString("verification_uri_complete", "");
            resp.expiresIn = json.optInt("expires_in", 0);
            resp.interval = json.optInt("interval", 0);
            return resp;
        }
    }

    /**
     * KimiTokenData holds the raw OAuth token response from Kimi.
     * 1:1 port of Go KimiTokenData struct.
     */
    public static class KimiTokenData {
        /** OAuth2 access token. */
        public String accessToken;
        /** OAuth2 refresh token. */
        public String refreshToken;
        /** Type of token, typically "Bearer". */
        public String tokenType;
        /** Unix timestamp when the token expires. */
        public long expiresAt;
        /** OAuth2 scope granted to the token. */
        public String scope;

        KimiTokenData() {}
    }

    /**
     * KimiAuthBundle bundles authentication data for storage.
     * 1:1 port of Go KimiAuthBundle struct.
     */
    public static class KimiAuthBundle {
        /** OAuth token information. */
        public KimiTokenData tokenData;
        /** Device identifier used during OAuth device flow. */
        public String deviceId;

        public KimiAuthBundle(KimiTokenData tokenData, String deviceId) {
            this.tokenData = tokenData;
            this.deviceId = deviceId;
        }
    }

    /**
     * KimiTokenStorage stores OAuth2 token information for Kimi API authentication.
     * 1:1 port of Go KimiTokenStorage struct.
     */
    public static class KimiTokenStorage {
        /** OAuth2 access token used for authenticating API requests. */
        public String accessToken;
        /** OAuth2 refresh token used to obtain new access tokens. */
        public String refreshToken;
        /** Type of token, typically "Bearer". */
        public String tokenType;
        /** OAuth2 scope granted to the token. */
        public String scope;
        /** OAuth device flow identifier used for Kimi requests. */
        public String deviceId;
        /** RFC3339 timestamp when the access token expires. */
        public String expired;
        /** Authentication provider type, always "kimi" for this storage. */
        public String type;
        /** Arbitrary key-value pairs injected via hooks. */
        public Map<String, Object> metadata;

        public KimiTokenStorage() {
            this.type = "kimi";
        }

        /**
         * Allows external callers to inject metadata into the storage before saving.
         * 1:1 port of Go SetMetadata().
         */
        public void setMetadata(Map<String, Object> meta) {
            this.metadata = meta;
        }

        /**
         * Checks if the token has expired.
         * 1:1 port of Go IsExpired().
         */
        public boolean isExpired() {
            if (expired == null || expired.isEmpty()) {
                return false; // No expiry set, assume valid
            }
            try {
                Instant expireTime = Instant.from(DateTimeFormatter.ISO_INSTANT.parse(expired));
                // Consider expired if within refresh threshold
                return Instant.now().plusSeconds(REFRESH_THRESHOLD_SECONDS).isAfter(expireTime);
            } catch (Exception e) {
                return true; // Has expiry string but can't parse
            }
        }

        /**
         * Checks if the token should be refreshed.
         * 1:1 port of Go NeedsRefresh().
         */
        public boolean needsRefresh() {
            if (refreshToken == null || refreshToken.isEmpty()) {
                return false; // Can't refresh without refresh token
            }
            return isExpired();
        }
    }

    // ========================================================================
    // Singleflight Dedup (1:1 port of Go singleflight.Group)
    // ========================================================================

    /** Singleflight group for deduplicating concurrent refresh calls per refresh token. */
    private static final ConcurrentHashMap<String, AtomicReference<RefreshResult>> refreshGroup = new ConcurrentHashMap<>();

    /**
     * Holder for singleflight result.
     */
    private static class RefreshResult {
        final KimiTokenData tokenData;
        final Exception error;

        RefreshResult(KimiTokenData tokenData, Exception error) {
            this.tokenData = tokenData;
            this.error = error;
        }
    }

    // ========================================================================
    // Device Flow Client (1:1 port of Go DeviceFlowClient)
    // ========================================================================

    /**
     * DeviceFlowClient handles the OAuth2 device flow for Kimi.
     * 1:1 port of Go DeviceFlowClient.
     */
    public static class DeviceFlowClient {
        private final String deviceId;
        private final int connectTimeout;
        private final int readTimeout;

        /**
         * Creates a new device flow client with a randomly generated device ID.
         * 1:1 port of Go NewDeviceFlowClient().
         */
        public DeviceFlowClient() {
            this("");
        }

        /**
         * Creates a new device flow client with the specified device ID.
         * 1:1 port of Go NewDeviceFlowClientWithDeviceID().
         */
        public DeviceFlowClient(String deviceId) {
            String resolved = (deviceId != null) ? deviceId.trim() : "";
            if (resolved.isEmpty()) {
                resolved = UUID.randomUUID().toString();
            }
            this.deviceId = resolved;
            this.connectTimeout = 30000;
            this.readTimeout = 30000;
        }

        /**
         * Returns the device ID used by this client.
         */
        public String getDeviceId() {
            return deviceId;
        }

        /**
         * Returns headers required for Kimi API requests.
         * 1:1 port of Go commonHeaders().
         */
        private Map<String, String> commonHeaders() {
            Map<String, String> headers = new HashMap<>();
            headers.put("X-Msh-Platform", "CLIProxyAPI");
            headers.put("X-Msh-Version", Build.VERSION.RELEASE);
            headers.put("X-Msh-Device-Name", Build.DEVICE);
            headers.put("X-Msh-Device-Model", Build.MODEL + " " + Build.MANUFACTURER);
            headers.put("X-Msh-Device-Id", deviceId);
            return headers;
        }

        /**
         * Initiates the device flow by requesting a device code from Kimi.
         * 1:1 port of Go RequestDeviceCode().
         */
        public DeviceCodeResponse requestDeviceCode() throws IOException {
            // Build form-encoded body (1:1 port of Go url.Values)
            StringBuilder body = new StringBuilder();
            body.append("client_id=").append(URLEncoder.encode(KIMI_CLIENT_ID, "UTF-8"));

            HttpURLConnection conn = (HttpURLConnection) new URL(KIMI_DEVICE_CODE_URL).openConnection();
            try {
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setRequestProperty("Accept", "application/json");
                for (Map.Entry<String, String> entry : commonHeaders().entrySet()) {
                    conn.setRequestProperty(entry.getKey(), entry.getValue());
                }
                conn.setDoOutput(true);
                conn.setConnectTimeout(connectTimeout);
                conn.setReadTimeout(readTimeout);

                byte[] postData = body.toString().getBytes(StandardCharsets.UTF_8);
                try (OutputStream os = conn.getOutputStream()) {
                    os.write(postData);
                    os.flush();
                }

                int responseCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn, responseCode);

                if (responseCode != HttpURLConnection.HTTP_OK) {
                    throw new IOException("kimi: device code request failed with status "
                            + responseCode + ": " + responseBody);
                }

                JSONObject json = parseJson(responseBody);
                return DeviceCodeResponse.fromJson(json);

            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("kimi: failed to parse device code response: " + e.getMessage(), e);
            } finally {
                conn.disconnect();
            }
        }

        /**
         * Polls the token endpoint until the user authorizes or the device code expires.
         * 1:1 port of Go PollForToken().
         */
        public KimiTokenData pollForToken(DeviceCodeResponse deviceCode) throws IOException, InterruptedException {
            if (deviceCode == null) {
                throw new IOException("kimi: device code is nil");
            }

            long intervalMs = (long) deviceCode.interval * 1000L;
            if (intervalMs < DEFAULT_POLL_INTERVAL_MS) {
                intervalMs = DEFAULT_POLL_INTERVAL_MS;
            }

            long deadline = System.currentTimeMillis() + MAX_POLL_DURATION_MS;
            if (deviceCode.expiresIn > 0) {
                long codeDeadline = System.currentTimeMillis() + (long) deviceCode.expiresIn * 1000L;
                if (codeDeadline < deadline) {
                    deadline = codeDeadline;
                }
            }

            while (true) {
                // Check for cancellation (1:1 port of Go ctx.Done())
                if (Thread.currentThread().isInterrupted()) {
                    throw new IOException("kimi: context cancelled");
                }

                Thread.sleep(intervalMs);

                // Check deadline (1:1 port of Go time.Now().After(deadline))
                if (System.currentTimeMillis() > deadline) {
                    throw new IOException("kimi: device code expired");
                }

                // exchangeDeviceCode returns (token, error, shouldContinue)
                ExchangeResult result = exchangeDeviceCode(deviceCode.deviceCode);
                if (result.token != null) {
                    return result.token;
                }
                if (!result.shouldContinue) {
                    throw result.error;
                }
                // Continue polling
            }
        }

        /**
         * Holds the result of a device code exchange attempt.
         * 1:1 port of Go tuple return (token, error, shouldContinue).
         */
        private static class ExchangeResult {
            final KimiTokenData token;
            final IOException error;
            final boolean shouldContinue;

            ExchangeResult(KimiTokenData token, IOException error, boolean shouldContinue) {
                this.token = token;
                this.error = error;
                this.shouldContinue = shouldContinue;
            }
        }

        /**
         * Attempts to exchange the device code for an access token.
         * Returns (token, error, shouldContinue).
         * 1:1 port of Go exchangeDeviceCode().
         */
        private ExchangeResult exchangeDeviceCode(String deviceCode) {
            try {
                // Build form-encoded body (1:1 port of Go url.Values)
                StringBuilder body = new StringBuilder();
                body.append("client_id=").append(URLEncoder.encode(KIMI_CLIENT_ID, "UTF-8"));
                body.append("&device_code=").append(URLEncoder.encode(deviceCode, "UTF-8"));
                body.append("&grant_type=").append(URLEncoder.encode(
                        "urn:ietf:params:oauth:grant-type:device_code", "UTF-8"));

                byte[] postData = body.toString().getBytes(StandardCharsets.UTF_8);
                HttpURLConnection conn = (HttpURLConnection) new URL(KIMI_TOKEN_URL).openConnection();
                try {
                    conn.setRequestMethod("POST");
                    conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                    conn.setRequestProperty("Accept", "application/json");
                    for (Map.Entry<String, String> entry : commonHeaders().entrySet()) {
                        conn.setRequestProperty(entry.getKey(), entry.getValue());
                    }
                    conn.setDoOutput(true);
                    conn.setConnectTimeout(connectTimeout);
                    conn.setReadTimeout(readTimeout);

                    try (OutputStream os = conn.getOutputStream()) {
                        os.write(postData);
                        os.flush();
                    }

                    int responseCode = conn.getResponseCode();
                    String responseBody = readResponseBody(conn, responseCode);

                    // Parse response - Kimi returns 200 for both success and pending states
                    JSONObject json = parseJson(responseBody);

                    // Check for OAuth error field (1:1 port of Go switch statement)
                    String error = json.optString("error", "");
                    if (!error.isEmpty()) {
                        switch (error) {
                            case "authorization_pending":
                                // Continue polling (1:1 port of Go case)
                                return new ExchangeResult(null, null, true);
                            case "slow_down":
                                // Continue polling (with increased interval handled by caller)
                                return new ExchangeResult(null, null, true);
                            case "expired_token":
                                return new ExchangeResult(null,
                                        new IOException("kimi: device code expired"), false);
                            case "access_denied":
                                return new ExchangeResult(null,
                                        new IOException("kimi: access denied by user"), false);
                            default:
                                String errorDesc = json.optString("error_description", "");
                                return new ExchangeResult(null,
                                        new IOException("kimi: OAuth error: "
                                                + error + " - " + errorDesc), false);
                        }
                    }

                    // Check for empty access token (1:1 port of Go empty check)
                    String accessToken = json.optString("access_token", "");
                    if (accessToken.isEmpty()) {
                        return new ExchangeResult(null,
                                new IOException("kimi: empty access token in response"), false);
                    }

                    // Calculate expiry (1:1 port of Go expiresAt calculation)
                    double expiresIn = json.optDouble("expires_in", 0);
                    long expiresAt = 0;
                    if (expiresIn > 0) {
                        expiresAt = System.currentTimeMillis() / 1000L + (long) expiresIn;
                    }

                    // Build token data (1:1 port of Go KimiTokenData construction)
                    KimiTokenData tokenData = new KimiTokenData();
                    tokenData.accessToken = accessToken;
                    tokenData.refreshToken = json.optString("refresh_token", "");
                    tokenData.tokenType = json.optString("token_type", "");
                    tokenData.expiresAt = expiresAt;
                    tokenData.scope = json.optString("scope", "");

                    return new ExchangeResult(tokenData, null, false);

                } finally {
                    conn.disconnect();
                }
            } catch (Exception e) {
                return new ExchangeResult(null,
                        new IOException("kimi: token request failed: " + e.getMessage()), false);
            }
        }

        /**
         * Exchanges a refresh token for a new access token.
         * Uses singleflight dedup for concurrent calls with the same refresh token.
         * 1:1 port of Go RefreshToken().
         */
        public KimiTokenData refreshToken(String refreshToken) throws IOException {
            if (refreshToken == null || refreshToken.trim().isEmpty()) {
                throw new IOException("kimi: refresh token is required");
            }
            final String rt = refreshToken.trim();

            // Singleflight dedup: only one concurrent call per refresh token
            // (1:1 port of Go singleflight.Group.Do)
            AtomicReference<RefreshResult> ref = new AtomicReference<>(null);
            AtomicReference<RefreshResult> existing = refreshGroup.putIfAbsent(rt, ref);
            if (existing != null) {
                // Another thread is already refreshing; share its result
                synchronized (existing) {
                    while (existing.get() == null) {
                        try {
                            existing.wait();
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            throw new IOException("kimi: token refresh interrupted", e);
                        }
                    }
                }
                RefreshResult result = existing.get();
                if (result.error != null) {
                    if (result.error instanceof IOException) {
                        throw (IOException) result.error;
                    }
                    throw new IOException("kimi: refresh token failed: "
                            + result.error.getMessage(), result.error);
                }
                return result.tokenData;
            }

            // We are the designated refresher for this token
            try {
                KimiTokenData tokenData = refreshTokenSingleFlight(rt);
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
                if (e instanceof IOException) {
                    throw (IOException) e;
                }
                throw new IOException("kimi: refresh token failed: " + e.getMessage(), e);
            } finally {
                refreshGroup.remove(rt, ref);
            }
        }

        /**
         * Performs the actual token refresh HTTP request.
         * 1:1 port of Go refreshTokenSingleFlight().
         */
        private KimiTokenData refreshTokenSingleFlight(String refreshToken) throws IOException {
            // Build form-encoded body (1:1 port of Go url.Values)
            StringBuilder body = new StringBuilder();
            body.append("client_id=").append(URLEncoder.encode(KIMI_CLIENT_ID, "UTF-8"));
            body.append("&grant_type=").append(URLEncoder.encode("refresh_token", "UTF-8"));
            body.append("&refresh_token=").append(URLEncoder.encode(refreshToken, "UTF-8"));

            byte[] postData = body.toString().getBytes(StandardCharsets.UTF_8);
            HttpURLConnection conn = (HttpURLConnection) new URL(KIMI_TOKEN_URL).openConnection();
            try {
                conn.setRequestMethod("POST");
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
                conn.setRequestProperty("Accept", "application/json");
                for (Map.Entry<String, String> entry : commonHeaders().entrySet()) {
                    conn.setRequestProperty(entry.getKey(), entry.getValue());
                }
                conn.setDoOutput(true);
                conn.setConnectTimeout(connectTimeout);
                conn.setReadTimeout(readTimeout);

                try (OutputStream os = conn.getOutputStream()) {
                    os.write(postData);
                    os.flush();
                }

                int responseCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn, responseCode);

                // Check for auth rejection (1:1 port of Go status check)
                if (responseCode == HttpURLConnection.HTTP_UNAUTHORIZED
                        || responseCode == HttpURLConnection.HTTP_FORBIDDEN) {
                    throw new IOException("kimi: refresh token rejected (status " + responseCode + ")");
                }

                if (responseCode != HttpURLConnection.HTTP_OK) {
                    throw new IOException("kimi: refresh failed with status "
                            + responseCode + ": " + responseBody);
                }

                JSONObject json = parseJson(responseBody);

                // Check for empty access token (1:1 port of Go empty check)
                String accessToken = json.optString("access_token", "");
                if (accessToken.isEmpty()) {
                    throw new IOException("kimi: empty access token in refresh response");
                }

                // Calculate expiry (1:1 port of Go expiresAt calculation)
                double expiresIn = json.optDouble("expires_in", 0);
                long expiresAt = 0;
                if (expiresIn > 0) {
                    expiresAt = System.currentTimeMillis() / 1000L + (long) expiresIn;
                }

                // Build token data (1:1 port of Go KimiTokenData construction)
                KimiTokenData tokenData = new KimiTokenData();
                tokenData.accessToken = accessToken;
                tokenData.refreshToken = json.optString("refresh_token", "");
                tokenData.tokenType = json.optString("token_type", "");
                tokenData.expiresAt = expiresAt;
                tokenData.scope = json.optString("scope", "");

                return tokenData;

            } finally {
                conn.disconnect();
            }
        }

        /**
         * Reads the response body from an HttpURLConnection.
         */
        private String readResponseBody(HttpURLConnection conn, int responseCode) throws IOException {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            try (java.io.InputStream is = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream() : conn.getErrorStream()) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            return baos.toString("UTF-8");
        }
    }

    // ========================================================================
    // KimiOAuth Instance (1:1 port of Go KimiAuth)
    // ========================================================================

    private final DeviceFlowClient deviceClient;

    /**
     * Creates a new KimiOAuth instance with a randomly generated device ID.
     * 1:1 port of Go NewKimiAuth().
     */
    public KimiOAuth() {
        super("kimi", KIMI_OAUTH_HOST, KIMI_TOKEN_URL, KIMI_CLIENT_ID, "");
        this.deviceClient = new DeviceFlowClient();
    }

    /**
     * Creates a new KimiOAuth instance with the specified device ID.
     * 1:1 port of Go NewDeviceFlowClientWithDeviceID().
     */
    public KimiOAuth(String deviceId) {
        super("kimi", KIMI_OAUTH_HOST, KIMI_TOKEN_URL, KIMI_CLIENT_ID, "");
        this.deviceClient = new DeviceFlowClient(deviceId);
    }

    /**
     * Returns the underlying DeviceFlowClient.
     */
    public DeviceFlowClient getDeviceClient() {
        return deviceClient;
    }

    /**
     * Initiates the device flow authentication.
     * 1:1 port of Go StartDeviceFlow().
     */
    public DeviceCodeResponse startDeviceFlow() throws IOException {
        return deviceClient.requestDeviceCode();
    }

    /**
     * Polls for user authorization and returns the auth bundle.
     * 1:1 port of Go WaitForAuthorization().
     */
    public KimiAuthBundle waitForAuthorization(DeviceCodeResponse deviceCode)
            throws IOException, InterruptedException {
        KimiTokenData tokenData = deviceClient.pollForToken(deviceCode);
        return new KimiAuthBundle(tokenData, deviceClient.getDeviceId());
    }

    /**
     * Creates a new KimiTokenStorage from auth bundle.
     * 1:1 port of Go CreateTokenStorage().
     */
    public KimiTokenStorage createTokenStorage(KimiAuthBundle bundle) {
        String expired = "";
        if (bundle.tokenData.expiresAt > 0) {
            expired = DateTimeFormatter.ISO_INSTANT.format(
                    Instant.ofEpochSecond(bundle.tokenData.expiresAt));
        }
        KimiTokenStorage storage = new KimiTokenStorage();
        storage.accessToken = bundle.tokenData.accessToken;
        storage.refreshToken = bundle.tokenData.refreshToken;
        storage.tokenType = bundle.tokenData.tokenType;
        storage.scope = bundle.tokenData.scope;
        storage.deviceId = bundle.deviceId != null ? bundle.deviceId.trim() : "";
        storage.expired = expired;
        storage.type = "kimi";
        return storage;
    }

    // ========================================================================
    // Logging
    // ========================================================================


}
    private static JSONObject parseJson(String body) throws IOException {
        try {
            return new JSONObject(body);
        } catch (org.json.JSONException e) {
            throw new IOException("kimi: failed to parse JSON response", e);
        }
    }
}
