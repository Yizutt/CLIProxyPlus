package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

/**
 * GeminiOAuth handles the Google OAuth2 authentication flow for Gemini AI services.
 * <p>
 * It provides methods for OAuth2 authorization URL generation, authorization code exchange,
 * token refresh, and token storage management for Google's Gemini AI APIs.
 * <p>
 * 1:1 port of internal/auth/gemini/ from CLIProxyAPIPlus.
 */
public class GeminiOAuth extends OAuthProvider {

    private static final String TAG = "GeminiOAuth";

    // ====== OAuth Configuration Constants (1:1 port of Go constants) ======

    /** Environment variable name for the Gemini OAuth client ID. */
    public static final String CLIENT_ID_ENV = "CLIPROXY_GEMINI_OAUTH_CLIENT_ID";

    /** Environment variable name for the Gemini OAuth client secret. */
    public static final String CLIENT_SECRET_ENV = "CLIPROXY_GEMINI_OAUTH_CLIENT_SECRET";

    /** Default callback port for the OAuth flow. */
    public static final int DEFAULT_CALLBACK_PORT = 8085;

    /** Gemini OAuth authorization endpoint. */
    public static final String AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";

    /** Gemini OAuth token endpoint. */
    public static final String TOKEN_URL = "https://oauth2.googleapis.com/token";

    /** Gemini OAuth redirect URI. */
    public static final String REDIRECT_URI = "http://localhost:8085/oauth2callback";

    /** Google user info endpoint for fetching authenticated user details. */
    public static final String USER_INFO_URL = "https://www.googleapis.com/oauth2/v1/userinfo?alt=json";

    /** OAuth scopes for Gemini authentication. */
    public static final String[] SCOPES = {
        "https://www.googleapis.com/auth/cloud-platform",
        "https://www.googleapis.com/auth/userinfo.email",
        "https://www.googleapis.com/auth/userinfo.profile"
    };

    /** Timeout for the OAuth callback flow (5 minutes). */
    private static final long CALLBACK_TIMEOUT_MS = 5 * 60 * 1000L;

    /** Delay before prompting the user for manual URL paste (15 seconds). */
    private static final long MANUAL_PROMPT_DELAY_MS = 15 * 1000L;

    // ====== Client ID / Secret from Environment (1:1 port of Go var init) ======

    /**
     * Returns the Gemini OAuth client ID from the CLIPROXY_GEMINI_OAUTH_CLIENT_ID
     * environment variable, trimmed of whitespace.
     * 1:1 port of Go strings.TrimSpace(os.Getenv(ClientIDEnv)).
     */
    public static String getClientIdFromEnv() {
        String val = System.getenv(CLIENT_ID_ENV);
        return val != null ? val.trim() : "";
    }

    /**
     * Returns the Gemini OAuth client secret from the CLIPROXY_GEMINI_OAUTH_CLIENT_SECRET
     * environment variable, trimmed of whitespace.
     * 1:1 port of Go strings.TrimSpace(os.Getenv(ClientSecretEnv)).
     */
    public static String getClientSecretFromEnv() {
        String val = System.getenv(CLIENT_SECRET_ENV);
        return val != null ? val.trim() : "";
    }

    // ====== GeminiTokenStorage (1:1 port of gemini_token.go) ======

    /**
     * GeminiTokenStorage stores OAuth2 token information for Google Gemini API authentication.
     * It maintains compatibility with the existing auth system while adding Gemini-specific fields
     * for managing access tokens, refresh tokens, and user account information.
     * <p>
     * 1:1 port of the Go GeminiTokenStorage struct.
     */
    public static class GeminiTokenStorage {
        /** Token holds the raw OAuth2 token data, including access and refresh tokens. */
        public Map<String, Object> token;

        /** ProjectID is the Google Cloud Project ID associated with this token. */
        public String projectId;

        /** Email is the email address of the authenticated user. */
        public String email;

        /** Auto indicates if the project ID was automatically selected. */
        public boolean auto;

        /** Checked indicates if the associated Cloud AI API has been verified as enabled. */
        public boolean checked;

        /** Type indicates the authentication provider type, always "gemini" for this storage. */
        public String type;

        /** Metadata holds arbitrary key-value pairs injected via hooks. */
        public Map<String, Object> metadata;

        public GeminiTokenStorage() {
            this.type = "gemini";
        }

        /**
         * Allows external callers to inject metadata into the storage before saving.
         * 1:1 port of Go SetMetadata().
         */
        public void setMetadata(Map<String, Object> meta) {
            this.metadata = meta;
        }
    }

    // ====== WebLoginOptions (1:1 port of Go WebLoginOptions) ======

    /**
     * WebLoginOptions customizes the interactive OAuth flow.
     * 1:1 port of the Go WebLoginOptions struct.
     */
    public static class WebLoginOptions {
        /** NoBrowser prevents the browser from being opened automatically. */
        public boolean noBrowser;

        /** CallbackPort overrides the default callback port. */
        public int callbackPort;

        /** Prompt is a function that prompts the user for manual callback URL input. */
        public Function<String, String> prompt;

        public WebLoginOptions() {
            this.callbackPort = 0;
        }

        public WebLoginOptions(boolean noBrowser, int callbackPort, Function<String, String> prompt) {
            this.noBrowser = noBrowser;
            this.callbackPort = callbackPort;
            this.prompt = prompt;
        }
    }

    // ====== OAuthCallbackResult (1:1 port of Go callback parsing) ======

    /**
     * Holds the result of parsing an OAuth callback URL.
     */
    public static class OAuthCallbackResult {
        public String code;
        public String state;
        public String error;
    }

    // ====== Singleflight Dedup for Token Refresh (1:1 port of Go singleflight.Group) ======

    /** Singleflight group for deduplicating concurrent refresh calls per refresh token. */
    private static final ConcurrentHashMap<String, AtomicReference<RefreshResult>> refreshGroup = new ConcurrentHashMap<>();

    /**
     * Holder for singleflight result.
     */
    private static class RefreshResult {
        final TokenData tokenData;
        final Exception error;

        RefreshResult(TokenData tokenData, Exception error) {
            this.tokenData = tokenData;
            this.error = error;
        }
    }

    // ====== Constructors ======

    public GeminiOAuth() {
        super("gemini", AUTH_URL, TOKEN_URL, getClientIdFromEnv(), REDIRECT_URI);
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

    // ====== Auth URL Generation (1:1 port of Go getTokenFromWeb URL construction) ======

    /**
     * Creates the OAuth authorization URL for Gemini.
     * <p>
     * 1:1 port of Go's oauth2.Config.AuthCodeURL with AccessTypeOffline and prompt=consent.
     *
     * @param state A random state parameter for CSRF protection
     * @return The complete authorization URL
     */
    public String generateAuthURL(String state) {
        StringBuilder sb = new StringBuilder();
        sb.append(AUTH_URL).append("?");
        appendParam(sb, "client_id", getClientIdFromEnv(), false);
        appendParam(sb, "response_type", "code", false);
        appendParam(sb, "redirect_uri", REDIRECT_URI, false);
        appendParam(sb, "scope", String.join(" ", SCOPES), false);
        sb.append("access_type=").append(URLEncoder.encode("offline", StandardCharsets.UTF_8)).append("&");
        sb.append("prompt=").append(URLEncoder.encode("consent", StandardCharsets.UTF_8)).append("&");
        sb.append("state=").append(URLEncoder.encode(state, StandardCharsets.UTF_8));
        return sb.toString();
    }

    private void appendParam(StringBuilder sb, String key, String value, boolean last) {
        sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
        sb.append("=");
        sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        if (!last) {
            sb.append("&");
        }
    }

    // ====== Token Exchange (1:1 port of Go config.Exchange) ======

    /**
     * Exchanges an authorization code for access and refresh tokens.
     * Uses form-encoded POST per Google's OAuth2 token endpoint requirements.
     * <p>
     * 1:1 port of Go oauth2.Config.Exchange().
     *
     * @param code The authorization code received from OAuth callback
     * @return The authentication result with tokens
     * @throws IOException if the token exchange request fails
     */
    public AuthResult exchangeCodeForTokens(String code) throws IOException {
        if (code == null || code.isEmpty()) {
            throw new IllegalArgumentException("authorization code is required");
        }

        // Build form-encoded body (1:1 port of Go oauth2 exchange)
        Map<String, String> params = new HashMap<>();
        params.put("code", code);
        params.put("client_id", getClientIdFromEnv());
        String clientSecret = getClientSecretFromEnv();
        if (!clientSecret.isEmpty()) {
            params.put("client_secret", clientSecret);
        }
        params.put("redirect_uri", REDIRECT_URI);
        params.put("grant_type", "authorization_code");

        String responseBody = postForm(TOKEN_URL, params);
        Log.d(TAG, "Token exchange response: " + responseBody);

        try {
            JSONObject json = new JSONObject(responseBody);
            String accessToken = json.optString("access_token", "");
            String refreshToken = json.optString("refresh_token", "");
            int expiresIn = json.optInt("expires_in", 0);
            String tokenType = json.optString("token_type", "Bearer");

            if (accessToken.isEmpty()) {
                throw new IOException("token exchange returned empty access_token");
            }

            // Build the raw token map (1:1 port of Go oauth2.Token marshaling with
            // additional fields from createTokenStorage)
            Map<String, Object> tokenMap = new HashMap<>();
            tokenMap.put("access_token", accessToken);
            tokenMap.put("token_type", tokenType);
            if (!refreshToken.isEmpty()) {
                tokenMap.put("refresh_token", refreshToken);
            }
            if (expiresIn > 0) {
                tokenMap.put("expiry", Instant.now().plusSeconds(expiresIn).toString());
            }
            // Google-specific fields (1:1 port of Go createTokenStorage)
            tokenMap.put("token_uri", TOKEN_URL);
            tokenMap.put("client_id", getClientIdFromEnv());
            if (!clientSecret.isEmpty()) {
                tokenMap.put("client_secret", clientSecret);
            }
            tokenMap.put("scopes", SCOPES);
            tokenMap.put("universe_domain", "googleapis.com");

            TokenData tokenData = new TokenData();
            tokenData.accessToken = accessToken;
            tokenData.refreshToken = refreshToken;
            tokenData.expiresIn = expiresIn;
            tokenData.expireAt = System.currentTimeMillis() + (long) expiresIn * 1000L;

            return new AuthResult(tokenData);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse token response", e);
            throw new IOException("Failed to parse token response: " + e.getMessage(), e);
        }
    }

    // ====== User Info (1:1 port of Go createTokenStorage user info fetch) ======

    /**
     * Fetches the authenticated user's email from Google's userinfo endpoint.
     * <p>
     * 1:1 port of Go createTokenStorage's user info HTTP request.
     *
     * @param accessToken The OAuth2 access token for authentication
     * @return The user's email address, or null if unavailable
     * @throws IOException if the request fails
     */
    public String fetchUserEmail(String accessToken) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(USER_INFO_URL).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            int responseCode = conn.getResponseCode();
            StringBuilder body = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(
                            responseCode >= 200 && responseCode < 300
                                    ? conn.getInputStream() : conn.getErrorStream(),
                            StandardCharsets.UTF_8))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    body.append(line);
                }
            }

            String responseBody = body.toString();
            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("get user info request failed with status "
                        + responseCode + ": " + responseBody);
            }

            JSONObject json = new JSONObject(responseBody);
            String email = json.optString("email", "");
            if (!email.isEmpty()) {
                Log.d(TAG, "Authenticated user email: " + email);
            } else {
                Log.w(TAG, "Failed to get user email from token");
            }
            return email.isEmpty() ? null : email;

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "Failed to fetch user info", e);
            return null;
        } finally {
            conn.disconnect();
        }
    }

    // ====== Token Storage Creation (1:1 port of Go createTokenStorage) ======

    /**
     * Creates a new GeminiTokenStorage from an AuthResult and project ID.
     * Fetches the user's email using the provided token and populates the storage structure.
     * <p>
     * 1:1 port of Go createTokenStorage().
     *
     * @param bundle    The authentication result containing token data
     * @param projectId The Google Cloud Project ID to associate with this token
     * @return A new token storage instance with user information
     * @throws IOException if the token storage creation fails
     */
    public GeminiTokenStorage createTokenStorage(AuthResult bundle, String projectId) throws IOException {
        if (bundle == null || bundle.tokenData == null) {
            throw new IllegalArgumentException("auth bundle is required");
        }

        String email = fetchUserEmail(bundle.tokenData.accessToken);

        // Build the token map (1:1 port of Go createTokenStorage)
        Map<String, Object> tokenMap = new HashMap<>();
        if (bundle.tokenData.accessToken != null) {
            tokenMap.put("access_token", bundle.tokenData.accessToken);
        }
        if (bundle.tokenData.refreshToken != null) {
            tokenMap.put("refresh_token", bundle.tokenData.refreshToken);
        }
        if (bundle.tokenData.expiresIn > 0) {
            tokenMap.put("expiry", Instant.now().plusSeconds(bundle.tokenData.expiresIn).toString());
        }
        tokenMap.put("token_type", "Bearer");
        tokenMap.put("token_uri", TOKEN_URL);
        tokenMap.put("client_id", getClientIdFromEnv());
        String clientSecret = getClientSecretFromEnv();
        if (!clientSecret.isEmpty()) {
            tokenMap.put("client_secret", clientSecret);
        }
        tokenMap.put("scopes", SCOPES);
        tokenMap.put("universe_domain", "googleapis.com");

        GeminiTokenStorage storage = new GeminiTokenStorage();
        storage.token = tokenMap;
        storage.projectId = projectId != null ? projectId : "";
        storage.email = email != null ? email : "";
        storage.auto = false;
        storage.checked = false;
        storage.type = "gemini";

        return storage;
    }

    // ====== Token Refresh (1:1 port of Go oauth2 token refresh) ======

    /**
     * Refreshes the access token using a refresh token.
     * Uses form-encoded POST per Google's OAuth2 token endpoint.
     * Uses singleflight dedup for concurrent calls with the same refresh token.
     * <p>
     * 1:1 port of Go oauth2.Config.Client() token refresh.
     *
     * @param refreshToken The refresh token to use for getting a new access token
     * @return The authentication result with refreshed tokens
     * @throws IOException if the token refresh fails
     */
    public TokenData refreshTokens(String refreshToken) throws IOException {
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new IllegalArgumentException("refresh token is required");
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
                        throw new IOException("token refresh interrupted", e);
                    }
                }
            }
            RefreshResult result = existing.get();
            if (result.error != null) {
                if (result.error instanceof IOException) {
                    throw (IOException) result.error;
                }
                throw new IOException("token refresh failed", result.error);
            }
            return result.tokenData;
        }

        // We are the designated refresher for this token
        try {
            TokenData tokenData = refreshTokensSingleFlight(rt);
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
            throw new IOException("token refresh failed", e);
        } finally {
            refreshGroup.remove(rt, ref);
        }
    }

    /**
     * Performs the actual HTTP request to refresh tokens.
     * 1:1 port of Go oauth2 token refresh via form-encoded POST.
     */
    private TokenData refreshTokensSingleFlight(String refreshToken) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("client_id", getClientIdFromEnv());
        String clientSecret = getClientSecretFromEnv();
        if (!clientSecret.isEmpty()) {
            params.put("client_secret", clientSecret);
        }
        params.put("grant_type", "refresh_token");
        params.put("refresh_token", refreshToken);

        String responseBody = postForm(TOKEN_URL, params);
        Log.d(TAG, "Token refresh response: " + responseBody);

        try {
            JSONObject json = new JSONObject(responseBody);
            String accessToken = json.optString("access_token", "");
            int expiresIn = json.optInt("expires_in", 0);
            String newRefreshToken = json.optString("refresh_token", refreshToken);
            String tokenType = json.optString("token_type", "Bearer");

            if (accessToken.isEmpty()) {
                throw new IOException("refresh returned empty access_token");
            }

            TokenData tokenData = new TokenData();
            tokenData.accessToken = accessToken;
            tokenData.refreshToken = newRefreshToken;
            tokenData.expiresIn = expiresIn;
            tokenData.expireAt = System.currentTimeMillis() + (long) expiresIn * 1000L;

            return tokenData;

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "Failed to parse refresh response", e);
            throw new IOException("Failed to parse refresh response: " + e.getMessage(), e);
        }
    }

    // ====== Refresh with Retry ======

    /**
     * Refreshes tokens with automatic retry logic.
     * Implements exponential backoff retry logic for token refresh operations.
     *
     * @param refreshToken The refresh token to use
     * @param maxRetries   The maximum number of retry attempts
     * @return The refreshed token data
     * @throws IOException if all retry attempts fail
     */
    public TokenData refreshTokensWithRetry(String refreshToken, int maxRetries) throws IOException {
        Exception lastError = null;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            if (attempt > 0) {
                try {
                    Thread.sleep((long) attempt * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("token refresh retry interrupted", e);
                }
            }

            try {
                TokenData tokenData = refreshTokens(refreshToken);
                if (tokenData != null) {
                    return tokenData;
                }
                lastError = new IOException("token refresh returned null");
            } catch (Exception e) {
                lastError = e;
                Log.w(TAG, "Token refresh attempt " + (attempt + 1) + " failed: " + e.getMessage());
            }
        }

        throw new IOException(
                "token refresh failed after " + maxRetries + " attempts",
                lastError);
    }

    // ====== Callback Server (1:1 port of Go getTokenFromWeb) ======

    /**
     * Starts a local HTTP server on the callback port, opens the authorization URL,
     * and waits for the OAuth callback. After 15 seconds, prompts the user to manually
     * paste the callback URL. Times out after 5 minutes.
     * <p>
     * 1:1 port of Go getTokenFromWeb().
     *
     * @param state The OAuth state parameter for CSRF protection
     * @return The authorization code from the callback
     * @throws IOException          if the callback flow fails
     * @throws InterruptedException if the thread is interrupted
     */
    public String getTokenFromWeb(String state) throws IOException, InterruptedException {
        return getTokenFromWeb(state, null);
    }

    /**
     * getTokenFromWeb with WebLoginOptions.
     * <p>
     * 1:1 port of Go getTokenFromWeb() with full opts support.
     *
     * @param state The OAuth state parameter for CSRF protection
     * @param opts  Options to customize the web login flow, or null for defaults
     * @return The authorization code from the callback
     * @throws IOException          if the callback flow fails
     * @throws InterruptedException if the thread is interrupted
     */
    public String getTokenFromWeb(String state, WebLoginOptions opts) throws IOException, InterruptedException {
        // Determine callback port (1:1 port of Go callbackPort resolution)
        int callbackPort = DEFAULT_CALLBACK_PORT;
        if (opts != null && opts.callbackPort > 0) {
            callbackPort = opts.callbackPort;
        }
        final String callbackURL = "http://localhost:" + callbackPort + "/oauth2callback";

        // Generate the authorization URL (1:1 port of Go config.AuthCodeURL)
        // In the Go code, config.RedirectURL is set to callbackURL and then
        // config.AuthCodeURL is called. We inline the same logic.
        String authURL = AUTH_URL
                + "?client_id=" + URLEncoder.encode(getClientIdFromEnv(), StandardCharsets.UTF_8)
                + "&response_type=" + URLEncoder.encode("code", StandardCharsets.UTF_8)
                + "&redirect_uri=" + URLEncoder.encode(callbackURL, StandardCharsets.UTF_8)
                + "&scope=" + URLEncoder.encode(String.join(" ", SCOPES), StandardCharsets.UTF_8)
                + "&access_type=" + URLEncoder.encode("offline", StandardCharsets.UTF_8)
                + "&prompt=" + URLEncoder.encode("consent", StandardCharsets.UTF_8)
                + "&state=" + URLEncoder.encode(state, StandardCharsets.UTF_8);

        // Start local callback server (1:1 port of Go http.Server)
        // Uses a simple ServerSocket-based HTTP server since com.sun.net.httpserver
        // is not available on Android.
        final ServerSocket serverSocket = new ServerSocket(callbackPort, 1,
                java.net.InetAddress.getByName("localhost"));

        // Result holders for the callback thread
        final Object lock = new Object();
        final String[] authCodeRef = new String[1];
        final Exception[] errorRef = new Exception[1];
        final boolean[] codeReceived = new boolean[1];

        // Start a thread to accept the callback HTTP request
        // (1:1 port of Go goroutine with server.ListenAndServe)
        Thread callbackThread = new Thread(() -> {
            try {
                Socket clientSocket = serverSocket.accept();
                clientSocket.setSoTimeout(30000);

                // Read the HTTP request (1:1 port of Go http.HandleFunc)
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
                String requestLine = reader.readLine();
                Log.d(TAG, "Callback request: " + requestLine);

                if (requestLine == null) {
                    synchronized (lock) {
                        errorRef[0] = new IOException("Empty callback request");
                        codeReceived[0] = true;
                        lock.notifyAll();
                    }
                    return;
                }

                // Parse the query string from the request line
                // GET /oauth2callback?code=...&state=... HTTP/1.1
                String queryString = "";
                String[] parts = requestLine.split(" ");
                if (parts.length >= 2) {
                    String path = parts[1];
                    int qIdx = path.indexOf('?');
                    if (qIdx >= 0) {
                        queryString = path.substring(qIdx + 1);
                    }
                }

                // Consume remaining headers
                String line;
                while ((line = reader.readLine()) != null && !line.isEmpty()) {
                    // headers consumed
                }

                // Parse query parameters
                Map<String, String> queryParams = parseQueryString(queryString);

                // Check for error parameter (1:1 port of Go r.URL.Query().Get("error"))
                String error = queryParams.get("error");
                if (error != null && !error.isEmpty()) {
                    String responseBody = "Authentication failed: " + error;
                    String httpResponse = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html; charset=UTF-8\r\n"
                            + "Content-Length: " + responseBody.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                            + "Connection: close\r\n\r\n"
                            + responseBody;
                    OutputStream os = clientSocket.getOutputStream();
                    os.write(httpResponse.getBytes(StandardCharsets.UTF_8));
                    os.flush();

                    synchronized (lock) {
                        errorRef[0] = new IOException("authentication failed via callback: " + error);
                        codeReceived[0] = true;
                        lock.notifyAll();
                    }
                    return;
                }

                // Check for code parameter (1:1 port of Go r.URL.Query().Get("code"))
                String code = queryParams.get("code");
                if (code == null || code.isEmpty()) {
                    String responseBody = "Authentication failed: code not found.";
                    String httpResponse = "HTTP/1.1 200 OK\r\n"
                            + "Content-Type: text/html; charset=UTF-8\r\n"
                            + "Content-Length: " + responseBody.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                            + "Connection: close\r\n\r\n"
                            + responseBody;
                    OutputStream os = clientSocket.getOutputStream();
                    os.write(httpResponse.getBytes(StandardCharsets.UTF_8));
                    os.flush();

                    synchronized (lock) {
                        errorRef[0] = new IOException("code not found in callback");
                        codeReceived[0] = true;
                        lock.notifyAll();
                    }
                    return;
                }

                // Write success response (1:1 port of Go Fprint)
                String responseBody = "<html><body><h1>Authentication successful!</h1>"
                        + "<p>You can close this window.</p></body></html>";
                String httpResponse = "HTTP/1.1 200 OK\r\n"
                        + "Content-Type: text/html; charset=UTF-8\r\n"
                        + "Content-Length: " + responseBody.getBytes(StandardCharsets.UTF_8).length + "\r\n"
                        + "Connection: close\r\n\r\n"
                        + responseBody;
                OutputStream os = clientSocket.getOutputStream();
                os.write(httpResponse.getBytes(StandardCharsets.UTF_8));
                os.flush();

                // Send the code to the main thread (1:1 port of Go codeChan <- code)
                synchronized (lock) {
                    authCodeRef[0] = code;
                    codeReceived[0] = true;
                    lock.notifyAll();
                }

            } catch (Exception e) {
                synchronized (lock) {
                    errorRef[0] = e;
                    codeReceived[0] = true;
                    lock.notifyAll();
                }
            } finally {
                try {
                    serverSocket.close();
                } catch (IOException ignored) {
                }
            }
        });
        callbackThread.setDaemon(true);
        callbackThread.start();

        // Open browser or print instructions (1:1 port of Go browser handling)
        boolean noBrowser = (opts != null) && opts.noBrowser;

        if (!noBrowser) {
            Log.d(TAG, "Opening browser for authentication...");
            // Note: Android browser opening is handled at the app level
            Log.i(TAG, "Please open this URL in your browser:\n\n" + authURL + "\n");
        } else {
            Log.i(TAG, "Please open this URL in your browser:\n\n" + authURL + "\n");
        }

        Log.i(TAG, "Waiting for authentication callback...");

        // Wait for the callback with timeout and optional manual prompt
        // (1:1 port of Go select with channels and timers)
        long startTime = System.currentTimeMillis();
        long timeoutTime = startTime + CALLBACK_TIMEOUT_MS;
        long promptTime = startTime + MANUAL_PROMPT_DELAY_MS;
        boolean prompted = false;

        synchronized (lock) {
            while (!codeReceived[0]) {
                long now = System.currentTimeMillis();

                // Check timeout (1:1 port of Go <-timeoutTimer.C)
                if (now >= timeoutTime) {
                    throw new IOException("oauth flow timed out");
                }

                // After 15 seconds, prompt for manual paste (1:1 port of Go manualPromptTimer)
                if (!prompted && now >= promptTime && opts != null && opts.prompt != null) {
                    prompted = true;
                    String input = opts.prompt.apply(
                            "Paste the Gemini callback URL (or press Enter to keep waiting): ");
                    if (input != null && !input.trim().isEmpty()) {
                        OAuthCallbackResult parsed = parseOAuthCallback(input.trim());
                        if (parsed != null) {
                            if (parsed.error != null && !parsed.error.isEmpty()) {
                                throw new IOException("authentication failed via callback: " + parsed.error);
                            }
                            if (parsed.code != null && !parsed.code.isEmpty()) {
                                authCodeRef[0] = parsed.code;
                                codeReceived[0] = true;
                                break;
                            }
                        }
                        // If parsed is null or code is empty, continue waiting
                    }
                }

                long waitTime = Math.min(timeoutTime - System.currentTimeMillis(), 1000L);
                if (waitTime <= 0) {
                    throw new IOException("oauth flow timed out");
                }
                try {
                    lock.wait(waitTime);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }

            if (errorRef[0] != null) {
                if (errorRef[0] instanceof IOException) {
                    throw (IOException) errorRef[0];
                }
                throw new IOException("oauth flow failed", errorRef[0]);
            }
        }

        // Shutdown the server (1:1 port of Go server.Shutdown)
        // Already closed in the finally block of the callback thread

        String authCode = authCodeRef[0];
        if (authCode == null || authCode.isEmpty()) {
            throw new IOException("failed to get authorization code from web");
        }

        Log.i(TAG, "Authentication successful.");
        return authCode;
    }

    // ====== Query String Parsing ======

    /**
     * Parses a URL query string into a map of key-value pairs.
     */
    private Map<String, String> parseQueryString(String query) {
        Map<String, String> params = new HashMap<>();
        if (query == null || query.isEmpty()) {
            return params;
        }
        String[] pairs = query.split("&");
        for (String pair : pairs) {
            int eqIdx = pair.indexOf('=');
            if (eqIdx > 0) {
                String key = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(eqIdx + 1), StandardCharsets.UTF_8);
                params.put(key, value);
            }
        }
        return params;
    }

    // ====== OAuth Callback URL Parsing (1:1 port of Go misc.ParseOAuthCallback) ======

    /**
     * Parses an OAuth callback URL string to extract the authorization code, state, and error.
     * <p>
     * 1:1 port of Go misc.ParseOAuthCallback().
     *
     * @param input The raw callback URL string
     * @return Parsed callback result, or null if parsing fails
     */
    public static OAuthCallbackResult parseOAuthCallback(String input) {
        if (input == null || input.trim().isEmpty()) {
            return null;
        }

        try {
            URL url = new URL(input.trim());
            OAuthCallbackResult result = new OAuthCallbackResult();

            String query = url.getQuery();
            if (query != null) {
                String[] pairs = query.split("&");
                for (String pair : pairs) {
                    int eqIdx = pair.indexOf('=');
                    if (eqIdx > 0) {
                        String key = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(pair.substring(eqIdx + 1), StandardCharsets.UTF_8);
                        if ("code".equals(key)) {
                            result.code = value;
                        } else if ("state".equals(key)) {
                            result.state = value;
                        } else if ("error".equals(key)) {
                            result.error = value;
                        }
                    }
                }
            }

            // Also check fragment (hash) parameters
            String fragment = url.getRef();
            if (fragment != null) {
                String[] pairs = fragment.split("&");
                for (String pair : pairs) {
                    int eqIdx = pair.indexOf('=');
                    if (eqIdx > 0) {
                        String key = URLDecoder.decode(pair.substring(0, eqIdx), StandardCharsets.UTF_8);
                        String value = URLDecoder.decode(pair.substring(eqIdx + 1), StandardCharsets.UTF_8);
                        if ("code".equals(key) && result.code == null) {
                            result.code = value;
                        } else if ("state".equals(key) && result.state == null) {
                            result.state = value;
                        } else if ("error".equals(key) && result.error == null) {
                            result.error = value;
                        }
                    }
                }
            }

            return result;
        } catch (Exception e) {
            Log.w(TAG, "Failed to parse OAuth callback URL: " + e.getMessage());
            return null;
        }
    }

    // ====== Token Storage to JSON (serialization helper) ======

    /**
     * Converts a GeminiTokenStorage to a JSONObject for serialization.
     * Merges any injected metadata into the top-level JSON object.
     * <p>
     * 1:1 port of Go SaveTokenToFile() with misc.MergeMetadata.
     *
     * @param storage The token storage to serialize
     * @return A JSONObject representation of the token storage
     */
    public JSONObject tokenStorageToJson(GeminiTokenStorage storage) {
        JSONObject json = new JSONObject();
        try {
            // Serialize the token map (1:1 port of Go json.Marshal(ts.Token))
            if (storage.token != null) {
                JSONObject tokenJson = new JSONObject();
                for (Map.Entry<String, Object> entry : storage.token.entrySet()) {
                    Object val = entry.getValue();
                    if (val instanceof String[]) {
                        // Handle scopes array (1:1 port of Go []string serialization)
                        String[] arr = (String[]) val;
                        StringBuilder sb = new StringBuilder();
                        for (int i = 0; i < arr.length; i++) {
                            if (i > 0) sb.append(" ");
                            sb.append(arr[i]);
                        }
                        tokenJson.put(entry.getKey(), sb.toString());
                    } else {
                        tokenJson.put(entry.getKey(), val);
                    }
                }
                json.put("token", tokenJson);
            }

            // Top-level fields (1:1 port of Go struct fields)
            json.put("project_id", storage.projectId != null ? storage.projectId : "");
            json.put("email", storage.email != null ? storage.email : "");
            json.put("auto", storage.auto);
            json.put("checked", storage.checked);
            json.put("type", "gemini");

            // Merge metadata (1:1 port of Go misc.MergeMetadata)
            if (storage.metadata != null) {
                for (Map.Entry<String, Object> entry : storage.metadata.entrySet()) {
                    json.put(entry.getKey(), entry.getValue());
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "Failed to serialize token storage", e);
        }
        return json;
    }

    // ====== Credential File Name (1:1 port of gemini_token.go CredentialFileName) ======

    /**
     * Returns the filename used to persist Gemini CLI credentials.
     * When projectID represents multiple projects (comma-separated or literal "all"),
     * the suffix is normalized to "all" and a "gemini-" prefix is enforced to keep
     * web and CLI generated files consistent.
     * <p>
     * 1:1 port of Go CredentialFileName().
     *
     * @param email                 The authenticated user's email address
     * @param projectId             The Google Cloud Project ID
     * @param includeProviderPrefix Whether to include the "gemini-" provider prefix
     * @return The credential filename
     */
    public static String credentialFileName(String email, String projectId, boolean includeProviderPrefix) {
        email = email != null ? email.trim() : "";
        String project = projectId != null ? projectId.trim() : "";

        // Normalize "all" or comma-separated projects (1:1 port of Go)
        if ("all".equalsIgnoreCase(project) || project.contains(",")) {
            return "gemini-" + email + "-all.json";
        }

        String prefix = "";
        if (includeProviderPrefix) {
            prefix = "gemini-";
        }
        return prefix + email + "-" + project + ".json";
    }

    // ====== Logging ======


}