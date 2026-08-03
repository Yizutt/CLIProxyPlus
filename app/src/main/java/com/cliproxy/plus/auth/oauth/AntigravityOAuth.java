package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;
import org.json.JSONArray;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;


/**
 * AntigravityOAuth handles OAuth2 authentication for the Antigravity (Google Cloud Code) provider.
 * <p>
 * Provides methods for generating authorization URLs, exchanging authorization codes for tokens,
 * fetching user info, and interacting with the Cloud Code Assist API (loadCodeAssist, onboardUser).
 * <p>
 * 1:1 port of internal/auth/antigravity/ from CLIProxyAPIPlus.
 */
public class AntigravityOAuth {

    private static final String TAG = "AntigravityOAuth";

    // ========================================================================
    // OAuth Client Credentials and Configuration
    // 1:1 port of constants.go
    // ========================================================================

    public static final String CLIENT_ID_ENV = "CLIPROXY_ANTIGRAVITY_OAUTH_CLIENT_ID";
    public static final String CLIENT_SECRET_ENV = "CLIPROXY_ANTIGRAVITY_OAUTH_CLIENT_SECRET";
    public static final String DEFAULT_CLIENT_ID = "";
    public static final String DEFAULT_CLIENT_SECRET = "";
    public static final int CALLBACK_PORT = 51121;

    // ========================================================================
    // OAuth2 Endpoints
    // 1:1 port of constants.go
    // ========================================================================

    public static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
    public static final String AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
    public static final String USER_INFO_ENDPOINT = "https://www.googleapis.com/oauth2/v2/userinfo?alt=json";

    // ========================================================================
    // Antigravity API Configuration
    // 1:1 port of constants.go
    // ========================================================================

    public static final String API_ENDPOINT = "https://cloudcode-pa.googleapis.com";
    public static final String DAILY_API_ENDPOINT = "https://daily-cloudcode-pa.googleapis.com";
    public static final String API_VERSION = "v1internal";

    // ========================================================================
    // OAuth Scopes
    // 1:1 port of constants.go var Scopes
    // ========================================================================

    public static final String[] SCOPES = {
            "https://www.googleapis.com/auth/cloud-platform",
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/userinfo.profile",
            "https://www.googleapis.com/auth/cclog",
            "https://www.googleapis.com/auth/experimentsandconfigs"
    };

    // ========================================================================
    // User-Agent Constants
    // 1:1 port of misc/antigravity_version.go
    // ========================================================================

    private static final String ANTIGRAVITY_FALLBACK_VERSION = "2.2.1";
    private static final String ANTIGRAVITY_HUB_PLATFORM = "darwin/arm64";
    private static final String ANTIGRAVITY_NODE_API_CLIENT_UA = "google-api-nodejs-client/10.3.0";
    private static final String ANTIGRAVITY_GOOG_API_CLIENT_UA = "gl-node/22.21.1";

    // ========================================================================
    // TokenResponse - 1:1 port of auth.go TokenResponse struct
    // ========================================================================

    public static class TokenResponse {
        public String accessToken;
        public String refreshToken;
        public long expiresIn;
        public String tokenType;

        public static TokenResponse fromJSON(JSONObject json) {
            TokenResponse t = new TokenResponse();
            t.accessToken = json.optString("access_token", null);
            t.refreshToken = json.optString("refresh_token", null);
            t.expiresIn = json.optLong("expires_in", 0);
            t.tokenType = json.optString("token_type", null);
            return t;
        }
    }

    // ========================================================================
    // UserInfo - 1:1 port of auth.go userInfo struct
    // ========================================================================

    private static class UserInfo {
        public String email;

        public static UserInfo fromJSON(JSONObject json) {
            UserInfo u = new UserInfo();
            u.email = json.optString("email", null);
            return u;
        }
    }

    // ========================================================================
    // OAuthClientID / OAuthClientSecret - 1:1 port of constants.go
    // ========================================================================

    /**
     * Returns the OAuth client ID, checking environment variable first, then default.
     * 1:1 port of Go OAuthClientID().
     */
    public static String getOAuthClientID() {
        String value = System.getenv(CLIENT_ID_ENV);
        if (value != null) {
            value = value.trim();
            if (!value.isEmpty()) {
                return value;
            }
        }
        return DEFAULT_CLIENT_ID;
    }

    /**
     * Returns the OAuth client secret, checking environment variable first, then default.
     * 1:1 port of Go OAuthClientSecret().
     */
    public static String getOAuthClientSecret() {
        String value = System.getenv(CLIENT_SECRET_ENV);
        if (value != null) {
            value = value.trim();
            if (!value.isEmpty()) {
                return value;
            }
        }
        return DEFAULT_CLIENT_SECRET;
    }

    // ========================================================================
    // User-Agent helpers - 1:1 port of auth.go and misc/antigravity_version.go
    // ========================================================================

    /**
     * Returns the short Antigravity runtime User-Agent.
     * 1:1 port of Go AntigravityRequestUserAgent("") which returns
     * "antigravity/hub/{version} {platform}".
     */
    private String shortUserAgent() {
        return "antigravity/hub/" + ANTIGRAVITY_FALLBACK_VERSION + " " + ANTIGRAVITY_HUB_PLATFORM;
    }

    /**
     * Returns the long Antigravity control-plane User-Agent for onboardUser requests.
     * 1:1 port of Go AntigravityOnboardUserUserAgent("") which returns
     * "antigravity/hub/{version} {platform} google-api-nodejs-client/{version}".
     */
    private String nodeUserAgent() {
        return shortUserAgent() + " " + ANTIGRAVITY_NODE_API_CLIENT_UA;
    }

    // ========================================================================
    // Metadata helpers - 1:1 port of auth.go
    // ========================================================================

    /**
     * Returns metadata for loadCodeAssist requests.
     * 1:1 port of Go antigravityLoadCodeAssistMetadata().
     */
    private static JSONObject antigravityLoadCodeAssistMetadata() {
        JSONObject meta = new JSONObject();
        try {
            meta.put("ideType", "ANTIGRAVITY");
        } catch (Exception e) {
            Log.e(TAG, "Failed to build loadCodeAssist metadata", e);
        }
        return meta;
    }

    /**
     * Returns metadata for control-plane (onboardUser) requests.
     * 1:1 port of Go antigravityControlPlaneMetadata().
     */
    private JSONObject antigravityControlPlaneMetadata(String userAgent) {
        JSONObject meta = new JSONObject();
        try {
            meta.put("ide_type", "ANTIGRAVITY");
            meta.put("ide_version", antigravityVersionFromUserAgent(userAgent));
            meta.put("ide_name", "antigravity");
        } catch (Exception e) {
            Log.e(TAG, "Failed to build control plane metadata", e);
        }
        return meta;
    }

    /**
     * Extracts the Cloud Code Companion project ID from a response data map.
     * Checks keys: cloudaicompanionProject, projectId, project.
     * 1:1 port of Go extractCloudaicompanionProject().
     */
    private static String extractCloudaicompanionProject(JSONObject data) {
        if (data == null) {
            return "";
        }
        String[] keys = {"cloudaicompanionProject", "projectId", "project"};
        for (String key : keys) {
            Object value = data.opt(key);
            if (value instanceof String) {
                String trimmed = ((String) value).trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            } else if (value instanceof JSONObject) {
                JSONObject obj = (JSONObject) value;
                String id = obj.optString("id", null);
                if (id != null) {
                    String trimmed = id.trim();
                    if (!trimmed.isEmpty()) {
                        return trimmed;
                    }
                }
            }
        }
        return "";
    }

    /**
     * Returns the default tier ID from a loadCodeAssist response, falling back to "free-tier".
     * 1:1 port of Go defaultAntigravityTierID().
     */
    private static String defaultAntigravityTierID(JSONObject loadResp) {
        JSONArray tiers = loadResp.optJSONArray("allowedTiers");
        if (tiers != null) {
            for (int i = 0; i < tiers.length(); i++) {
                JSONObject tier = tiers.optJSONObject(i);
                if (tier == null) {
                    continue;
                }
                if (tier.optBoolean("isDefault", false)) {
                    String id = tier.optString("id", null);
                    if (id != null) {
                        String trimmed = id.trim();
                        if (!trimmed.isEmpty()) {
                            return trimmed;
                        }
                    }
                }
            }
        }
        JSONObject currentTier = loadResp.optJSONObject("currentTier");
        if (currentTier != null) {
            String id = currentTier.optString("id", null);
            if (id != null) {
                String trimmed = id.trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return "free-tier";
    }

    /**
     * Extracts the Antigravity version from a User-Agent string.
     * 1:1 port of Go AntigravityVersionFromUserAgent().
     */
    private static String antigravityVersionFromUserAgent(String userAgent) {
        if (userAgent == null) {
            userAgent = "";
        }
        String base = antigravityBaseUserAgent(userAgent);
        String lower = base.toLowerCase();
        if (lower.startsWith("antigravity/hub/")) {
            String rest = base.substring("antigravity/hub/".length());
            int idx = indexOfAny(rest, " \t");
            if (idx >= 0) {
                rest = rest.substring(0, idx);
            }
            rest = rest.trim();
            if (rest.isEmpty()) {
                return ANTIGRAVITY_FALLBACK_VERSION;
            }
            return rest;
        }
        final String legacyPrefix = "antigravity/";
        if (!lower.startsWith(legacyPrefix)) {
            return ANTIGRAVITY_FALLBACK_VERSION;
        }
        String rest = base.substring(legacyPrefix.length());
        int idx = indexOfAny(rest, " \t");
        if (idx >= 0) {
            rest = rest.substring(0, idx);
        }
        rest = rest.trim();
        if (rest.isEmpty()) {
            return ANTIGRAVITY_FALLBACK_VERSION;
        }
        return rest;
    }

    private static String antigravityBaseUserAgent(String userAgent) {
        if (userAgent == null) {
            userAgent = "";
        }
        userAgent = userAgent.trim();
        if (userAgent.isEmpty()) {
            return "antigravity/hub/" + ANTIGRAVITY_FALLBACK_VERSION + " " + ANTIGRAVITY_HUB_PLATFORM;
        }
        String lower = userAgent.toLowerCase();
        if (lower.startsWith("antigravity/hub/") || lower.startsWith("antigravity/")) {
            int idx = lower.indexOf(" google-api-nodejs-client/");
            if (idx >= 0) {
                String trimmed = userAgent.substring(0, idx).trim();
                if (!trimmed.isEmpty()) {
                    return trimmed;
                }
            }
        }
        return userAgent;
    }

    private static int indexOfAny(String str, String chars) {
        for (int i = 0; i < str.length(); i++) {
            if (chars.indexOf(str.charAt(i)) >= 0) {
                return i;
            }
        }
        return -1;
    }

    // ========================================================================
    // BuildAuthURL - 1:1 port of auth.go BuildAuthURL()
    // ========================================================================

    /**
     * Generates the OAuth authorization URL.
     * 1:1 port of Go AntigravityAuth.BuildAuthURL().
     *
     * @param state       OAuth state parameter for CSRF protection.
     * @param redirectURI Redirect URI; if null/empty defaults to http://localhost:{CALLBACK_PORT}/oauth-callback.
     * @return The full authorization URL.
     */
    public String buildAuthURL(String state, String redirectURI) {
        if (redirectURI == null || redirectURI.trim().isEmpty()) {
            redirectURI = "http://localhost:" + CALLBACK_PORT + "/oauth-callback";
        }
        try {
            StringBuilder sb = new StringBuilder(AUTH_ENDPOINT);
            sb.append("?");
            sb.append("access_type=").append(URLEncoder.encode("offline", "UTF-8"));
            sb.append("&client_id=").append(URLEncoder.encode(getOAuthClientID(), "UTF-8"));
            sb.append("&prompt=").append(URLEncoder.encode("consent", "UTF-8"));
            sb.append("&redirect_uri=").append(URLEncoder.encode(redirectURI, "UTF-8"));
            sb.append("&response_type=").append(URLEncoder.encode("code", "UTF-8"));
            sb.append("&scope=").append(URLEncoder.encode(joinScopes(SCOPES, " "), "UTF-8"));
            sb.append("&state=").append(URLEncoder.encode(state, "UTF-8"));
            return sb.toString();
        } catch (Exception e) {
            Log.e(TAG, "Failed to build auth URL", e);
            return "";
        }
    }

    private static String joinScopes(String[] scopes, String delimiter) {
        if (scopes == null || scopes.length == 0) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < scopes.length; i++) {
            if (i > 0) sb.append(delimiter);
            sb.append(scopes[i]);
        }
        return sb.toString();
    }

    // ========================================================================
    // ExchangeCodeForTokens - 1:1 port of auth.go ExchangeCodeForTokens()
    // ========================================================================

    /**
     * Exchanges an authorization code for access and refresh tokens.
     * Uses form-encoded POST to the token endpoint.
     * 1:1 port of Go AntigravityAuth.ExchangeCodeForTokens().
     *
     * @param code        The authorization code from the OAuth callback.
     * @param redirectURI The redirect URI used in the auth request.
     * @return TokenResponse containing access and refresh tokens.
     * @throws AntigravityException if the exchange fails.
     */
    public TokenResponse exchangeCodeForTokens(String code, String redirectURI) throws AntigravityException {
        // Build form-encoded body (1:1 port of Go url.Values)
        StringBuilder bodyBuilder = new StringBuilder();
        try {
            appendFormParam(bodyBuilder, "code", code, false);
            appendFormParam(bodyBuilder, "client_id", getOAuthClientID(), false);
            appendFormParam(bodyBuilder, "client_secret", getOAuthClientSecret(), false);
            appendFormParam(bodyBuilder, "redirect_uri", redirectURI, false);
            appendFormParam(bodyBuilder, "grant_type", "authorization_code", true);
        } catch (Exception e) {
            throw new AntigravityException("antigravity token exchange: build form: " + e.getMessage(), e);
        }
        byte[] postData = bodyBuilder.toString().getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = null;
        try {
            URL url = new URL(TOKEN_ENDPOINT);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int statusCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, statusCode);

            if (statusCode < 200 || statusCode >= 300) {
                String trimmedBody = responseBody != null ? responseBody.trim() : "";
                if (trimmedBody.isEmpty()) {
                    throw new AntigravityException("antigravity token exchange: request failed: status " + statusCode);
                }
                throw new AntigravityException("antigravity token exchange: request failed: status " + statusCode + ": " + trimmedBody);
            }

            try {
                JSONObject json = new JSONObject(responseBody);
                return TokenResponse.fromJSON(json);
            } catch (Exception e) {
                throw new AntigravityException("antigravity token exchange: decode response: " + e.getMessage(), e);
            }
        } catch (AntigravityException e) {
            throw e;
        } catch (IOException e) {
            throw new AntigravityException("antigravity token exchange: execute request: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // FetchUserInfo - 1:1 port of auth.go FetchUserInfo()
    // ========================================================================

    /**
     * Fetches the user's email from Google's userinfo endpoint.
     * 1:1 port of Go AntigravityAuth.FetchUserInfo().
     *
     * @param accessToken The OAuth access token.
     * @return The user's email address.
     * @throws AntigravityException if the request fails or email is missing.
     */
    public String fetchUserInfo(String accessToken) throws AntigravityException {
        if (accessToken == null) {
            accessToken = "";
        }
        accessToken = accessToken.trim();
        if (accessToken.isEmpty()) {
            throw new AntigravityException("antigravity userinfo: missing access token");
        }

        HttpURLConnection conn = null;
        try {
            URL url = new URL(USER_INFO_ENDPOINT);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestProperty("User-Agent", shortUserAgent());
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            int statusCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, statusCode);

            if (statusCode < 200 || statusCode >= 300) {
                String trimmedBody = responseBody != null ? responseBody.trim() : "";
                if (trimmedBody.isEmpty()) {
                    throw new AntigravityException("antigravity userinfo: request failed: status " + statusCode);
                }
                throw new AntigravityException("antigravity userinfo: request failed: status " + statusCode + ": " + trimmedBody);
            }

            try {
                JSONObject json = new JSONObject(responseBody);
                UserInfo info = UserInfo.fromJSON(json);
                String email = info.email;
                if (email != null) {
                    email = email.trim();
                }
                if (email == null || email.isEmpty()) {
                    throw new AntigravityException("antigravity userinfo: response missing email");
                }
                return email;
            } catch (AntigravityException e) {
                throw e;
            } catch (Exception e) {
                throw new AntigravityException("antigravity userinfo: decode response: " + e.getMessage(), e);
            }
        } catch (AntigravityException e) {
            throw e;
        } catch (IOException e) {
            throw new AntigravityException("antigravity userinfo: execute request: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // FetchProjectID - 1:1 port of auth.go FetchProjectID()
    // ========================================================================

    /**
     * Fetches the project ID for the authenticated user via loadCodeAssist.
     * Falls back to onboardUser polling if the project ID is not directly available.
     * 1:1 port of Go AntigravityAuth.FetchProjectID().
     *
     * @param accessToken The OAuth access token.
     * @return The project ID string.
     * @throws AntigravityException if the request fails.
     */
    public String fetchProjectID(String accessToken) throws AntigravityException {
        String userAgent = shortUserAgent();

        // Build request body (1:1 port of Go map[string]any)
        JSONObject loadReqBody = new JSONObject();
        try {
            loadReqBody.put("metadata", antigravityLoadCodeAssistMetadata());
        } catch (Exception e) {
            throw new AntigravityException("marshal request body: " + e.getMessage(), e);
        }
        String rawBody = loadReqBody.toString();

        String endpointURL = API_ENDPOINT + "/" + API_VERSION + ":loadCodeAssist";

        HttpURLConnection conn = null;
        try {
            conn = openPostConnection(endpointURL, accessToken, userAgent, rawBody);
            int statusCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, statusCode);

            if (statusCode < 200 || statusCode >= 300) {
                throw new AntigravityException("request failed with status " + statusCode + ": " + (responseBody != null ? responseBody.trim() : ""));
            }

            JSONObject loadResp;
            try {
                loadResp = new JSONObject(responseBody);
            } catch (Exception e) {
                throw new AntigravityException("decode response: " + e.getMessage(), e);
            }

            String projectID = extractCloudaicompanionProject(loadResp);

            if (projectID == null || projectID.isEmpty()) {
                String tierID = defaultAntigravityTierID(loadResp);
                projectID = onboardUser(accessToken, tierID);
                if (projectID == null || projectID.isEmpty()) {
                    throw new AntigravityException("project id not found in loadCodeAssist or onboardUser response");
                }
                return projectID;
            }

            return projectID;
        } catch (AntigravityException e) {
            throw e;
        } catch (IOException e) {
            throw new AntigravityException("execute request: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // OnboardUser - 1:1 port of auth.go OnboardUser()
    // ========================================================================

    /**
     * Attempts to fetch the project ID via onboardUser by polling for completion.
     * 1:1 port of Go AntigravityAuth.OnboardUser().
     *
     * @param accessToken The OAuth access token.
     * @param tierID      The tier ID to use for onboarding.
     * @return The project ID string.
     * @throws AntigravityException if onboarding fails after all attempts.
     */
    public String onboardUser(String accessToken, String tierID) throws AntigravityException {
        Log.i(TAG, "Antigravity: onboarding user with tier: " + tierID);
        String userAgent = nodeUserAgent();

        // Build request body (1:1 port of Go map[string]any)
        JSONObject requestBody = new JSONObject();
        try {
            requestBody.put("tier_id", tierID);
            requestBody.put("metadata", antigravityControlPlaneMetadata(userAgent));
        } catch (Exception e) {
            throw new AntigravityException("marshal request body: " + e.getMessage(), e);
        }
        String rawBody = requestBody.toString();

        int maxAttempts = 5;
        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            Log.d(TAG, "Polling attempt " + attempt + "/" + maxAttempts);

            String endpointURL = DAILY_API_ENDPOINT + "/" + API_VERSION + ":onboardUser";

            HttpURLConnection conn = null;
            try {
                conn = openPostConnection(endpointURL, accessToken, userAgent, rawBody);
                conn.setRequestProperty("X-Goog-Api-Client", ANTIGRAVITY_GOOG_API_CLIENT_UA);
                conn.setConnectTimeout(30000);
                conn.setReadTimeout(30000);

                int statusCode = conn.getResponseCode();
                String responseBody = readResponseBody(conn, statusCode);

                if (statusCode == 200) {
                    try {
                        JSONObject data = new JSONObject(responseBody);
                        boolean done = data.optBoolean("done", false);
                        if (done) {
                            String projectID = "";
                            JSONObject responseData = data.optJSONObject("response");
                            if (responseData != null) {
                                projectID = extractCloudaicompanionProject(responseData);
                            }

                            if (projectID != null && !projectID.isEmpty()) {
                                Log.i(TAG, "Successfully fetched project_id: " + maskAPIKey(projectID));
                                return projectID;
                            }

                            throw new AntigravityException("no project_id in response");
                        }
                    } catch (AntigravityException e) {
                        throw e;
                    } catch (Exception e) {
                        throw new AntigravityException("decode response: " + e.getMessage(), e);
                    }

                    // Not done yet, wait and retry
                    try {
                        Thread.sleep(2000);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new AntigravityException("onboardUser polling interrupted", ie);
                    }
                    continue;
                }

                // Non-200 response
                String responsePreview = responseBody != null ? responseBody.trim() : "";
                if (responsePreview.length() > 500) {
                    responsePreview = responsePreview.substring(0, 500);
                }
                String responseErr = responsePreview;
                if (responseErr.length() > 200) {
                    responseErr = responseErr.substring(0, 200);
                }
                throw new AntigravityException("http " + statusCode + ": " + responseErr);

            } catch (AntigravityException e) {
                throw e;
            } catch (IOException e) {
                throw new AntigravityException("execute request: " + e.getMessage(), e);
            } finally {
                if (conn != null) {
                    conn.disconnect();
                }
            }
        }

        throw new AntigravityException("onboard user did not complete after " + maxAttempts + " attempts");
    }

    // ========================================================================
    // CredentialFileName - 1:1 port of filename.go
    // ========================================================================

    /**
     * Returns the filename used to persist Antigravity credentials.
     * Uses the email as a suffix to disambiguate accounts.
     * 1:1 port of Go CredentialFileName().
     *
     * @param email The user's email address.
     * @return The credential filename.
     */
    public static String credentialFileName(String email) {
        if (email == null) {
            email = "";
        }
        email = email.trim();
        if (email.isEmpty()) {
            return "antigravity.json";
        }
        return "antigravity-" + email + ".json";
    }

    // ========================================================================
    // HTTP Helper Methods
    // ========================================================================

    /**
     * Opens an HttpURLConnection for a POST request with standard Antigravity headers.
     */
    private HttpURLConnection openPostConnection(String urlStr, String accessToken, String userAgent, String body)
            throws IOException {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        conn.setRequestProperty("Accept", "*/*");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setRequestProperty("User-Agent", userAgent);
        conn.setDoOutput(true);
        conn.setConnectTimeout(15000);
        conn.setReadTimeout(15000);

        byte[] postData = body.getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(postData);
            os.flush();
        }

        return conn;
    }

    /**
     * Reads the full response body from an HttpURLConnection.
     */
    private static String readResponseBody(HttpURLConnection conn, int statusCode) throws IOException {
        InputStream is = null;
        try {
            is = (statusCode >= 200 && statusCode < 300) ? conn.getInputStream() : conn.getErrorStream();
            if (is == null) {
                return "";
            }
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            int n;
            while ((n = is.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            return baos.toString("UTF-8");
        } finally {
            if (is != null) {
                try {
                    is.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    /**
     * Appends a key-value pair to a form-encoded body builder.
     */
    private void appendFormParam(StringBuilder sb, String key, String value, boolean last) throws Exception {
        sb.append(URLEncoder.encode(key, "UTF-8"));
        sb.append("=");
        sb.append(URLEncoder.encode(value, "UTF-8"));
        if (!last) {
            sb.append("&");
        }
    }

    // ========================================================================
    // Utility
    // ========================================================================

    /**
     * Masks an API key for logging purposes, showing only the first and last few characters.
     * 1:1 port of Go util.HideAPIKey().
     */
    private static String maskAPIKey(String key) {
        if (key == null) {
            return "";
        }
        key = key.trim();
        if (key.isEmpty()) {
            return "";
        }
        if (key.length() <= 8) {
            return key.substring(0, 1) + "..." + key.substring(key.length() - 1);
        }
        return key.substring(0, 4) + "..." + key.substring(key.length() - 4);
    }

    // ========================================================================
    // AntigravityException - Custom exception for Antigravity OAuth errors
    // ========================================================================

    /**
     * Exception type for Antigravity OAuth and API errors.
     */
    public static class AntigravityException extends Exception {
        public AntigravityException(String message) {
            super(message);
        }

        public AntigravityException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}