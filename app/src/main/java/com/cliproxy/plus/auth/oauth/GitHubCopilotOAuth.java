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

/**
 * GitHubCopilotOAuth handles the GitHub Copilot OAuth2 Device Flow authentication.
 * <p>
 * It implements the OAuth2 device code flow for authenticating with GitHub
 * and exchanging the GitHub access token for a Copilot API token.
 * <p>
 * 1:1 port of internal/auth/copilot/ from CLIProxyAPIPlus.
 */
public class GitHubCopilotOAuth extends OAuthProvider {

    private static final String TAG = "GitHubCopilotOAuth";

    // ========================================================================
    // OAuth Configuration Constants
    // ========================================================================

    /** GitHub OAuth device code URL. */
    public static final String DEVICE_CODE_URL = "https://github.com/login/device/code";

    /** GitHub OAuth token URL. */
    public static final String TOKEN_URL = "https://github.com/login/oauth/access_token";

    /** GitHub API user info URL. */
    public static final String USER_INFO_URL = "https://api.github.com/user";

    /** Copilot API token URL. */
    public static final String COPILOT_API_TOKEN_URL = "https://api.github.com/copilot_internal/v2/token";

    /** Copilot API base endpoint. */
    public static final String COPILOT_API_ENDPOINT = "https://api.githubcopilot.com";

    /** GitHub OAuth client ID for Copilot. */
    public static final String CLIENT_ID = "Iv1.b507a08c87ecfe98";

    // ========================================================================
    // Copilot HTTP Header Constants
    // ========================================================================

    private static final String COPILOT_USER_AGENT = "GithubCopilot/1.0";
    private static final String COPILOT_EDITOR_VERSION = "vscode/1.100.0";
    private static final String COPILOT_PLUGIN_VERSION = "copilot/1.300.0";
    private static final String COPILOT_INTEGRATION_ID = "vscode-chat";
    private static final String COPILOT_OPENAI_INTENT = "conversation-panel";

    // ========================================================================
    // Polling Constants
    // ========================================================================

    private static final long DEFAULT_POLL_INTERVAL_MS = 5000L; // 5 seconds
    private static final long MAX_POLL_DURATION_MS = 900000L; // 15 minutes

    // ========================================================================
    // Constructors
    // ========================================================================

    public GitHubCopilotOAuth() {
        super("github-copilot", "", "", CLIENT_ID, "");
    }

    // ========================================================================
    // Data Classes (1:1 port of Go structs from token.go)
    // ========================================================================

    /**
     * DeviceCodeResponse represents GitHub's device code response.
     * 1:1 port of the Go DeviceCodeResponse struct.
     */
    public static class DeviceCodeResponse {
        /** The device verification code. */
        public String deviceCode;
        /** The code the user must enter at the verification URI. */
        public String userCode;
        /** The URL where the user should enter the code. */
        public String verificationUri;
        /** The number of seconds until the device code expires. */
        public int expiresIn;
        /** The minimum number of seconds to wait between polling requests. */
        public int interval;

        public DeviceCodeResponse() {}
    }

    /**
     * CopilotTokenData holds the raw OAuth token response from GitHub.
     * 1:1 port of the Go CopilotTokenData struct.
     */
    public static class CopilotTokenData {
        /** The OAuth2 access token. */
        public String accessToken;
        /** The type of token, typically "bearer". */
        public String tokenType;
        /** The OAuth2 scope granted to the token. */
        public String scope;

        public CopilotTokenData() {}
    }

    /**
     * CopilotAuthBundle bundles authentication data for storage.
     * 1:1 port of the Go CopilotAuthBundle struct.
     */
    public static class CopilotAuthBundle {
        /** The OAuth token information. */
        public CopilotTokenData tokenData;
        /** The GitHub username. */
        public String username;
        /** The GitHub email address. */
        public String email;
        /** The GitHub display name. */
        public String name;

        public CopilotAuthBundle() {}
    }

    /**
     * CopilotTokenStorage stores OAuth2 token information for GitHub Copilot API authentication.
     * Maintains compatibility with the existing auth system while adding Copilot-specific fields
     * for managing access tokens and user account information.
     * 1:1 port of the Go CopilotTokenStorage struct.
     */
    public static class CopilotTokenStorage {
        /** The OAuth2 access token used for authenticating API requests. */
        public String accessToken;
        /** The type of token, typically "bearer". */
        public String tokenType;
        /** The OAuth2 scope granted to the token. */
        public String scope;
        /** The timestamp when the access token expires (if provided). */
        public String expiresAt;
        /** The GitHub username associated with this token. */
        public String username;
        /** The GitHub email address associated with this token. */
        public String email;
        /** The GitHub display name associated with this token. */
        public String name;
        /** Indicates the authentication provider type, always "github-copilot" for this storage. */
        public String type;

        public CopilotTokenStorage() {
            this.type = "github-copilot";
        }
    }

    /**
     * CopilotAPIToken represents the Copilot API token response.
     * 1:1 port of the Go CopilotAPIToken struct.
     */
    public static class CopilotAPIToken {
        /** The JWT token for authenticating with the Copilot API. */
        public String token;
        /** The Unix timestamp when the token expires. */
        public long expiresAt;
        /** The available API endpoints. */
        public CopilotAPITokenEndpoints endpoints;
        /** Error information if the request failed. */
        public CopilotAPITokenErrorDetails errorDetails;

        /**
         * Endpoints contains the available API endpoints.
         * 1:1 port of the Go CopilotAPIToken.Endpoints struct.
         */
        public static class CopilotAPITokenEndpoints {
            public String api;
            public String proxy;
            public String originTracker;
            public String telemetry;
        }

        /**
         * ErrorDetails contains error information if the request failed.
         * 1:1 port of the Go CopilotAPIToken.ErrorDetails struct.
         */
        public static class CopilotAPITokenErrorDetails {
            public String url;
            public String message;
            public String documentationUrl;
        }
    }

    /**
     * GitHubUserInfo holds GitHub user profile information.
     * 1:1 port of the Go GitHubUserInfo struct.
     */
    public static class GitHubUserInfo {
        /** The GitHub username. */
        public String login;
        /** The primary email address (may be empty if not public). */
        public String email;
        /** The display name. */
        public String name;

        public GitHubUserInfo() {}
    }

    // ========================================================================
    // Error Classes (1:1 port of errors.go)
    // ========================================================================

    /**
     * OAuthError represents an OAuth-specific error.
     * 1:1 port of the Go OAuthError struct.
     */
    public static class OAuthError {
        /** The OAuth error code. */
        public String code;
        /** A human-readable description of the error. */
        public String description;
        /** A URI identifying a human-readable web page with information about the error. */
        public String uri;
        /** The HTTP status code associated with the error. */
        public int statusCode;

        public OAuthError(String code, String description, int statusCode) {
            this.code = code;
            this.description = description;
            this.statusCode = statusCode;
        }

        @Override
        public String toString() {
            if (description != null && !description.isEmpty()) {
                return "OAuth error " + code + ": " + description;
            }
            return "OAuth error: " + code;
        }
    }

    /**
     * NewOAuthError creates a new OAuth error with the specified code, description, and status code.
     * 1:1 port of Go NewOAuthError().
     */
    public static OAuthError newOAuthError(String code, String description, int statusCode) {
        return new OAuthError(code, description, statusCode);
    }

    /**
     * AuthenticationError represents authentication-related errors.
     * 1:1 port of the Go AuthenticationError struct.
     */
    public static class AuthenticationError extends Exception {
        /** The type of authentication error. */
        public String type;
        /** A human-readable message describing the error. */
        public String message;
        /** The HTTP status code associated with the error. */
        public int code;
        /** The underlying error that caused this authentication error. */
        public Throwable cause;

        public AuthenticationError(String type, String message, int code) {
            super(message);
            this.type = type;
            this.message = message;
            this.code = code;
        }

        public AuthenticationError(String type, String message, int code, Throwable cause) {
            super(message, cause);
            this.type = type;
            this.message = message;
            this.code = code;
            this.cause = cause;
        }
    }

    // Common authentication error types for GitHub Copilot device flow (1:1 port of Go error variables)
    public static final AuthenticationError ERR_DEVICE_CODE_FAILED =
            new AuthenticationError("device_code_failed", "Failed to request device code from GitHub", 400);
    public static final AuthenticationError ERR_DEVICE_CODE_EXPIRED =
            new AuthenticationError("device_code_expired", "Device code has expired. Please try again.", 410);
    public static final AuthenticationError ERR_AUTHORIZATION_PENDING =
            new AuthenticationError("authorization_pending", "Authorization is pending. Waiting for user to authorize.", 202);
    public static final AuthenticationError ERR_SLOW_DOWN =
            new AuthenticationError("slow_down", "Polling too frequently. Slowing down.", 429);
    public static final AuthenticationError ERR_ACCESS_DENIED =
            new AuthenticationError("access_denied", "User denied authorization", 403);
    public static final AuthenticationError ERR_TOKEN_EXCHANGE_FAILED =
            new AuthenticationError("token_exchange_failed", "Failed to exchange device code for access token", 400);
    public static final AuthenticationError ERR_POLLING_TIMEOUT =
            new AuthenticationError("polling_timeout", "Timeout waiting for user authorization", 408);
    public static final AuthenticationError ERR_USER_INFO_FAILED =
            new AuthenticationError("user_info_failed", "Failed to fetch GitHub user information", 400);

    /**
     * NewAuthenticationError creates a new authentication error with a cause based on a base error.
     * 1:1 port of Go NewAuthenticationError().
     */
    public static AuthenticationError newAuthenticationError(AuthenticationError baseErr, Throwable cause) {
        return new AuthenticationError(baseErr.type, baseErr.message, baseErr.code, cause);
    }

    // ========================================================================
    // Device Flow Methods (1:1 port of oauth.go DeviceFlowClient)
    // ========================================================================

    /**
     * RequestDeviceCode initiates the device flow by requesting a device code from GitHub.
     * 1:1 port of Go DeviceFlowClient.RequestDeviceCode().
     */
    public DeviceCodeResponse requestDeviceCode() throws AuthenticationError {
        StringBuilder body = new StringBuilder();
        appendUrlEncodedParam(body, "client_id", CLIENT_ID, false);
        appendUrlEncodedParam(body, "scope", "read:user user:email", true);

        byte[] postData = body.toString().getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(DEVICE_CODE_URL).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn);

            if (!isHttpSuccess(responseCode)) {
                throw newAuthenticationError(ERR_DEVICE_CODE_FAILED,
                        new IOException("status " + responseCode + ": " + responseBody));
            }

            JSONObject json = new JSONObject(responseBody);
            DeviceCodeResponse deviceCode = new DeviceCodeResponse();
            deviceCode.deviceCode = json.optString("device_code", "");
            deviceCode.userCode = json.optString("user_code", "");
            deviceCode.verificationUri = json.optString("verification_uri", "");
            deviceCode.expiresIn = json.optInt("expires_in", 0);
            deviceCode.interval = json.optInt("interval", 0);

            return deviceCode;

        } catch (AuthenticationError e) {
            throw e;
        } catch (Exception e) {
            throw newAuthenticationError(ERR_DEVICE_CODE_FAILED, e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * PollForToken polls the token endpoint until the user authorizes or the device code expires.
     * 1:1 port of Go DeviceFlowClient.PollForToken().
     */
    public CopilotTokenData pollForToken(DeviceCodeResponse deviceCode) throws AuthenticationError {
        if (deviceCode == null) {
            throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                    new IllegalArgumentException("device code is null"));
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
            if (Thread.currentThread().isInterrupted()) {
                throw newAuthenticationError(ERR_POLLING_TIMEOUT,
                        new InterruptedException("Polling interrupted"));
            }

            if (System.currentTimeMillis() >= deadline) {
                throw ERR_POLLING_TIMEOUT;
            }

            try {
                return exchangeDeviceCode(deviceCode.deviceCode);
            } catch (AuthenticationError e) {
                switch (e.type) {
                    case "authorization_pending":
                        try {
                            Thread.sleep(intervalMs);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw newAuthenticationError(ERR_POLLING_TIMEOUT, ie);
                        }
                        continue;
                    case "slow_down":
                        intervalMs += 5000L;
                        try {
                            Thread.sleep(intervalMs);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw newAuthenticationError(ERR_POLLING_TIMEOUT, ie);
                        }
                        continue;
                    case "device_code_expired":
                    case "access_denied":
                        throw e;
                    default:
                        throw e;
                }
            }
        }
    }

    /**
     * exchangeDeviceCode attempts to exchange the device code for an access token.
     * 1:1 port of Go DeviceFlowClient.exchangeDeviceCode().
     */
    private CopilotTokenData exchangeDeviceCode(String deviceCode) throws AuthenticationError {
        StringBuilder body = new StringBuilder();
        appendUrlEncodedParam(body, "client_id", CLIENT_ID, false);
        appendUrlEncodedParam(body, "device_code", deviceCode, false);
        appendUrlEncodedParam(body, "grant_type", "urn:ietf:params:oauth:grant-type:device_code", true);

        byte[] postData = body.toString().getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(TOKEN_URL).openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            // GitHub returns 200 for both success and error cases in device flow.
            // Check for OAuth error response first.
            String responseBody = readResponse(conn);

            JSONObject json = new JSONObject(responseBody);
            String oauthError = json.optString("error", null);

            if (oauthError != null && !oauthError.isEmpty()) {
                String errorDescription = json.optString("error_description", "");
                switch (oauthError) {
                    case "authorization_pending":
                        throw ERR_AUTHORIZATION_PENDING;
                    case "slow_down":
                        throw ERR_SLOW_DOWN;
                    case "expired_token":
                        throw ERR_DEVICE_CODE_EXPIRED;
                    case "access_denied":
                        throw ERR_ACCESS_DENIED;
                    default:
                        throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                                new IOException("OAuth error " + oauthError + ": " + errorDescription));
                }
            }

            String accessToken = json.optString("access_token", null);
            if (accessToken == null || accessToken.isEmpty()) {
                throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                        new IOException("empty access token"));
            }

            CopilotTokenData tokenData = new CopilotTokenData();
            tokenData.accessToken = accessToken;
            tokenData.tokenType = json.optString("token_type", "");
            tokenData.scope = json.optString("scope", "");

            return tokenData;

        } catch (AuthenticationError e) {
            throw e;
        } catch (Exception e) {
            throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED, e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * FetchUserInfo retrieves the GitHub user profile for the authenticated user.
     * 1:1 port of Go DeviceFlowClient.FetchUserInfo().
     */
    public GitHubUserInfo fetchUserInfo(String accessToken) throws AuthenticationError {
        if (accessToken == null || accessToken.isEmpty()) {
            throw newAuthenticationError(ERR_USER_INFO_FAILED,
                    new IllegalArgumentException("access token is empty"));
        }

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(USER_INFO_URL).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", "CLIProxyAPI");
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn);

            if (!isHttpSuccess(responseCode)) {
                throw newAuthenticationError(ERR_USER_INFO_FAILED,
                        new IOException("status " + responseCode + ": " + responseBody));
            }

            JSONObject json = new JSONObject(responseBody);
            String login = json.optString("login", "");
            if (login.isEmpty()) {
                throw newAuthenticationError(ERR_USER_INFO_FAILED,
                        new IOException("empty username"));
            }

            GitHubUserInfo userInfo = new GitHubUserInfo();
            userInfo.login = login;
            userInfo.email = json.optString("email", "");
            userInfo.name = json.optString("name", "");

            return userInfo;

        } catch (AuthenticationError e) {
            throw e;
        } catch (Exception e) {
            throw newAuthenticationError(ERR_USER_INFO_FAILED, e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    // ========================================================================
    // Copilot Auth Methods (1:1 port of copilot_auth.go)
    // ========================================================================

    /**
     * StartDeviceFlow initiates the device flow authentication.
     * Returns the device code response containing the user code and verification URI.
     * 1:1 port of Go CopilotAuth.StartDeviceFlow().
     */
    public DeviceCodeResponse startDeviceFlow() throws AuthenticationError {
        return requestDeviceCode();
    }

    /**
     * WaitForAuthorization polls for user authorization and returns the auth bundle.
     * 1:1 port of Go CopilotAuth.WaitForAuthorization().
     */
    public CopilotAuthBundle waitForAuthorization(DeviceCodeResponse deviceCode) throws AuthenticationError {
        CopilotTokenData tokenData = pollForToken(deviceCode);

        // Fetch the GitHub username
        GitHubUserInfo userInfo = null;
        try {
            userInfo = fetchUserInfo(tokenData.accessToken);
        } catch (AuthenticationError e) {
            Log.w(TAG, "copilot: failed to fetch user info: " + e.getMessage());
        }

        String username = (userInfo != null && userInfo.login != null && !userInfo.login.isEmpty())
                ? userInfo.login : "github-user";

        CopilotAuthBundle bundle = new CopilotAuthBundle();
        bundle.tokenData = tokenData;
        bundle.username = username;
        bundle.email = (userInfo != null) ? userInfo.email : "";
        bundle.name = (userInfo != null) ? userInfo.name : "";

        return bundle;
    }

    /**
     * GetCopilotAPIToken exchanges a GitHub access token for a Copilot API token.
     * This token is used to make authenticated requests to the Copilot API.
     * 1:1 port of Go CopilotAuth.GetCopilotAPIToken().
     */
    public CopilotAPIToken getCopilotAPIToken(String githubAccessToken) throws AuthenticationError {
        if (githubAccessToken == null || githubAccessToken.isEmpty()) {
            throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                    new IllegalArgumentException("github access token is empty"));
        }

        HttpURLConnection conn = null;
        try {
            conn = (HttpURLConnection) new URL(COPILOT_API_TOKEN_URL).openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "token " + githubAccessToken);
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("User-Agent", COPILOT_USER_AGENT);
            conn.setRequestProperty("Editor-Version", COPILOT_EDITOR_VERSION);
            conn.setRequestProperty("Editor-Plugin-Version", COPILOT_PLUGIN_VERSION);
            conn.setConnectTimeout(30000);
            conn.setReadTimeout(30000);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponse(conn);

            if (!isHttpSuccess(responseCode)) {
                throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                        new IOException("status " + responseCode + ": " + responseBody));
            }

            JSONObject json = new JSONObject(responseBody);

            CopilotAPIToken apiToken = new CopilotAPIToken();
            apiToken.token = json.optString("token", "");
            apiToken.expiresAt = json.optLong("expires_at", 0);

            // Parse endpoints
            JSONObject endpointsJson = json.optJSONObject("endpoints");
            if (endpointsJson != null) {
                CopilotAPIToken.CopilotAPITokenEndpoints endpoints =
                        new CopilotAPIToken.CopilotAPITokenEndpoints();
                endpoints.api = endpointsJson.optString("api", "");
                endpoints.proxy = endpointsJson.optString("proxy", "");
                endpoints.originTracker = endpointsJson.optString("origin-tracker", "");
                endpoints.telemetry = endpointsJson.optString("telemetry", "");
                apiToken.endpoints = endpoints;
            }

            // Parse error details
            JSONObject errorDetailsJson = json.optJSONObject("error_details");
            if (errorDetailsJson != null) {
                CopilotAPIToken.CopilotAPITokenErrorDetails errorDetails =
                        new CopilotAPIToken.CopilotAPITokenErrorDetails();
                errorDetails.url = errorDetailsJson.optString("url", "");
                errorDetails.message = errorDetailsJson.optString("message", "");
                errorDetails.documentationUrl = errorDetailsJson.optString("documentation_url", "");
                apiToken.errorDetails = errorDetails;
            }

            if (apiToken.token == null || apiToken.token.isEmpty()) {
                throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                        new IOException("empty copilot api token"));
            }

            return apiToken;

        } catch (AuthenticationError e) {
            throw e;
        } catch (Exception e) {
            throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED, e);
        } finally {
            if (conn != null) conn.disconnect();
        }
    }

    /**
     * ValidateToken checks if a GitHub access token is valid by attempting to fetch user info.
     * Returns true if valid, and sets the login in the provided array if non-null.
     * 1:1 port of Go CopilotAuth.ValidateToken().
     */
    public boolean validateToken(String accessToken, String[] outLogin) throws AuthenticationError {
        if (accessToken == null || accessToken.isEmpty()) {
            return false;
        }

        try {
            GitHubUserInfo userInfo = fetchUserInfo(accessToken);
            if (outLogin != null && outLogin.length > 0) {
                outLogin[0] = userInfo.login;
            }
            return true;
        } catch (AuthenticationError e) {
            if (ERR_USER_INFO_FAILED.type.equals(e.type)) {
                return false;
            }
            throw e;
        }
    }

    /**
     * CreateTokenStorage creates a new CopilotTokenStorage from auth bundle.
     * 1:1 port of Go CopilotAuth.CreateTokenStorage().
     */
    public CopilotTokenStorage createTokenStorage(CopilotAuthBundle bundle) {
        CopilotTokenStorage storage = new CopilotTokenStorage();
        if (bundle.tokenData != null) {
            storage.accessToken = bundle.tokenData.accessToken;
            storage.tokenType = bundle.tokenData.tokenType;
            storage.scope = bundle.tokenData.scope;
        }
        storage.username = bundle.username;
        storage.email = bundle.email;
        storage.name = bundle.name;
        storage.type = "github-copilot";
        return storage;
    }

    /**
     * LoadAndValidateToken loads a token from storage and validates it.
     * Returns true if valid, or throws an error if the token is invalid or expired.
     * 1:1 port of Go CopilotAuth.LoadAndValidateToken().
     */
    public boolean loadAndValidateToken(CopilotTokenStorage storage) throws AuthenticationError {
        if (storage == null || storage.accessToken == null || storage.accessToken.isEmpty()) {
            throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                    new IllegalArgumentException("no token available"));
        }

        // Check if we can still use the GitHub token to get a Copilot API token
        CopilotAPIToken apiToken = getCopilotAPIToken(storage.accessToken);

        // Check if the API token is expired
        if (apiToken.expiresAt > 0 && System.currentTimeMillis() / 1000L >= apiToken.expiresAt) {
            throw newAuthenticationError(ERR_TOKEN_EXCHANGE_FAILED,
                    new IOException("copilot api token expired"));
        }

        return true;
    }

    /**
     * GetAPIEndpoint returns the Copilot API endpoint URL.
     * 1:1 port of Go CopilotAuth.GetAPIEndpoint().
     */
    public String getAPIEndpoint() {
        return COPILOT_API_ENDPOINT;
    }

    // ========================================================================
    // HTTP Helpers
    // ========================================================================

    /**
     * Checks if the status code indicates success (2xx).
     * 1:1 port of Go isHTTPSuccess().
     */
    private static boolean isHttpSuccess(int statusCode) {
        return statusCode >= 200 && statusCode < 300;
    }

    /**
     * Reads the full response body from an HttpURLConnection.
     * Uses getInputStream() for 2xx responses, getErrorStream() otherwise.
     */
    private static String readResponse(HttpURLConnection conn) throws IOException {
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
        return baos.toString("UTF-8");
    }

    /**
     * Appends a URL-encoded key=value pair to the StringBuilder.
     * If last is true, no trailing "&" is appended.
     */
    private static void appendUrlEncodedParam(StringBuilder sb, String key, String value, boolean last) {
        sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
        sb.append("=");
        sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        if (!last) {
            sb.append("&");
        }
    }
}