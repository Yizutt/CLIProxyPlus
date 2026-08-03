package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * CodexOAuth handles the OpenAI OAuth2 authentication flow for Codex.
 * <p>
 * It provides methods for generating authorization URLs with PKCE,
 * exchanging authorization codes for tokens, and refreshing access tokens.
 * <p>
 * 1:1 port of internal/auth/codex/ from CLIProxyAPIPlus.
 */
public class CodexOAuth extends OAuthProvider {

    private static final String TAG = "CodexOAuth";

    // OAuth configuration constants for OpenAI Codex
    public static final String AUTH_URL = "https://auth.openai.com/oauth/authorize";
    public static final String TOKEN_URL = "https://auth.openai.com/oauth/token";
    public static final String CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
    public static final String REDIRECT_URI = "http://localhost:1455/auth/callback";

    // Dedup support for concurrent token refreshes (singleflight pattern)
    private final ConcurrentHashMap<String, Object> refreshLocks = new ConcurrentHashMap<>();

    // ========================================================================
    // Constructors
    // ========================================================================

    public CodexOAuth() {
        super("codex", AUTH_URL, TOKEN_URL, CLIENT_ID, REDIRECT_URI);
    }

    // ========================================================================
    // JWT Claims (1:1 port of jwt_parser.go)
    // ========================================================================

    /**
     * JWTClaims represents the claims section of a JSON Web Token (JWT).
     * 1:1 port of the Go JWTClaims struct.
     */
    public static class JWTClaims {
        public String atHash;
        public String[] aud;
        public String authProvider;
        public int authTime;
        public String email;
        public boolean emailVerified;
        public int exp;
        public CodexAuthInfo codexAuthInfo;
        public int iat;
        public String iss;
        public String jti;
        public int rat;
        public String sid;
        public String sub;

        /**
         * GetUserEmail extracts the user's email address from the JWT claims.
         * 1:1 port of Go JWTClaims.GetUserEmail().
         */
        public String getEmail() {
            return email;
        }

        /**
         * GetAccountID extracts the user's account ID (ChatGPT account ID) from the JWT claims.
         * 1:1 port of Go JWTClaims.GetAccountID().
         */
        public String getAccountID() {
            if (codexAuthInfo != null) {
                return codexAuthInfo.chatgptAccountId;
            }
            return null;
        }
    }

    /**
     * Organizations defines the structure for organization details within the JWT claims.
     * 1:1 port of the Go Organizations struct.
     */
    public static class Organizations {
        public String id;
        public boolean isDefault;
        public String role;
        public String title;
    }

    /**
     * CodexAuthInfo contains authentication-related details specific to Codex.
     * 1:1 port of the Go CodexAuthInfo struct.
     */
    public static class CodexAuthInfo {
        public String chatgptAccountId;
        public String chatgptPlanType;
        public Object chatgptSubscriptionActiveStart;
        public Object chatgptSubscriptionActiveUntil;
        public String chatgptSubscriptionLastChecked;
        public String chatgptUserId;
        public Object[] groups;
        public Organizations[] organizations;
        public String userId;
    }

    /**
     * ParseJWTToken parses a JWT token string and extracts its claims without performing
     * cryptographic signature verification.
     * 1:1 port of Go ParseJWTToken().
     */
    public static JWTClaims parseJWTToken(String token) {
        if (token == null || token.isEmpty()) {
            return null;
        }
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            logStatic("Invalid JWT token format: expected 3 parts, got " + parts.length);
            return null;
        }

        try {
            // Decode the claims (payload) part
            byte[] claimsData = base64URLDecode(parts[1]);
            if (claimsData == null) {
                return null;
            }
            String jsonStr = new String(claimsData, StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(jsonStr);

            JWTClaims claims = new JWTClaims();
            claims.atHash = json.optString("at_hash", null);
            claims.aud = optStringArray(json, "aud");
            claims.authProvider = json.optString("auth_provider", null);
            claims.authTime = json.optInt("auth_time", 0);
            claims.email = json.optString("email", null);
            claims.emailVerified = json.optBoolean("email_verified", false);
            claims.exp = json.optInt("exp", 0);
            claims.iat = json.optInt("iat", 0);
            claims.iss = json.optString("iss", null);
            claims.jti = json.optString("jti", null);
            claims.rat = json.optInt("rat", 0);
            claims.sid = json.optString("sid", null);
            claims.sub = json.optString("sub", null);

            // Parse CodexAuthInfo from https://api.openai.com/auth claim
            JSONObject authInfoJson = json.optJSONObject("https://api.openai.com/auth");
            if (authInfoJson != null) {
                CodexAuthInfo authInfo = new CodexAuthInfo();
                authInfo.chatgptAccountId = authInfoJson.optString("chatgpt_account_id", null);
                authInfo.chatgptPlanType = authInfoJson.optString("chatgpt_plan_type", null);
                authInfo.chatgptSubscriptionActiveStart = authInfoJson.opt("chatgpt_subscription_active_start");
                authInfo.chatgptSubscriptionActiveUntil = authInfoJson.opt("chatgpt_subscription_active_until");
                authInfo.chatgptSubscriptionLastChecked = authInfoJson.optString("chatgpt_subscription_last_checked", null);
                authInfo.chatgptUserId = authInfoJson.optString("chatgpt_user_id", null);
                authInfo.groups = optObjectArray(authInfoJson, "groups");
                authInfo.userId = authInfoJson.optString("user_id", null);

                // Parse organizations
                org.json.JSONArray orgsJson = authInfoJson.optJSONArray("organizations");
                if (orgsJson != null) {
                    authInfo.organizations = new Organizations[orgsJson.length()];
                    for (int i = 0; i < orgsJson.length(); i++) {
                        JSONObject orgJson = orgsJson.getJSONObject(i);
                        Organizations org = new Organizations();
                        org.id = orgJson.optString("id", null);
                        org.isDefault = orgJson.optBoolean("is_default", false);
                        org.role = orgJson.optString("role", null);
                        org.title = orgJson.optString("title", null);
                        authInfo.organizations[i] = org;
                    }
                }

                claims.codexAuthInfo = authInfo;
            }

            return claims;
        } catch (Exception e) {
            logStatic("Failed to parse JWT claims: " + e.getMessage());
            return null;
        }
    }

    /**
     * base64URLDecode decodes a Base64 URL-encoded string, adding padding if necessary.
     * 1:1 port of Go base64URLDecode().
     */
    private static byte[] base64URLDecode(String data) {
        // Add padding if necessary (1:1 port of Go switch statement)
        switch (data.length() % 4) {
            case 2:
                data += "==";
                break;
            case 3:
                data += "=";
                break;
        }
        try {
            return Base64.getUrlDecoder().decode(data);
        } catch (IllegalArgumentException e) {
            logStatic("Failed to decode JWT claims: " + e.getMessage());
            return null;
        }
    }

    private static String[] optStringArray(JSONObject json, String key) throws Exception {
        org.json.JSONArray arr = json.optJSONArray(key);
        if (arr == null) {
            return null;
        }
        String[] result = new String[arr.length()];
        for (int i = 0; i < arr.length(); i++) {
            result[i] = arr.optString(i, null);
        }
        return result;
    }

    private static Object[] optObjectArray(JSONObject json, String key) throws Exception {
        org.json.JSONArray arr = json.optJSONArray(key);
        if (arr == null) {
            return null;
        }
        Object[] result = new Object[arr.length()];
        for (int i = 0; i < arr.length(); i++) {
            result[i] = arr.get(i);
        }
        return result;
    }

    private static void logStatic(String msg) {
        Log.d(TAG, msg);
    }

    // ========================================================================
    // CodexTokenStorage (1:1 port of token.go)
    // ========================================================================

    /**
     * CodexTokenStorage stores OAuth2 token information for OpenAI Codex API authentication.
     * 1:1 port of the Go CodexTokenStorage struct.
     */
    public static class CodexTokenStorage {
        public String idToken;
        public String accessToken;
        public String refreshToken;
        public String accountId;
        public String lastRefresh;
        public String email;
        public String type;
        public String expire;
        public Map<String, Object> metadata;

        public CodexTokenStorage() {
            this.type = "codex";
        }

        /**
         * SetMetadata allows external callers to inject metadata into the storage before saving.
         * 1:1 port of Go SetMetadata().
         */
        public void setMetadata(Map<String, Object> meta) {
            this.metadata = meta;
        }
    }

    // ========================================================================
    // OAuthError (1:1 port of errors.go)
    // ========================================================================

    /**
     * OAuthError represents an OAuth-specific error.
     * 1:1 port of the Go OAuthError struct.
     */
    public static class OAuthError {
        public String code;
        public String description;
        public String uri;
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
        public String type;
        public String message;
        public int code;
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

    // Common authentication error types (1:1 port of Go error variables)
    public static final AuthenticationError ERR_INVALID_STATE =
            new AuthenticationError("invalid_state", "OAuth state parameter is invalid", 400);
    public static final AuthenticationError ERR_CODE_EXCHANGE_FAILED =
            new AuthenticationError("code_exchange_failed", "Failed to exchange authorization code for tokens", 400);
    public static final AuthenticationError ERR_SERVER_START_FAILED =
            new AuthenticationError("server_start_failed", "Failed to start OAuth callback server", 500);
    public static final AuthenticationError ERR_PORT_IN_USE =
            new AuthenticationError("port_in_use", "OAuth callback port is already in use", 13);
    public static final AuthenticationError ERR_CALLBACK_TIMEOUT =
            new AuthenticationError("callback_timeout", "Timeout waiting for OAuth callback", 408);
    public static final AuthenticationError ERR_BROWSER_OPEN_FAILED =
            new AuthenticationError("browser_open_failed", "Failed to open browser for authentication", 500);

    /**
     * NewAuthenticationError creates a new authentication error with a cause based on a base error.
     * 1:1 port of Go NewAuthenticationError().
     */
    public static AuthenticationError newAuthenticationError(AuthenticationError baseErr, Throwable cause) {
        return new AuthenticationError(baseErr.type, baseErr.message, baseErr.code, cause);
    }

    // ========================================================================
    // Auth URL Generation (1:1 port of openai_auth.go GenerateAuthURL)
    // ========================================================================

    /**
     * GenerateAuthURL creates the OAuth authorization URL with PKCE (Proof Key for Code Exchange).
     * 1:1 port of Go CodexAuth.GenerateAuthURL().
     */
    public String generateAuthURL(String state, PKCECodes pkceCodes) {
        if (pkceCodes == null) {
            throw new IllegalArgumentException("PKCE codes are required");
        }

        StringBuilder url = new StringBuilder(AUTH_URL);
        url.append("?");
        appendParam(url, "client_id", CLIENT_ID, false);
        appendParam(url, "response_type", "code", false);
        appendParam(url, "redirect_uri", REDIRECT_URI, false);
        appendParam(url, "scope", "openid email profile offline_access", false);
        appendParam(url, "state", state, false);
        appendParam(url, "code_challenge", pkceCodes.codeChallenge, false);
        appendParam(url, "code_challenge_method", "S256", false);
        appendParam(url, "prompt", "login", false);
        appendParam(url, "codex_cli_simplified_flow", "true", false);
        appendParam(url, "id_token_add_organizations", "true", true);

        return url.toString();
    }

    private void appendParam(StringBuilder sb, String key, String value, boolean last) {
        sb.append(URLEncoder.encode(key, StandardCharsets.UTF_8));
        sb.append("=");
        sb.append(URLEncoder.encode(value, StandardCharsets.UTF_8));
        if (!last) {
            sb.append("&");
        }
    }

    // ========================================================================
    // Token Exchange (1:1 port of openai_auth.go ExchangeCodeForTokens*)
    // ========================================================================

    /**
     * ExchangeCodeForTokens exchanges an authorization code for access and refresh tokens.
     * 1:1 port of Go CodexAuth.ExchangeCodeForTokens().
     */
    public AuthResult exchangeCodeForTokens(String code, PKCECodes pkceCodes) throws OAuthException {
        return exchangeCodeForTokensWithRedirect(code, REDIRECT_URI, pkceCodes);
    }

    /**
     * ExchangeCodeForTokensWithRedirect exchanges an authorization code for tokens using
     * a caller-provided redirect URI.
     * 1:1 port of Go CodexAuth.ExchangeCodeForTokensWithRedirect().
     */
    public AuthResult exchangeCodeForTokensWithRedirect(String code, String redirectURI, PKCECodes pkceCodes)
            throws OAuthException {
        if (pkceCodes == null) {
            throw new OAuthException(OAuthException.TYPE_AUTH, "PKCE codes are required for token exchange");
        }
        if (redirectURI == null || redirectURI.trim().isEmpty()) {
            throw new OAuthException(OAuthException.TYPE_AUTH, "redirect URI is required for token exchange");
        }

        // Prepare token exchange request (1:1 port of Go url.Values)
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("client_id", CLIENT_ID);
        params.put("code", code);
        params.put("redirect_uri", redirectURI.trim());
        params.put("code_verifier", pkceCodes.codeVerifier);

        try {
            String responseBody = postForm(TOKEN_URL, params);

            // Parse token response (1:1 port of Go struct)
            JSONObject json = new JSONObject(responseBody);
            String accessToken = json.optString("access_token", null);
            String refreshToken = json.optString("refresh_token", null);
            String idToken = json.optString("id_token", null);
            String tokenType = json.optString("token_type", null);
            int expiresIn = json.optInt("expires_in", 0);

            // Extract account ID from ID token (1:1 port of Go claims extraction)
            JWTClaims claims = parseJWTToken(idToken);

            String accountID = "";
            String email = "";
            if (claims != null) {
                accountID = claims.getAccountID() != null ? claims.getAccountID() : "";
                email = claims.getEmail() != null ? claims.getEmail() : "";
            }

            // Create token data (1:1 port of Go CodexTokenData)
            TokenData tokenData = new TokenData();
            tokenData.idToken = idToken;
            tokenData.accessToken = accessToken;
            tokenData.refreshToken = refreshToken;
            tokenData.accountId = accountID;
            tokenData.email = email;
            tokenData.expiresIn = expiresIn;
            tokenData.expireAt = System.currentTimeMillis() + (long) expiresIn * 1000L;

            // Create auth bundle (1:1 port of Go CodexAuthBundle)
            return new AuthResult(tokenData);

        } catch (IOException e) {
            logError("Token exchange request failed", e);
            throw new OAuthException(OAuthException.TYPE_NETWORK, "Token exchange failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logError("Failed to parse token response", e);
            throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                    "Failed to parse token response: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // Token Refresh (1:1 port of openai_auth.go RefreshTokens*)
    // ========================================================================

    /**
     * RefreshTokens refreshes an access token using a refresh token.
     * Uses singleflight dedup for concurrent calls with the same refresh token.
     * 1:1 port of Go CodexAuth.RefreshTokens().
     */
    public TokenData refreshTokens(String refreshToken) throws OAuthException {
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new OAuthException(OAuthException.TYPE_AUTH, "refresh token is required");
        }

        // Singleflight dedup: only one concurrent call per refresh token (1:1 port of Go singleflight.Group)
        Object lock = refreshLocks.computeIfAbsent(refreshToken, k -> new Object());
        synchronized (lock) {
            try {
                return refreshTokensSingleFlight(refreshToken);
            } finally {
                refreshLocks.remove(refreshToken);
            }
        }
    }

    /**
     * refreshTokensSingleFlight performs the actual token refresh HTTP request.
     * 1:1 port of Go CodexAuth.refreshTokensSingleFlight().
     */
    private TokenData refreshTokensSingleFlight(String refreshToken) throws OAuthException {
        // Prepare refresh request (1:1 port of Go url.Values)
        Map<String, String> params = new HashMap<>();
        params.put("client_id", CLIENT_ID);
        params.put("grant_type", "refresh_token");
        params.put("refresh_token", refreshToken);
        params.put("scope", "openid profile email");

        try {
            String responseBody = postForm(TOKEN_URL, params);

            // Parse refresh response (1:1 port of Go struct)
            JSONObject json = new JSONObject(responseBody);
            String accessToken = json.optString("access_token", null);
            String newRefreshToken = json.optString("refresh_token", null);
            String idToken = json.optString("id_token", null);
            String tokenType = json.optString("token_type", null);
            int expiresIn = json.optInt("expires_in", 0);

            // Extract account ID from ID token (1:1 port of Go claims extraction)
            JWTClaims claims = parseJWTToken(idToken);

            String accountID = "";
            String email = "";
            if (claims != null) {
                accountID = claims.getAccountID() != null ? claims.getAccountID() : "";
                email = claims.getEmail() != null ? claims.getEmail() : "";
            }

            // Create token data (1:1 port of Go CodexTokenData)
            TokenData tokenData = new TokenData();
            tokenData.idToken = idToken;
            tokenData.accessToken = accessToken;
            tokenData.refreshToken = newRefreshToken;
            tokenData.accountId = accountID;
            tokenData.email = email;
            tokenData.expiresIn = expiresIn;
            tokenData.expireAt = System.currentTimeMillis() + (long) expiresIn * 1000L;

            return tokenData;

        } catch (IOException e) {
            logError("Token refresh request failed", e);
            throw new OAuthException(OAuthException.TYPE_NETWORK, "Token refresh failed: " + e.getMessage(), e);
        } catch (Exception e) {
            logError("Failed to parse refresh response", e);
            throw new OAuthException(OAuthException.TYPE_PROVIDER_ERROR,
                    "Failed to parse refresh response: " + e.getMessage(), e);
        }
    }

    // ========================================================================
    // Refresh with Retry (1:1 port of openai_auth.go RefreshTokensWithRetry)
    // ========================================================================

    /**
     * RefreshTokensWithRetry refreshes tokens with a built-in retry mechanism.
     * It attempts to refresh the tokens up to a specified maximum number of retries,
     * with an exponential backoff strategy.
     * 1:1 port of Go CodexAuth.RefreshTokensWithRetry().
     */
    public TokenData refreshTokensWithRetry(String refreshToken, int maxRetries) throws OAuthException {
        OAuthException lastErr = null;

        for (int attempt = 0; attempt < maxRetries; attempt++) {
            if (attempt > 0) {
                // Wait before retry (exponential backoff: attempt seconds, 1:1 port of Go)
                try {
                    Thread.sleep((long) attempt * 1000L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new OAuthException(OAuthException.TYPE_NETWORK,
                            "Token refresh interrupted", e);
                }
            }

            try {
                return refreshTokens(refreshToken);
            } catch (OAuthException e) {
                if (isNonRetryableRefreshErr(e)) {
                    log("Token refresh attempt " + (attempt + 1) + " failed with non-retryable error: " + e.getMessage());
                    throw e;
                }
                lastErr = e;
                log("Token refresh attempt " + (attempt + 1) + " failed: " + e.getMessage());
            }
        }

        throw new OAuthException(OAuthException.TYPE_NETWORK,
                "Token refresh failed after " + maxRetries + " attempts", lastErr);
    }

    /**
     * isNonRetryableRefreshErr checks if the error indicates a non-retryable condition.
     * 1:1 port of Go isNonRetryableRefreshErr().
     */
    private boolean isNonRetryableRefreshErr(OAuthException err) {
        if (err == null) {
            return false;
        }
        String msg = err.getMessage();
        if (msg == null) {
            return false;
        }
        return msg.toLowerCase().contains("refresh_token_reused");
    }

    // ========================================================================
    // Token Storage / Bundle (1:1 port of openai_auth.go CreateTokenStorage, UpdateTokenStorage)
    // ========================================================================

    /**
     * CreateTokenStorage creates a new CodexTokenStorage from an AuthResult.
     * 1:1 port of Go CodexAuth.CreateTokenStorage().
     */
    public CodexTokenStorage createTokenStorage(AuthResult bundle) {
        CodexTokenStorage storage = new CodexTokenStorage();
        storage.idToken = bundle.tokenData.idToken;
        storage.accessToken = bundle.tokenData.accessToken;
        storage.refreshToken = bundle.tokenData.refreshToken;
        storage.accountId = bundle.tokenData.accountId;
        storage.lastRefresh = bundle.lastRefresh;
        storage.email = bundle.tokenData.email;
        storage.expire = Instant.now().plusSeconds(bundle.tokenData.expiresIn).toString();
        return storage;
    }

    /**
     * UpdateTokenStorage updates an existing CodexTokenStorage with new token data.
     * 1:1 port of Go CodexAuth.UpdateTokenStorage().
     */
    public void updateTokenStorage(CodexTokenStorage storage, TokenData tokenData) {
        storage.idToken = tokenData.idToken;
        storage.accessToken = tokenData.accessToken;
        storage.refreshToken = tokenData.refreshToken;
        storage.accountId = tokenData.accountId;
        storage.lastRefresh = Instant.now().toString();
        storage.email = tokenData.email;
        storage.expire = Instant.now().plusSeconds(tokenData.expiresIn).toString();
    }

    // ========================================================================
    // Credential File Name (1:1 port of filename.go)
    // ========================================================================

    /**
     * CredentialFileName returns the filename used to persist Codex OAuth credentials.
     * 1:1 port of Go CredentialFileName().
     */
    public static String credentialFileName(String email, String planType, String hashAccountID,
                                             boolean includeProviderPrefix) {
        email = email.trim();
        String plan = normalizePlanTypeForFilename(planType);
        hashAccountID = hashAccountID.trim();

        String prefix = "";
        if (includeProviderPrefix) {
            prefix = "codex";
        }

        // 1:1 port of Go fmt.Sprintf patterns
        if (!hashAccountID.isEmpty()) {
            if (plan.isEmpty()) {
                return prefix + "-" + hashAccountID + "-" + email + ".json";
            }
            return prefix + "-" + hashAccountID + "-" + email + "-" + plan + ".json";
        }
        if (plan.isEmpty()) {
            return prefix + "-" + email + ".json";
        }
        return prefix + "-" + email + "-" + plan + ".json";
    }

    /**
     * normalizePlanTypeForFilename normalizes a plan type string for use in filenames.
     * 1:1 port of Go normalizePlanTypeForFilename().
     */
    private static String normalizePlanTypeForFilename(String planType) {
        planType = planType.trim();
        if (planType.isEmpty()) {
            return "";
        }

        // Split on non-alphanumeric characters (1:1 port of Go FieldsFunc)
        StringBuilder current = new StringBuilder();
        StringBuilder result = new StringBuilder();
        boolean inWord = false;

        for (int i = 0; i < planType.length(); i++) {
            char c = planType.charAt(i);
            if (Character.isLetterOrDigit(c)) {
                current.append(c);
                inWord = true;
            } else {
                if (inWord && current.length() > 0) {
                    if (result.length() > 0) result.append("-");
                    result.append(current.toString().toLowerCase().trim());
                    current.setLength(0);
                }
                inWord = false;
            }
        }

        // Last word
        if (inWord && current.length() > 0) {
            if (result.length() > 0) result.append("-");
            result.append(current.toString().toLowerCase().trim());
        }

        return result.toString();
    }
}