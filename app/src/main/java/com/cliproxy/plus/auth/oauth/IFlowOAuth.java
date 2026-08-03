package com.cliproxy.plus.auth.oauth;

import android.util.Log;

import org.json.JSONObject;
import org.json.JSONException;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URL;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.zip.GZIPInputStream;

/**
 * OAuth2 authentication implementation for iFlow.
 * <p>
 * Provides complete OAuth2 flow including authorization code exchange,
 * token refresh, user info retrieval, and cookie-based authentication.
 * Uses form-encoded POST with Basic Auth for token requests.
 * <p>
 * 1:1 port of CLIProxyAPIPlus/internal/auth/iflow/.
 */
public class IFlowOAuth extends OAuthProvider {

    private static final String TAG = "IFlowOAuth";

    // ====== OAuth Endpoints ======

    /** iFlow OAuth token endpoint. */
    public static final String TOKEN_ENDPOINT = "https://iflow.cn/oauth/token";

    /** iFlow OAuth authorize endpoint. */
    public static final String AUTHORIZE_ENDPOINT = "https://iflow.cn/oauth";

    /** iFlow user info endpoint. */
    public static final String USER_INFO_ENDPOINT = "https://iflow.cn/api/oauth/getUserInfo";

    /** iFlow success redirect URL. */
    public static final String SUCCESS_REDIRECT_URL = "https://iflow.cn/oauth/success";

    /** iFlow error redirect URL. */
    public static final String ERROR_REDIRECT_URL = "https://iflow.cn/oauth/error";

    /** iFlow API key endpoint for cookie-based auth. */
    public static final String API_KEY_ENDPOINT = "https://platform.iflow.cn/api/openapi/apikey";

    // ====== Client Credentials ======

    /** iFlow OAuth client ID. */
    public static final String CLIENT_ID = "10009311001";

    /** Default client secret (can be overridden via IFLOW_CLIENT_SECRET env var). */
    public static final String DEFAULT_CLIENT_SECRET = "4Z3YjXycVsQvyGF1etiNlIBB4RsqSDtW";

    /** Local callback port for OAuth redirect. */
    public static final int CALLBACK_PORT = 11451;

    /** Default API base URL for chat completions. */
    public static final String DEFAULT_API_BASE_URL = "https://apis.iflow.cn/v1";

    // ====== Token Response ======

    /**
     * Represents the raw response from the iFlow OAuth token endpoint.
     */
    private static class IFlowTokenResponse {
        String accessToken;
        String refreshToken;
        int expiresIn;
        String tokenType;
        String scope;

        static IFlowTokenResponse fromJson(JSONObject json) {
            IFlowTokenResponse resp = new IFlowTokenResponse();
            resp.accessToken = json.optString("access_token", "");
            resp.refreshToken = json.optString("refresh_token", "");
            resp.expiresIn = json.optInt("expires_in", 0);
            resp.tokenType = json.optString("token_type", "");
            resp.scope = json.optString("scope", "");
            return resp;
        }
    }

    // ====== Data Classes ======

    /**
     * Captures processed token details for iFlow.
     */
    public static class IFlowTokenData {
        public String accessToken;
        public String refreshToken;
        public String tokenType;
        public String scope;
        public String expire;
        public String apiKey;
        public String email;
        public String cookie;

        public IFlowTokenData() {}

        public IFlowTokenData(String accessToken, String refreshToken, String tokenType,
                              String scope, String expire, String apiKey, String email) {
            this.accessToken = accessToken;
            this.refreshToken = refreshToken;
            this.tokenType = tokenType;
            this.scope = scope;
            this.expire = expire;
            this.apiKey = apiKey;
            this.email = email;
        }
    }

    /**
     * User info response structure.
     */
    private static class UserInfoResponse {
        boolean success;
        UserInfoData data;

        static UserInfoResponse fromJson(JSONObject json) {
            UserInfoResponse resp = new UserInfoResponse();
            resp.success = json.optBoolean("success", false);
            JSONObject d = json.optJSONObject("data");
            if (d != null) {
                UserInfoData ud = new UserInfoData();
                ud.apiKey = d.optString("apiKey", "");
                ud.email = d.optString("email", "");
                ud.phone = d.optString("phone", "");
                resp.data = ud;
            }
            return resp;
        }
    }

    private static class UserInfoData {
        String apiKey;
        String email;
        String phone;
    }

    /**
     * API key response from the cookie-based endpoint.
     */
    private static class IFlowAPIKeyResponse {
        boolean success;
        String code;
        String message;
        IFlowKeyData data;

        static IFlowAPIKeyResponse fromJson(JSONObject json) {
            IFlowAPIKeyResponse resp = new IFlowAPIKeyResponse();
            resp.success = json.optBoolean("success", false);
            resp.code = json.optString("code", "");
            resp.message = json.optString("message", "");
            JSONObject d = json.optJSONObject("data");
            if (d != null) {
                IFlowKeyData kd = new IFlowKeyData();
                kd.hasExpired = d.optBoolean("hasExpired", false);
                kd.expireTime = d.optString("expireTime", "");
                kd.name = d.optString("name", "");
                kd.apiKey = d.optString("apiKey", "");
                kd.apiKeyMask = d.optString("apiKeyMask", "");
                resp.data = kd;
            }
            return resp;
        }
    }

    private static class IFlowKeyData {
        boolean hasExpired;
        String expireTime;
        String name;
        String apiKey;
        String apiKeyMask;
    }

    /**
     * Stores OAuth2 token information for iFlow API authentication.
     */
    public static class IFlowTokenStorage {
        public String accessToken;
        public String refreshToken;
        public String lastRefresh;
        public String expire;
        public String apiKey;
        public String email;
        public String tokenType;
        public String scope;
        public String cookie;
        public String type;
        public Map<String, Object> metadata;

        public IFlowTokenStorage() {
            this.type = "iflow";
        }

        public void setMetadata(Map<String, Object> meta) {
            this.metadata = meta;
        }
    }

    // ====== OAuth Server for Callback Handling ======

    /**
     * Minimal HTTP server for handling the iFlow OAuth callback.
     * Listens on localhost for the redirect from the OAuth provider.
     */
    public static class OAuthServer {
        private static final String TAG = "IFlowOAuthServer";

        private final int port;
        private volatile boolean running;
        private ServerSocket serverSocket;
        private Thread serverThread;
        private final BlockingQueue<OAuthCallbackResult> resultQueue = new LinkedBlockingQueue<>(1);
        private final CountDownLatch startedLatch = new CountDownLatch(1);

        public OAuthServer(int port) {
            this.port = port;
        }

        /**
         * Starts the callback listener on a background thread.
         * Blocks briefly to ensure the server socket is bound before returning.
         */
        public void start() throws IOException {
            if (running) {
                throw new IOException("iFlow OAuth server already running");
            }
            if (!isPortAvailable()) {
                throw new IOException("Port " + port + " is already in use");
            }

            serverSocket = new ServerSocket(port, 0, java.net.InetAddress.getByName("localhost"));
            running = true;

            serverThread = new Thread(() -> {
                try {
                    startedLatch.countDown();
                    while (running && !serverSocket.isClosed()) {
                        try {
                            Socket client = serverSocket.accept();
                            if (!running) break;
                            handleClient(client);
                        } catch (IOException e) {
                            if (running) {
                                Log.e(TAG, "Accept failed", e);
                            }
                            break;
                        }
                    }
                } finally {
                    running = false;
                }
            }, "iflow-oauth-server");
            serverThread.setDaemon(true);
            serverThread.start();

            try {
                startedLatch.await(500, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        /**
         * Stops the callback listener gracefully.
         */
        public void stop() {
            running = false;
            if (serverSocket != null && !serverSocket.isClosed()) {
                try {
                    serverSocket.close();
                } catch (IOException ignored) {
                }
            }
            if (serverThread != null && serverThread.isAlive()) {
                serverThread.interrupt();
                try {
                    serverThread.join(1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }
        }

        /**
         * Blocks until a callback result is received, or the timeout expires.
         *
         * @param timeoutMs maximum time to wait in milliseconds
         * @return the OAuth callback result
         * @throws IOException if timeout or server error occurs
         */
        public OAuthCallbackResult waitForCallback(long timeoutMs) throws IOException {
            try {
                OAuthCallbackResult result = resultQueue.poll(timeoutMs, TimeUnit.MILLISECONDS);
                if (result == null) {
                    throw new IOException("Timeout waiting for OAuth callback");
                }
                return result;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted waiting for OAuth callback", e);
            }
        }

        private void handleClient(Socket client) {
            try {
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
                OutputStreamWriter writer = new OutputStreamWriter(
                        client.getOutputStream(), StandardCharsets.UTF_8);

                // Parse the HTTP request line
                String requestLine = reader.readLine();
                if (requestLine == null) {
                    client.close();
                    return;
                }

                StringTokenizer tokenizer = new StringTokenizer(requestLine);
                String method = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : "";
                String path = tokenizer.hasMoreTokens() ? tokenizer.nextToken() : "";

                // Read headers
                Map<String, String> headers = new HashMap<>();
                String headerLine;
                while ((headerLine = reader.readLine()) != null && !headerLine.isEmpty()) {
                    int colonIdx = headerLine.indexOf(':');
                    if (colonIdx > 0) {
                        headers.put(headerLine.substring(0, colonIdx).trim().toLowerCase(),
                                headerLine.substring(colonIdx + 1).trim());
                    }
                }

                // Only handle GET /oauth2callback
                if (!"GET".equalsIgnoreCase(method) || !path.startsWith("/oauth2callback")) {
                    writeHttpResponse(writer, "405 Method Not Allowed",
                            "<html><body><h1>Method Not Allowed</h1></body></html>");
                    client.close();
                    return;
                }

                // Parse query parameters
                String query = "";
                int qIdx = path.indexOf('?');
                if (qIdx >= 0) {
                    query = path.substring(qIdx + 1);
                }

                Map<String, String> params = parseQueryParams(query);
                String error = params.get("error");
                String code = params.get("code");
                String state = params.get("state");

                OAuthCallbackResult result = new OAuthCallbackResult();
                result.state = state;

                if (error != null && !error.isEmpty()) {
                    result.error = error;
                    resultQueue.offer(result);
                    writeHttpResponse(writer, "302 Found",
                            "<html><body>Redirecting...</body></html>",
                            ERROR_REDIRECT_URL);
                } else if (code == null || code.isEmpty()) {
                    result.error = "missing_code";
                    resultQueue.offer(result);
                    writeHttpResponse(writer, "302 Found",
                            "<html><body>Redirecting...</body></html>",
                            ERROR_REDIRECT_URL);
                } else {
                    result.code = code;
                    resultQueue.offer(result);
                    writeHttpResponse(writer, "302 Found",
                            "<html><body>Redirecting...</body></html>",
                            SUCCESS_REDIRECT_URL);
                }

                client.close();
            } catch (IOException e) {
                Log.e(TAG, "Error handling callback client", e);
            } finally {
                try {
                    client.close();
                } catch (IOException ignored) {
                }
            }
        }

        private void writeHttpResponse(OutputStreamWriter writer, String status,
                                       String body) throws IOException {
            writeHttpResponse(writer, status, body, null);
        }

        private void writeHttpResponse(OutputStreamWriter writer, String status,
                                       String body, String redirectLocation) throws IOException {
            writer.write("HTTP/1.1 " + status + "\r\n");
            writer.write("Content-Type: text/html; charset=utf-8\r\n");
            writer.write("Content-Length: " + body.getBytes(StandardCharsets.UTF_8).length + "\r\n");
            writer.write("Connection: close\r\n");
            if (redirectLocation != null) {
                writer.write("Location: " + redirectLocation + "\r\n");
            }
            writer.write("\r\n");
            writer.write(body);
            writer.flush();
        }

        private Map<String, String> parseQueryParams(String query) {
            Map<String, String> params = new HashMap<>();
            if (query == null || query.isEmpty()) return params;
            String[] pairs = query.split("&");
            for (String pair : pairs) {
                int eqIdx = pair.indexOf('=');
                if (eqIdx > 0) {
                    try {
                        String key = URLDecoder.decode(pair.substring(0, eqIdx), "UTF-8");
                        String value = URLDecoder.decode(pair.substring(eqIdx + 1), "UTF-8");
                        params.put(key, value);
                    } catch (Exception ignored) {
                    }
                }
            }
            return params;
        }

        private boolean isPortAvailable() {
            try {
                ServerSocket ss = new ServerSocket(port, 0, java.net.InetAddress.getByName("localhost"));
                ss.close();
                return true;
            } catch (IOException e) {
                return false;
            }
        }
    }

    // ====== Constructors ======

    public IFlowOAuth() {
        super("iflow", AUTHORIZE_ENDPOINT, TOKEN_ENDPOINT, CLIENT_ID,
                "http://localhost:" + CALLBACK_PORT + "/oauth2callback");
    }

    // ====== Helpers ======

    private static String nowRfc3339() {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.now());
    }

    private static String getIFlowClientSecret() {
        String secret = System.getenv("IFLOW_CLIENT_SECRET");
        if (secret != null && !secret.isEmpty()) {
            return secret;
        }
        return DEFAULT_CLIENT_SECRET;
    }

    private static String basicAuthHeader() {
        String credentials = CLIENT_ID + ":" + getIFlowClientSecret();
        return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    // ====== Auth URL Generation ======

    /**
     * Creates the iFlow OAuth authorization URL.
     *
     * @param state a random state parameter for CSRF protection
     * @return the complete authorization URL
     */
    public String generateAuthURL(String state) {
        return generateAuthURL(state, CALLBACK_PORT);
    }

    /**
     * Creates the iFlow OAuth authorization URL with a custom callback port.
     *
     * @param state a random state parameter for CSRF protection
     * @param port  the local callback port
     * @return the complete authorization URL and redirect URI as a pair [authUrl, redirectUri]
     */
    public String[] generateAuthURL(String state, int port) {
        String redirectUri = "http://localhost:" + port + "/oauth2callback";
        try {
            StringBuilder sb = new StringBuilder();
            sb.append(AUTHORIZE_ENDPOINT).append("?");
            sb.append("loginMethod=").append(URLEncoder.encode("phone", "UTF-8"));
            sb.append("&type=").append(URLEncoder.encode("phone", "UTF-8"));
            sb.append("&redirect=").append(URLEncoder.encode(redirectUri, "UTF-8"));
            sb.append("&state=").append(URLEncoder.encode(state, "UTF-8"));
            sb.append("&client_id=").append(URLEncoder.encode(CLIENT_ID, "UTF-8"));
            return new String[]{sb.toString(), redirectUri};
        } catch (IOException e) {
            throw new RuntimeException("Failed to encode auth URL parameters", e);
        }
    }

    // ====== HTTP Helpers ======

    /**
     * Performs a form-encoded POST with Basic Auth header for token requests.
     */
    private String postFormWithBasicAuth(String urlStr, Map<String, String> params) throws IOException {
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
            conn.setRequestProperty("Authorization", basicAuthHeader());
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
            try (InputStream is = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream() : conn.getErrorStream()) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            String responseBody = baos.toString("UTF-8");

            Log.d(TAG, "Token request status=" + responseCode + " body=" + responseBody);

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("iflow token: " + responseCode + " " + responseBody.trim());
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Performs a GET request with optional cookie header and gzip handling.
     */
    private String getWithCookie(String urlStr, String cookie) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json, text/plain, */*");
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
            conn.setRequestProperty("Accept-Encoding", "gzip, deflate, br");
            conn.setRequestProperty("Connection", "keep-alive");
            conn.setRequestProperty("Sec-Fetch-Dest", "empty");
            conn.setRequestProperty("Sec-Fetch-Mode", "cors");
            conn.setRequestProperty("Sec-Fetch-Site", "same-origin");

            if (cookie != null && !cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
            }

            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            int responseCode = conn.getResponseCode();

            // Handle gzip compression
            InputStream rawStream = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream() : conn.getErrorStream();

            InputStream decompressed;
            String contentEncoding = conn.getHeaderField("Content-Encoding");
            if ("gzip".equals(contentEncoding)) {
                decompressed = new GZIPInputStream(rawStream);
            } else {
                decompressed = rawStream;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = decompressed.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            String responseBody = baos.toString("UTF-8");

            Log.d(TAG, "GET request status=" + responseCode + " body=" + responseBody);

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("iflow cookie: GET request failed with status " + responseCode + ": " + responseBody.trim());
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Performs a POST request with cookie header and JSON body, with gzip handling.
     */
    private String postJsonWithCookie(String urlStr, String jsonBody, String cookie) throws IOException {
        byte[] postData = jsonBody.getBytes(StandardCharsets.UTF_8);

        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json, text/plain, */*");
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
                    "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36");
            conn.setRequestProperty("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8");
            conn.setRequestProperty("Accept-Encoding", "gzip, deflate, br");
            conn.setRequestProperty("Connection", "keep-alive");
            conn.setRequestProperty("Origin", "https://platform.iflow.cn");
            conn.setRequestProperty("Referer", "https://platform.iflow.cn/");

            if (cookie != null && !cookie.isEmpty()) {
                conn.setRequestProperty("Cookie", cookie);
            }

            conn.setDoOutput(true);
            conn.setConnectTimeout(15000);
            conn.setReadTimeout(15000);

            try (OutputStream os = conn.getOutputStream()) {
                os.write(postData);
                os.flush();
            }

            int responseCode = conn.getResponseCode();

            InputStream rawStream = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream() : conn.getErrorStream();

            InputStream decompressed;
            String contentEncoding = conn.getHeaderField("Content-Encoding");
            if ("gzip".equals(contentEncoding)) {
                decompressed = new GZIPInputStream(rawStream);
            } else {
                decompressed = rawStream;
            }

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = decompressed.read(buf)) != -1) {
                baos.write(buf, 0, n);
            }
            String responseBody = baos.toString("UTF-8");

            Log.d(TAG, "POST request status=" + responseCode + " body=" + responseBody);

            if (responseCode < 200 || responseCode >= 300) {
                throw new IOException("iflow cookie refresh: POST request failed with status " + responseCode + ": " + responseBody.trim());
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    /**
     * Performs a simple GET request to the user info endpoint.
     */
    private String getWithAccept(String urlStr) throws IOException {
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
            try (InputStream is = (responseCode >= 200 && responseCode < 300)
                    ? conn.getInputStream() : conn.getErrorStream()) {
                while ((n = is.read(buf)) != -1) {
                    baos.write(buf, 0, n);
                }
            }
            String responseBody = baos.toString("UTF-8");

            if (responseCode < 200 || responseCode >= 300) {
                Log.d(TAG, "iflow api key failed: status=" + responseCode + " body=" + responseBody);
                throw new IOException("iflow api key: " + responseCode + " " + responseBody.trim());
            }
            return responseBody;
        } finally {
            conn.disconnect();
        }
    }

    // ====== Token Exchange ======

    /**
     * Exchanges an authorization code for access and refresh tokens.
     *
     * @param code        the authorization code from the OAuth callback
     * @param redirectUri the redirect URI used in the authorization request
     * @return the token data with API key and email
     * @throws IOException if the token exchange or user info fetch fails
     */
    public IFlowTokenData exchangeCodeForTokens(String code, String redirectUri) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "authorization_code");
        params.put("code", code);
        params.put("redirect_uri", redirectUri);
        params.put("client_id", CLIENT_ID);
        params.put("client_secret", getIFlowClientSecret());

        String responseBody = postFormWithBasicAuth(TOKEN_ENDPOINT, params);

        JSONObject json;
        try {
            json = new JSONObject(responseBody);
        } catch (JSONException e) {
            throw new IOException("iflow token: decode response failed: " + e.getMessage(), e);
        }

        IFlowTokenResponse tokenResp = IFlowTokenResponse.fromJson(json);

        if (tokenResp.accessToken == null || tokenResp.accessToken.isEmpty()) {
            Log.d(TAG, responseBody);
            throw new IOException("iflow token: missing access token in response");
        }

        String expire = Instant.now()
                .plusSeconds(tokenResp.expiresIn)
                .toString();

        // Fetch user info to get API key and email
        UserInfoData userInfo = fetchUserInfo(tokenResp.accessToken);

        if (userInfo.apiKey == null || userInfo.apiKey.trim().isEmpty()) {
            throw new IOException("iflow token: empty api key returned");
        }

        String email = userInfo.email != null ? userInfo.email.trim() : "";
        if (email.isEmpty()) {
            email = userInfo.phone != null ? userInfo.phone.trim() : "";
        }
        if (email.isEmpty()) {
            throw new IOException("iflow token: missing account email/phone in user info");
        }

        IFlowTokenData data = new IFlowTokenData();
        data.accessToken = tokenResp.accessToken;
        data.refreshToken = tokenResp.refreshToken;
        data.tokenType = tokenResp.tokenType;
        data.scope = tokenResp.scope;
        data.expire = expire;
        data.apiKey = userInfo.apiKey;
        data.email = email;

        return data;
    }

    // ====== Token Refresh ======

    /**
     * Refreshes the access token using a refresh token.
     *
     * @param refreshToken the refresh token
     * @return the new token data
     * @throws IOException if the refresh request fails
     */
    public IFlowTokenData refreshTokens(String refreshToken) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("grant_type", "refresh_token");
        params.put("refresh_token", refreshToken);
        params.put("client_id", CLIENT_ID);
        params.put("client_secret", getIFlowClientSecret());

        String responseBody = postFormWithBasicAuth(TOKEN_ENDPOINT, params);

        JSONObject json;
        try {
            json = new JSONObject(responseBody);
        } catch (JSONException e) {
            throw new IOException("iflow token: decode response failed: " + e.getMessage(), e);
        }

        IFlowTokenResponse tokenResp = IFlowTokenResponse.fromJson(json);

        if (tokenResp.accessToken == null || tokenResp.accessToken.isEmpty()) {
            Log.d(TAG, responseBody);
            throw new IOException("iflow token: missing access token in response");
        }

        String expire = Instant.now()
                .plusSeconds(tokenResp.expiresIn)
                .toString();

        // Fetch user info
        UserInfoData userInfo = fetchUserInfo(tokenResp.accessToken);

        if (userInfo.apiKey == null || userInfo.apiKey.trim().isEmpty()) {
            throw new IOException("iflow token: empty api key returned");
        }

        String email = userInfo.email != null ? userInfo.email.trim() : "";
        if (email.isEmpty()) {
            email = userInfo.phone != null ? userInfo.phone.trim() : "";
        }
        if (email.isEmpty()) {
            throw new IOException("iflow token: missing account email/phone in user info");
        }

        IFlowTokenData data = new IFlowTokenData();
        data.accessToken = tokenResp.accessToken;
        data.refreshToken = tokenResp.refreshToken;
        data.tokenType = tokenResp.tokenType;
        data.scope = tokenResp.scope;
        data.expire = expire;
        data.apiKey = userInfo.apiKey;
        data.email = email;

        return data;
    }

    // ====== User Info ======

    /**
     * Fetches user account metadata (including API key) for the provided access token.
     *
     * @param accessToken the OAuth access token
     * @return user info data containing API key, email, and phone
     * @throws IOException if the request fails
     */
    public UserInfoData fetchUserInfo(String accessToken) throws IOException {
        if (accessToken == null || accessToken.trim().isEmpty()) {
            throw new IOException("iflow api key: access token is empty");
        }

        String endpoint = USER_INFO_ENDPOINT + "?accessToken=" + URLEncoder.encode(accessToken, "UTF-8");
        String responseBody = getWithAccept(endpoint);

        JSONObject json;
        try {
            json = new JSONObject(responseBody);
        } catch (JSONException e) {
            throw new IOException("iflow api key: decode body failed: " + e.getMessage(), e);
        }

        UserInfoResponse result = UserInfoResponse.fromJson(json);

        if (!result.success) {
            throw new IOException("iflow api key: request not successful");
        }

        if (result.data == null || result.data.apiKey == null || result.data.apiKey.isEmpty()) {
            throw new IOException("iflow api key: missing api key in response");
        }

        return result.data;
    }

    // ====== Cookie Authentication ======

    /**
     * Authenticates using browser cookies to obtain an API key.
     *
     * @param cookie the browser cookie string (must contain BXAuth)
     * @return the token data with API key, expiry, and email
     * @throws IOException if authentication fails
     */
    public IFlowTokenData authenticateWithCookie(String cookie) throws IOException {
        if (cookie == null || cookie.trim().isEmpty()) {
            throw new IOException("iflow cookie authentication: cookie is empty");
        }

        // First, get initial API key information using GET request to obtain the name
        IFlowKeyData keyInfo = fetchAPIKeyInfo(cookie);

        // Refresh the API key using POST request
        IFlowKeyData refreshedKeyInfo = refreshAPIKey(cookie, keyInfo.name);

        // Convert to token data format using refreshed key
        IFlowTokenData data = new IFlowTokenData();
        data.apiKey = refreshedKeyInfo.apiKey;
        data.expire = refreshedKeyInfo.expireTime;
        data.email = refreshedKeyInfo.name;
        data.cookie = cookie;

        return data;
    }

    /**
     * Retrieves API key information using GET request with cookie.
     */
    private IFlowKeyData fetchAPIKeyInfo(String cookie) throws IOException {
        String responseBody = getWithCookie(API_KEY_ENDPOINT, cookie);

        JSONObject json;
        try {
            json = new JSONObject(responseBody);
        } catch (JSONException e) {
            throw new IOException("iflow cookie: decode GET response failed: " + e.getMessage(), e);
        }

        IFlowAPIKeyResponse keyResp = IFlowAPIKeyResponse.fromJson(json);

        if (!keyResp.success) {
            throw new IOException("iflow cookie: GET request not successful: " + keyResp.message);
        }

        // Handle initial response where apiKey field might be apiKeyMask
        if ((keyResp.data.apiKey == null || keyResp.data.apiKey.isEmpty())
                && keyResp.data.apiKeyMask != null && !keyResp.data.apiKeyMask.isEmpty()) {
            keyResp.data.apiKey = keyResp.data.apiKeyMask;
        }

        return keyResp.data;
    }

    /**
     * Refreshes the API key using POST request with cookie.
     */
    private IFlowKeyData refreshAPIKey(String cookie, String name) throws IOException {
        if (cookie == null || cookie.trim().isEmpty()) {
            throw new IOException("iflow cookie refresh: cookie is empty");
        }
        if (name == null || name.trim().isEmpty()) {
            throw new IOException("iflow cookie refresh: name is empty");
        }

        JSONObject refreshReq = new JSONObject();
        try {
            refreshReq.put("name", name);
        } catch (JSONException e) {
            throw new IOException("iflow cookie refresh: marshal request failed: " + e.getMessage(), e);
        }

        String responseBody = postJsonWithCookie(API_KEY_ENDPOINT, refreshReq.toString(), cookie);

        JSONObject json;
        try {
            json = new JSONObject(responseBody);
        } catch (JSONException e) {
            throw new IOException("iflow cookie refresh: decode POST response failed: " + e.getMessage(), e);
        }

        IFlowAPIKeyResponse keyResp = IFlowAPIKeyResponse.fromJson(json);

        if (!keyResp.success) {
            throw new IOException("iflow cookie refresh: POST request not successful: " + keyResp.message);
        }

        return keyResp.data;
    }

    // ====== Token Storage ======

    /**
     * Creates a new IFlowTokenStorage from token data obtained via OAuth flow.
     *
     * @param data the token data from the OAuth flow
     * @return a new token storage instance
     */
    public IFlowTokenStorage createTokenStorage(IFlowTokenData data) {
        if (data == null) return null;

        IFlowTokenStorage storage = new IFlowTokenStorage();
        storage.accessToken = data.accessToken;
        storage.refreshToken = data.refreshToken;
        storage.lastRefresh = nowRfc3339();
        storage.expire = data.expire;
        storage.apiKey = data.apiKey;
        storage.email = data.email;
        storage.tokenType = data.tokenType;
        storage.scope = data.scope;
        return storage;
    }

    /**
     * Updates an existing token storage with new token data.
     *
     * @param storage the existing token storage to update
     * @param data    the new token data
     */
    public void updateTokenStorage(IFlowTokenStorage storage, IFlowTokenData data) {
        if (storage == null || data == null) return;

        storage.accessToken = data.accessToken;
        storage.refreshToken = data.refreshToken;
        storage.lastRefresh = nowRfc3339();
        storage.expire = data.expire;
        if (data.apiKey != null && !data.apiKey.isEmpty()) {
            storage.apiKey = data.apiKey;
        }
        if (data.email != null && !data.email.isEmpty()) {
            storage.email = data.email;
        }
        storage.tokenType = data.tokenType;
        storage.scope = data.scope;
    }

    /**
     * Creates a token storage from cookie-based authentication data.
     * Only saves the BXAuth field from the cookie.
     *
     * @param data the token data from cookie authentication
     * @return a new token storage instance
     */
    public IFlowTokenStorage createCookieTokenStorage(IFlowTokenData data) {
        if (data == null) return null;

        // Only save the BXAuth field from the cookie
        String bxAuth = extractBXAuth(data.cookie);
        String cookieToSave = "";
        if (bxAuth != null && !bxAuth.isEmpty()) {
            cookieToSave = "BXAuth=" + bxAuth + ";";
        }

        IFlowTokenStorage storage = new IFlowTokenStorage();
        storage.apiKey = data.apiKey;
        storage.email = data.email;
        storage.expire = data.expire;
        storage.cookie = cookieToSave;
        storage.lastRefresh = nowRfc3339();
        return storage;
    }

    /**
     * Updates an existing token storage with refreshed API key data from cookie auth.
     *
     * @param storage the existing token storage to update
     * @param keyData the refreshed API key data
     */
    public void updateCookieTokenStorage(IFlowTokenStorage storage, IFlowKeyData keyData) {
        if (storage == null || keyData == null) return;

        storage.apiKey = keyData.apiKey;
        storage.expire = keyData.expireTime;
        storage.lastRefresh = nowRfc3339();
    }

    // ====== Cookie Helpers ======

    /**
     * Normalizes a raw cookie string for iFlow authentication flows.
     *
     * @param raw the raw cookie string
     * @return the normalized cookie string ending with ';'
     * @throws IOException if the cookie is empty or missing BXAuth
     */
    public static String normalizeCookie(String raw) throws IOException {
        String trimmed = raw != null ? raw.trim() : "";
        if (trimmed.isEmpty()) {
            throw new IOException("cookie cannot be empty");
        }

        // Collapse whitespace
        String combined = trimmed.replaceAll("\\s+", " ");
        if (!combined.endsWith(";")) {
            combined += ";";
        }
        if (!combined.contains("BXAuth=")) {
            throw new IOException("cookie missing BXAuth field");
        }
        return combined;
    }

    /**
     * Sanitizes user identifiers for safe filename usage.
     * Replaces '*' with 'x' and removes non-alphanumeric characters
     * except '@', '.', '_', '-'.
     *
     * @param raw the raw identifier string
     * @return a sanitized, safe filename string
     */
    public static String sanitizeIFlowFileName(String raw) {
        if (raw == null || raw.isEmpty()) return "";
        String cleanEmail = raw.replace("*", "x");
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < cleanEmail.length(); i++) {
            char c = cleanEmail.charAt(i);
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                    || (c >= '0' && c <= '9') || c == '_' || c == '@' || c == '.' || c == '-') {
                result.append(c);
            }
        }
        return result.toString().trim();
    }

    /**
     * Extracts the BXAuth value from a cookie string.
     *
     * @param cookie the cookie string
     * @return the BXAuth value, or empty string if not found
     */
    public static String extractBXAuth(String cookie) {
        if (cookie == null) return "";
        String[] parts = cookie.split(";");
        for (String part : parts) {
            part = part.trim();
            if (part.startsWith("BXAuth=")) {
                return part.substring("BXAuth=".length());
            }
        }
        return "";
    }

    // ====== Expiry Check ======

    /**
     * Checks if the API key needs to be refreshed (within 2 days of expiry).
     *
     * @param expireTime the expiry time string in "yyyy-MM-dd HH:mm" format
     * @return a result containing whether refresh is needed, time until expiry in ms, or null on error
     */
    public static ExpiryCheckResult shouldRefreshAPIKey(String expireTime) {
        if (expireTime == null || expireTime.trim().isEmpty()) {
            return null;
        }

        try {
            // Parse "yyyy-MM-dd HH:mm" format
            java.time.format.DateTimeFormatter formatter =
                    java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");
            java.time.LocalDateTime expireDateTime =
                    java.time.LocalDateTime.parse(expireTime.trim(), formatter);
            java.time.Instant expireInstant = expireDateTime.atZone(java.time.ZoneId.systemDefault()).toInstant();

            java.time.Instant now = java.time.Instant.now();
            java.time.Instant twoDaysFromNow = now.plusSeconds(48 * 3600);

            boolean needsRefresh = expireInstant.isBefore(twoDaysFromNow);
            long timeUntilExpiryMs = expireInstant.toEpochMilli() - now.toEpochMilli();

            return new ExpiryCheckResult(needsRefresh, timeUntilExpiryMs);
        } catch (Exception e) {
            Log.e(TAG, "iflow cookie: parse expire time failed: " + expireTime, e);
            return null;
        }
    }

    /**
     * Result of the API key expiry check.
     */
    public static class ExpiryCheckResult {
        public final boolean needsRefresh;
        public final long timeUntilExpiryMs;

        public ExpiryCheckResult(boolean needsRefresh, long timeUntilExpiryMs) {
            this.needsRefresh = needsRefresh;
            this.timeUntilExpiryMs = timeUntilExpiryMs;
        }
    }
}