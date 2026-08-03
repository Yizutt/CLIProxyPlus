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
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Kilo AI OAuth 设备流认证实现。
 * <p>
 * 提供 Kilo AI API 的完整设备授权流程（RFC 8628 Device Authorization Grant），
 * 包括设备码请求、令牌轮询、用户信息获取和令牌存储。
 * <p>
 * 1:1 移植自 CLIProxyAPIPlus/internal/auth/kilo/。
 *
 * <h3>API 端点</h3>
 * <ul>
 *   <li>BaseURL: https://api.kilo.ai/api</li>
 *   <li>设备码请求: POST /device-auth/codes (空 JSON body)</li>
 *   <li>状态轮询: GET /device-auth/codes/{code}</li>
 *   <li>用户信息: GET /profile (Bearer 认证)</li>
 *   <li>默认设置: GET /defaults 或 /organizations/{orgID}/defaults (Bearer 认证)</li>
 * </ul>
 */
public class KiloOAuth extends OAuthProvider {

    private static final String TAG = "KiloOAuth";

    // ========================================================================
    // 常量 — 1:1 移植自 Go const 块
    // ========================================================================

    /** Kilo AI API 基础 URL。 */
    public static final String BASE_URL = "https://api.kilo.ai/api";

    /** 默认轮询间隔（5 秒）。 */
    private static final long POLL_INTERVAL_MS = 5000L;

    // ========================================================================
    // 数据类 — 1:1 移植自 Go structs
    // ========================================================================

    /**
     * DeviceAuthResponse 表示发起设备流时的响应。
     * 1:1 移植自 Go DeviceAuthResponse 结构体。
     */
    public static class DeviceAuthResponse {
        /** 设备验证码，用于后续轮询。 */
        public String code;
        /** 用户应访问的验证 URL。 */
        public String verificationUrl;
        /** 设备码过期时间（秒）。 */
        public int expiresIn;

        /**
         * 从 JSONObject 解析响应。
         *
         * @param json 原始 JSON 响应
         * @return 解析后的 DeviceAuthResponse 实例
         */
        static DeviceAuthResponse fromJson(JSONObject json) {
            DeviceAuthResponse resp = new DeviceAuthResponse();
            resp.code = json.optString("code", "");
            resp.verificationUrl = json.optString("verificationUrl", "");
            resp.expiresIn = json.optInt("expiresIn", 0);
            return resp;
        }
    }

    /**
     * DeviceStatusResponse 表示轮询设备流状态时的响应。
     * 1:1 移植自 Go DeviceStatusResponse 结构体。
     */
    public static class DeviceStatusResponse {
        /** 状态: approved | denied | expired | pending。 */
        public String status;
        /** 授权成功后返回的访问令牌。 */
        public String token;
        /** 授权成功后返回的用户邮箱。 */
        public String userEmail;

        /**
         * 从 JSONObject 解析响应。
         *
         * @param json 原始 JSON 响应
         * @return 解析后的 DeviceStatusResponse 实例
         */
        static DeviceStatusResponse fromJson(JSONObject json) {
            DeviceStatusResponse resp = new DeviceStatusResponse();
            resp.status = json.optString("status", "");
            resp.token = json.optString("token", "");
            resp.userEmail = json.optString("userEmail", "");
            return resp;
        }
    }

    /**
     * Profile 表示 Kilo AI 用户信息。
     * 1:1 移植自 Go Profile 结构体。
     */
    public static class Profile {
        /** 用户邮箱地址。 */
        public String email;
        /** 用户所属组织列表。 */
        public List<Organization> organizations;

        /**
         * 从 JSONObject 解析用户信息。
         *
         * @param json 原始 JSON 响应
         * @return 解析后的 Profile 实例
         */
        static Profile fromJson(JSONObject json) {
            Profile profile = new Profile();
            profile.email = json.optString("email", "");
            profile.organizations = new ArrayList<>();

            JSONArray orgsArray = json.optJSONArray("organizations");
            if (orgsArray != null) {
                for (int i = 0; i < orgsArray.length(); i++) {
                    JSONObject orgJson = orgsArray.optJSONObject(i);
                    if (orgJson != null) {
                        profile.organizations.add(Organization.fromJson(orgJson));
                    }
                }
            }
            return profile;
        }
    }

    /**
     * Organization 表示 Kilo AI 组织信息。
     * 1:1 移植自 Go Organization 结构体。
     */
    public static class Organization {
        /** 组织 ID。 */
        public String id;
        /** 组织名称。 */
        public String name;

        /**
         * 从 JSONObject 解析组织信息。
         *
         * @param json 原始 JSON 响应
         * @return 解析后的 Organization 实例
         */
        static Organization fromJson(JSONObject json) {
            Organization org = new Organization();
            org.id = json.optString("id", "");
            org.name = json.optString("name", "");
            return org;
        }
    }

    /**
     * Defaults 表示组织或用户的默认设置。
     * 1:1 移植自 Go Defaults 结构体。
     */
    public static class Defaults {
        /** 默认模型名称。 */
        public String model;

        /**
         * 从 JSONObject 解析默认设置。
         *
         * @param json 原始 JSON 响应
         * @return 解析后的 Defaults 实例
         */
        static Defaults fromJson(JSONObject json) {
            Defaults defaults = new Defaults();
            defaults.model = json.optString("model", "");
            return defaults;
        }
    }

    /**
     * KiloTokenStorage 存储 Kilo AI 认证令牌信息。
     * 1:1 移植自 Go KiloTokenStorage 结构体。
     */
    public static class KiloTokenStorage {
        /** Kilo 访问令牌。 */
        public String kilocodeToken;
        /** Kilo 组织 ID。 */
        public String kilocodeOrganizationId;
        /** 默认使用的模型。 */
        public String kilocodeModel;
        /** 已认证用户的邮箱地址。 */
        public String email;
        /** 认证提供商类型，固定为 "kilo"。 */
        public String type;

        /** 任意键值对，通过钩子注入。 */
        public java.util.Map<String, Object> metadata;

        /**
         * 创建 KiloTokenStorage 实例，默认 type 为 "kilo"。
         */
        public KiloTokenStorage() {
            this.type = "kilo";
        }

        /**
         * 允许外部调用者在保存前向存储注入元数据。
         * 1:1 移植自 Go SetMetadata()。
         *
         * @param meta 要注入的元数据
         */
        public void setMetadata(java.util.Map<String, Object> meta) {
            this.metadata = meta;
        }
    }

    // ========================================================================
    // KiloOAuth 实例 — 1:1 移植自 Go KiloAuth
    // ========================================================================

    /** HTTP 连接超时（毫秒）。 */
    private final int connectTimeout;

    /** HTTP 读取超时（毫秒）。 */
    private final int readTimeout;

    /**
     * 创建 KiloOAuth 实例，使用默认的 30 秒超时。
     * 1:1 移植自 Go NewKiloAuth()。
     */
    public KiloOAuth() {
        super("kilo", BASE_URL, "", "", "");
        this.connectTimeout = 30000;
        this.readTimeout = 30000;
        Log.d(TAG, "创建 KiloOAuth 实例");
    }

    /**
     * 创建带有自定义超时设置的 KiloOAuth 实例。
     *
     * @param connectTimeoutMs 连接超时（毫秒）
     * @param readTimeoutMs    读取超时（毫秒）
     */
    public KiloOAuth(int connectTimeoutMs, int readTimeoutMs) {
        super("kilo", BASE_URL, "", "", "");
        this.connectTimeout = connectTimeoutMs;
        this.readTimeout = readTimeoutMs;
        Log.d(TAG, "创建 KiloOAuth 实例 (connectTimeout=" + connectTimeoutMs
                + ", readTimeout=" + readTimeoutMs + ")");
    }

    // ========================================================================
    // 设备流 — 1:1 移植自 Go InitiateDeviceFlow
    // ========================================================================

    /**
     * 发起设备认证流程。
     * <p>
     * 向 Kilo API 发送 POST 请求（空 JSON body），
     * 获取设备码和验证 URL。
     * 1:1 移植自 Go InitiateDeviceFlow()。
     *
     * @return 设备认证响应，包含设备码和验证 URL
     * @throws IOException 如果请求失败或响应解析失败
     */
    public DeviceAuthResponse initiateDeviceFlow() throws IOException {
        Log.d(TAG, "发起设备认证流程...");

        HttpURLConnection conn = null;
        try {
            URL url = new URL(BASE_URL + "/device-auth/codes");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("Accept", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);

            // 发送空 JSON body（1:1 移植自 Go POST 空 body）
            try (OutputStream os = conn.getOutputStream()) {
                os.write("{}".getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            int responseCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, responseCode);

            Log.d(TAG, "设备认证响应: status=" + responseCode);

            // 检查状态码（1:1 移植自 Go 201/200 检查）
            if (responseCode != HttpURLConnection.HTTP_CREATED
                    && responseCode != HttpURLConnection.HTTP_OK) {
                String errorMsg = "发起设备认证失败: status " + responseCode;
                Log.e(TAG, errorMsg + " body=" + responseBody);
                throw new IOException(errorMsg + " - " + responseBody.trim());
            }

            JSONObject json = parseJson(responseBody);
            DeviceAuthResponse result = DeviceAuthResponse.fromJson(json);

            Log.d(TAG, "设备认证发起成功: code=" + result.code
                    + ", verificationUrl=" + result.verificationUrl
                    + ", expiresIn=" + result.expiresIn);

            return result;

        } catch (IOException e) {
            Log.e(TAG, "发起设备认证失败", e);
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "解析设备认证响应失败", e);
            throw new IOException("解析设备认证响应失败: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // 令牌轮询 — 1:1 移植自 Go PollForToken
    // ========================================================================

    /**
     * 轮询设备流完成状态，直到用户授权、拒绝或过期。
     * <p>
     * 每 5 秒轮询一次，检查设备码状态。
     * 1:1 移植自 Go PollForToken()。
     *
     * @param code 设备码（来自 initiateDeviceFlow 的响应）
     * @return 设备状态响应，包含令牌和用户邮箱
     * @throws IOException 如果轮询失败、用户拒绝或过期
     */
    public DeviceStatusResponse pollForToken(String code) throws IOException {
        if (code == null || code.trim().isEmpty()) {
            throw new IOException("kilo: 设备码不能为空");
        }

        Log.d(TAG, "开始轮询令牌, code=" + code);

        while (true) {
            // 检查中断状态（1:1 移植自 Go ctx.Done()）
            if (Thread.currentThread().isInterrupted()) {
                throw new IOException("kilo: 上下文已取消");
            }

            // 等待 5 秒（1:1 移植自 Go time.NewTicker(5 * time.Second)）
            try {
                Thread.sleep(POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("kilo: 轮询被中断", e);
            }

            // 执行轮询请求（1:1 移植自 Go client.Get）
            DeviceStatusResponse result = pollOnce(code);
            if (result == null) {
                continue;
            }

            // 状态处理（1:1 移植自 Go switch 语句）
            switch (result.status) {
                case "approved":
                    Log.d(TAG, "设备流已批准, userEmail=" + result.userEmail);
                    return result;
                case "denied":
                    Log.e(TAG, "设备流已被用户拒绝");
                    throw new IOException("kilo: 设备流被拒绝");
                case "expired":
                    Log.e(TAG, "设备码已过期");
                    throw new IOException("kilo: 设备码已过期");
                case "pending":
                    // 继续轮询（1:1 移植自 Go continue）
                    Log.d(TAG, "设备流状态: pending, 继续轮询...");
                    continue;
                default:
                    Log.e(TAG, "未知状态: " + result.status);
                    throw new IOException("kilo: 未知状态: " + result.status);
            }
        }
    }

    /**
     * 执行一次轮询请求。
     * 1:1 移植自 Go ticker 循环中的 GET 请求。
     *
     * @param code 设备码
     * @return 设备状态响应，如果状态为 pending 则返回 null
     * @throws IOException 如果 HTTP 请求失败
     */
    private DeviceStatusResponse pollOnce(String code) throws IOException {
        HttpURLConnection conn = null;
        try {
            URL url = new URL(BASE_URL + "/device-auth/codes/" + code);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, responseCode);

            Log.d(TAG, "轮询响应: status=" + responseCode + " body=" + responseBody);

            if (responseCode != HttpURLConnection.HTTP_OK) {
                Log.e(TAG, "轮询请求失败: HTTP " + responseCode);
                throw new IOException("kilo: 轮询请求失败: status " + responseCode);
            }

            JSONObject json = parseJson(responseBody);
            return DeviceStatusResponse.fromJson(json);

        } catch (IOException e) {
            Log.e(TAG, "轮询异常", e);
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "解析轮询响应失败", e);
            throw new IOException("kilo: 解析轮询响应失败: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // 用户信息 — 1:1 移植自 Go GetProfile
    // ========================================================================

    /**
     * 获取已认证用户的个人信息。
     * <p>
     * 使用 Bearer 令牌认证访问 /profile 端点。
     * 1:1 移植自 Go GetProfile()。
     *
     * @param token 访问令牌
     * @return 用户信息，包含邮箱和所属组织列表
     * @throws IOException 如果请求失败或响应解析失败
     */
    public Profile getProfile(String token) throws IOException {
        if (token == null || token.trim().isEmpty()) {
            throw new IOException("kilo: 令牌不能为空");
        }

        Log.d(TAG, "获取用户信息...");

        HttpURLConnection conn = null;
        try {
            URL url = new URL(BASE_URL + "/profile");
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, responseCode);

            Log.d(TAG, "获取用户信息响应: status=" + responseCode);

            // 检查状态码（1:1 移植自 Go 200 检查）
            if (responseCode != HttpURLConnection.HTTP_OK) {
                String errorMsg = "获取用户信息失败: status " + responseCode;
                Log.e(TAG, errorMsg + " body=" + responseBody);
                throw new IOException(errorMsg + " - " + responseBody.trim());
            }

            JSONObject json = parseJson(responseBody);
            Profile profile = Profile.fromJson(json);

            Log.d(TAG, "用户信息获取成功: email=" + profile.email
                    + ", organizations=" + (profile.organizations != null
                    ? profile.organizations.size() : 0));

            return profile;

        } catch (IOException e) {
            Log.e(TAG, "获取用户信息失败", e);
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "解析用户信息响应失败", e);
            throw new IOException("kilo: 解析用户信息响应失败: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // 默认设置 — 1:1 移植自 Go GetDefaults
    // ========================================================================

    /**
     * 获取组织或用户的默认设置（如默认模型）。
     * <p>
     * 如果 orgID 为空，则获取用户级默认设置；否则获取指定组织的默认设置。
     * 1:1 移植自 Go GetDefaults()。
     *
     * @param token 访问令牌
     * @param orgID 组织 ID（可选，为空时获取用户级默认设置）
     * @return 默认设置，包含默认模型名称
     * @throws IOException 如果请求失败或响应解析失败
     */
    public Defaults getDefaults(String token, String orgID) throws IOException {
        if (token == null || token.trim().isEmpty()) {
            throw new IOException("kilo: 令牌不能为空");
        }

        // 构建 URL（1:1 移植自 Go URL 构建逻辑）
        String urlStr;
        if (orgID != null && !orgID.trim().isEmpty()) {
            urlStr = BASE_URL + "/organizations/" + orgID.trim() + "/defaults";
        } else {
            urlStr = BASE_URL + "/defaults";
        }

        Log.d(TAG, "获取默认设置: url=" + urlStr);

        HttpURLConnection conn = null;
        try {
            URL url = new URL(urlStr);
            conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Accept", "application/json");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setConnectTimeout(connectTimeout);
            conn.setReadTimeout(readTimeout);

            int responseCode = conn.getResponseCode();
            String responseBody = readResponseBody(conn, responseCode);

            Log.d(TAG, "获取默认设置响应: status=" + responseCode);

            // 检查状态码（1:1 移植自 Go 200 检查）
            if (responseCode != HttpURLConnection.HTTP_OK) {
                String errorMsg = "获取默认设置失败: status " + responseCode;
                Log.e(TAG, errorMsg + " body=" + responseBody);
                throw new IOException(errorMsg + " - " + responseBody.trim());
            }

            JSONObject json = parseJson(responseBody);
            Defaults defaults = Defaults.fromJson(json);

            Log.d(TAG, "默认设置获取成功: model=" + defaults.model);

            return defaults;

        } catch (IOException e) {
            Log.e(TAG, "获取默认设置失败", e);
            throw e;
        } catch (Exception e) {
            Log.e(TAG, "解析默认设置响应失败", e);
            throw new IOException("kilo: 解析默认设置响应失败: " + e.getMessage(), e);
        } finally {
            if (conn != null) {
                conn.disconnect();
            }
        }
    }

    // ========================================================================
    // 令牌存储 — 1:1 移植自 Go KiloTokenStorage.SaveTokenToFile
    // ========================================================================

    /**
     * 创建 KiloTokenStorage 实例，填充认证信息。
     * 在保存前调用 {@link KiloTokenStorage#setMetadata(java.util.Map)} 可注入元数据。
     * <p>
     * 1:1 移植自 Go KiloTokenStorage 的构造逻辑。
     *
     * @param token  Kilo 访问令牌
     * @param orgID  Kilo 组织 ID（可选）
     * @param model  默认模型（可选）
     * @param email  用户邮箱
     * @return 填充好的 KiloTokenStorage 实例
     */
    public KiloTokenStorage createTokenStorage(String token, String orgID,
                                               String model, String email) {
        KiloTokenStorage storage = new KiloTokenStorage();
        storage.kilocodeToken = token != null ? token.trim() : "";
        storage.kilocodeOrganizationId = orgID != null ? orgID.trim() : "";
        storage.kilocodeModel = model != null ? model.trim() : "";
        storage.email = email != null ? email.trim() : "";
        storage.type = "kilo";

        Log.d(TAG, "创建令牌存储: email=" + storage.email
                + ", orgID=" + storage.kilocodeOrganizationId
                + ", model=" + storage.kilocodeModel);

        return storage;
    }

    /**
     * 从 DeviceStatusResponse 和可选组织/模型信息创建令牌存储。
     *
     * @param statusRes 设备状态响应（需包含 token 和 userEmail）
     * @param orgID     Kilo 组织 ID（可选）
     * @param model     默认模型（可选）
     * @return 填充好的 KiloTokenStorage 实例
     */
    public KiloTokenStorage createTokenStorageFromDeviceResponse(
            DeviceStatusResponse statusRes, String orgID, String model) {
        if (statusRes == null) {
            throw new IllegalArgumentException("kilo: DeviceStatusResponse 不能为空");
        }
        return createTokenStorage(statusRes.token, orgID, model, statusRes.userEmail);
    }

    // ========================================================================
    // 内部工具方法
    // ========================================================================

    /**
     * 从 HttpURLConnection 读取响应 body。
     *
     * @param conn         HTTP 连接
     * @param responseCode HTTP 响应码
     * @return 响应 body 字符串
     * @throws IOException 如果读取失败
     */
    private String readResponseBody(HttpURLConnection conn, int responseCode) throws IOException {
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
     * 解析 JSON 字符串。
     *
     * @param body JSON 字符串
     * @return JSONObject 实例
     * @throws IOException 如果解析失败
     */
    private static JSONObject parseJson(String body) throws IOException {
        try {
            return new JSONObject(body);
        } catch (JSONException e) {
            throw new IOException("kilo: 解析 JSON 响应失败: " + e.getMessage(), e);
        }
    }
}