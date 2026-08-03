package com.cliproxy.plus.management;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * ManagementAPIClient - 通过 HTTP 调用 Go 服务器的管理 API
 * 所有 UI 控件通过此类与 rootfs 中的 cliproxy-server 通信
 */
public class ManagementAPIClient {

    private static final String TAG = "MgmtAPI";
    private final String baseUrl;

    public ManagementAPIClient(String baseUrl) {
        this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length()-1) : baseUrl;
    }

    // ==================== 服务器控制 ====================

    /** 健康检查 */
    public boolean isHealthy() {
        try {
            String resp = httpGet("/healthz");
            return resp != null && resp.contains("ok");
        } catch (Exception e) {
            return false;
        }
    }

    // ==================== 配置管理 ====================

    /** 获取完整配置 (JSON) */
    public JSONObject getConfig() throws Exception {
        String resp = httpGet("/v0/management/config");
        return new JSONObject(resp);
    }

    /** 获取配置字段 */
    public String getConfigField(String path) throws Exception {
        return httpGet("/v0/management/config/" + path);
    }

    /** 设置配置字段 */
    public void setConfigField(String path, String value) throws Exception {
        JSONObject body = new JSONObject();
        body.put("value", value);
        httpPatch("/v0/management/config/" + path, body.toString());
    }

    /** 获取端口 */
    public int getPort() throws Exception {
        String resp = getConfigField("port");
        return Integer.parseInt(resp.trim());
    }

    // ==================== 提供商/凭证管理 ====================

    /** 获取 OAuth 认证 URL */
    public String getAuthUrl(String provider) throws Exception {
        String endpoint = "/v0/management/" + provider + "-auth-url";
        return httpGet(endpoint);
    }

    /** 检查 OAuth 状态 */
    public JSONObject getAuthStatus(String state) throws Exception {
        String resp = httpGet("/v0/management/get-auth-status?state=" + URLEncoder.encode(state, "UTF-8"));
        return new JSONObject(resp);
    }

    /** 列出所有凭证文件 */
    public JSONArray listAuthFiles() throws Exception {
        String resp = httpGet("/v0/management/auth-files");
        return new JSONObject(resp).optJSONArray("files");
    }

    // ==================== API Key 管理 ====================

    /** 获取 Gemini API Keys */
    public JSONArray getGeminiKeys() throws Exception {
        String resp = httpGet("/v0/management/gemini-api-key");
        return new JSONArray(resp);
    }

    /** 获取 Claude API Keys */
    public JSONArray getClaudeKeys() throws Exception {
        String resp = httpGet("/v0/management/claude-api-key");
        return new JSONArray(resp);
    }

    /** 获取 Codex API Keys */
    public JSONArray getCodexKeys() throws Exception {
        String resp = httpGet("/v0/management/codex-api-key");
        return new JSONArray(resp);
    }

    /** 添加 API Key */
    public void addApiKey(String provider, String key, int weight) throws Exception {
        JSONObject body = new JSONObject();
        JSONArray entries = new JSONArray();
        JSONObject entry = new JSONObject();
        entry.put("api-key", key);
        if (weight > 0) entry.put("weight", weight);
        entries.put(entry);
        body.put("value", entries);
        httpPut("/v0/management/" + provider + "-api-key", body.toString());
    }

    /** 删除 API Key */
    public void deleteApiKey(String provider, String key) throws Exception {
        JSONObject body = new JSONObject();
        JSONArray entries = new JSONArray();
        JSONObject entry = new JSONObject();
        entry.put("api-key", key);
        entries.put(entry);
        body.put("value", entries);
        httpDelete("/v0/management/" + provider + "-api-key", body.toString());
    }

    // ==================== 用量统计 ====================

    /** 获取用量统计 */
    public JSONObject getUsage() throws Exception {
        String resp = httpGet("/v0/management/usage");
        return new JSONObject(resp);
    }

    // ==================== 日志 ====================

    /** 获取日志 */
    public String getLogs(int limit) throws Exception {
        return httpGet("/v0/management/logs?limit=" + limit);
    }

    // ==================== 路由策略 ====================

    /** 获取路由策略 */
    public String getRoutingStrategy() throws Exception {
        return httpGet("/v0/management/routing/strategy");
    }

    /** 设置路由策略 */
    public void setRoutingStrategy(String strategy) throws Exception {
        JSONObject body = new JSONObject();
        body.put("value", strategy);
        httpPut("/v0/management/routing/strategy", body.toString());
    }

    // ==================== HTTP 工具 ====================

    private String httpGet(String path) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        conn.setRequestMethod("GET");
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        return readResponse(conn);
    }

    private String httpPut(String path, String jsonBody) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        conn.setRequestMethod("PUT");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        return readResponse(conn);
    }

    private String httpPatch(String path, String jsonBody) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        conn.setRequestMethod("PATCH");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
        }
        return readResponse(conn);
    }

    private String httpDelete(String path, String jsonBody) throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(baseUrl + path).openConnection();
        conn.setRequestMethod("DELETE");
        conn.setRequestProperty("Content-Type", "application/json");
        conn.setDoOutput(true);
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        if (jsonBody != null) {
            try (OutputStream os = conn.getOutputStream()) {
                os.write(jsonBody.getBytes(StandardCharsets.UTF_8));
            }
        }
        return readResponse(conn);
    }

    private String readResponse(HttpURLConnection conn) throws Exception {
        try {
            int code = conn.getResponseCode();
            BufferedReader reader = new BufferedReader(new InputStreamReader(
                    (code >= 200 && code < 300) ? conn.getInputStream() : conn.getErrorStream(),
                    StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) sb.append(line);
            reader.close();
            return sb.toString();
        } finally {
            conn.disconnect();
        }
    }
}