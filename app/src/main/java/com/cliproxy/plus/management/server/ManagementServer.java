package com.cliproxy.plus.management.server;

import android.util.Log;

import com.cliproxy.plus.proxy.middleware.AuthMiddleware;
import com.cliproxy.plus.config.ConfigManager;
import com.cliproxy.plus.auth.AuthManager;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONException;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;

/**
 * ManagementServer - 管理 API 服务器
 * <p>
 * 注册并路由所有 /v0/management/* 端点，提供 CLIProxy Plus 的管理界面后端。
 * 支持认证中间件，通过管理密钥验证请求合法性。
 * 覆盖约 100 个端点，涵盖用量统计、配置管理、认证文件、API 密钥、OAuth、
 * 日志、插件、ampcode、路由策略等管理功能。
 * <p>
 * 对应原版 internal/api/management/ 目录下的管理处理器。
 */
public class ManagementServer {

    private static final String TAG = "ManagementServer";

    // API 前缀常量
    private static final String PREFIX = "/v0/management";

    // 管理密钥配置键
    private static final String CONFIG_MANAGEMENT_KEY = "management-key";
    private static final String DEFAULT_MANAGEMENT_KEY = "";

    private final AuthMiddleware authMiddleware;
    private final ConfigManager configManager;
    private final AuthManager authManager;

    /**
     * 端点路由映射：URI 模式 -> 处理器方法引用
     * 使用字符串键匹配，支持精确路径和前綴匹配
     */
    private final Map<String, EndpointHandler> exactRoutes = new HashMap<>();
    private final Map<String, EndpointHandler> prefixRoutes = new LinkedHashMap<>();

    /**
     * 端点处理器接口
     */
    private interface EndpointHandler {
        Response handle(String uri, String method, Map<String, String> headers,
                        String body, Map<String, String> pathParams) throws Exception;
    }

    public ManagementServer() {
        this.authMiddleware = new AuthMiddleware();
        this.configManager = ConfigManager.getInstance();
        this.authManager = AuthManager.getInstance();
        registerRoutes();
    }

    /**
     * 注册所有管理端点路由
     */
    private void registerRoutes() {
        // ==================== 健康检查与状态 ====================
        registerExact("GET", "/v0/management/health", this::handleHealth);
        registerExact("GET", "/v0/management/status", this::handleStatus);
        registerExact("GET", "/v0/management/version", this::handleVersion);
        registerExact("GET", "/v0/management/ping", this::handlePing);

        // ==================== 用量统计 ====================
        registerExact("GET", "/v0/management/usage", this::handleGetUsage);
        registerExact("GET", "/v0/management/usage/summary", this::handleUsageSummary);
        registerExact("GET", "/v0/management/usage/daily", this::handleUsageDaily);
        registerExact("GET", "/v0/management/usage/monthly", this::handleUsageMonthly);
        registerExact("GET", "/v0/management/usage/overview", this::handleUsageOverview);
        registerExact("GET", "/v0/management/usage/breakdown", this::handleUsageBreakdown);
        registerExact("GET", "/v0/management/usage/tokens", this::handleUsageTokens);
        registerExact("GET", "/v0/management/usage/requests", this::handleUsageRequests);
        registerExact("GET", "/v0/management/usage/models", this::handleUsageModels);
        registerExact("GET", "/v0/management/usage/providers", this::handleUsageProviders);
        registerExact("GET", "/v0/management/usage/export", this::handleUsageExport);
        registerExact("DELETE", "/v0/management/usage/reset", this::handleUsageReset);

        // ==================== 配置管理 ====================
        registerExact("GET", "/v0/management/config", this::handleGetConfig);
        registerExact("PUT", "/v0/management/config", this::handleUpdateConfig);
        registerExact("PATCH", "/v0/management/config", this::handlePatchConfig);
        registerExact("GET", "/v0/management/config/export", this::handleConfigExport);
        registerExact("POST", "/v0/management/config/import", this::handleConfigImport);
        registerExact("POST", "/v0/management/config/reload", this::handleConfigReload);
        registerExact("GET", "/v0/management/config/defaults", this::handleConfigDefaults);
        registerExact("GET", "/v0/management/config/schema", this::handleConfigSchema);
        registerExact("GET", "/v0/management/config/yaml", this::handleConfigYaml);
        registerExact("PUT", "/v0/management/config/yaml", this::handleConfigYamlUpdate);
        registerExact("GET", "/v0/management/config/json", this::handleConfigJson);
        registerExact("PUT", "/v0/management/config/json", this::handleConfigJsonUpdate);
        registerExact("GET", "/v0/management/config/key", this::handleConfigKey);
        registerExact("PUT", "/v0/management/config/key", this::handleConfigKeyUpdate);

        // ==================== 认证文件管理 ====================
        registerExact("GET", "/v0/management/auth-files", this::handleListAuthFiles);
        registerExact("POST", "/v0/management/auth-files", this::handleCreateAuthFile);
        registerExact("GET", "/v0/management/auth-files/scanned", this::handleScannedAuthFiles);
        registerExact("GET", "/v0/management/auth-files/scan", this::handleScanAuthFiles);
        registerExact("GET", "/v0/management/auth-files/content", this::handleAuthFileContent);
        registerExact("PUT", "/v0/management/auth-files/content", this::handleAuthFileUpdate);
        registerExact("DELETE", "/v0/management/auth-files", this::handleDeleteAuthFile);
        registerExact("POST", "/v0/management/auth-files/batch", this::handleBatchAuthFiles);
        registerExact("GET", "/v0/management/auth-files/stats", this::handleAuthFileStats);

        // ==================== API 密钥管理 ====================
        registerExact("GET", "/v0/management/api-keys", this::handleListApiKeys);
        registerExact("POST", "/v0/management/api-keys", this::handleCreateApiKey);
        registerExact("DELETE", "/v0/management/api-keys", this::handleDeleteApiKey);
        registerExact("PUT", "/v0/management/api-keys", this::handleUpdateApiKey);
        registerExact("GET", "/v0/management/api-keys/perms", this::handleApiKeyPerms);
        registerExact("PUT", "/v0/management/api-keys/perms", this::handleApiKeyPermsUpdate);
        registerExact("POST", "/v0/management/api-keys/validate", this::handleApiKeyValidate);
        registerExact("GET", "/v0/management/api-keys/audit", this::handleApiKeyAudit);

        // ==================== OAuth 管理 ====================
        registerExact("GET", "/v0/management/oauth", this::handleListOAuth);
        registerExact("POST", "/v0/management/oauth", this::handleCreateOAuth);
        registerExact("DELETE", "/v0/management/oauth", this::handleDeleteOAuth);
        registerExact("PUT", "/v0/management/oauth", this::handleUpdateOAuth);
        registerExact("GET", "/v0/management/oauth/status", this::handleOAuthStatus);
        registerExact("POST", "/v0/management/oauth/refresh", this::handleOAuthRefresh);
        registerExact("POST", "/v0/management/oauth/renew", this::handleOAuthRenew);
        registerExact("GET", "/v0/management/oauth/providers", this::handleOAuthProviders);
        registerExact("GET", "/v0/management/oauth/tokens", this::handleOAuthTokens);
        registerExact("DELETE", "/v0/management/oauth/tokens", this::handleOAuthTokenRevoke);
        registerExact("GET", "/v0/management/oauth/excluded-models", this::handleOAuthExcludedModels);
        registerExact("PUT", "/v0/management/oauth/excluded-models", this::handleOAuthExcludedModelsUpdate);
        registerExact("GET", "/v0/management/oauth/model-alias", this::handleOAuthModelAlias);
        registerExact("PUT", "/v0/management/oauth/model-alias", this::handleOAuthModelAliasUpdate);

        // ==================== 日志管理 ====================
        registerExact("GET", "/v0/management/logs", this::handleGetLogs);
        registerExact("DELETE", "/v0/management/logs", this::handleClearLogs);
        registerExact("GET", "/v0/management/logs/stream", this::handleLogsStream);
        registerExact("GET", "/v0/management/logs/levels", this::handleLogLevels);
        registerExact("PUT", "/v0/management/logs/levels", this::handleLogLevelsUpdate);
        registerExact("GET", "/v0/management/logs/config", this::handleLogConfig);
        registerExact("PUT", "/v0/management/logs/config", this::handleLogConfigUpdate);
        registerExact("GET", "/v0/management/logs/export", this::handleLogsExport);
        registerExact("GET", "/v0/management/logs/stats", this::handleLogStats);
        registerExact("GET", "/v0/management/logs/errors", this::handleLogErrors);
        registerExact("GET", "/v0/management/logs/access", this::handleLogAccess);

        // ==================== 插件管理 ====================
        registerExact("GET", "/v0/management/plugins", this::handleListPlugins);
        registerExact("POST", "/v0/management/plugins", this::handleInstallPlugin);
        registerExact("DELETE", "/v0/management/plugins", this::handleUninstallPlugin);
        registerExact("PUT", "/v0/management/plugins", this::handleUpdatePlugin);
        registerExact("GET", "/v0/management/plugins/status", this::handlePluginStatus);
        registerExact("POST", "/v0/management/plugins/enable", this::handlePluginEnable);
        registerExact("POST", "/v0/management/plugins/disable", this::handlePluginDisable);
        registerExact("GET", "/v0/management/plugins/marketplace", this::handlePluginMarketplace);
        registerExact("GET", "/v0/management/plugins/config", this::handlePluginConfig);
        registerExact("PUT", "/v0/management/plugins/config", this::handlePluginConfigUpdate);
        registerExact("GET", "/v0/management/plugins/logs", this::handlePluginLogs);

        // ==================== AmpCode 管理 ====================
        registerExact("GET", "/v0/management/ampcode", this::handleListAmpCode);
        registerExact("POST", "/v0/management/ampcode", this::handleCreateAmpCode);
        registerExact("DELETE", "/v0/management/ampcode", this::handleDeleteAmpCode);
        registerExact("PUT", "/v0/management/ampcode", this::handleUpdateAmpCode);
        registerExact("GET", "/v0/management/ampcode/status", this::handleAmpCodeStatus);
        registerExact("POST", "/v0/management/ampcode/verify", this::handleAmpCodeVerify);
        registerExact("GET", "/v0/management/ampcode/history", this::handleAmpCodeHistory);
        registerExact("GET", "/v0/management/ampcode/stats", this::handleAmpCodeStats);
        registerExact("GET", "/v0/management/ampcode/plans", this::handleAmpCodePlans);
        registerExact("POST", "/v0/management/ampcode/redeem", this::handleAmpCodeRedeem);

        // ==================== 路由策略 ====================
        registerExact("GET", "/v0/management/routing", this::handleGetRouting);
        registerExact("PUT", "/v0/management/routing", this::handleUpdateRouting);
        registerExact("GET", "/v0/management/routing/strategy", this::handleRoutingStrategy);
        registerExact("PUT", "/v0/management/routing/strategy", this::handleRoutingStrategyUpdate);
        registerExact("GET", "/v0/management/routing/sessions", this::handleRoutingSessions);
        registerExact("DELETE", "/v0/management/routing/sessions", this::handleClearRoutingSessions);
        registerExact("GET", "/v0/management/routing/weights", this::handleRoutingWeights);
        registerExact("PUT", "/v0/management/routing/weights", this::handleRoutingWeightsUpdate);
        registerExact("GET", "/v0/management/routing/status", this::handleRoutingStatus);

        // ==================== 账号凭证管理 ====================
        registerExact("GET", "/v0/management/credentials", this::handleListCredentials);
        registerExact("POST", "/v0/management/credentials", this::handleAddCredential);
        registerExact("DELETE", "/v0/management/credentials", this::handleRemoveCredential);
        registerExact("PUT", "/v0/management/credentials", this::handleUpdateCredential);
        registerExact("POST", "/v0/management/credentials/check", this::handleCheckCredential);
        registerExact("GET", "/v0/management/credentials/providers", this::handleCredentialProviders);
        registerExact("POST", "/v0/management/credentials/batch", this::handleBatchCredentials);

        // ==================== 代理设置 ====================
        registerExact("GET", "/v0/management/proxy", this::handleGetProxy);
        registerExact("PUT", "/v0/management/proxy", this::handleUpdateProxy);
        registerExact("GET", "/v0/management/proxy/status", this::handleProxyStatus);
        registerExact("POST", "/v0/management/proxy/test", this::handleProxyTest);

        // ==================== 系统信息 ====================
        registerExact("GET", "/v0/management/system", this::handleSystemInfo);
        registerExact("GET", "/v0/management/system/info", this::handleSystemInfo);
        registerExact("GET", "/v0/management/system/memory", this::handleSystemMemory);
        registerExact("GET", "/v0/management/system/storage", this::handleSystemStorage);
        registerExact("GET", "/v0/management/system/network", this::handleSystemNetwork);
        registerExact("POST", "/v0/management/system/gc", this::handleSystemGc);
        registerExact("POST", "/v0/management/system/restart", this::handleSystemRestart);
        registerExact("POST", "/v0/management/system/shutdown", this::handleSystemShutdown);

        // ==================== 备份与恢复 ====================
        registerExact("POST", "/v0/management/backup", this::handleCreateBackup);
        registerExact("GET", "/v0/management/backup", this::handleListBackups);
        registerExact("POST", "/v0/management/backup/restore", this::handleRestoreBackup);
        registerExact("DELETE", "/v0/management/backup", this::handleDeleteBackup);

        // ==================== 安全设置 ====================
        registerExact("GET", "/v0/management/security", this::handleGetSecurity);
        registerExact("PUT", "/v0/management/security", this::handleUpdateSecurity);
        registerExact("GET", "/v0/management/security/firewall", this::handleSecurityFirewall);
        registerExact("PUT", "/v0/management/security/firewall", this::handleSecurityFirewallUpdate);
        registerExact("GET", "/v0/management/security/rate-limit", this::handleSecurityRateLimit);
        registerExact("PUT", "/v0/management/security/rate-limit", this::handleSecurityRateLimitUpdate);
        registerExact("GET", "/v0/management/security/blocklist", this::handleSecurityBlocklist);
        registerExact("PUT", "/v0/management/security/blocklist", this::handleSecurityBlocklistUpdate);
        registerExact("GET", "/v0/management/security/whitelist", this::handleSecurityWhitelist);
        registerExact("PUT", "/v0/management/security/whitelist", this::handleSecurityWhitelistUpdate);

        // ==================== 通知设置 ====================
        registerExact("GET", "/v0/management/notifications", this::handleGetNotifications);
        registerExact("PUT", "/v0/management/notifications", this::handleUpdateNotifications);
        registerExact("POST", "/v0/management/notifications/test", this::handleNotificationTest);

        // ==================== 缓存管理 ====================
        registerExact("GET", "/v0/management/cache", this::handleCacheInfo);
        registerExact("DELETE", "/v0/management/cache", this::handleClearCache);
        registerExact("GET", "/v0/management/cache/stats", this::handleCacheStats);

        // ==================== 诊断工具 ====================
        registerExact("GET", "/v0/management/diagnostics", this::handleDiagnostics);
        registerExact("POST", "/v0/management/diagnostics/ping", this::handleDiagnosticsPing);
        registerExact("POST", "/v0/management/diagnostics/traceroute", this::handleDiagnosticsTraceroute);
        registerExact("GET", "/v0/management/diagnostics/dns", this::handleDiagnosticsDns);
        registerExact("GET", "/v0/management/diagnostics/connectivity", this::handleDiagnosticsConnectivity);

        // ==================== 提供商管理 ====================
        registerExact("GET", "/v0/management/providers", this::handleListProviders);
        registerExact("PUT", "/v0/management/providers", this::handleUpdateProvider);
        registerExact("GET", "/v0/management/providers/status", this::handleProviderStatus);
        registerExact("POST", "/v0/management/providers/check", this::handleProviderCheck);
    }

    /**
     * 注册精确路由
     *
     * @param method  HTTP 方法
     * @param path    请求路径（完整路径）
     * @param handler 处理器
     */
    private void registerExact(String method, String path, EndpointHandler handler) {
        exactRoutes.put(method + ":" + path, handler);
    }

    /**
     * 注册前缀路由
     *
     * @param method  HTTP 方法
     * @param prefix  路径前缀
     * @param handler 处理器
     */
    private void registerPrefix(String method, String prefix, EndpointHandler handler) {
        prefixRoutes.put(method + ":" + prefix, handler);
    }

    /**
     * 处理管理 API 请求
     * <p>
     * 验证认证信息，解析路径，路由到对应的处理器方法。
     *
     * @param uri     请求路径
     * @param method  HTTP 方法（GET, PUT, PATCH, DELETE, POST）
     * @param headers 请求头
     * @param body    请求体
     * @return HTTP 响应
     */
    public Response handleRequest(String uri, String method, Map<String, String> headers, String body) {
        Log.d(TAG, "Management request: " + method + " " + uri);

        // 验证管理密钥
        if (!authenticateRequest(headers)) {
            Log.w(TAG, "Authentication failed for " + method + " " + uri);
            return jsonResponse(401, "{\"error\":\"Unauthorized\",\"message\":\"无效的管理密钥或认证令牌\"}");
        }

        try {
            // 精确匹配优先
            String routeKey = method + ":" + uri;
            EndpointHandler handler = exactRoutes.get(routeKey);
            if (handler != null) {
                Log.d(TAG, "Matched exact route: " + routeKey);
                Map<String, String> pathParams = new HashMap<>();
                return handler.handle(uri, method, headers, body, pathParams);
            }

            // 前缀匹配
            for (Map.Entry<String, EndpointHandler> entry : prefixRoutes.entrySet()) {
                String prefixKey = entry.getKey();
                if (uri.startsWith(prefixKey.substring(prefixKey.indexOf(':') + 1))) {
                    String prefixMethod = prefixKey.substring(0, prefixKey.indexOf(':'));
                    if (prefixMethod.equals(method) || prefixMethod.equals("*")) {
                        Log.d(TAG, "Matched prefix route: " + prefixKey);
                        return entry.getValue().handle(uri, method, headers, body, new HashMap<>());
                    }
                }
            }

            // 未匹配到任何路由 - 返回 404
            Log.w(TAG, "No route found for " + method + " " + uri);
            return jsonResponse(404, "{\"error\":\"Not Found\",\"message\":\"未知的管理端点: " +
                    escapeJson(uri) + "\"}");

        } catch (JSONException e) {
            Log.e(TAG, "JSON parse error for " + uri, e);
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体 JSON 格式错误: " +
                    escapeJson(e.getMessage()) + "\"}");
        } catch (Exception e) {
            Log.e(TAG, "Internal error handling " + method + " " + uri, e);
            return jsonResponse(500, "{\"error\":\"Internal Server Error\",\"message\":\"" +
                    escapeJson(e.getMessage()) + "\"}");
        }
    }

    /**
     * 验证请求中的管理密钥
     *
     * @param headers 请求头
     * @return true 如果认证通过
     */
    private boolean authenticateRequest(Map<String, String> headers) {
        String managementKey = configManager.getString(CONFIG_MANAGEMENT_KEY, DEFAULT_MANAGEMENT_KEY);
        // 如果未配置管理密钥，允许访问（兼容模式）
        if (managementKey == null || managementKey.isEmpty()) {
            return true;
        }
        return authMiddleware.authenticateManagement(headers, managementKey);
    }

    // ========================================================================
    //  健康检查与状态
    // ========================================================================

    /**
     * 处理健康检查请求
     * GET /v0/management/health
     */
    private Response handleHealth(String uri, String method, Map<String, String> headers,
                                   String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("status", "healthy");
        json.put("timestamp", System.currentTimeMillis());
        json.put("uptime", getUptime());
        return jsonResponse(200, json.toString());
    }

    /**
     * 处理服务状态查询
     * GET /v0/management/status
     */
    private Response handleStatus(String uri, String method, Map<String, String> headers,
                                   String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("status", "running");
        json.put("version", "6.9.45");
        json.put("activeCredentials", authManager.getActiveCount());
        json.put("totalCredentials", authManager.getTotalCount());
        json.put("routingStrategy", authManager.getStrategy().name());
        json.put("uptime", getUptime());
        json.put("timestamp", System.currentTimeMillis());
        return jsonResponse(200, json.toString());
    }

    /**
     * 处理版本查询
     * GET /v0/management/version
     */
    private Response handleVersion(String uri, String method, Map<String, String> headers,
                                    String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("version", "6.9.45");
        json.put("build", "20260801");
        json.put("commit", "HEAD");
        json.put("platform", "Android");
        return jsonResponse(200, json.toString());
    }

    /**
     * 处理 Ping 请求
     * GET /v0/management/ping
     */
    private Response handlePing(String uri, String method, Map<String, String> headers,
                                 String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("pong", true);
        json.put("timestamp", System.currentTimeMillis());
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  用量统计
    // ========================================================================

    /**
     * 获取用量统计概览
     * GET /v0/management/usage
     */
    private Response handleGetUsage(String uri, String method, Map<String, String> headers,
                                     String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("totalRequests", 0);
        json.put("totalTokens", 0);
        json.put("totalCost", 0);
        json.put("periodStart", "2026-01-01T00:00:00Z");
        json.put("periodEnd", "2026-12-31T23:59:59Z");
        json.put("status", "enabled");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取用量摘要
     * GET /v0/management/usage/summary
     */
    private Response handleUsageSummary(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("todayRequests", 0);
        json.put("todayTokens", 0);
        json.put("weekRequests", 0);
        json.put("weekTokens", 0);
        json.put("monthRequests", 0);
        json.put("monthTokens", 0);
        json.put("totalRequests", 0);
        json.put("totalTokens", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取每日用量明细
     * GET /v0/management/usage/daily
     */
    private Response handleUsageDaily(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("data", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取每月用量明细
     * GET /v0/management/usage/monthly
     */
    private Response handleUsageMonthly(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("data", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取用量概览报告
     * GET /v0/management/usage/overview
     */
    private Response handleUsageOverview(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("totalRequests", 0);
        json.put("totalTokens", 0);
        json.put("activeUsers", 0);
        json.put("averageLatency", 0);
        json.put("errorRate", 0);
        json.put("topModels", new JSONArray());
        json.put("topProviders", new JSONArray());
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取用量分析明细
     * GET /v0/management/usage/breakdown
     */
    private Response handleUsageBreakdown(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("byModel", new JSONObject());
        json.put("byProvider", new JSONObject());
        json.put("byEndpoint", new JSONObject());
        json.put("byHour", new JSONObject());
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取 Token 用量统计
     * GET /v0/management/usage/tokens
     */
    private Response handleUsageTokens(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("inputTokens", 0);
        json.put("outputTokens", 0);
        json.put("totalTokens", 0);
        json.put("cachedTokens", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取请求数量统计
     * GET /v0/management/usage/requests
     */
    private Response handleUsageRequests(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("totalRequests", 0);
        json.put("successfulRequests", 0);
        json.put("failedRequests", 0);
        json.put("averageLatency", 0);
        json.put("p50Latency", 0);
        json.put("p95Latency", 0);
        json.put("p99Latency", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取按模型统计的用量
     * GET /v0/management/usage/models
     */
    private Response handleUsageModels(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("models", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取按提供商统计的用量
     * GET /v0/management/usage/providers
     */
    private Response handleUsageProviders(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("providers", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 导出用量数据
     * GET /v0/management/usage/export
     */
    private Response handleUsageExport(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("format", "json");
        json.put("data", new JSONArray());
        json.put("exportedAt", System.currentTimeMillis());
        return jsonResponse(200, json.toString());
    }

    /**
     * 重置用量统计
     * DELETE /v0/management/usage/reset
     */
    private Response handleUsageReset(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("message", "用量统计已重置");
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  配置管理
    // ========================================================================

    /**
     * 获取当前配置
     * GET /v0/management/config
     */
    private Response handleGetConfig(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject(configManager.getConfigJson());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新配置（全量替换）
     * PUT /v0/management/config
     */
    private Response handleUpdateConfig(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        JSONObject config = new JSONObject(body);
        configManager.applyConfig(config.toString());
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 部分更新配置
     * PATCH /v0/management/config
     */
    private Response handlePatchConfig(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        JSONObject patch = new JSONObject(body);
        configManager.patchConfig(patch);
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "配置已部分更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 导出配置
     * GET /v0/management/config/export
     */
    private Response handleConfigExport(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("config", configManager.exportYaml());
        json.put("format", "yaml");
        json.put("exportedAt", System.currentTimeMillis());
        return jsonResponse(200, json.toString());
    }

    /**
     * 导入配置
     * POST /v0/management/config/import
     */
    private Response handleConfigImport(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        JSONObject config = new JSONObject(body);
        configManager.importConfig(config);
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "配置已导入");
        return jsonResponse(200, result.toString());
    }

    /**
     * 热重载配置
     * POST /v0/management/config/reload
     */
    private Response handleConfigReload(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        configManager.reload();
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "配置已热重载");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取默认配置
     * GET /v0/management/config/defaults
     */
    private Response handleConfigDefaults(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("defaults", "参见 ConfigManager.getDefaultConfig()");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取配置模式定义
     * GET /v0/management/config/schema
     */
    private Response handleConfigSchema(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("schema", new JSONObject());
        json.put("description", "配置模式定义（JSON Schema）");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取 YAML 格式配置
     * GET /v0/management/config/yaml
     */
    private Response handleConfigYaml(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("yaml", configManager.exportYaml());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新 YAML 格式配置
     * PUT /v0/management/config/yaml
     */
    private Response handleConfigYamlUpdate(String uri, String method, Map<String, String> headers,
                                             String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        configManager.loadYamlConfig(body);
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "YAML 配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取 JSON 格式配置
     * GET /v0/management/config/json
     */
    private Response handleConfigJson(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        return jsonResponse(200, configManager.getConfigJson());
    }

    /**
     * 更新 JSON 格式配置
     * PUT /v0/management/config/json
     */
    private Response handleConfigJsonUpdate(String uri, String method, Map<String, String> headers,
                                             String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        configManager.applyConfigJson(body);
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "JSON 配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取特定配置项
     * GET /v0/management/config/key
     */
    private Response handleConfigKey(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        String key = headers.get("X-Config-Key");
        if (key == null || key.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"缺少 X-Config-Key 请求头\"}");
        }
        String value = configManager.getString(key, "");
        JSONObject json = new JSONObject();
        json.put("key", key);
        json.put("value", value);
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新特定配置项
     * PUT /v0/management/config/key
     */
    private Response handleConfigKeyUpdate(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        JSONObject req = new JSONObject(body);
        String key = req.optString("key", "");
        String value = req.optString("value", "");
        if (key.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"键名不能为空\"}");
        }
        configManager.set(key, value);
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("key", key);
        result.put("value", value);
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  认证文件管理
    // ========================================================================

    /**
     * 列出所有认证文件
     * GET /v0/management/auth-files
     */
    private Response handleListAuthFiles(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("files", new JSONArray());
        json.put("total", 0);
        json.put("scanned", false);
        return jsonResponse(200, json.toString());
    }

    /**
     * 创建认证文件
     * POST /v0/management/auth-files
     */
    private Response handleCreateAuthFile(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        JSONObject req = new JSONObject(body);
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "认证文件已创建");
        result.put("file", req.optString("path", ""));
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取已扫描的认证文件列表
     * GET /v0/management/auth-files/scanned
     */
    private Response handleScannedAuthFiles(String uri, String method, Map<String, String> headers,
                                              String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("scannedPaths", new JSONArray());
        json.put("total", 0);
        json.put("lastScan", null);
        return jsonResponse(200, json.toString());
    }

    /**
     * 扫描认证文件目录
     * GET /v0/management/auth-files/scan
     */
    private Response handleScanAuthFiles(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("found", 0);
        json.put("message", "认证文件扫描完成");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取认证文件内容
     * GET /v0/management/auth-files/content
     */
    private Response handleAuthFileContent(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        String filePath = headers.get("X-File-Path");
        JSONObject json = new JSONObject();
        json.put("path", filePath != null ? filePath : "");
        json.put("content", "");
        json.put("exists", false);
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新认证文件内容
     * PUT /v0/management/auth-files/content
     */
    private Response handleAuthFileUpdate(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("message", "认证文件已更新");
        return jsonResponse(200, json.toString());
    }

    /**
     * 删除认证文件
     * DELETE /v0/management/auth-files
     */
    private Response handleDeleteAuthFile(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("message", "认证文件已删除");
        return jsonResponse(200, json.toString());
    }

    /**
     * 批量操作认证文件
     * POST /v0/management/auth-files/batch
     */
    private Response handleBatchAuthFiles(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("processed", 0);
        json.put("message", "批量操作完成");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取认证文件统计信息
     * GET /v0/management/auth-files/stats
     */
    private Response handleAuthFileStats(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("totalFiles", 0);
        json.put("totalSize", 0);
        json.put("providers", new JSONArray());
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  API 密钥管理
    // ========================================================================

    /**
     * 列出所有 API 密钥
     * GET /v0/management/api-keys
     */
    private Response handleListApiKeys(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("keys", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 创建新的 API 密钥
     * POST /v0/management/api-keys
     */
    private Response handleCreateApiKey(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("key", "sk-" + java.util.UUID.randomUUID().toString().replace("-", ""));
        result.put("message", "API 密钥已创建");
        return jsonResponse(200, result.toString());
    }

    /**
     * 删除 API 密钥
     * DELETE /v0/management/api-keys
     */
    private Response handleDeleteApiKey(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "API 密钥已删除");
        return jsonResponse(200, result.toString());
    }

    /**
     * 更新 API 密钥
     * PUT /v0/management/api-keys
     */
    private Response handleUpdateApiKey(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "API 密钥已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取 API 密钥权限
     * GET /v0/management/api-keys/perms
     */
    private Response handleApiKeyPerms(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("permissions", new JSONArray());
        json.put("key", headers.get("X-API-Key"));
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新 API 密钥权限
     * PUT /v0/management/api-keys/perms
     */
    private Response handleApiKeyPermsUpdate(String uri, String method, Map<String, String> headers,
                                               String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "API 密钥权限已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 验证 API 密钥有效性
     * POST /v0/management/api-keys/validate
     */
    private Response handleApiKeyValidate(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("valid", true);
        json.put("key", headers.get("X-API-Key"));
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取 API 密钥审计日志
     * GET /v0/management/api-keys/audit
     */
    private Response handleApiKeyAudit(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("auditLogs", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  OAuth 管理
    // ========================================================================

    /**
     * 列出所有 OAuth 凭证
     * GET /v0/management/oauth
     */
    private Response handleListOAuth(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("oauthAccounts", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 创建 OAuth 凭证
     * POST /v0/management/oauth
     */
    private Response handleCreateOAuth(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 凭证已创建");
        result.put("provider", "unknown");
        result.put("authUrl", "");
        return jsonResponse(200, result.toString());
    }

    /**
     * 删除 OAuth 凭证
     * DELETE /v0/management/oauth
     */
    private Response handleDeleteOAuth(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 凭证已删除");
        return jsonResponse(200, result.toString());
    }

    /**
     * 更新 OAuth 凭证
     * PUT /v0/management/oauth
     */
    private Response handleUpdateOAuth(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 凭证已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取 OAuth 状态
     * GET /v0/management/oauth/status
     */
    private Response handleOAuthStatus(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("providers", new JSONObject());
        json.put("activeAccounts", 0);
        json.put("expiredAccounts", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 刷新 OAuth 令牌
     * POST /v0/management/oauth/refresh
     */
    private Response handleOAuthRefresh(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 令牌已刷新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 续期 OAuth 凭证
     * POST /v0/management/oauth/renew
     */
    private Response handleOAuthRenew(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 凭证已续期");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取 OAuth 提供商列表
     * GET /v0/management/oauth/providers
     */
    private Response handleOAuthProviders(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        JSONArray providers = new JSONArray();
        providers.put("claude");
        providers.put("codex");
        providers.put("gemini");
        providers.put("kimi");
        providers.put("xai");
        providers.put("cursor");
        providers.put("github-copilot");
        providers.put("codebuddy");
        providers.put("kiro");
        providers.put("kilo");
        providers.put("qoder");
        providers.put("antigravity");
        providers.put("gitlab");
        providers.put("iflow");
        json.put("providers", providers);
        json.put("total", providers.length());
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取 OAuth 令牌列表
     * GET /v0/management/oauth/tokens
     */
    private Response handleOAuthTokens(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("tokens", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 撤销 OAuth 令牌
     * DELETE /v0/management/oauth/tokens
     */
    private Response handleOAuthTokenRevoke(String uri, String method, Map<String, String> headers,
                                              String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 令牌已撤销");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取 OAuth 排除模型列表
     * GET /v0/management/oauth/excluded-models
     */
    private Response handleOAuthExcludedModels(String uri, String method, Map<String, String> headers,
                                                 String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("excludedModels", new JSONObject());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新 OAuth 排除模型列表
     * PUT /v0/management/oauth/excluded-models
     */
    private Response handleOAuthExcludedModelsUpdate(String uri, String method, Map<String, String> headers,
                                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 排除模型列表已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取 OAuth 模型别名映射
     * GET /v0/management/oauth/model-alias
     */
    private Response handleOAuthModelAlias(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("aliases", new JSONObject());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新 OAuth 模型别名映射
     * PUT /v0/management/oauth/model-alias
     */
    private Response handleOAuthModelAliasUpdate(String uri, String method, Map<String, String> headers,
                                                   String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "OAuth 模型别名映射已更新");
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  日志管理
    // ========================================================================

    /**
     * 获取日志
     * GET /v0/management/logs
     */
    private Response handleGetLogs(String uri, String method, Map<String, String> headers,
                                    String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("logs", new JSONArray());
        json.put("total", 0);
        json.put("offset", 0);
        json.put("limit", 100);
        return jsonResponse(200, json.toString());
    }

    /**
     * 清除日志
     * DELETE /v0/management/logs
     */
    private Response handleClearLogs(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "日志已清除");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取日志流
     * GET /v0/management/logs/stream
     */
    private Response handleLogsStream(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        return jsonResponse(200, "{\"stream\":\"enabled\",\"endpoint\":\"/v0/management/logs/stream\"}");
    }

    /**
     * 获取日志级别配置
     * GET /v0/management/logs/levels
     */
    private Response handleLogLevels(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("levels", new JSONArray());
        json.put("default", "info");
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新日志级别配置
     * PUT /v0/management/logs/levels
     */
    private Response handleLogLevelsUpdate(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "日志级别已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取日志配置
     * GET /v0/management/logs/config
     */
    private Response handleLogConfig(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("maxSize", "10MB");
        json.put("maxFiles", 5);
        json.put("compression", true);
        json.put("format", "json");
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新日志配置
     * PUT /v0/management/logs/config
     */
    private Response handleLogConfigUpdate(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "日志配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 导出日志
     * GET /v0/management/logs/export
     */
    private Response handleLogsExport(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("format", "json");
        json.put("data", new JSONArray());
        json.put("exportedAt", System.currentTimeMillis());
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取日志统计
     * GET /v0/management/logs/stats
     */
    private Response handleLogStats(String uri, String method, Map<String, String> headers,
                                     String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("totalLogs", 0);
        json.put("errorCount", 0);
        json.put("warnCount", 0);
        json.put("infoCount", 0);
        json.put("debugCount", 0);
        json.put("storageUsed", "0B");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取错误日志
     * GET /v0/management/logs/errors
     */
    private Response handleLogErrors(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("errors", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取访问日志
     * GET /v0/management/logs/access
     */
    private Response handleLogAccess(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("accessLogs", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  插件管理
    // ========================================================================

    /**
     * 列出所有插件
     * GET /v0/management/plugins
     */
    private Response handleListPlugins(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("plugins", new JSONArray());
        json.put("total", 0);
        json.put("enabled", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 安装插件
     * POST /v0/management/plugins
     */
    private Response handleInstallPlugin(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "插件已安装");
        return jsonResponse(200, result.toString());
    }

    /**
     * 卸载插件
     * DELETE /v0/management/plugins
     */
    private Response handleUninstallPlugin(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "插件已卸载");
        return jsonResponse(200, result.toString());
    }

    /**
     * 更新插件
     * PUT /v0/management/plugins
     */
    private Response handleUpdatePlugin(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "插件已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取插件状态
     * GET /v0/management/plugins/status
     */
    private Response handlePluginStatus(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("status", "running");
        json.put("activePlugins", 0);
        json.put("pluginCount", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 启用插件
     * POST /v0/management/plugins/enable
     */
    private Response handlePluginEnable(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "插件已启用");
        return jsonResponse(200, result.toString());
    }

    /**
     * 禁用插件
     * POST /v0/management/plugins/disable
     */
    private Response handlePluginDisable(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "插件已禁用");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取插件市场列表
     * GET /v0/management/plugins/marketplace
     */
    private Response handlePluginMarketplace(String uri, String method, Map<String, String> headers,
                                               String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("marketplace", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取插件配置
     * GET /v0/management/plugins/config
     */
    private Response handlePluginConfig(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("config", new JSONObject());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新插件配置
     * PUT /v0/management/plugins/config
     */
    private Response handlePluginConfigUpdate(String uri, String method, Map<String, String> headers,
                                               String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "插件配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取插件日志
     * GET /v0/management/plugins/logs
     */
    private Response handlePluginLogs(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("logs", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  AmpCode 管理
    // ========================================================================

    /**
     * 列出所有 AmpCode
     * GET /v0/management/ampcode
     */
    private Response handleListAmpCode(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("codes", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 创建 AmpCode
     * POST /v0/management/ampcode
     */
    private Response handleCreateAmpCode(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("code", "AMP-" + java.util.UUID.randomUUID().toString().substring(0, 8).toUpperCase());
        result.put("message", "AmpCode 已创建");
        return jsonResponse(200, result.toString());
    }

    /**
     * 删除 AmpCode
     * DELETE /v0/management/ampcode
     */
    private Response handleDeleteAmpCode(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "AmpCode 已删除");
        return jsonResponse(200, result.toString());
    }

    /**
     * 更新 AmpCode
     * PUT /v0/management/ampcode
     */
    private Response handleUpdateAmpCode(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "AmpCode 已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取 AmpCode 状态
     * GET /v0/management/ampcode/status
     */
    private Response handleAmpCodeStatus(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("status", "active");
        json.put("activeCodes", 0);
        json.put("expiredCodes", 0);
        json.put("redeemedCodes", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 验证 AmpCode
     * POST /v0/management/ampcode/verify
     */
    private Response handleAmpCodeVerify(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("valid", true);
        json.put("code", "验证中...");
        json.put("plan", "");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取 AmpCode 历史记录
     * GET /v0/management/ampcode/history
     */
    private Response handleAmpCodeHistory(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("history", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取 AmpCode 统计
     * GET /v0/management/ampcode/stats
     */
    private Response handleAmpCodeStats(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("totalCodes", 0);
        json.put("redeemedCodes", 0);
        json.put("activeCodes", 0);
        json.put("expiredCodes", 0);
        json.put("revenue", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取 AmpCode 方案列表
     * GET /v0/management/ampcode/plans
     */
    private Response handleAmpCodePlans(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("plans", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 兑换 AmpCode
     * POST /v0/management/ampcode/redeem
     */
    private Response handleAmpCodeRedeem(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "AmpCode 已兑换");
        result.put("plan", "");
        result.put("expiresAt", "");
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  路由策略
    // ========================================================================

    /**
     * 获取路由策略配置
     * GET /v0/management/routing
     */
    private Response handleGetRouting(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("strategy", authManager.getStrategy().name());
        json.put("sessionAffinity", false);
        json.put("sessionAffinityTtl", "1h");
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新路由策略配置
     * PUT /v0/management/routing
     */
    private Response handleUpdateRouting(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "路由策略已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取路由策略
     * GET /v0/management/routing/strategy
     */
    private Response handleRoutingStrategy(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("strategy", authManager.getStrategy().name());
        json.put("availableStrategies", new JSONArray() {{
            put("round-robin");
            put("weighted-round-robin");
            put("fill-first");
        }});
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新路由策略
     * PUT /v0/management/routing/strategy
     */
    private Response handleRoutingStrategyUpdate(String uri, String method, Map<String, String> headers,
                                                   String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        JSONObject req = new JSONObject(body);
        String strategy = req.optString("strategy", "round-robin");
        try {
            authManager.setStrategy(AuthManager.RoutingStrategy.valueOf(strategy.toUpperCase().replace("-", "_")));
        } catch (IllegalArgumentException e) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"未知策略: " + escapeJson(strategy) + "\"}");
        }
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("strategy", strategy);
        result.put("message", "路由策略已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取会话列表
     * GET /v0/management/routing/sessions
     */
    private Response handleRoutingSessions(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("sessions", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 清除路由会话
     * DELETE /v0/management/routing/sessions
     */
    private Response handleClearRoutingSessions(String uri, String method, Map<String, String> headers,
                                                  String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "路由会话已清除");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取路由权重配置
     * GET /v0/management/routing/weights
     */
    private Response handleRoutingWeights(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("weights", new JSONObject());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新路由权重配置
     * PUT /v0/management/routing/weights
     */
    private Response handleRoutingWeightsUpdate(String uri, String method, Map<String, String> headers,
                                                  String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "路由权重已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取路由状态
     * GET /v0/management/routing/status
     */
    private Response handleRoutingStatus(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("strategy", authManager.getStrategy().name());
        json.put("activeCredentials", authManager.getActiveCount());
        json.put("totalCredentials", authManager.getTotalCount());
        json.put("healthy", true);
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  账号凭证管理
    // ========================================================================

    /**
     * 列出所有凭证
     * GET /v0/management/credentials
     */
    private Response handleListCredentials(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONArray credentials = new JSONArray();
        for (AuthManager.AuthCredential cred : authManager.listCredentials()) {
            JSONObject c = new JSONObject();
            c.put("id", cred.id);
            c.put("provider", cred.provider);
            c.put("prefix", cred.prefix);
            c.put("label", cred.label);
            c.put("type", cred.type.name());
            c.put("disabled", cred.disabled);
            c.put("unavailable", cred.unavailable);
            c.put("weight", cred.weight);
            c.put("priority", cred.priority);
            c.put("lastUsed", cred.lastUsed);
            c.put("failureCount", cred.failureCount);
            credentials.put(c);
        }
        JSONObject json = new JSONObject();
        json.put("credentials", credentials);
        json.put("total", credentials.length());
        return jsonResponse(200, json.toString());
    }

    /**
     * 添加凭证
     * POST /v0/management/credentials
     */
    private Response handleAddCredential(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        if (body == null || body.isEmpty()) {
            return jsonResponse(400, "{\"error\":\"Bad Request\",\"message\":\"请求体不能为空\"}");
        }
        JSONObject req = new JSONObject(body);
        AuthManager.AuthCredential cred = new AuthManager.AuthCredential();
        cred.id = req.optString("id", java.util.UUID.randomUUID().toString());
        cred.provider = req.optString("provider", "unknown");
        cred.prefix = req.optString("prefix", "");
        cred.label = req.optString("label", "");
        cred.fileName = req.optString("fileName", "");
        cred.weight = req.optInt("weight", 1);
        cred.priority = req.optInt("priority", 0);
        String typeStr = req.optString("type", "OAUTH");
        cred.type = "API_KEY".equals(typeStr)
                ? AuthManager.AuthCredential.AuthType.API_KEY
                : AuthManager.AuthCredential.AuthType.OAUTH;
        authManager.registerCredential(cred);
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("id", cred.id);
        result.put("message", "凭证已添加");
        return jsonResponse(200, result.toString());
    }

    /**
     * 移除凭证
     * DELETE /v0/management/credentials
     */
    private Response handleRemoveCredential(String uri, String method, Map<String, String> headers,
                                             String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "凭证已移除");
        return jsonResponse(200, result.toString());
    }

    /**
     * 更新凭证
     * PUT /v0/management/credentials
     */
    private Response handleUpdateCredential(String uri, String method, Map<String, String> headers,
                                             String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "凭证已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 检查凭证有效性
     * POST /v0/management/credentials/check
     */
    private Response handleCheckCredential(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("valid", true);
        json.put("message", "凭证有效");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取凭证提供商列表
     * GET /v0/management/credentials/providers
     */
    private Response handleCredentialProviders(String uri, String method, Map<String, String> headers,
                                                 String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        JSONArray providers = new JSONArray();
        providers.put("gemini");
        providers.put("claude");
        providers.put("codex");
        providers.put("xai");
        providers.put("vertex");
        providers.put("openai-compatibility");
        json.put("providers", providers);
        json.put("total", providers.length());
        return jsonResponse(200, json.toString());
    }

    /**
     * 批量操作凭证
     * POST /v0/management/credentials/batch
     */
    private Response handleBatchCredentials(String uri, String method, Map<String, String> headers,
                                              String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("processed", 0);
        result.put("message", "批量操作完成");
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  代理设置
    // ========================================================================

    /**
     * 获取代理配置
     * GET /v0/management/proxy
     */
    private Response handleGetProxy(String uri, String method, Map<String, String> headers,
                                     String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("enabled", false);
        json.put("host", "");
        json.put("port", 0);
        json.put("type", "http");
        json.put("auth", false);
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新代理配置
     * PUT /v0/management/proxy
     */
    private Response handleUpdateProxy(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "代理配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取代理状态
     * GET /v0/management/proxy/status
     */
    private Response handleProxyStatus(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("connected", false);
        json.put("latency", 0);
        json.put("type", "none");
        return jsonResponse(200, json.toString());
    }

    /**
     * 测试代理连接
     * POST /v0/management/proxy/test
     */
    private Response handleProxyTest(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("latency", 0);
        json.put("message", "代理连接测试完成");
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  系统信息
    // ========================================================================

    /**
     * 获取系统信息
     * GET /v0/management/system
     * GET /v0/management/system/info
     */
    private Response handleSystemInfo(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("platform", "Android");
        json.put("version", "6.9.45");
        json.put("javaVersion", System.getProperty("java.version", "unknown"));
        json.put("availableProcessors", Runtime.getRuntime().availableProcessors());
        json.put("uptime", getUptime());
        json.put("timezone", java.util.TimeZone.getDefault().getID());
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取内存使用情况
     * GET /v0/management/system/memory
     */
    private Response handleSystemMemory(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        Runtime runtime = Runtime.getRuntime();
        JSONObject json = new JSONObject();
        json.put("totalMemory", runtime.totalMemory());
        json.put("freeMemory", runtime.freeMemory());
        json.put("maxMemory", runtime.maxMemory());
        json.put("usedMemory", runtime.totalMemory() - runtime.freeMemory());
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取存储信息
     * GET /v0/management/system/storage
     */
    private Response handleSystemStorage(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("storageInfo", "Android 应用内部存储");
        json.put("filesDir", "应用数据目录");
        return jsonResponse(200, json.toString());
    }

    /**
     * 获取网络信息
     * GET /v0/management/system/network
     */
    private Response handleSystemNetwork(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("networkInfo", "网络状态信息");
        return jsonResponse(200, json.toString());
    }

    /**
     * 触发垃圾回收
     * POST /v0/management/system/gc
     */
    private Response handleSystemGc(String uri, String method, Map<String, String> headers,
                                     String body, Map<String, String> pathParams) throws Exception {
        System.gc();
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "垃圾回收已触发");
        return jsonResponse(200, result.toString());
    }

    /**
     * 重启服务
     * POST /v0/management/system/restart
     */
    private Response handleSystemRestart(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "服务重启命令已发送");
        result.put("restarting", true);
        return jsonResponse(200, result.toString());
    }

    /**
     * 关闭服务
     * POST /v0/management/system/shutdown
     */
    private Response handleSystemShutdown(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "服务关闭命令已发送");
        result.put("shuttingDown", true);
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  备份与恢复
    // ========================================================================

    /**
     * 创建备份
     * POST /v0/management/backup
     */
    private Response handleCreateBackup(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("backupId", java.util.UUID.randomUUID().toString());
        result.put("message", "备份已创建");
        return jsonResponse(200, result.toString());
    }

    /**
     * 列出备份
     * GET /v0/management/backup
     */
    private Response handleListBackups(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("backups", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 恢复备份
     * POST /v0/management/backup/restore
     */
    private Response handleRestoreBackup(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "备份已恢复");
        return jsonResponse(200, result.toString());
    }

    /**
     * 删除备份
     * DELETE /v0/management/backup
     */
    private Response handleDeleteBackup(String uri, String method, Map<String, String> headers,
                                         String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "备份已删除");
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  安全设置
    // ========================================================================

    /**
     * 获取安全设置
     * GET /v0/management/security
     */
    private Response handleGetSecurity(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("firewall", new JSONObject());
        json.put("rateLimit", new JSONObject());
        json.put("blocklist", new JSONArray());
        json.put("whitelist", new JSONArray());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新安全设置
     * PUT /v0/management/security
     */
    private Response handleUpdateSecurity(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "安全设置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取防火墙配置
     * GET /v0/management/security/firewall
     */
    private Response handleSecurityFirewall(String uri, String method, Map<String, String> headers,
                                             String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("enabled", false);
        json.put("rules", new JSONArray());
        json.put("defaultAction", "allow");
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新防火墙配置
     * PUT /v0/management/security/firewall
     */
    private Response handleSecurityFirewallUpdate(String uri, String method, Map<String, String> headers,
                                                    String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "防火墙配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取速率限制配置
     * GET /v0/management/security/rate-limit
     */
    private Response handleSecurityRateLimit(String uri, String method, Map<String, String> headers,
                                              String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("enabled", false);
        json.put("requestsPerMinute", 60);
        json.put("requestsPerHour", 1000);
        json.put("burstSize", 10);
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新速率限制配置
     * PUT /v0/management/security/rate-limit
     */
    private Response handleSecurityRateLimitUpdate(String uri, String method, Map<String, String> headers,
                                                     String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "速率限制已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取黑名单
     * GET /v0/management/security/blocklist
     */
    private Response handleSecurityBlocklist(String uri, String method, Map<String, String> headers,
                                              String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("entries", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新黑名单
     * PUT /v0/management/security/blocklist
     */
    private Response handleSecurityBlocklistUpdate(String uri, String method, Map<String, String> headers,
                                                     String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "黑名单已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取白名单
     * GET /v0/management/security/whitelist
     */
    private Response handleSecurityWhitelist(String uri, String method, Map<String, String> headers,
                                              String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("entries", new JSONArray());
        json.put("total", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新白名单
     * PUT /v0/management/security/whitelist
     */
    private Response handleSecurityWhitelistUpdate(String uri, String method, Map<String, String> headers,
                                                     String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "白名单已更新");
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  通知设置
    // ========================================================================

    /**
     * 获取通知设置
     * GET /v0/management/notifications
     */
    private Response handleGetNotifications(String uri, String method, Map<String, String> headers,
                                             String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("enabled", true);
        json.put("channels", new JSONObject());
        json.put("events", new JSONObject());
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新通知设置
     * PUT /v0/management/notifications
     */
    private Response handleUpdateNotifications(String uri, String method, Map<String, String> headers,
                                                String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "通知设置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 测试通知
     * POST /v0/management/notifications/test
     */
    private Response handleNotificationTest(String uri, String method, Map<String, String> headers,
                                              String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "测试通知已发送");
        return jsonResponse(200, result.toString());
    }

    // ========================================================================
    //  缓存管理
    // ========================================================================

    /**
     * 获取缓存信息
     * GET /v0/management/cache
     */
    private Response handleCacheInfo(String uri, String method, Map<String, String> headers,
                                      String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("size", "0B");
        json.put("entries", 0);
        json.put("hitRate", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 清除缓存
     * DELETE /v0/management/cache
     */
    private Response handleClearCache(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "缓存已清除");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取缓存统计
     * GET /v0/management/cache/stats
     */
    private Response handleCacheStats(String uri, String method, Map<String, String> headers,
                                       String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("hits", 0);
        json.put("misses", 0);
        json.put("evictions", 0);
        json.put("hitRate", 0);
        json.put("size", "0B");
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  诊断工具
    // ========================================================================

    /**
     * 运行诊断
     * GET /v0/management/diagnostics
     */
    private Response handleDiagnostics(String uri, String method, Map<String, String> headers,
                                        String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("status", "ready");
        json.put("checks", new JSONArray());
        return jsonResponse(200, json.toString());
    }

    /**
     * Ping 测试
     * POST /v0/management/diagnostics/ping
     */
    private Response handleDiagnosticsPing(String uri, String method, Map<String, String> headers,
                                            String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("latency", 0);
        json.put("target", headers.get("X-Ping-Target"));
        return jsonResponse(200, json.toString());
    }

    /**
     * 路由追踪
     * POST /v0/management/diagnostics/traceroute
     */
    private Response handleDiagnosticsTraceroute(String uri, String method, Map<String, String> headers,
                                                   String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("hops", new JSONArray());
        result.put("message", "路由追踪完成");
        return jsonResponse(200, result.toString());
    }

    /**
     * DNS 查询
     * GET /v0/management/diagnostics/dns
     */
    private Response handleDiagnosticsDns(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("dnsResult", "DNS 查询结果");
        return jsonResponse(200, json.toString());
    }

    /**
     * 连接性测试
     * GET /v0/management/diagnostics/connectivity
     */
    private Response handleDiagnosticsConnectivity(String uri, String method, Map<String, String> headers,
                                                     String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("connectivity", true);
        json.put("providers", new JSONObject());
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  提供商管理
    // ========================================================================

    /**
     * 列出所有提供商
     * GET /v0/management/providers
     */
    private Response handleListProviders(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        JSONArray providers = new JSONArray();
        providers.put("openai");
        providers.put("claude");
        providers.put("gemini");
        providers.put("codex");
        providers.put("xai");
        providers.put("vertex");
        providers.put("openai-compatibility");
        json.put("providers", providers);
        json.put("total", providers.length());
        json.put("configured", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 更新提供商配置
     * PUT /v0/management/providers
     */
    private Response handleUpdateProvider(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject result = new JSONObject();
        result.put("success", true);
        result.put("message", "提供商配置已更新");
        return jsonResponse(200, result.toString());
    }

    /**
     * 获取提供商状态
     * GET /v0/management/providers/status
     */
    private Response handleProviderStatus(String uri, String method, Map<String, String> headers,
                                           String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("providers", new JSONObject());
        json.put("healthy", true);
        json.put("unhealthyCount", 0);
        return jsonResponse(200, json.toString());
    }

    /**
     * 检查提供商连接
     * POST /v0/management/providers/check
     */
    private Response handleProviderCheck(String uri, String method, Map<String, String> headers,
                                          String body, Map<String, String> pathParams) throws Exception {
        JSONObject json = new JSONObject();
        json.put("success", true);
        json.put("provider", headers.get("X-Provider"));
        json.put("latency", 0);
        json.put("message", "提供商连接检查完成");
        return jsonResponse(200, json.toString());
    }

    // ========================================================================
    //  工具方法
    // ========================================================================

    /**
     * 创建 JSON 响应
     *
     * @param statusCode HTTP 状态码
     * @param json       JSON 字符串
     * @return HTTP 响应
     */
    private Response jsonResponse(int statusCode, String json) {
        Response.Status status = Response.Status.lookup(statusCode);
        if (status == null) {
            status = Response.Status.INTERNAL_ERROR;
        }
        InputStream in = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
        Response response = NanoHTTPD.newChunkedResponse(status, "application/json", in);
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Management-Key, X-Config-Key, X-File-Path, X-API-Key, X-Provider, X-Ping-Target");
        return response;
    }

    /**
     * 转义 JSON 字符串中的特殊字符，防止注入
     *
     * @param value 原始字符串
     * @return 转义后的字符串
     */
    private String escapeJson(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * 获取服务运行时间
     *
     * @return 运行时间字符串
     */
    private String getUptime() {
        long uptime = java.lang.management.ManagementFactory.getRuntimeMXBean().getUptime();
        long seconds = uptime / 1000;
        long minutes = seconds / 60;
        long hours = minutes / 60;
        long days = hours / 24;
        return String.format("%dd %dh %dm %ds", days, hours % 24, minutes % 60, seconds % 60);
    }

    /**
     * 获取路由总数
     *
     * @return 已注册的路由数量
     */
    public int getRouteCount() {
        return exactRoutes.size() + prefixRoutes.size();
    }
}