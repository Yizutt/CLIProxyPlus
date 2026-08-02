package com.cliproxy.plus.agent.tools;

import android.util.Log;

import com.cliproxy.plus.auth.AuthManager;
import com.cliproxy.plus.auth.AuthManager.AuthCredential;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;
import java.util.UUID;

/**
 * AuthTools - 认证管理 AI Agent 工具集
 * <p>
 * 提供 AI Agent 调用的认证凭证管理工具，包括列表查询、详情获取、
 * 新增、删除、启用、禁用和连通性测试等功能。
 * 所有工具方法均为静态方法，接收 JSONObject 参数并返回 JSONObject 结果。
 * <p>
 * 工具列表：
 * <ul>
 *   <li>auth_list - 列出所有认证凭证</li>
 *   <li>auth_get - 获取指定凭证详情</li>
 *   <li>auth_add - 新增认证凭证</li>
 *   <li>auth_delete - 删除认证凭证</li>
 *   <li>auth_enable - 启用认证凭证</li>
 *   <li>auth_disable - 禁用认证凭证</li>
 *   <li>auth_test - 测试认证凭证连通性</li>
 * </ul>
 *
 * @author CLIProxy Plus
 * @version 1.0
 */
public final class AuthTools {

    private static final String TAG = "AuthTools";

    private AuthTools() {
        // 工具类，禁止实例化
    }

    // ========================================================================
    // 工具：auth_list
    // ========================================================================

    /**
     * auth_list - 列出所有认证凭证
     * <p>
     * 返回当前所有已注册的认证凭证列表，支持按提供商（provider）过滤。
     * 每个凭证项包含 id、provider、label、type、disabled、unavailable 等字段。
     * <p>
     * 参数（JSONObject）：
     * <pre>
     * {
     *   "provider": "gemini"   // 可选，按提供商过滤
     * }
     * </pre>
     * <p>
     * 返回（JSONObject）：
     * <pre>
     * {
     *   "success": true,
     *   "tools": "auth_list",
     *   "data": {
     *     "credentials": [ ... ],
     *     "total": 5,
     *     "active": 3
     *   }
     * }
     * </pre>
     *
     * @param params 请求参数，可为 null
     * @return 执行结果 JSONObject
     */
    public static JSONObject auth_list(JSONObject params) {
        Log.d(TAG, "auth_list called with params: " + params);
        try {
            AuthManager authManager = AuthManager.getInstance();
            String provider = params != null ? params.optString("provider", null) : null;

            List<AuthCredential> credentials;
            if (provider != null && !provider.isEmpty()) {
                credentials = authManager.listCredentialsByProvider(provider);
            } else {
                credentials = authManager.listCredentials();
            }

            JSONArray credsArray = new JSONArray();
            for (AuthCredential cred : credentials) {
                credsArray.put(credentialToJson(cred));
            }

            JSONObject data = new JSONObject();
            data.put("credentials", credsArray);
            data.put("total", authManager.getTotalCount());
            data.put("active", authManager.getActiveCount());

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("tool", "auth_list");
            result.put("data", data);

            Log.d(TAG, "auth_list: found " + credentials.size() + " credentials");
            return result;
        } catch (Exception e) {
            Log.e(TAG, "auth_list failed: " + e.getMessage(), e);
            return errorResult("auth_list", "查询凭证列表失败: " + e.getMessage());
        }
    }

    // ========================================================================
    // 工具：auth_get
    // ========================================================================

    /**
     * auth_get - 获取指定认证凭证详情
     * <p>
     * 根据凭证 ID 查询单个认证凭证的详细信息，包括提供商、类型、状态、权重等。
     * <p>
     * 参数（JSONObject）：
     * <pre>
     * {
     *   "id": "cred-xxx"   // 必填，凭证 ID
     * }
     * </pre>
     * <p>
     * 返回（JSONObject）：
     * <pre>
     * {
     *   "success": true,
     *   "tool": "auth_get",
     *   "data": { "credential": { ... } }
     * }
     * </pre>
     *
     * @param params 请求参数，必须包含 "id" 字段
     * @return 执行结果 JSONObject
     */
    public static JSONObject auth_get(JSONObject params) {
        Log.d(TAG, "auth_get called with params: " + params);
        try {
            String id = params != null ? params.optString("id", null) : null;
            if (id == null || id.isEmpty()) {
                return errorResult("auth_get", "缺少必填参数: id");
            }

            AuthManager authManager = AuthManager.getInstance();
            // AuthManager 没有直接根据 ID 查询的方法，遍历查找
            List<AuthCredential> credentials = authManager.listCredentials();
            AuthCredential target = null;
            for (AuthCredential cred : credentials) {
                if (id.equals(cred.id)) {
                    target = cred;
                    break;
                }
            }

            if (target == null) {
                return errorResult("auth_get", "凭证不存在: " + id);
            }

            JSONObject data = new JSONObject();
            data.put("credential", credentialToJson(target));

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("tool", "auth_get");
            result.put("data", data);

            Log.d(TAG, "auth_get: found credential: " + id);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "auth_get failed: " + e.getMessage(), e);
            return errorResult("auth_get", "查询凭证详情失败: " + e.getMessage());
        }
    }

    // ========================================================================
    // 工具：auth_add
    // ========================================================================

    /**
     * auth_add - 新增认证凭证
     * <p>
     * 创建一个新的认证凭证并注册到 AuthManager 中。
     * 至少需要提供 provider 参数，其他字段可选（会自动填充默认值）。
     * <p>
     * 参数（JSONObject）：
     * <pre>
     * {
     *   "provider": "gemini",        // 必填，提供商名称
     *   "label": "我的 Gemini 账号",  // 可选，显示标签
     *   "prefix": "gemini",          // 可选，模型命名空间前缀，默认同 provider
     *   "type": "OAUTH",             // 可选，OAUTH 或 API_KEY，默认 OAUTH
     *   "weight": 1,                 // 可选，权重，默认 1
     *   "priority": 0,               // 可选，优先级，默认 0
     *   "proxyUrl": "",              // 可选，代理覆盖地址
     *   "metadata": { ... }          // 可选，附加元数据
     * }
     * </pre>
     * <p>
     * 返回（JSONObject）：
     * <pre>
     * {
     *   "success": true,
     *   "tool": "auth_add",
     *   "data": { "credential": { ... } }
     * }
     * </pre>
     *
     * @param params 请求参数，必须包含 "provider"
     * @return 执行结果 JSONObject
     */
    public static JSONObject auth_add(JSONObject params) {
        Log.d(TAG, "auth_add called with params: " + params);
        try {
            if (params == null) {
                return errorResult("auth_add", "请求参数不能为空");
            }

            String provider = params.optString("provider", null);
            if (provider == null || provider.isEmpty()) {
                return errorResult("auth_add", "缺少必填参数: provider");
            }

            AuthCredential credential = new AuthCredential();
            credential.id = "cred-" + UUID.randomUUID().toString().substring(0, 8);
            credential.provider = provider;
            credential.prefix = params.optString("prefix", provider);
            credential.label = params.optString("label", provider + " 凭证");
            credential.type = "API_KEY".equalsIgnoreCase(params.optString("type", "OAUTH"))
                    ? AuthCredential.AuthType.API_KEY
                    : AuthCredential.AuthType.OAUTH;
            credential.weight = params.optInt("weight", 1);
            credential.priority = params.optInt("priority", 0);
            credential.proxyUrl = params.optString("proxyUrl", null);
            credential.disabled = false;
            credential.unavailable = false;
            credential.failureCount = 0;
            credential.cooldownUntil = 0;

            // 处理元数据
            JSONObject metadata = params.optJSONObject("metadata");
            if (metadata != null) {
                for (String key : metadata.keySet()) {
                    credential.metadata.put(key, metadata.optString(key, ""));
                }
            }

            AuthManager.getInstance().registerCredential(credential);

            JSONObject data = new JSONObject();
            data.put("credential", credentialToJson(credential));

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("tool", "auth_add");
            result.put("data", data);

            Log.d(TAG, "auth_add: created credential: " + credential.id + " [" + provider + "]");
            return result;
        } catch (Exception e) {
            Log.e(TAG, "auth_add failed: " + e.getMessage(), e);
            return errorResult("auth_add", "新增凭证失败: " + e.getMessage());
        }
    }

    // ========================================================================
    // 工具：auth_delete
    // ========================================================================

    /**
     * auth_delete - 删除认证凭证
     * <p>
     * 根据凭证 ID 从 AuthManager 中移除指定的认证凭证。
     * 操作不可逆，删除后如需恢复需重新添加。
     * <p>
     * 参数（JSONObject）：
     * <pre>
     * {
     *   "id": "cred-xxx"   // 必填，要删除的凭证 ID
     * }
     * </pre>
     * <p>
     * 返回（JSONObject）：
     * <pre>
     * {
     *   "success": true,
     *   "tool": "auth_delete",
     *   "data": { "id": "cred-xxx", "deleted": true }
     * }
     * </pre>
     *
     * @param params 请求参数，必须包含 "id" 字段
     * @return 执行结果 JSONObject
     */
    public static JSONObject auth_delete(JSONObject params) {
        Log.d(TAG, "auth_delete called with params: " + params);
        try {
            String id = params != null ? params.optString("id", null) : null;
            if (id == null || id.isEmpty()) {
                return errorResult("auth_delete", "缺少必填参数: id");
            }

            // 检查凭证是否存在
            AuthManager authManager = AuthManager.getInstance();
            List<AuthCredential> credentials = authManager.listCredentials();
            boolean exists = false;
            for (AuthCredential cred : credentials) {
                if (id.equals(cred.id)) {
                    exists = true;
                    break;
                }
            }

            if (!exists) {
                return errorResult("auth_delete", "凭证不存在: " + id);
            }

            authManager.removeCredential(id);

            JSONObject data = new JSONObject();
            data.put("id", id);
            data.put("deleted", true);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("tool", "auth_delete");
            result.put("data", data);

            Log.d(TAG, "auth_delete: deleted credential: " + id);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "auth_delete failed: " + e.getMessage(), e);
            return errorResult("auth_delete", "删除凭证失败: " + e.getMessage());
        }
    }

    // ========================================================================
    // 工具：auth_enable
    // ========================================================================

    /**
     * auth_enable - 启用认证凭证
     * <p>
     * 将指定 ID 的认证凭证标记为启用状态。启用后该凭证可被路由策略选中用于请求。
     * 如果凭证已处于启用状态，则直接返回成功。
     * <p>
     * 参数（JSONObject）：
     * <pre>
     * {
     *   "id": "cred-xxx"   // 必填，凭证 ID
     * }
     * </pre>
     * <p>
     * 返回（JSONObject）：
     * <pre>
     * {
     *   "success": true,
     *   "tool": "auth_enable",
     *   "data": { "id": "cred-xxx", "disabled": false, "previousDisabled": true }
     * }
     * </pre>
     *
     * @param params 请求参数，必须包含 "id" 字段
     * @return 执行结果 JSONObject
     */
    public static JSONObject auth_enable(JSONObject params) {
        Log.d(TAG, "auth_enable called with params: " + params);
        try {
            String id = params != null ? params.optString("id", null) : null;
            if (id == null || id.isEmpty()) {
                return errorResult("auth_enable", "缺少必填参数: id");
            }

            AuthManager authManager = AuthManager.getInstance();
            List<AuthCredential> credentials = authManager.listCredentials();
            AuthCredential target = null;
            for (AuthCredential cred : credentials) {
                if (id.equals(cred.id)) {
                    target = cred;
                    break;
                }
            }

            if (target == null) {
                return errorResult("auth_enable", "凭证不存在: " + id);
            }

            boolean previousDisabled = target.disabled;
            target.disabled = false;
            // 同时清除不可用状态和冷却时间，确保凭证可被立即使用
            target.unavailable = false;
            target.cooldownUntil = 0;

            JSONObject data = new JSONObject();
            data.put("id", id);
            data.put("disabled", false);
            data.put("previousDisabled", previousDisabled);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("tool", "auth_enable");
            result.put("data", data);

            Log.d(TAG, "auth_enable: enabled credential: " + id
                    + " (was disabled: " + previousDisabled + ")");
            return result;
        } catch (Exception e) {
            Log.e(TAG, "auth_enable failed: " + e.getMessage(), e);
            return errorResult("auth_enable", "启用凭证失败: " + e.getMessage());
        }
    }

    // ========================================================================
    // 工具：auth_disable
    // ========================================================================

    /**
     * auth_disable - 禁用认证凭证
     * <p>
     * 将指定 ID 的认证凭证标记为禁用状态。禁用后该凭证不会被路由策略选中，
     * 但保留其配置信息，可在需要时重新启用。
     * 如果凭证已处于禁用状态，则直接返回成功。
     * <p>
     * 参数（JSONObject）：
     * <pre>
     * {
     *   "id": "cred-xxx"   // 必填，凭证 ID
     * }
     * </pre>
     * <p>
     * 返回（JSONObject）：
     * <pre>
     * {
     *   "success": true,
     *   "tool": "auth_disable",
     *   "data": { "id": "cred-xxx", "disabled": true, "previousDisabled": false }
     * }
     * </pre>
     *
     * @param params 请求参数，必须包含 "id" 字段
     * @return 执行结果 JSONObject
     */
    public static JSONObject auth_disable(JSONObject params) {
        Log.d(TAG, "auth_disable called with params: " + params);
        try {
            String id = params != null ? params.optString("id", null) : null;
            if (id == null || id.isEmpty()) {
                return errorResult("auth_disable", "缺少必填参数: id");
            }

            AuthManager authManager = AuthManager.getInstance();
            List<AuthCredential> credentials = authManager.listCredentials();
            AuthCredential target = null;
            for (AuthCredential cred : credentials) {
                if (id.equals(cred.id)) {
                    target = cred;
                    break;
                }
            }

            if (target == null) {
                return errorResult("auth_disable", "凭证不存在: " + id);
            }

            boolean previousDisabled = target.disabled;
            target.disabled = true;

            JSONObject data = new JSONObject();
            data.put("id", id);
            data.put("disabled", true);
            data.put("previousDisabled", previousDisabled);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("tool", "auth_disable");
            result.put("data", data);

            Log.d(TAG, "auth_disable: disabled credential: " + id
                    + " (was disabled: " + previousDisabled + ")");
            return result;
        } catch (Exception e) {
            Log.e(TAG, "auth_disable failed: " + e.getMessage(), e);
            return errorResult("auth_disable", "禁用凭证失败: " + e.getMessage());
        }
    }

    // ========================================================================
    // 工具：auth_test
    // ========================================================================

    /**
     * auth_test - 测试认证凭证连通性
     * <p>
     * 检查指定 ID 的认证凭证当前是否可用。验证 disabled、unavailable 和
     * cooldownUntil 状态字段，返回凭证的可用性判断结果及详细状态信息。
     * 注意：此方法仅进行状态检查，不发起实际的网络请求。
     * <p>
     * 参数（JSONObject）：
     * <pre>
     * {
     *   "id": "cred-xxx"   // 必填，凭证 ID
     * }
     * </pre>
     * <p>
     * 返回（JSONObject）：
     * <pre>
     * {
     *   "success": true,
     *   "tool": "auth_test",
     *   "data": {
     *     "id": "cred-xxx",
     *     "available": true,
     *     "disabled": false,
     *     "unavailable": false,
     *     "failureCount": 0,
     *     "inCooldown": false,
     *     "cooldownRemainingMs": 0
     *   }
     * }
     * </pre>
     *
     * @param params 请求参数，必须包含 "id" 字段
     * @return 执行结果 JSONObject
     */
    public static JSONObject auth_test(JSONObject params) {
        Log.d(TAG, "auth_test called with params: " + params);
        try {
            String id = params != null ? params.optString("id", null) : null;
            if (id == null || id.isEmpty()) {
                return errorResult("auth_test", "缺少必填参数: id");
            }

            AuthManager authManager = AuthManager.getInstance();
            List<AuthCredential> credentials = authManager.listCredentials();
            AuthCredential target = null;
            for (AuthCredential cred : credentials) {
                if (id.equals(cred.id)) {
                    target = cred;
                    break;
                }
            }

            if (target == null) {
                return errorResult("auth_test", "凭证不存在: " + id);
            }

            long now = System.currentTimeMillis();
            boolean inCooldown = now < target.cooldownUntil;

            JSONObject data = new JSONObject();
            data.put("id", target.id);
            data.put("provider", target.provider);
            data.put("label", target.label);
            data.put("available", target.isAvailable());
            data.put("disabled", target.disabled);
            data.put("unavailable", target.unavailable);
            data.put("failureCount", target.failureCount);
            data.put("inCooldown", inCooldown);
            data.put("cooldownRemainingMs", inCooldown ? (target.cooldownUntil - now) : 0);
            data.put("lastUsed", target.lastUsed);

            JSONObject result = new JSONObject();
            result.put("success", true);
            result.put("tool", "auth_test");
            result.put("data", data);

            Log.d(TAG, "auth_test: credential " + id
                    + " available=" + target.isAvailable());
            return result;
        } catch (Exception e) {
            Log.e(TAG, "auth_test failed: " + e.getMessage(), e);
            return errorResult("auth_test", "测试凭证失败: " + e.getMessage());
        }
    }

    // ========================================================================
    // 内部辅助方法
    // ========================================================================

    /**
     * 将 AuthCredential 对象转换为 JSONObject 表示。
     *
     * @param credential 认证凭证对象
     * @return JSON 表示
     */
    private static JSONObject credentialToJson(AuthCredential credential) {
        try {
            JSONObject json = new JSONObject();
            json.put("id", credential.id);
            json.put("provider", credential.provider);
            json.put("prefix", credential.prefix);
            json.put("label", credential.label);
            json.put("type", credential.type.name());
            json.put("disabled", credential.disabled);
            json.put("unavailable", credential.unavailable);
            json.put("available", credential.isAvailable());
            json.put("weight", credential.weight);
            json.put("priority", credential.priority);
            json.put("failureCount", credential.failureCount);
            json.put("lastUsed", credential.lastUsed);

            if (credential.proxyUrl != null && !credential.proxyUrl.isEmpty()) {
                json.put("proxyUrl", credential.proxyUrl);
            }

            // 将 metadata 转换为 JSONObject
            JSONObject metadataJson = new JSONObject();
            for (String key : credential.metadata.keySet()) {
                metadataJson.put(key, credential.metadata.get(key));
            }
            json.put("metadata", metadataJson);

            return json;
        } catch (Exception e) {
            Log.e(TAG, "序列化凭证失败: " + e.getMessage(), e);
            return new JSONObject();
        }
    }

    /**
     * 构造错误响应 JSONObject。
     * <p>
     * 统一错误格式：
     * <pre>
     * {
     *   "success": false,
     *   "tool": "auth_xxx",
     *   "error": "错误描述"
     * }
     * </pre>
     *
     * @param toolName  工具名称
     * @param message   错误消息
     * @return 错误结果 JSONObject
     */
    private static JSONObject errorResult(String toolName, String message) {
        try {
            JSONObject result = new JSONObject();
            result.put("success", false);
            result.put("tool", toolName);
            result.put("error", message);
            return result;
        } catch (Exception e) {
            Log.e(TAG, "构造错误响应失败: " + e.getMessage(), e);
            return new JSONObject();
        }
    }
}