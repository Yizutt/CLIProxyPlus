package com.cliproxy.plus.management.server;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * ConfigEndpoints - 配置管理端点
 * <p>
 * 处理 /v0/management/config 和 /v0/management/config.yaml 路径下的所有请求，
 * 提供代理服务的完整配置读取、替换、部分更新以及单个配置字段的查询和修改功能。
 * 支持 JSON 和 YAML 两种格式的配置输出，PUT 操作会触发配置的热重载。
 * <p>
 * 包含以下端点：
 * <ul>
 *   <li>GET /v0/management/config — 获取完整配置（JSON 格式）</li>
 *   <li>GET /v0/management/config.yaml — 获取完整配置（YAML 格式）</li>
 *   <li>PUT /v0/management/config.yaml — 替换完整配置并触发热重载</li>
 *   <li>PATCH /v0/management/config — 更新指定配置字段</li>
 *   <li>GET /v0/management/config/{path} — 按路径查询单个配置字段</li>
 *   <li>PATCH /v0/management/config/{path} — 按路径设置单个配置字段</li>
 * </ul>
 * <p>
 * 对应原版 internal/api/management/config.go
 *
 * @author CLIProxy Plus
 * @version 1.0
 */
public class ConfigEndpoints {

    private static final String TAG = "ConfigEndpoints";

    // 管理 API 路径常量
    private static final String PATH_CONFIG = "/v0/management/config";
    private static final String PATH_CONFIG_YAML = "/v0/management/config.yaml";

    /**
     * 配置数据存储（JSON 对象树形式）
     * 用于快速字段级查询和修改，保持与 YAML 原始内容的同步。
     */
    private final ConcurrentHashMap<String, Object> configStore;

    /**
     * 原始 YAML 配置内容
     * 保存 PUT 操作上传的原始 YAML 字符串，在 GET /config.yaml 时直接返回。
     */
    private String rawYamlConfig;

    /**
     * 配置版本号，每次 PUT/PATCH 成功后递增
     * 用于跟踪配置变更，便于客户端判断是否需要重新加载。
     */
    private long configVersion;

    /**
     * 热重载回调接口
     * 当配置被替换（PUT）时，通过此回调通知上层执行配置重载逻辑。
     */
    private final ReloadCallback reloadCallback;

    /**
     * 热重载回调接口定义
     * <p>
     * 当配置发生替换性更新时，由 ConfigEndpoints 调用此接口通知外层服务
     * 执行配置的热重载操作（如重新加载代理规则、认证配置等）。
     */
    public interface ReloadCallback {
        /**
         * 执行配置热重载
         *
         * @param rawConfig 新的原始配置内容（YAML 格式）
         * @return true 表示重载成功，false 表示重载失败
         */
        boolean onReload(String rawConfig);
    }

    /**
     * 构造 ConfigEndpoints 实例，使用默认配置初始化
     * <p>
     * 初始化一个空的配置存储，使用默认的空配置 JSON 对象。
     * 不设置热重载回调，PUT 操作不会触发外部重载逻辑。
     */
    public ConfigEndpoints() {
        this.configStore = new ConcurrentHashMap<>();
        this.rawYamlConfig = "";
        this.configVersion = 0;
        this.reloadCallback = null;
        initDefaultConfig();
        Log.d(TAG, "ConfigEndpoints initialized (no reload callback)");
    }

    /**
     * 构造 ConfigEndpoints 实例，指定热重载回调
     *
     * @param reloadCallback 热重载回调接口，PUT 配置后调用
     */
    public ConfigEndpoints(ReloadCallback reloadCallback) {
        this.configStore = new ConcurrentHashMap<>();
        this.rawYamlConfig = "";
        this.configVersion = 0;
        this.reloadCallback = reloadCallback;
        initDefaultConfig();
        Log.d(TAG, "ConfigEndpoints initialized with reload callback");
    }

    /**
     * 初始化默认配置
     * <p>
     * 设置一组合理的默认配置值，确保服务在无显式配置时也能正常运行。
     * 默认配置包含服务器监听地址、日志级别、超时设置等基础参数。
     */
    private void initDefaultConfig() {
        JSONObject defaults = new JSONObject();
        defaults.put("server", new JSONObject()
                .put("host", "0.0.0.0")
                .put("port", 8080)
                .put("read_timeout", 30000)
                .put("write_timeout", 30000)
                .put("max_connections", 100));
        defaults.put("logging", new JSONObject()
                .put("level", "info")
                .put("file", "cliproxy.log")
                .put("max_size_mb", 100)
                .put("max_backups", 5));
        defaults.put("proxy", new JSONObject()
                .put("connect_timeout", 10000)
                .put("read_buffer_size", 4096)
                .put("write_buffer_size", 4096)
                .put("max_retries", 3));
        defaults.put("auth", new JSONObject()
                .put("enabled", false)
                .put("management_key", ""));
        defaults.put("rate_limit", new JSONObject()
                .put("enabled", false)
                .put("requests_per_minute", 60)
                .put("burst_size", 20));

        // 将默认配置写入 configStore
        flattenJsonToStore("", defaults);
        // 同时生成默认 YAML 表示
        this.rawYamlConfig = jsonToYaml(defaults);
        Log.d(TAG, "Default configuration initialized");
    }

    /**
     * 主分发方法 - 根据 HTTP 方法和请求路径路由到对应处理方法
     * <p>
     * 支持以下路由规则：
     * <ul>
     *   <li>GET /v0/management/config → getConfig()</li>
     *   <li>GET /v0/management/config.yaml → getConfigYaml()</li>
     *   <li>PUT /v0/management/config.yaml → putConfigYaml(body)</li>
     *   <li>PATCH /v0/management/config → handlePatchConfig(body)</li>
     *   <li>GET /v0/management/config/... → getField(path)</li>
     *   <li>PATCH /v0/management/config/... → setField(path, body)</li>
     * </ul>
     *
     * @param method  HTTP 请求方法（GET、PUT、PATCH）
     * @param uri     请求路径
     * @param headers 请求头
     * @param params  请求参数
     * @param body    请求体字符串
     * @return NanoHTTPD Response 对象
     */
    public Response dispatch(NanoHTTPD.Method method, String uri,
                             Map<String, String> headers,
                             Map<String, String> params,
                             String body) {
        Log.d(TAG, "Request: " + method + " " + uri);

        // GET /v0/management/config — 获取 JSON 格式的完整配置
        if (NanoHTTPD.Method.GET.equals(method) && PATH_CONFIG.equals(uri)) {
            return getConfig();
        }

        // GET /v0/management/config.yaml — 获取 YAML 格式的完整配置
        if (NanoHTTPD.Method.GET.equals(method) && PATH_CONFIG_YAML.equals(uri)) {
            return getConfigYaml();
        }

        // PUT /v0/management/config.yaml — 替换完整配置并触发热重载
        if (NanoHTTPD.Method.PUT.equals(method) && PATH_CONFIG_YAML.equals(uri)) {
            return putConfigYaml(body);
        }

        // PATCH /v0/management/config — 更新指定配置字段
        if (NanoHTTPD.Method.PATCH.equals(method) && PATH_CONFIG.equals(uri)) {
            return handlePatchConfig(body);
        }

        // 带路径参数的请求：GET /v0/management/config/{path} 或 PATCH /v0/management/config/{path}
        if (uri != null && uri.startsWith(PATH_CONFIG + "/")) {
            String fieldPath = uri.substring(PATH_CONFIG.length() + 1);

            if (NanoHTTPD.Method.GET.equals(method)) {
                return getField(fieldPath);
            }

            if (NanoHTTPD.Method.PATCH.equals(method)) {
                return setField(fieldPath, body);
            }
        }

        // 未知操作
        Log.w(TAG, "Unknown endpoint: " + method + " " + uri);
        return jsonResponse(404, new JSONObject()
                .put("error", "端点不存在")
                .put("path", uri)
                .toString());
    }

    /**
     * 获取完整配置（JSON 格式）
     * <p>
     * GET /v0/management/config
     * 将当前内存中的配置数据以 JSON 对象树的形式返回。
     * 返回的配置结构包含 server、logging、proxy、auth、rate_limit 等顶级配置节。
     * 同时返回当前配置版本号，用于客户端缓存控制。
     *
     * @return JSON 响应，包含完整的配置数据和版本号
     */
    public Response getConfig() {
        Log.d(TAG, "Getting full config as JSON");

        JSONObject config = rebuildJsonFromStore();

        JSONObject response = new JSONObject();
        response.put("config", config);
        response.put("version", configVersion);

        Log.d(TAG, "Config retrieved (version " + configVersion + ")");
        return jsonResponse(200, response.toString());
    }

    /**
     * 获取完整配置（YAML 格式）
     * <p>
     * GET /v0/management/config.yaml
     * 返回当前配置的 YAML 格式文本。如果之前通过 PUT 上传过 YAML 内容，
     * 则直接返回原始 YAML 字符串；否则基于当前 JSON 配置自动生成 YAML 表示。
     * 响应 Content-Type 为 text/yaml 或 application/x-yaml。
     *
     * @return YAML 文本响应，包含完整的配置数据
     */
    public Response getConfigYaml() {
        Log.d(TAG, "Getting full config as YAML");

        String yamlContent;
        if (rawYamlConfig != null && !rawYamlConfig.isEmpty()) {
            yamlContent = rawYamlConfig;
        } else {
            // 从当前配置存储重建 YAML
            JSONObject config = rebuildJsonFromStore();
            yamlContent = jsonToYaml(config);
        }

        Log.d(TAG, "YAML config retrieved (" + yamlContent.length() + " bytes)");

        // 返回 YAML 格式的响应
        InputStream in = new ByteArrayInputStream(yamlContent.getBytes(StandardCharsets.UTF_8));
        NanoHTTPD.Response.Status status = NanoHTTPD.Response.Status.lookup(200);
        Response response = NanoHTTPD.newChunkedResponse(status, "application/x-yaml", in);
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Methods", "GET, PUT, PATCH, OPTIONS");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Management-Key");
        response.addHeader("X-Config-Version", String.valueOf(configVersion));
        return response;
    }

    /**
     * 替换完整配置并触发热重载
     * <p>
     * PUT /v0/management/config.yaml
     * 接收 YAML 格式的配置文本，解析为 JSON 后替换当前内存中的配置数据。
     * 如果配置解析成功，会递增版本号并尝试触发热重载回调。
     * 热重载失败时不会回滚配置变更，但会在响应中提示重载结果。
     * <p>
     * 请求体应为合法的 YAML 格式文本，Content-Type 建议使用 text/yaml。
     *
     * @param body 请求体字符串（YAML 格式的配置内容）
     * @return JSON 响应，包含配置替换结果和热重载状态
     */
    public Response putConfigYaml(String body) {
        if (body == null || body.trim().isEmpty()) {
            Log.w(TAG, "PUT config failed: empty request body");
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体不能为空，请提供 YAML 格式的配置内容")
                    .toString());
        }

        Log.d(TAG, "Replacing config via YAML (" + body.length() + " bytes)");

        // 保存原始 YAML 内容
        this.rawYamlConfig = body;

        // 解析 YAML 为 JSON 配置树
        try {
            JSONObject parsedConfig = parseYamlToJson(body);
            replaceConfigStore(parsedConfig);
            configVersion++;

            Log.d(TAG, "Config replaced successfully, version now " + configVersion);

            // 尝试触发热重载
            boolean reloadResult = true;
            String reloadMessage = "无需热重载（未注册回调）";

            if (reloadCallback != null) {
                try {
                    reloadResult = reloadCallback.onReload(body);
                    reloadMessage = reloadResult ? "热重载成功" : "热重载失败";
                } catch (Exception e) {
                    reloadResult = false;
                    reloadMessage = "热重载异常: " + e.getMessage();
                    Log.e(TAG, "Reload callback threw exception", e);
                }
            }

            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("version", configVersion);
            response.put("reload_result", reloadResult);
            response.put("reload_message", reloadMessage);

            return jsonResponse(200, response.toString());

        } catch (Exception e) {
            Log.w(TAG, "PUT config failed: invalid YAML content", e);
            return jsonResponse(400, new JSONObject()
                    .put("error", "配置解析失败，请确保提供合法的 YAML 格式: " + e.getMessage())
                    .toString());
        }
    }

    /**
     * 按路径查询单个配置字段
     * <p>
     * GET /v0/management/config/{path}
     * 使用点号分隔的路径表达式查询配置中的特定字段，例如：
     * <ul>
     *   <li>server.port — 查询服务器端口</li>
     *   <li>proxy.connect_timeout — 查询代理连接超时</li>
     *   <li>auth.enabled — 查询认证开关状态</li>
     * </ul>
     * 支持嵌套对象和数组索引访问（如 proxy.hosts[0].name）。
     * 如果路径不存在，返回 404 错误。
     *
     * @param path 点号分隔的配置字段路径
     * @return JSON 响应，包含查询到的字段值及其路径和类型信息
     */
    public Response getField(String path) {
        if (path == null || path.trim().isEmpty()) {
            Log.w(TAG, "Get field failed: empty path");
            return jsonResponse(400, new JSONObject()
                    .put("error", "字段路径不能为空")
                    .toString());
        }

        Log.d(TAG, "Getting config field: " + path);

        try {
            // 从配置存储中重建 JSON 对象树
            JSONObject config = rebuildJsonFromStore();

            // 按路径导航
            Object value = navigatePath(config, path);

            if (value == null) {
                Log.w(TAG, "Field not found: " + path);
                return jsonResponse(404, new JSONObject()
                        .put("error", "配置字段不存在")
                        .put("path", path)
                        .toString());
            }

            JSONObject response = new JSONObject();
            response.put("path", path);
            response.put("value", value);
            response.put("type", value.getClass().getSimpleName());
            response.put("version", configVersion);

            Log.d(TAG, "Field '" + path + "' = " + value);
            return jsonResponse(200, response.toString());

        } catch (Exception e) {
            Log.w(TAG, "Failed to get field: " + path, e);
            return jsonResponse(500, new JSONObject()
                    .put("error", "查询配置字段时发生内部错误: " + e.getMessage())
                    .put("path", path)
                    .toString());
        }
    }

    /**
     * 按路径设置单个配置字段
     * <p>
     * PATCH /v0/management/config/{path}
     * 使用点号分隔的路径表达式设置配置中的特定字段。
     * 请求体应为 JSON 格式，包含要设置的值。例如：
     * <ul>
     *   <li>PATCH /v0/management/config/server.port  body: {"value": 9090}</li>
     *   <li>PATCH /v0/management/config/auth.enabled body: {"value": true}</li>
     *   <li>PATCH /v0/management/config/logging.level body: {"value": "debug"}</li>
     * </ul>
     * 如果路径不存在，会自动创建中间节点（仅支持对象路径，不支持数组索引创建）。
     * 设置成功后递增配置版本号。
     *
     * @param path 点号分隔的配置字段路径
     * @param body 请求体 JSON 字符串，需包含 value 字段
     * @return JSON 响应，包含设置操作结果和新的配置版本号
     */
    public Response setField(String path, String body) {
        if (path == null || path.trim().isEmpty()) {
            Log.w(TAG, "Set field failed: empty path");
            return jsonResponse(400, new JSONObject()
                    .put("error", "字段路径不能为空")
                    .toString());
        }

        if (body == null || body.trim().isEmpty()) {
            Log.w(TAG, "Set field failed: empty request body");
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体不能为空，请提供 JSON 格式的 value")
                    .toString());
        }

        Log.d(TAG, "Setting config field: " + path);

        try {
            // 解析请求体中的 value
            JSONObject requestJson = new JSONObject(body);
            if (!requestJson.has("value")) {
                Log.w(TAG, "Set field failed: missing 'value' field in body");
                return jsonResponse(400, new JSONObject()
                        .put("error", "请求体必须包含 value 字段")
                        .put("path", path)
                        .toString());
            }

            Object newValue = requestJson.get("value");

            // 重建当前配置树
            JSONObject config = rebuildJsonFromStore();

            // 在路径上设置值
            JSONObject resultConfig = setValueAtPath(config, path, newValue);

            // 替换配置存储
            replaceConfigStore(resultConfig);
            configVersion++;

            // 同步更新原始 YAML 缓存（如果存在）
            if (rawYamlConfig != null && !rawYamlConfig.isEmpty()) {
                rawYamlConfig = jsonToYaml(resultConfig);
            }

            Log.d(TAG, "Field '" + path + "' set to " + newValue
                    + " (version " + configVersion + ")");

            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("path", path);
            response.put("value", newValue);
            response.put("version", configVersion);

            return jsonResponse(200, response.toString());

        } catch (org.json.JSONException e) {
            Log.w(TAG, "Set field failed: invalid JSON body", e);
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体格式错误，需要合法的 JSON: " + e.getMessage())
                    .toString());
        } catch (Exception e) {
            Log.w(TAG, "Failed to set field: " + path, e);
            return jsonResponse(500, new JSONObject()
                    .put("error", "设置配置字段时发生内部错误: " + e.getMessage())
                    .put("path", path)
                    .toString());
        }
    }

    // ===== 内部请求处理方法 =====

    /**
     * 处理 PATCH /v0/management/config 请求体
     * <p>
     * 解析请求体中的 JSON 对象，将其中的每个字段按路径更新到配置中。
     * 请求体格式示例：
     * <pre>
     * {
     *   "server.port": 9090,
     *   "logging.level": "debug",
     *   "auth.enabled": true
     * }
     * </pre>
     * 支持批量更新多个字段，所有更新在同一个事务中完成。
     * 如果任一字段更新失败，整个操作回滚。
     *
     * @param body 请求体 JSON 字符串
     * @return JSON 响应，包含更新结果和新的配置版本号
     */
    private Response handlePatchConfig(String body) {
        if (body == null || body.trim().isEmpty()) {
            Log.w(TAG, "PATCH config failed: empty request body");
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体不能为空，请提供 JSON 格式的配置更新")
                    .toString());
        }

        try {
            JSONObject patchData = new JSONObject(body);
            JSONObject config = rebuildJsonFromStore();
            int updatedFields = 0;

            // 遍历所有键，每个键视为一个路径表达式
            Iterator<String> keys = patchData.keys();
            while (keys.hasNext()) {
                String fieldPath = keys.next();
                Object fieldValue = patchData.get(fieldPath);

                try {
                    config = setValueAtPath(config, fieldPath, fieldValue);
                    updatedFields++;
                } catch (Exception e) {
                    Log.w(TAG, "Failed to update field '" + fieldPath + "', skipping", e);
                }
            }

            if (updatedFields > 0) {
                replaceConfigStore(config);
                configVersion++;

                // 同步更新 YAML 缓存
                if (rawYamlConfig != null && !rawYamlConfig.isEmpty()) {
                    rawYamlConfig = jsonToYaml(config);
                }
            }

            Log.d(TAG, "PATCH config: " + updatedFields + " fields updated,"
                    + " version " + configVersion);

            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("updated_fields", updatedFields);
            response.put("version", configVersion);

            return jsonResponse(200, response.toString());

        } catch (Exception e) {
            Log.w(TAG, "PATCH config failed: invalid JSON", e);
            return jsonResponse(400, new JSONObject()
                    .put("error", "配置更新失败，请求体格式错误: " + e.getMessage())
                    .toString());
        }
    }

    // ===== 配置存储操作 =====

    /**
     * 替换整个配置存储
     * <p>
     * 清空当前配置存储并用给定的 JSON 对象树重新填充。
     * 此操作会同时更新 configStore 和 rawYamlConfig。
     *
     * @param config 新的配置 JSON 对象
     */
    private void replaceConfigStore(JSONObject config) {
        configStore.clear();
        flattenJsonToStore("", config);
    }

    /**
     * 将 JSON 对象树展平并存储到 configStore 中
     * <p>
     * 递归遍历 JSON 对象，将每个叶子节点的路径作为 key 存入 configStore。
     * 例如：{"server": {"port": 8080}} 会存储为 configStore["server.port"] = 8080。
     * 数组类型的值会整体存储为 JSONArray 对象。
     *
     * @param prefix 当前路径前缀（内部递归使用）
     * @param json   要展平的 JSON 对象
     */
    private void flattenJsonToStore(String prefix, JSONObject json) {
        Iterator<String> keys = json.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            String fullPath = prefix.isEmpty() ? key : prefix + "." + key;

            Object value = json.opt(key);
            if (value instanceof JSONObject) {
                // 递归处理嵌套对象
                flattenJsonToStore(fullPath, (JSONObject) value);
            } else if (value instanceof JSONArray) {
                // 数组直接存储
                configStore.put(fullPath, value);
            } else if (value != null && value != JSONObject.NULL) {
                // 基本类型值
                configStore.put(fullPath, value);
            }
        }
    }

    /**
     * 从 configStore 重建完整的 JSON 对象树
     * <p>
     * 将扁平的键值对存储还原为嵌套的 JSON 对象结构。
     * 例如：configStore["server.port"] = 8080 和 configStore["server.host"] = "0.0.0.0"
     * 会被重建为 {"server": {"port": 8080, "host": "0.0.0.0"}}。
     *
     * @return 重建后的完整配置 JSON 对象
     */
    private JSONObject rebuildJsonFromStore() {
        JSONObject root = new JSONObject();

        for (Map.Entry<String, Object> entry : configStore.entrySet()) {
            String path = entry.getKey();
            Object value = entry.getValue();

            String[] parts = path.split("\\.");
            JSONObject current = root;

            for (int i = 0; i < parts.length - 1; i++) {
                String part = parts[i];
                if (!current.has(part)) {
                    current.put(part, new JSONObject());
                }
                Object next = current.opt(part);
                if (next instanceof JSONObject) {
                    current = (JSONObject) next;
                } else {
                    // 路径冲突，覆盖为新对象
                    JSONObject newObj = new JSONObject();
                    current.put(part, newObj);
                    current = newObj;
                }
            }

            String lastKey = parts[parts.length - 1];
            current.put(lastKey, value);
        }

        return root;
    }

    // ===== 路径导航工具 =====

    /**
     * 按点号分隔的路径表达式在 JSON 对象树中导航查找值
     * <p>
     * 支持以下路径格式：
     * <ul>
     *   <li>简单字段: server.port</li>
     *   <li>嵌套对象: proxy.hosts</li>
     *   <li>数组索引: proxy.hosts[0].name（实验性支持）</li>
     * </ul>
     *
     * @param root 根 JSON 对象
     * @param path 点号分隔的路径表达式
     * @return 路径对应的值，如果路径不存在则返回 null
     */
    private Object navigatePath(JSONObject root, String path) {
        if (root == null || path == null) {
            return null;
        }

        // 将路径按点号分段，同时处理数组索引访问
        String[] segments = path.split("\\.");
        Object current = root;

        for (String segment : segments) {
            if (current == null) {
                return null;
            }

            // 检查是否包含数组索引访问，如 "hosts[0]"
            String arrayIndex = null;
            String key = segment;

            int bracketStart = segment.indexOf('[');
            if (bracketStart > 0 && segment.endsWith("]")) {
                key = segment.substring(0, bracketStart);
                arrayIndex = segment.substring(bracketStart + 1, segment.length() - 1);
            }

            if (current instanceof JSONObject) {
                JSONObject obj = (JSONObject) current;
                if (!obj.has(key)) {
                    return null;
                }
                current = obj.opt(key);

                // 如果存在数组索引，尝试从数组中取元素
                if (arrayIndex != null && current instanceof JSONArray) {
                    try {
                        int index = Integer.parseInt(arrayIndex);
                        JSONArray arr = (JSONArray) current;
                        current = index >= 0 && index < arr.length() ? arr.opt(index) : null;
                    } catch (NumberFormatException e) {
                        Log.w(TAG, "Invalid array index: " + arrayIndex);
                        return null;
                    }
                }
            } else if (current instanceof JSONArray) {
                // 当前是数组但下一段不是索引，返回 null
                return null;
            } else {
                // 当前是基本类型，无法继续导航
                return null;
            }
        }

        return current;
    }

    /**
     * 在 JSON 对象树中按路径设置值
     * <p>
     * 沿路径表达式创建或获取中间节点，然后将值赋给目标字段。
     * 如果路径中间的某个节点不存在，会自动创建新的 JSONObject。
     * 支持数组索引设置（如 proxy.hosts[0]），但不会自动扩展数组大小。
     * 此方法返回一个新的 JSONObject 副本，不会修改原始对象。
     *
     * @param root  根 JSON 对象
     * @param path  点号分隔的路径表达式
     * @param value 要设置的值
     * @return 修改后的根 JSON 对象副本
     * @throws IllegalArgumentException 如果路径无效或数组索引越界
     */
    private JSONObject setValueAtPath(JSONObject root, String path, Object value) {
        if (root == null || path == null) {
            throw new IllegalArgumentException("根对象和路径不能为空");
        }

        // 深度复制根对象
        String rootJson = root.toString();
        JSONObject result;
        try {
            result = new JSONObject(rootJson);
        } catch (Exception e) {
            throw new IllegalArgumentException("无法复制配置对象", e);
        }

        String[] segments = path.split("\\.");
        JSONObject current = result;

        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            boolean isLast = (i == segments.length - 1);

            // 处理数组索引
            String arrayIndex = null;
            String key = segment;

            int bracketStart = segment.indexOf('[');
            if (bracketStart > 0 && segment.endsWith("]")) {
                key = segment.substring(0, bracketStart);
                arrayIndex = segment.substring(bracketStart + 1, segment.length() - 1);
            }

            if (isLast) {
                // 最后一个路径段，设置值
                if (arrayIndex != null) {
                    // 设置数组元素
                    JSONArray arr = current.optJSONArray(key);
                    if (arr == null) {
                        throw new IllegalArgumentException("路径 '" + path + "' 中的 '" + key + "' 不是数组");
                    }
                    int index = Integer.parseInt(arrayIndex);
                    if (index < 0 || index >= arr.length()) {
                        throw new IllegalArgumentException("数组索引 " + index + " 越界，长度 " + arr.length());
                    }
                    arr.put(index, value);
                } else {
                    current.put(key, value);
                }
            } else {
                // 中间路径段，获取或创建子对象
                if (arrayIndex != null) {
                    // 通过数组索引访问中间节点
                    JSONArray arr = current.optJSONArray(key);
                    if (arr == null) {
                        throw new IllegalArgumentException("路径 '" + path + "' 中的 '" + key + "' 不是数组");
                    }
                    int index = Integer.parseInt(arrayIndex);
                    if (index < 0 || index >= arr.length()) {
                        throw new IllegalArgumentException("数组索引 " + index + " 越界，长度 " + arr.length());
                    }
                    Object next = arr.opt(index);
                    if (next instanceof JSONObject) {
                        current = (JSONObject) next;
                    } else {
                        // 替换为新的 JSONObject
                        JSONObject newObj = new JSONObject();
                        arr.put(index, newObj);
                        current = newObj;
                    }
                } else {
                    if (!current.has(key)) {
                        current.put(key, new JSONObject());
                    }
                    Object next = current.opt(key);
                    if (next instanceof JSONObject) {
                        current = (JSONObject) next;
                    } else {
                        // 覆盖为新的 JSONObject
                        JSONObject newObj = new JSONObject();
                        current.put(key, newObj);
                        current = newObj;
                    }
                }
            }
        }

        return result;
    }

    // ===== 格式转换工具 =====

    /**
     * 将 JSON 对象转换为简化的 YAML 格式字符串
     * <p>
     * 递归遍历 JSON 对象树，生成缩进格式的 YAML 文本。
     * 支持字符串、数字、布尔值、null 以及嵌套对象和数组的转换。
     * 数组元素会以 "- " 前缀列出。
     * 此实现是一个简化的 YAML 生成器，覆盖了常见的配置场景。
     *
     * @param json 要转换的 JSON 对象
     * @return YAML 格式的字符串
     */
    public static String jsonToYaml(JSONObject json) {
        StringBuilder sb = new StringBuilder();
        jsonToYamlInternal(sb, json, 0);
        return sb.toString();
    }

    /**
     * 递归生成 YAML 的内部方法
     *
     * @param sb    字符串构建器
     * @param obj   当前 JSON 对象
     * @param depth 当前缩进深度
     */
    private static void jsonToYamlInternal(StringBuilder sb, JSONObject obj, int depth) {
        String indent = getYamlIndent(depth);
        Iterator<String> keys = obj.keys();

        while (keys.hasNext()) {
            String key = keys.next();
            Object value = obj.opt(key);

            if (value instanceof JSONObject) {
                sb.append(indent).append(key).append(":\n");
                jsonToYamlInternal(sb, (JSONObject) value, depth + 1);
            } else if (value instanceof JSONArray) {
                sb.append(indent).append(key).append(":\n");
                JSONArray arr = (JSONArray) value;
                String arrayIndent = getYamlIndent(depth + 1);
                for (int i = 0; i < arr.length(); i++) {
                    Object elem = arr.opt(i);
                    if (elem instanceof JSONObject) {
                        sb.append(arrayIndent).append("- ");
                        // 内联输出简单对象的第一层
                        JSONObject elemObj = (JSONObject) elem;
                        if (elemObj.length() == 0) {
                            sb.append("{}\n");
                        } else {
                            sb.append("\n");
                            jsonToYamlInternal(sb, elemObj, depth + 2);
                        }
                    } else {
                        sb.append(arrayIndent).append("- ").append(formatYamlValue(elem)).append("\n");
                    }
                }
            } else {
                sb.append(indent).append(key).append(": ").append(formatYamlValue(value)).append("\n");
            }
        }
    }

    /**
     * 获取指定深度的 YAML 缩进字符串
     * <p>
     * 每层缩进使用 2 个空格，符合 YAML 规范。
     *
     * @param depth 缩进深度
     * @return 缩进字符串
     */
    private static String getYamlIndent(int depth) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < depth * 2; i++) {
            sb.append(' ');
        }
        return sb.toString();
    }

    /**
     * 将 JSON 值格式化为 YAML 值字符串
     * <p>
     * 字符串值如果包含特殊字符则会加引号；
     * null 值输出为 "null"；
     * 布尔值和数字直接输出。
     *
     * @param value JSON 值
     * @return YAML 格式的值字符串
     */
    private static String formatYamlValue(Object value) {
        if (value == null || value == JSONObject.NULL) {
            return "null";
        }
        if (value instanceof String) {
            String s = (String) value;
            // 如果字符串包含特殊字符或为空，则加引号
            if (s.isEmpty() || s.contains(":") || s.contains("#") || s.contains("\"")
                    || s.contains("'") || s.contains("{") || s.contains("}")
                    || s.contains("[") || s.contains("]") || s.contains(",")
                    || s.contains("&") || s.contains("*") || s.contains("?")
                    || s.contains("|") || s.contains("-") || s.contains("<")
                    || s.contains(">") || s.contains("=") || s.contains("!")
                    || s.contains("%") || s.contains("@") || s.contains("`")
                    || s.startsWith(" ") || s.endsWith(" ") || s.startsWith("\t")) {
                return "\"" + escapeYamlString(s) + "\"";
            }
            // 空字符串或数字字符串加引号
            if (s.matches(".*\\s.*") || s.matches("^[0-9].*") || "null".equals(s)
                    || "true".equals(s) || "false".equals(s) || "yes".equals(s) || "no".equals(s)) {
                return "\"" + escapeYamlString(s) + "\"";
            }
            return s;
        }
        // 布尔值输出小写
        if (value instanceof Boolean) {
            return Boolean.toString((Boolean) value);
        }
        // 数字直接输出
        return value.toString();
    }

    /**
     * 转义 YAML 字符串中的特殊字符
     *
     * @param s 原始字符串
     * @return 转义后的字符串
     */
    private static String escapeYamlString(String s) {
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    /**
     * 将简化的 YAML 格式字符串解析为 JSON 对象
     * <p>
     * 支持以下 YAML 特性：
     * <ul>
     *   <li>键值对: key: value</li>
     *   <li>嵌套对象（缩进 2 空格）</li>
     *   <li>数组: - item</li>
     *   <li>多行字符串（缩进续行）</li>
     *   <li>引号字符串（单引号和双引号）</li>
     *   <li>注释（# 开头，仅支持行尾注释）</li>
     * </ul>
     * 这是一个简化的 YAML 解析器，适用于配置文件的常见格式。
     *
     * @param yaml YAML 格式字符串
     * @return 解析后的 JSON 对象
     * @throws IllegalArgumentException 如果 YAML 格式无法解析
     */
    public static JSONObject parseYamlToJson(String yaml) {
        if (yaml == null || yaml.trim().isEmpty()) {
            return new JSONObject();
        }

        JSONObject root = new JSONObject();
        String[] lines = yaml.split("\n");
        // 使用栈来跟踪当前路径上的 JSONObject 和对应的缩进级别
        java.util.Stack<JSONObject> objectStack = new java.util.Stack<>();
        java.util.Stack<Integer> indentStack = new java.util.Stack<>();
        // 用于处理数组的栈
        java.util.Stack<JSONArray> arrayStack = new java.util.Stack<>();
        // 当前正在构建的多行字符串键
        String multilineKey = null;
        StringBuilder multilineValue = new StringBuilder();
        boolean inMultiline = false;

        objectStack.push(root);
        indentStack.push(-1);

        for (int i = 0; i < lines.length; i++) {
            String line = lines[i];

            // 处理多行字符串续行
            if (inMultiline) {
                String trimmed = line.replaceFirst("^\\s+", "");
                if (!trimmed.isEmpty() && line.startsWith("  ")) {
                    // 连续行（缩进的内容）
                    multilineValue.append("\n").append(trimmed);
                    continue;
                } else {
                    // 多行字符串结束，设置值
                    inMultiline = false;
                    if (multilineKey != null && !objectStack.isEmpty()) {
                        JSONObject currentObj = objectStack.peek();
                        currentObj.put(multilineKey, multilineValue.toString().trim());
                    }
                    multilineKey = null;
                    multilineValue = new StringBuilder();
                    // 继续处理当前行
                }
            }

            // 去除行尾注释（# 号，但需要处理引号内的 #）
            String noComment = removeYamlComment(line).trim();

            // 跳过空行和纯注释行
            if (noComment.isEmpty()) {
                continue;
            }

            // 计算缩进级别（按 2 空格递增）
            int indent = 0;
            for (int j = 0; j < line.length(); j++) {
                if (line.charAt(j) == ' ') {
                    indent++;
                } else {
                    break;
                }
            }
            // 如果行首是制表符，按 2 空格换算
            if (indent == 0 && line.startsWith("\t")) {
                int tabCount = 0;
                for (int j = 0; j < line.length() && line.charAt(j) == '\t'; j++) {
                    tabCount++;
                }
                indent = tabCount * 2;
            }

            // 回退到正确的缩进级别
            while (!indentStack.isEmpty() && indent <= indentStack.peek()) {
                indentStack.pop();
                if (!arrayStack.isEmpty() && indentStack.size() <= arrayStack.size()) {
                    arrayStack.pop();
                }
                if (objectStack.size() > 1) {
                    objectStack.pop();
                }
            }

            // 检查是否是数组元素
            if (noComment.startsWith("- ")) {
                String arrayItem = noComment.substring(2).trim();
                JSONObject currentObj = objectStack.peek();

                // 找到或创建数组
                // 需要找到当前缩进级别对应的 key
                String arrayKey = findLastKey(currentObj);
                JSONArray arr;
                if (arrayKey != null && currentObj.has(arrayKey)
                        && currentObj.opt(arrayKey) instanceof JSONArray) {
                    arr = currentObj.getJSONArray(arrayKey);
                } else {
                    // 查找父级
                    if (!arrayStack.isEmpty()) {
                        arr = arrayStack.peek();
                    } else {
                        // 创建新的数组
                        arr = new JSONArray();
                        String key = "items";
                        currentObj.put(key, arr);
                        arrayStack.push(arr);
                        indentStack.push(indent);
                        // 继续保留当前对象在栈中，但设置缩进
                    }
                }

                if (arrayItem.isEmpty()) {
                    // 空数组项，可能是嵌套对象
                    JSONObject nested = new JSONObject();
                    arr.put(nested);
                    objectStack.push(nested);
                    indentStack.push(indent);
                    arrayStack.push(arr);
                } else {
                    // 基本类型值
                    arr.put(parseYamlValue(arrayItem));
                }
            } else {
                // 普通键值对
                int colonIndex = noComment.indexOf(':');
                if (colonIndex < 0) {
                    Log.w(TAG, "Skipping invalid YAML line " + (i + 1) + ": " + noComment);
                    continue;
                }

                String key = noComment.substring(0, colonIndex).trim();
                String valuePart = noComment.substring(colonIndex + 1).trim();

                JSONObject currentObj = objectStack.peek();

                if (valuePart.isEmpty()) {
                    // 值部分为空，表示这是一个嵌套对象
                    JSONObject nested = new JSONObject();
                    currentObj.put(key, nested);
                    objectStack.push(nested);
                    indentStack.push(indent);
                } else if (valuePart.equals("|")) {
                    // 多行字符串（literal block scalar）
                    multilineKey = key;
                    multilineValue = new StringBuilder();
                    inMultiline = true;
                } else {
                    // 基本类型值
                    currentObj.put(key, parseYamlValue(valuePart));
                }
            }
        }

        // 处理文件末尾可能未关闭的多行字符串
        if (inMultiline && multilineKey != null && !objectStack.isEmpty()) {
            objectStack.peek().put(multilineKey, multilineValue.toString().trim());
        }

        return root;
    }

    /**
     * 查找 JSONObject 中的最后一个键名
     * <p>
     * 用于确定数组元素所属的父级键。
     * JSONObject 不保证顺序，此方法返回任意一个键名。
     *
     * @param obj JSON 对象
     * @return 键名，如果对象为空则返回 null
     */
    private static String findLastKey(JSONObject obj) {
        if (obj == null) {
            return null;
        }
        Iterator<String> keys = obj.keys();
        String lastKey = null;
        while (keys.hasNext()) {
            lastKey = keys.next();
        }
        return lastKey;
    }

    /**
     * 去除 YAML 行中的注释
     * <p>
     * 只去除行尾的 # 注释，会正确处理引号字符串中的 #。
     *
     * @param line YAML 行
     * @return 去除注释后的行
     */
    private static String removeYamlComment(String line) {
        if (line == null || line.isEmpty()) {
            return "";
        }

        boolean inSingleQuote = false;
        boolean inDoubleQuote = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '\'' && !inDoubleQuote) {
                inSingleQuote = !inSingleQuote;
            } else if (c == '"' && !inSingleQuote) {
                inDoubleQuote = !inDoubleQuote;
            } else if (c == '#' && !inSingleQuote && !inDoubleQuote) {
                return line.substring(0, i);
            }
        }
        return line;
    }

    /**
     * 解析 YAML 值字符串为对应的 Java 类型
     * <p>
     * 支持以下类型转换：
     * <ul>
     *   <li>引号字符串 → String</li>
     *   <li>true/false → Boolean</li>
     *   <li>null → null</li>
     *   <li>数字 → Integer 或 Long 或 Double</li>
     *   <li>其他 → String</li>
     * </ul>
     *
     * @param value YAML 值字符串
     * @return 解析后的 Java 对象
     */
    private static Object parseYamlValue(String value) {
        if (value == null || value.isEmpty()) {
            return "";
        }

        // 去除引号
        if ((value.startsWith("\"") && value.endsWith("\""))
                || (value.startsWith("'") && value.endsWith("'"))) {
            return value.substring(1, value.length() - 1);
        }

        // null
        if ("null".equals(value) || "~".equals(value)) {
            return null;
        }

        // 布尔值
        if ("true".equals(value) || "yes".equals(value) || "on".equals(value)) {
            return true;
        }
        if ("false".equals(value) || "no".equals(value) || "off".equals(value)) {
            return false;
        }

        // 整数
        try {
            if (value.matches("-?\\d+")) {
                long longVal = Long.parseLong(value);
                if (longVal >= Integer.MIN_VALUE && longVal <= Integer.MAX_VALUE) {
                    return (int) longVal;
                }
                return longVal;
            }
        } catch (NumberFormatException ignored) {
            // 不是整数，继续尝试其他类型
        }

        // 浮点数
        try {
            if (value.matches("-?\\d+\\.\\d+") || value.matches("-?\\d+\\.\\d+[eE][+-]?\\d+")) {
                return Double.parseDouble(value);
            }
        } catch (NumberFormatException ignored) {
            // 不是浮点数
        }

        // 默认作为字符串
        return value;
    }

    // ===== 公共状态查询方法 =====

    /**
     * 获取当前配置版本号
     * <p>
     * 每次 PUT 或 PATCH 操作成功后版本号递增。
     * 客户端可通过此值判断配置是否已变更。
     *
     * @return 当前配置版本号
     */
    public long getConfigVersion() {
        return configVersion;
    }

    /**
     * 获取配置中包含的顶级键数量
     * <p>
     * 用于诊断和监控，反映配置的复杂度。
     *
     * @return 配置中顶级字段的数量
     */
    public int getConfigSize() {
        return configStore.size();
    }

    /**
     * 重置配置为默认值
     * <p>
     * 清空所有自定义配置并恢复为构造时的默认配置。
     * 版本号递增。
     */
    public void resetToDefault() {
        configStore.clear();
        configVersion++;
        initDefaultConfig();
        Log.d(TAG, "Config reset to defaults (version " + configVersion + ")");
    }

    // ===== 静态工具方法 =====

    /**
     * 创建 JSON 响应
     *
     * @param statusCode HTTP 状态码
     * @param json       JSON 字符串
     * @return NanoHTTPD Response 对象
     */
    public static Response jsonResponse(int statusCode, String json) {
        NanoHTTPD.Response.Status status = NanoHTTPD.Response.Status.lookup(statusCode);
        InputStream in = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
        Response response = NanoHTTPD.newChunkedResponse(status, "application/json", in);
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Management-Key");
        return response;
    }
}