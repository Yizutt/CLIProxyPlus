package com.cliproxy.plus.auth.cloak;

import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicLong;

import okhttp3.Headers;
import okhttp3.Request;

/**
 * HeaderInjector - Claude Code CLI 请求头注入与设备指纹管理
 * <p>
 * 管理和注入 HTTP 请求头，使代理请求在外观上匹配官方 Claude Code CLI 的请求特征。
 * 维护一组默认头（User-Agent、包版本、运行时版本、OS、架构、超时），
 * 并提供 {@code stabilize-device-profile} 机制用于指纹固定，确保同一设备
 * 在一段时间内生成一致的请求头指纹，避免因指纹漂移被检测。
 * <p>
 * 对应 Claude Code CLI 的 identity/header 层。
 */
public class HeaderInjector {

    private static final String TAG = "HeaderInjector";

    // ============================================================
    // 默认请求头常量 - 匹配官方 Claude Code CLI 2.1.44
    // ============================================================

    /** 头名称：User-Agent */
    public static final String HEADER_USER_AGENT = "User-Agent";

    /** 官方 Claude Code CLI User-Agent 值 */
    public static final String DEFAULT_USER_AGENT = "claude-cli/2.1.44";

    /** 头名称：包版本 */
    public static final String HEADER_PACKAGE_VERSION = "X-Claude-Package-Version";

    /** 默认包版本 */
    public static final String DEFAULT_PACKAGE_VERSION = "0.74.0";

    /** 头名称：运行时版本 */
    public static final String HEADER_RUNTIME_VERSION = "X-Claude-Runtime-Version";

    /** 默认 Node.js 运行时版本 */
    public static final String DEFAULT_RUNTIME_VERSION = "v24.3.0";

    /** 头名称：操作系统 */
    public static final String HEADER_OS = "X-Claude-OS";

    /** 默认操作系统 */
    public static final String DEFAULT_OS = "MacOS";

    /** 头名称：系统架构 */
    public static final String HEADER_ARCH = "X-Claude-Arch";

    /** 默认系统架构 */
    public static final String DEFAULT_ARCH = "arm64";

    /** 头名称：请求超时 */
    public static final String HEADER_TIMEOUT = "X-Claude-Timeout";

    /** 默认请求超时秒数 */
    public static final String DEFAULT_TIMEOUT = "600";

    /** 头名称：客户端类型 */
    public static final String HEADER_CLIENT_TYPE = "X-Claude-Client-Type";

    /** 默认客户端类型 */
    public static final String DEFAULT_CLIENT_TYPE = "cli";

    /** 头名称：设备指纹标识 */
    public static final String HEADER_DEVICE_FINGERPRINT = "X-Claude-Device-Fingerprint";

    // ============================================================
    // 已知的 Claude Code CLI 请求头集合
    // ============================================================

    /** 所有 Claude Code CLI 特有请求头的名称集合（用于检测） */
    private static final Set<String> CLAUDE_CLI_HEADERS = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            HEADER_USER_AGENT,
            HEADER_PACKAGE_VERSION,
            HEADER_RUNTIME_VERSION,
            HEADER_OS,
            HEADER_ARCH,
            HEADER_TIMEOUT,
            HEADER_CLIENT_TYPE,
            HEADER_DEVICE_FINGERPRINT
    )));

    /** 默认客户端类型列表 */
    private static final List<String> SUPPORTED_CLIENT_TYPES = Collections.unmodifiableList(Arrays.asList(
            "cli", "vscode", "jetbrains", "cursor", "windsurf"
    ));

    // ============================================================
    // 设备指纹稳定化（stabilize-device-profile）
    // ============================================================

    /** 设备指纹种子键（用于生成稳定指纹） */
    private static final String FINGERPRINT_SEED_KEY = "fingerprint_seed";

    /** 指纹稳定化窗口毫秒数（默认 24 小时） */
    private static final long DEFAULT_STABILIZE_WINDOW_MS = 24 * 60 * 60 * 1000L;

    /** 设备指纹缓存：种子 -> 生成的指纹 JSON */
    private final ConcurrentMap<String, String> fingerprintCache = new ConcurrentHashMap<>();

    /** 设备指纹生成时间戳 */
    private final AtomicLong fingerprintGeneratedAt = new AtomicLong(0);

    /** 当前指纹种子 */
    private volatile String fingerprintSeed;

    /** 指纹稳定化窗口 */
    private volatile long stabilizeWindowMs = DEFAULT_STABILIZE_WINDOW_MS;

    /** 是否启用设备指纹稳定化 */
    private volatile boolean stabilizeEnabled = true;

    // ============================================================
    // 单例
    // ============================================================

    /** 单例实例 */
    private static volatile HeaderInjector instance;

    // ============================================================
    // 构造与单例
    // ============================================================

    private HeaderInjector() {
        // 初始化指纹种子
        this.fingerprintSeed = generateDefaultSeed();
        Log.d(TAG, "HeaderInjector initialized with fingerprint seed: " + fingerprintSeed);
    }

    /**
     * 获取 HeaderInjector 单例实例
     *
     * @return 全局唯一的 HeaderInjector 实例
     */
    public static HeaderInjector getInstance() {
        if (instance == null) {
            synchronized (HeaderInjector.class) {
                if (instance == null) {
                    instance = new HeaderInjector();
                }
            }
        }
        return instance;
    }

    // ============================================================
    // 默认头
    // ============================================================

    /**
     * 获取 Claude Code CLI 默认请求头映射。
     * <p>
     * 返回的映射包含与官方 Claude Code CLI 2.1.44 一致的默认值：
     * <ul>
     *   <li>User-Agent: claude-cli/2.1.44</li>
     *   <li>X-Claude-Package-Version: 0.74.0</li>
     *   <li>X-Claude-Runtime-Version: v24.3.0</li>
     *   <li>X-Claude-OS: MacOS</li>
     *   <li>X-Claude-Arch: arm64</li>
     *   <li>X-Claude-Timeout: 600</li>
     *   <li>X-Claude-Client-Type: cli</li>
     * </ul>
     *
     * @return 不可变的默认请求头映射
     */
    public Map<String, String> getDefaultHeaders() {
        Map<String, String> defaults = new HashMap<>();
        defaults.put(HEADER_USER_AGENT, DEFAULT_USER_AGENT);
        defaults.put(HEADER_PACKAGE_VERSION, DEFAULT_PACKAGE_VERSION);
        defaults.put(HEADER_RUNTIME_VERSION, DEFAULT_RUNTIME_VERSION);
        defaults.put(HEADER_OS, DEFAULT_OS);
        defaults.put(HEADER_ARCH, DEFAULT_ARCH);
        defaults.put(HEADER_TIMEOUT, DEFAULT_TIMEOUT);
        defaults.put(HEADER_CLIENT_TYPE, DEFAULT_CLIENT_TYPE);
        return Collections.unmodifiableMap(defaults);
    }

    /**
     * 获取默认请求头，并以 okhttp3.Headers 对象返回。
     *
     * @return okhttp3.Headers 格式的默认头
     */
    public Headers getDefaultOkHttpHeaders() {
        Headers.Builder builder = new Headers.Builder();
        for (Map.Entry<String, String> entry : getDefaultHeaders().entrySet()) {
            builder.add(entry.getKey(), entry.getValue());
        }
        return builder.build();
    }

    // ============================================================
    // injectHeaders - 注入请求头
    // ============================================================

    /**
     * 向指定的请求头映射中注入 Claude Code CLI 兼容的请求头。
     * <p>
     * 根据客户端类型选择适当的头配置。对于已知的客户端类型（cli、vscode、jetbrains、
     * cursor、windsurf），注入对应的头集合；对于未知类型，使用默认的 CLI 头。
     * 如果设备指纹稳定化已启用，还会注入稳定的设备指纹头。
     * <p>
     * 已有值的头不会被覆盖，以保留调用者显式设置的优先级。
     *
     * @param headers    目标请求头映射（会被修改填充）
     * @param clientType 客户端类型标识（如 "cli"、"vscode"、"cursor"），
     *                   为 null 或空字符串时使用默认 CLI 头
     * @throws IllegalArgumentException 如果 headers 为 null
     */
    public void injectHeaders(Map<String, String> headers, String clientType) {
        if (headers == null) {
            throw new IllegalArgumentException("headers map must not be null");
        }

        try {
            String effectiveType = normalizeClientType(clientType);

            // 注入基础头
            putIfAbsent(headers, HEADER_USER_AGENT, DEFAULT_USER_AGENT);
            putIfAbsent(headers, HEADER_PACKAGE_VERSION, DEFAULT_PACKAGE_VERSION);
            putIfAbsent(headers, HEADER_RUNTIME_VERSION, DEFAULT_RUNTIME_VERSION);
            putIfAbsent(headers, HEADER_OS, DEFAULT_OS);
            putIfAbsent(headers, HEADER_ARCH, DEFAULT_ARCH);
            putIfAbsent(headers, HEADER_TIMEOUT, DEFAULT_TIMEOUT);
            putIfAbsent(headers, HEADER_CLIENT_TYPE, effectiveType);

            // 注入设备指纹（如果稳定化启用）
            if (stabilizeEnabled) {
                String fingerprint = getOrCreateStableFingerprint();
                if (fingerprint != null) {
                    putIfAbsent(headers, HEADER_DEVICE_FINGERPRINT, fingerprint);
                }
            }

            Log.d(TAG, "Headers injected for client type: " + effectiveType
                    + ", total headers: " + headers.size());

        } catch (Exception e) {
            Log.e(TAG, "Failed to inject headers for client type: " + clientType, e);
        }
    }

    /**
     * 向 okhttp3.Request 中注入 Claude Code CLI 兼容的请求头。
     * <p>
     * 此重载方法方便在构建 OkHttp 请求时直接使用。
     *
     * @param original   原始请求构建器
     * @param clientType 客户端类型标识
     * @return 添加了注入头后的请求构建器
     * @throws IllegalArgumentException 如果 original 为 null
     */
    public Request.Builder injectHeaders(Request.Builder original, String clientType) {
        if (original == null) {
            throw new IllegalArgumentException("Request.Builder must not be null");
        }

        Map<String, String> headersMap = new HashMap<>();
        injectHeaders(headersMap, clientType);

        for (Map.Entry<String, String> entry : headersMap.entrySet()) {
            original.header(entry.getKey(), entry.getValue());
        }

        return original;
    }

    /**
     * 向 okhttp3.Request.Builder 中注入头，仅当尚未设置时添加。
     *
     * @param builder   请求构建器
     * @param clientType 客户端类型
     * @return 同一个请求构建器（便于链式调用）
     */
    public Request.Builder injectHeadersIfAbsent(Request.Builder builder, String clientType) {
        if (builder == null) {
            return null;
        }

        Map<String, String> headersMap = new HashMap<>();
        injectHeaders(headersMap, clientType);

        for (Map.Entry<String, String> entry : headersMap.entrySet()) {
            // 检查是否已设置
            String existing = builder.build().header(entry.getKey());
            if (existing == null) {
                builder.header(entry.getKey(), entry.getValue());
            }
        }

        return builder;
    }

    // ============================================================
    // isClaudeCodeClient - 检测 Claude Code 客户端
    // ============================================================

    /**
     * 判断给定的请求头映射是否来自 Claude Code CLI 客户端。
     * <p>
     * 检查请求头中是否包含 Claude Code CLI 特有的标识，包括：
     * <ul>
     *   <li>User-Agent 以 "claude-cli/" 开头</li>
     *   <li>存在 X-Claude-Package-Version 头</li>
     *   <li>存在 X-Claude-Client-Type 头且值为 "cli"</li>
     * </ul>
     * 满足任一条件即判定为 Claude Code CLI 客户端。
     *
     * @param headers 请求头映射
     * @return 如果请求来自 Claude Code CLI 返回 true；
     *         如果 headers 为 null 或为空返回 false
     */
    public boolean isClaudeCodeClient(Map<String, String> headers) {
        if (headers == null || headers.isEmpty()) {
            return false;
        }

        try {
            // 检查 1: User-Agent 以 claude-cli/ 开头
            String userAgent = getHeaderIgnoreCase(headers, HEADER_USER_AGENT);
            if (userAgent != null && userAgent.startsWith("claude-cli/")) {
                Log.d(TAG, "Detected Claude Code CLI client via User-Agent: " + userAgent);
                return true;
            }

            // 检查 2: 存在 X-Claude-Package-Version
            String packageVersion = getHeaderIgnoreCase(headers, HEADER_PACKAGE_VERSION);
            if (packageVersion != null && !packageVersion.isEmpty()) {
                Log.d(TAG, "Detected Claude Code CLI client via package version: " + packageVersion);
                return true;
            }

            // 检查 3: X-Claude-Client-Type 为 cli
            String clientType = getHeaderIgnoreCase(headers, HEADER_CLIENT_TYPE);
            if ("cli".equalsIgnoreCase(clientType)) {
                Log.d(TAG, "Detected Claude Code CLI client via client type: cli");
                return true;
            }

            // 检查 4: 存在 X-Claude-Runtime-Version
            String runtimeVersion = getHeaderIgnoreCase(headers, HEADER_RUNTIME_VERSION);
            if (runtimeVersion != null && runtimeVersion.startsWith("v")) {
                Log.d(TAG, "Detected Claude Code CLI client via runtime version: " + runtimeVersion);
                return true;
            }

            Log.d(TAG, "Request does not appear to be from Claude Code CLI");
            return false;

        } catch (Exception e) {
            Log.e(TAG, "Error checking for Claude Code client", e);
            return false;
        }
    }

    /**
     * 判断给定的 okhttp3.Request 是否来自 Claude Code CLI 客户端。
     *
     * @param request OkHttp 请求对象
     * @return 如果请求来自 Claude Code CLI 返回 true
     * @throws IllegalArgumentException 如果 request 为 null
     */
    public boolean isClaudeCodeClient(Request request) {
        if (request == null) {
            throw new IllegalArgumentException("request must not be null");
        }

        Map<String, String> headers = new HashMap<>();
        for (int i = 0; i < request.headers().size(); i++) {
            String name = request.headers().name(i);
            String value = request.headers().value(i);
            headers.put(name, value);
        }

        return isClaudeCodeClient(headers);
    }

    /**
     * 判断给定的 okhttp3.Headers 是否来自 Claude Code CLI 客户端。
     *
     * @param headers OkHttp Headers 对象
     * @return 如果请求来自 Claude Code CLI 返回 true
     */
    public boolean isClaudeCodeClient(Headers headers) {
        if (headers == null) {
            return false;
        }

        Map<String, String> headersMap = new HashMap<>();
        for (int i = 0; i < headers.size(); i++) {
            headersMap.put(headers.name(i), headers.value(i));
        }

        return isClaudeCodeClient(headersMap);
    }

    // ============================================================
    // 设备指纹稳定化（stabilize-device-profile）
    // ============================================================

    /**
     * 获取或创建一个稳定的设备指纹。
     * <p>
     * 设备指纹是一个 JSON 字符串，包含当前指纹种子、时间窗口信息和随机化因子，
     * 用于在稳定化窗口内生成一致的指纹值。这可以防止因指纹漂移导致的检测。
     * <p>
     * 如果指纹已缓存且未过期，直接返回缓存的指纹；否则重新生成。
     *
     * @return 设备指纹 JSON 字符串，如果生成失败则返回 null
     */
    public String getOrCreateStableFingerprint() {
        if (!stabilizeEnabled) {
            return null;
        }

        long now = System.currentTimeMillis();
        long lastGen = fingerprintGeneratedAt.get();

        // 检查缓存是否有效
        if (lastGen > 0 && (now - lastGen) < stabilizeWindowMs) {
            String cached = fingerprintCache.get(fingerprintSeed);
            if (cached != null) {
                return cached;
            }
        }

        // 需要重新生成
        try {
            JSONObject fingerprint = new JSONObject();
            fingerprint.put("seed", fingerprintSeed);
            fingerprint.put("generated_at", now);
            fingerprint.put("window_ms", stabilizeWindowMs);
            fingerprint.put("window_expires_at", now + stabilizeWindowMs);
            fingerprint.put("os", DEFAULT_OS);
            fingerprint.put("arch", DEFAULT_ARCH);
            fingerprint.put("runtime", DEFAULT_RUNTIME_VERSION);

            // 添加随机化因子以确保唯一性，但在窗口内保持稳定
            String fingerprintStr = fingerprint.toString();

            fingerprintCache.put(fingerprintSeed, fingerprintStr);
            fingerprintGeneratedAt.set(now);

            Log.d(TAG, "Generated new device fingerprint, valid until: " + (now + stabilizeWindowMs));
            return fingerprintStr;

        } catch (JSONException e) {
            Log.e(TAG, "Failed to generate device fingerprint JSON", e);
            return null;
        }
    }

    /**
     * 重置设备指纹缓存，强制下次调用时重新生成。
     * <p>
     * 在检测到指纹可能被污染或需要强制刷新时调用。
     */
    public void resetFingerprint() {
        fingerprintCache.clear();
        fingerprintGeneratedAt.set(0);
        // 生成新的种子
        this.fingerprintSeed = generateDefaultSeed();
        Log.d(TAG, "Device fingerprint reset, new seed: " + fingerprintSeed);
    }

    /**
     * 使用指定的种子初始化设备指纹，实现指纹的确定性固定。
     * <p>
     * 可用于从持久化配置中恢复指纹，确保应用重启后指纹一致。
     *
     * @param seed 指纹种子字符串
     * @throws IllegalArgumentException 如果 seed 为 null 或空
     */
    public void stabilizeDeviceProfile(String seed) {
        if (seed == null || seed.trim().isEmpty()) {
            throw new IllegalArgumentException("fingerprint seed must not be null or empty");
        }

        String normalizedSeed = seed.trim();
        this.fingerprintSeed = normalizedSeed;
        // 清除旧缓存，下次获取时使用新种子生成
        fingerprintCache.clear();
        fingerprintGeneratedAt.set(0);

        Log.d(TAG, "Device profile stabilized with seed: " + normalizedSeed);
    }

    /**
     * 从 JSON 配置中恢复设备指纹配置。
     * <p>
     * 支持从持久化的配置 JSON 中恢复种子和稳定化窗口设置。
     *
     * @param configJson 包含指纹配置的 JSON 字符串
     * @throws IllegalArgumentException 如果 configJson 为 null
     */
    public void stabilizeDeviceProfileFromJson(String configJson) {
        if (configJson == null) {
            throw new IllegalArgumentException("configJson must not be null");
        }

        try {
            JSONObject config = new JSONObject(configJson);
            if (config.has("seed")) {
                String seed = config.optString("seed", null);
                if (seed != null && !seed.isEmpty()) {
                    stabilizeDeviceProfile(seed);
                }
            }
            if (config.has("window_ms")) {
                long window = config.optLong("window_ms", DEFAULT_STABILIZE_WINDOW_MS);
                if (window > 0) {
                    this.stabilizeWindowMs = window;
                }
            }
            Log.d(TAG, "Device profile stabilized from JSON config");
        } catch (JSONException e) {
            Log.e(TAG, "Failed to parse device profile JSON config", e);
        }
    }

    /**
     * 将当前设备指纹配置导出为 JSON 字符串，用于持久化。
     *
     * @return 设备指纹配置的 JSON 字符串
     */
    public String exportDeviceProfileJson() {
        try {
            JSONObject config = new JSONObject();
            config.put("seed", fingerprintSeed);
            config.put("window_ms", stabilizeWindowMs);
            config.put("stabilize_enabled", stabilizeEnabled);
            config.put("os", DEFAULT_OS);
            config.put("arch", DEFAULT_ARCH);
            config.put("runtime", DEFAULT_RUNTIME_VERSION);
            return config.toString();
        } catch (JSONException e) {
            Log.e(TAG, "Failed to export device profile JSON", e);
            return "{}";
        }
    }

    // ============================================================
    // 配置方法
    // ============================================================

    /**
     * 启用或禁用设备指纹稳定化。
     *
     * @param enabled 是否启用
     */
    public void setStabilizeEnabled(boolean enabled) {
        this.stabilizeEnabled = enabled;
        Log.d(TAG, "Device fingerprint stabilization " + (enabled ? "enabled" : "disabled"));
    }

    /**
     * 检查设备指纹稳定化是否已启用。
     *
     * @return 如果稳定化已启用返回 true
     */
    public boolean isStabilizeEnabled() {
        return stabilizeEnabled;
    }

    /**
     * 设置指纹稳定化窗口时长。
     * <p>
     * 在窗口期内，所有请求使用相同的设备指纹。窗口过期后自动重新生成。
     *
     * @param windowMs 窗口时长（毫秒），必须大于 0
     * @throws IllegalArgumentException 如果 windowMs <= 0
     */
    public void setStabilizeWindowMs(long windowMs) {
        if (windowMs <= 0) {
            throw new IllegalArgumentException("stabilize window must be positive");
        }
        this.stabilizeWindowMs = windowMs;
        // 窗口改变时重置指纹
        fingerprintCache.clear();
        fingerprintGeneratedAt.set(0);
        Log.d(TAG, "Fingerprint stabilize window set to " + windowMs + "ms");
    }

    /**
     * 获取当前指纹稳定化窗口时长。
     *
     * @return 窗口时长（毫秒）
     */
    public long getStabilizeWindowMs() {
        return stabilizeWindowMs;
    }

    /**
     * 获取当前指纹种子。
     *
     * @return 指纹种子字符串
     */
    public String getFingerprintSeed() {
        return fingerprintSeed;
    }

    // ============================================================
    // 辅助方法
    // ============================================================

    /**
     * 规范化客户端类型字符串。
     * <p>
     * 将 null、空字符串和未知类型统一为默认的 "cli"。
     *
     * @param clientType 原始客户端类型
     * @return 规范化后的客户端类型
     */
    private String normalizeClientType(String clientType) {
        if (clientType == null || clientType.trim().isEmpty()) {
            return DEFAULT_CLIENT_TYPE;
        }
        String normalized = clientType.trim().toLowerCase();
        for (String supported : SUPPORTED_CLIENT_TYPES) {
            if (supported.equals(normalized)) {
                return normalized;
            }
        }
        // 未知类型：使用默认
        Log.w(TAG, "Unknown client type: " + clientType + ", falling back to: " + DEFAULT_CLIENT_TYPE);
        return DEFAULT_CLIENT_TYPE;
    }

    /**
     * 生成默认的指纹种子。
     * <p>
     * 基于系统时间戳和哈希值生成一个唯一但稳定的种子标识。
     *
     * @return 种子字符串
     */
    private String generateDefaultSeed() {
        long timestamp = System.currentTimeMillis();
        int hash = Integer.toHexString(timestamp).hashCode();
        return "claude-device-" + Integer.toHexString(Math.abs(hash)) + "-"
                + Long.toHexString(timestamp);
    }

    /**
     * 从请求头映射中忽略大小写地获取头值。
     * <p>
     * HTTP 头名称不区分大小写，此方法同时检查精确匹配和大小写折叠匹配。
     *
     * @param headers 请求头映射
     * @param name    头名称
     * @return 头值，如果未找到则返回 null
     */
    private String getHeaderIgnoreCase(Map<String, String> headers, String name) {
        if (headers.containsKey(name)) {
            return headers.get(name);
        }
        // 大小写折叠查找
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && entry.getKey().equalsIgnoreCase(name)) {
                return entry.getValue();
            }
        }
        return null;
    }

    /**
     * 仅当键不存在时设置值（不覆盖已有值）。
     *
     * @param map   目标映射
     * @param key   键
     * @param value 值
     */
    private void putIfAbsent(Map<String, String> map, String key, String value) {
        if (!map.containsKey(key)) {
            map.put(key, value);
        }
    }

    // ============================================================
    // 工具方法
    // ============================================================

    /**
     * 从请求头映射中提取所有 Claude Code CLI 相关的头。
     *
     * @param headers 原始请求头映射
     * @return 仅包含 Claude Code CLI 相关头的映射
     */
    public Map<String, String> extractClaudeHeaders(Map<String, String> headers) {
        if (headers == null) {
            return Collections.emptyMap();
        }

        Map<String, String> result = new HashMap<>();
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            if (entry.getKey() != null && CLAUDE_CLI_HEADERS.contains(entry.getKey())) {
                result.put(entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    /**
     * 验证给定的请求头映射是否包含所有必需的 Claude Code CLI 头。
     *
     * @param headers 请求头映射
     * @return 如果包含所有必需头返回 true
     */
    public boolean hasRequiredHeaders(Map<String, String> headers) {
        if (headers == null) {
            return false;
        }
        // 必需的字段：User-Agent 和 X-Claude-Package-Version
        String ua = getHeaderIgnoreCase(headers, HEADER_USER_AGENT);
        String pv = getHeaderIgnoreCase(headers, HEADER_PACKAGE_VERSION);
        return ua != null && !ua.isEmpty() && pv != null && !pv.isEmpty();
    }

    @Override
    public String toString() {
        return "HeaderInjector{" +
                "stabilizeEnabled=" + stabilizeEnabled +
                ", fingerprintSeed='" + fingerprintSeed + '\'' +
                ", stabilizeWindowMs=" + stabilizeWindowMs +
                ", fingerprintCached=" + (fingerprintCache.get(fingerprintSeed) != null) +
                '}';
    }
}