package com.cliproxy.plus.config;

import android.util.Log;
import android.graphics.Color;
import android.widget.Toast;

import org.json.JSONObject;
import org.json.JSONArray;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * RetryConfig - 请求重试配置
 * 指数退避重试策略，对应原版 internal/config/config.go 中的重试设置
 * <p>
 * 字段默认值从 ConfigManager 加载:
 * - request-retry → maxRetries (default 3)
 * - max-retry-interval → maxRetryInterval (default 30)
 */
public class RetryConfig {

    private static final String TAG = "RetryConfig";

    /** 默认最大重试次数 */
    private static final int DEFAULT_MAX_RETRIES = 3;

    /** 默认最大重试间隔（秒） */
    private static final int DEFAULT_MAX_RETRY_INTERVAL = 30;

    /** 默认瞬态错误冷却时间（秒） */
    private static final long DEFAULT_TRANSIENT_ERROR_COOLDOWN = 5L;

    /** 需要重试的 HTTP 状态码集合 */
    private static final Set<Integer> RETRYABLE_STATUS_CODES = new HashSet<>(Arrays.asList(
            403, 408, 500, 502, 503, 504
    ));

    /** 基础退避延迟（毫秒） */
    private static final long BASE_BACKOFF_MS = 1000L;

    /** 最大重试次数 */
    private int maxRetries;

    /** 最大重试间隔（秒） */
    private int maxRetryInterval;

    /** 是否禁用冷却 */
    private boolean disableCooling;

    /** 瞬态错误冷却时间（秒） */
    private long transientErrorCooldownSeconds;

    /**
     * 使用默认值构造 RetryConfig
     */
    public RetryConfig() {
        this.maxRetries = DEFAULT_MAX_RETRIES;
        this.maxRetryInterval = DEFAULT_MAX_RETRY_INTERVAL;
        this.disableCooling = false;
        this.transientErrorCooldownSeconds = DEFAULT_TRANSIENT_ERROR_COOLDOWN;
        Log.d(TAG, "RetryConfig initialized with defaults: maxRetries=" + maxRetries
                + ", maxRetryInterval=" + maxRetryInterval
                + ", disableCooling=" + disableCooling
                + ", cooldown=" + transientErrorCooldownSeconds + "s");
    }

    /**
     * 从 ConfigManager 加载配置构造 RetryConfig
     *
     * @param configManager 配置管理器实例
     */
    public RetryConfig(ConfigManager configManager) {
        this();
        if (configManager != null) {
            this.maxRetries = configManager.getInt("request-retry", DEFAULT_MAX_RETRIES);
            this.maxRetryInterval = configManager.getInt("max-retry-interval", DEFAULT_MAX_RETRY_INTERVAL);
            Log.i(TAG, "RetryConfig loaded from ConfigManager: maxRetries=" + maxRetries
                    + ", maxRetryInterval=" + maxRetryInterval);
        }
    }

    /**
     * 从 JSONObject 加载配置构造 RetryConfig
     *
     * @param json JSON 配置对象
     */
    public RetryConfig(JSONObject json) {
        this();
        if (json != null) {
            this.maxRetries = json.optInt("request-retry", DEFAULT_MAX_RETRIES);
            this.maxRetryInterval = json.optInt("max-retry-interval", DEFAULT_MAX_RETRY_INTERVAL);
            this.disableCooling = json.optBoolean("disable-cooling", false);
            this.transientErrorCooldownSeconds = json.optLong("transient-error-cooldown-seconds",
                    DEFAULT_TRANSIENT_ERROR_COOLDOWN);
            Log.i(TAG, "RetryConfig loaded from JSON: maxRetries=" + maxRetries
                    + ", maxRetryInterval=" + maxRetryInterval
                    + ", disableCooling=" + disableCooling
                    + ", cooldown=" + transientErrorCooldownSeconds + "s");
        }
    }

    /**
     * 计算指定重试次数的退避延迟
     * 使用指数退避策略：base * 2^attempt，上限为 maxRetryInterval
     *
     * @param attempt 当前重试次数（从 0 开始）
     * @return 退避延迟（毫秒）
     */
    public long getBackoffDelay(int attempt) {
        if (attempt < 0) {
            Log.w(TAG, "Invalid attempt value: " + attempt + ", using 0");
            attempt = 0;
        }
        if (attempt >= maxRetries) {
            Log.w(TAG, "Attempt " + attempt + " exceeds maxRetries " + maxRetries
                    + ", returning max interval");
            return maxRetryInterval * 1000L;
        }

        // 指数退避: base * 2^attempt
        long delay = BASE_BACKOFF_MS * (1L << attempt);

        // 加入随机抖动 (±25%)
        double jitter = 0.75 + Math.random() * 0.5;
        delay = (long) (delay * jitter);

        // 上限 maxRetryInterval
        long maxDelayMs = maxRetryInterval * 1000L;
        if (delay > maxDelayMs) {
            delay = maxDelayMs;
        }

        Log.d(TAG, "Backoff delay for attempt " + attempt + ": " + delay + "ms");
        return delay;
    }

    /**
     * 判断给定的 HTTP 状态码是否应该触发重试
     *
     * @param statusCode HTTP 响应状态码
     * @return 如果应该重试返回 true
     */
    public boolean shouldRetry(int statusCode) {
        boolean retryable = RETRYABLE_STATUS_CODES.contains(statusCode);
        Log.d(TAG, "Status code " + statusCode + " is "
                + (retryable ? "retryable" : "non-retryable"));
        return retryable;
    }

    /**
     * 判断是否需要进入冷却状态
     * 瞬态错误（如 503/504）后应进入冷却
     *
     * @param statusCode HTTP 响应状态码
     * @return 如果需要冷却返回 true
     */
    public boolean needsCooldown(int statusCode) {
        if (disableCooling) {
            return false;
        }
        // 503 Service Unavailable 和 504 Gateway Timeout 通常需要冷却
        return statusCode == 503 || statusCode == 504;
    }

    // ===== Getters & Setters =====

    public int getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(int maxRetries) {
        if (maxRetries < 0) {
            Log.w(TAG, "Invalid maxRetries: " + maxRetries + ", clamping to 0");
            this.maxRetries = 0;
        } else {
            this.maxRetries = maxRetries;
        }
    }

    public int getMaxRetryInterval() {
        return maxRetryInterval;
    }

    public void setMaxRetryInterval(int maxRetryInterval) {
        if (maxRetryInterval < 1) {
            Log.w(TAG, "Invalid maxRetryInterval: " + maxRetryInterval + ", clamping to 1");
            this.maxRetryInterval = 1;
        } else {
            this.maxRetryInterval = maxRetryInterval;
        }
    }

    public boolean isDisableCooling() {
        return disableCooling;
    }

    public void setDisableCooling(boolean disableCooling) {
        this.disableCooling = disableCooling;
    }

    public long getTransientErrorCooldownSeconds() {
        return transientErrorCooldownSeconds;
    }

    public void setTransientErrorCooldownSeconds(long transientErrorCooldownSeconds) {
        if (transientErrorCooldownSeconds < 0) {
            Log.w(TAG, "Invalid cooldown: " + transientErrorCooldownSeconds + ", clamping to 0");
            this.transientErrorCooldownSeconds = 0;
        } else {
            this.transientErrorCooldownSeconds = transientErrorCooldownSeconds;
        }
    }

    /**
     * 导出为 JSONObject
     *
     * @return JSON 配置对象
     */
    public JSONObject toJson() {
        JSONObject json = new JSONObject();
        try {
            json.put("request-retry", maxRetries);
            json.put("max-retry-interval", maxRetryInterval);
            json.put("disable-cooling", disableCooling);
            json.put("transient-error-cooldown-seconds", transientErrorCooldownSeconds);
        } catch (Exception e) {
            Log.e(TAG, "Failed to serialize RetryConfig to JSON", e);
        }
        return json;
    }

    /**
     * 获取可重试状态码数组
     *
     * @return 可重试状态码数组
     */
    public static int[] getRetryableStatusCodes() {
        return RETRYABLE_STATUS_CODES.stream()
                .mapToInt(Integer::intValue)
                .toArray();
    }

    @Override
    public String toString() {
        return "RetryConfig{" +
                "maxRetries=" + maxRetries +
                ", maxRetryInterval=" + maxRetryInterval +
                ", disableCooling=" + disableCooling +
                ", transientErrorCooldownSeconds=" + transientErrorCooldownSeconds +
                '}';
    }
}