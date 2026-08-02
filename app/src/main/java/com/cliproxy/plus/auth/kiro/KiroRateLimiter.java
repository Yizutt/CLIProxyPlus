package com.cliproxy.plus.auth.kiro;

import android.util.Log;

import org.json.JSONObject;

import java.security.SecureRandom;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * KiroRateLimiter - AWS Kiro (CodeWhisperer) 速率限制器
 * <p>
 * 基于令牌桶算法实现，支持抖动（jitter）和退避策略（backoff）。
 * 用于控制对 AWS CodeWhisperer API 的请求频率，避免触发服务端限流。
 * 每个 tokenId 对应一个独立的令牌桶，支持细粒度控制。
 * <p>
 * 核心算法：
 * <ol>
 *   <li>每个令牌桶按可配置的间隔（含抖动）持续补充令牌</li>
 *   <li>acquire() 消耗一个令牌，无可用令牌时返回限流状态</li>
 *   <li>release() 将令牌返还桶中（不超过容量上限）</li>
 *   <li>每日配额独立跟踪，达到上限后全局限流</li>
 *   <li>退避策略计算限流后的建议等待时间</li>
 * </ol>
 * <p>
 * 配置项：
 * <ul>
 *   <li>min-token-interval：最小令牌发放间隔（默认 1000ms）</li>
 *   <li>max-token-interval：最大令牌发放间隔（默认 2000ms）</li>
 *   <li>daily-max-requests：每日最大请求数（默认 500）</li>
 *   <li>jitter-percent：抖动百分比（默认 0.3，即 ±30%）</li>
 *   <li>backoff-strategy：退避策略（EXPONENTIAL / LINEAR / FIXED）</li>
 * </ul>
 * <p>
 * 对应原版 CLIProxyAPIPlus/internal/auth/kiro/ 中的 Go 实现。
 */
public class KiroRateLimiter {

    private static final String TAG = "KiroRateLimiter";

    // ================================================================
    //  默认配置常量
    // ================================================================

    /** 默认最小令牌发放间隔（毫秒） */
    private static final long DEFAULT_MIN_TOKEN_INTERVAL_MS = 1000L;

    /** 默认最大令牌发放间隔（毫秒） */
    private static final long DEFAULT_MAX_TOKEN_INTERVAL_MS = 2000L;

    /** 默认每日最大请求数 */
    private static final int DEFAULT_DAILY_MAX_REQUESTS = 500;

    /** 默认抖动百分比（0.0 ~ 1.0） */
    private static final double DEFAULT_JITTER_PERCENT = 0.3;

    /** 默认退避策略 */
    private static final BackoffStrategy DEFAULT_BACKOFF_STRATEGY = BackoffStrategy.EXPONENTIAL;

    /** 默认退避基础等待时间（毫秒） */
    private static final long DEFAULT_BACKOFF_BASE_MS = 1000L;

    /** 最大退避等待时间（毫秒）—— 30 秒 */
    private static final long MAX_BACKOFF_WAIT_MS = 30000L;

    /** 每日配额重置周期（毫秒）—— 24 小时 */
    private static final long DAILY_RESET_PERIOD_MS = TimeUnit.DAYS.toMillis(1);

    /** 每个桶的最大令牌容量 */
    private static final double DEFAULT_BUCKET_CAPACITY = 5.0;

    /** 每日配额检查的 HTTP 端点（仅用于远程配额同步） */
    private static final String QUOTA_ENDPOINT = "https://view.awsapps.com/auth/kiro/quota";

    // ================================================================
    //  退避策略枚举
    // ================================================================

    /**
     * 退避策略枚举。
     * <p>
     * 定义在请求被限流后，建议等待时间的计算方式：
     * <ul>
     *   <li>{@link #EXPONENTIAL}：指数退避，wait = base × 2^failures</li>
     *   <li>{@link #LINEAR}：线性退避，wait = base × (failures + 1)</li>
     *   <li>{@link #FIXED}：固定退避，wait = base</li>
     * </ul>
     */
    public enum BackoffStrategy {
        EXPONENTIAL,
        LINEAR,
        FIXED
    }

    // ================================================================
    //  获取结果枚举
    // ================================================================

    /**
     * 获取令牌的结果状态。
     */
    public enum AcquireResult {
        /** 成功获取令牌 */
        ACQUIRED,
        /** 被限流，应等待后重试 */
        THROTTLED,
        /** 超过每日配额上限 */
        QUOTA_EXCEEDED
    }

    // ================================================================
    //  配置
    // ================================================================

    private final long minTokenIntervalMs;
    private final long maxTokenIntervalMs;
    private final int dailyMaxRequests;
    private final double jitterPercent;
    private final BackoffStrategy backoffStrategy;
    private final long backoffBaseMs;
    private final double bucketCapacity;

    private final SecureRandom random;
    private final OkHttpClient httpClient;

    // ================================================================
    //  状态
    // ================================================================

    /** 每个 tokenId 对应的令牌桶 */
    private final ConcurrentMap<String, TokenBucket> buckets = new ConcurrentHashMap<>();

    /** 每日请求计数 */
    private final AtomicInteger dailyRequestCount = new AtomicInteger(0);

    /** 每日配额重置时间戳（epoch millis） */
    private volatile long dailyResetTime;

    /** 每日重置锁 */
    private final ReentrantLock dailyResetLock = new ReentrantLock();

    // ================================================================
    //  内部类：TokenBucket
    // ================================================================

    /**
     * 令牌桶，管理单个 tokenId 的令牌状态。
     * <p>
     * 每个桶独立维护令牌数量、上次补充时间和连续失败次数。
     * 桶的访问是线程安全的，使用 ReentrantLock 保护关键路径。
     */
    private static class TokenBucket {
        final String tokenId;
        final double maxTokens;
        final ReentrantLock lock = new ReentrantLock();

        /** 当前可用令牌数 */
        volatile double tokens;

        /** 上次补充时间戳（epoch millis） */
        final AtomicLong lastRefillTimeMs;

        /** 上次访问时间戳（epoch millis） */
        final AtomicLong lastAccessTimeMs;

        /** 连续失败次数（用于退避计算） */
        volatile int consecutiveFailures;

        /** 当前补充间隔（毫秒），每次补充后重新计算 */
        volatile long currentIntervalMs;

        /**
         * 创建一个新的令牌桶。
         *
         * @param tokenId    令牌标识符
         * @param maxTokens  桶的最大容量
         * @param initialIntervalMs 初始补充间隔（毫秒）
         */
        TokenBucket(String tokenId, double maxTokens, long initialIntervalMs) {
            this.tokenId = tokenId;
            this.maxTokens = maxTokens;
            this.tokens = maxTokens; // 初始满桶
            this.lastRefillTimeMs = new AtomicLong(System.currentTimeMillis());
            this.lastAccessTimeMs = new AtomicLong(System.currentTimeMillis());
            this.currentIntervalMs = initialIntervalMs;
            this.consecutiveFailures = 0;
        }

        /**
         * 获取当前时间戳，用于单元测试时可覆盖。
         */
        long now() {
            return System.currentTimeMillis();
        }
    }

    // ================================================================
    //  内部类：QuotaInfo
    // ================================================================

    /**
     * 配额信息，包含指定 tokenId 的当前速率限制状态。
     */
    public static class QuotaInfo {
        /** 剩余可用请求数 */
        public final int remainingRequests;

        /** 每日请求上限 */
        public final int dailyLimit;

        /** 配额重置时间戳（epoch millis） */
        public final long resetTimeMs;

        /** 当前桶中可用令牌数 */
        public final double availableTokens;

        /** 建议等待时间（毫秒），0 表示无需等待 */
        public final long recommendedWaitMs;

        /** 连续失败次数 */
        public final int consecutiveFailures;

        /** 当前退避等待时间（毫秒） */
        public final long backoffWaitMs;

        public QuotaInfo(int remainingRequests, int dailyLimit, long resetTimeMs,
                         double availableTokens, long recommendedWaitMs,
                         int consecutiveFailures, long backoffWaitMs) {
            this.remainingRequests = remainingRequests;
            this.dailyLimit = dailyLimit;
            this.resetTimeMs = resetTimeMs;
            this.availableTokens = availableTokens;
            this.recommendedWaitMs = recommendedWaitMs;
            this.consecutiveFailures = consecutiveFailures;
            this.backoffWaitMs = backoffWaitMs;
        }
    }

    // ================================================================
    //  构造
    // ================================================================

    /**
     * 使用默认配置创建 KiroRateLimiter 实例。
     */
    public KiroRateLimiter() {
        this(new Builder());
    }

    /**
     * 使用 Builder 配置创建 KiroRateLimiter 实例。
     *
     * @param builder 配置构建器
     */
    private KiroRateLimiter(Builder builder) {
        this.minTokenIntervalMs = builder.minTokenIntervalMs;
        this.maxTokenIntervalMs = builder.maxTokenIntervalMs;
        this.dailyMaxRequests = builder.dailyMaxRequests;
        this.jitterPercent = builder.jitterPercent;
        this.backoffStrategy = builder.backoffStrategy;
        this.backoffBaseMs = builder.backoffBaseMs;
        this.bucketCapacity = builder.bucketCapacity;
        this.random = new SecureRandom();
        this.dailyResetTime = calculateDailyResetTime();

        this.httpClient = new OkHttpClient.Builder()
                .connectTimeout(10, TimeUnit.SECONDS)
                .readTimeout(10, TimeUnit.SECONDS)
                .writeTimeout(10, TimeUnit.SECONDS)
                .build();

        log("KiroRateLimiter initialized: minInterval=" + minTokenIntervalMs
                + "ms, maxInterval=" + maxTokenIntervalMs
                + "ms, dailyMax=" + dailyMaxRequests
                + ", jitter=" + jitterPercent
                + ", backoff=" + backoffStrategy);
    }

    // ================================================================
    //  公共方法
    // ================================================================

    /**
     * 尝试获取一个令牌。
     * <p>
     * 如果令牌桶中有可用令牌且未超过每日配额，则消耗一个令牌并返回
     * {@link AcquireResult#ACQUIRED}。如果被限流或超过配额，返回对应的
     * 状态码，调用方应根据 {@link #getRemainingQuota(String)} 返回的
     * 建议等待时间决定何时重试。
     * <p>
     * 此方法不会阻塞，无论结果如何都会立即返回。
     *
     * @param tokenId 令牌标识符，标识要获取令牌的桶
     * @return 获取结果状态
     * @throws IllegalArgumentException 如果 tokenId 为 null 或空
     */
    public AcquireResult acquire(String tokenId) {
        if (tokenId == null || tokenId.trim().isEmpty()) {
            throw new IllegalArgumentException("tokenId must not be null or empty");
        }

        // 检查每日配额
        if (isDailyQuotaExceeded()) {
            log("Daily quota exceeded for tokenId=" + tokenId
                    + ", count=" + dailyRequestCount.get()
                    + ", limit=" + dailyMaxRequests);
            return AcquireResult.QUOTA_EXCEEDED;
        }

        // 获取或创建令牌桶
        TokenBucket bucket = getOrCreateBucket(tokenId);

        bucket.lock.lock();
        try {
            // 补充令牌
            refillBucket(bucket);

            // 尝试消耗令牌
            if (bucket.tokens >= 1.0) {
                bucket.tokens -= 1.0;
                bucket.lastAccessTimeMs.set(System.currentTimeMillis());
                bucket.consecutiveFailures = 0;

                // 增加每日计数
                int currentCount = dailyRequestCount.incrementAndGet();
                if (currentCount >= dailyMaxRequests) {
                    log("Daily quota reached after acquire: " + currentCount);
                }

                log("Token ACQUIRED for tokenId=" + tokenId
                        + ", remaining=" + bucket.tokens);
                return AcquireResult.ACQUIRED;
            } else {
                // 限流
                bucket.consecutiveFailures++;
                bucket.lastAccessTimeMs.set(System.currentTimeMillis());

                log("Token THROTTLED for tokenId=" + tokenId
                        + ", tokens=" + bucket.tokens
                        + ", failures=" + bucket.consecutiveFailures);
                return AcquireResult.THROTTLED;
            }
        } finally {
            bucket.lock.unlock();
        }
    }

    /**
     * 释放一个令牌回桶中。
     * <p>
     * 当请求成功完成后调用，将令牌放回桶中。如果桶中令牌数已达到
     * 容量上限，则丢弃多余的令牌。此操作还会重置该 tokenId 的
     * 连续失败计数。
     *
     * @param tokenId 令牌标识符
     * @throws IllegalArgumentException 如果 tokenId 为 null 或空
     */
    public void release(String tokenId) {
        if (tokenId == null || tokenId.trim().isEmpty()) {
            throw new IllegalArgumentException("tokenId must not be null or empty");
        }

        TokenBucket bucket = buckets.get(tokenId);
        if (bucket == null) {
            // 没有对应的桶，忽略
            return;
        }

        bucket.lock.lock();
        try {
            // 补充令牌（时间流逝可能已经产生新令牌）
            refillBucket(bucket);

            // 返还令牌（不超过容量上限）
            bucket.tokens = Math.min(bucket.tokens + 1.0, bucket.maxTokens);
            bucket.consecutiveFailures = 0;
            bucket.lastAccessTimeMs.set(System.currentTimeMillis());

            log("Token RELEASED for tokenId=" + tokenId
                    + ", tokens=" + bucket.tokens);
        } finally {
            bucket.lock.unlock();
        }
    }

    /**
     * 检查指定的 tokenId 当前是否被限流。
     * <p>
     * 如果该 tokenId 的令牌桶中可用令牌不足 1 个，或者每日配额已用完，
     * 则返回 true。
     *
     * @param tokenId 令牌标识符
     * @return true 如果当前被限流（无法获取令牌）
     */
    public boolean isThrottled(String tokenId) {
        if (tokenId == null || tokenId.trim().isEmpty()) {
            return true;
        }

        // 检查每日配额
        if (isDailyQuotaExceeded()) {
            return true;
        }

        TokenBucket bucket = buckets.get(tokenId);
        if (bucket == null) {
            // 没有桶说明从未使用过，不受限
            return false;
        }

        bucket.lock.lock();
        try {
            refillBucket(bucket);
            return bucket.tokens < 1.0;
        } finally {
            bucket.lock.unlock();
        }
    }

    /**
     * 获取指定 tokenId 的剩余配额信息。
     * <p>
     * 返回包含每日剩余请求数、配额重置时间、当前可用令牌数、
     * 建议等待时间等详细信息的 {@link QuotaInfo} 对象。
     *
     * @param tokenId 令牌标识符
     * @return 配额信息对象，永远不会返回 null
     */
    public QuotaInfo getRemainingQuota(String tokenId) {
        if (tokenId == null || tokenId.trim().isEmpty()) {
            return new QuotaInfo(0, dailyMaxRequests, dailyResetTime,
                    0.0, 0L, 0, 0L);
        }

        TokenBucket bucket = buckets.get(tokenId);
        if (bucket == null) {
            return new QuotaInfo(
                    Math.max(0, dailyMaxRequests - dailyRequestCount.get()),
                    dailyMaxRequests,
                    dailyResetTime,
                    bucketCapacity,
                    0L,
                    0,
                    0L);
        }

        bucket.lock.lock();
        try {
            refillBucket(bucket);

            int remainingDaily = Math.max(0, dailyMaxRequests - dailyRequestCount.get());
            long backoffWait = calculateBackoffWait(bucket.consecutiveFailures);
            long recommendedWait = computeRecommendedWait(bucket, backoffWait);

            return new QuotaInfo(
                    remainingDaily,
                    dailyMaxRequests,
                    dailyResetTime,
                    bucket.tokens,
                    recommendedWait,
                    bucket.consecutiveFailures,
                    backoffWait);
        } finally {
            bucket.lock.unlock();
        }
    }

    /**
     * 从 OkHttp Response 中解析速率限制头部并更新对应桶的状态。
     * <p>
     * AWS Kiro API 在响应头中返回速率限制信息：
     * <ul>
     *   <li>X-RateLimit-Limit：请求上限</li>
     *   <li>X-RateLimit-Remaining：剩余请求数</li>
     *   <li>X-RateLimit-Reset：配额重置时间（Unix 时间戳）</li>
     * </ul>
     * <p>
     * 此方法解析这些头部并更新本地状态，使速率限制器与服务端保持同步。
     *
     * @param tokenId 令牌标识符
     * @param response OkHttp Response 对象
     */
    public void updateFromResponse(String tokenId, Response response) {
        if (tokenId == null || response == null) {
            return;
        }

        try {
            // 解析速率限制头部
            String limitHeader = response.header("X-RateLimit-Limit");
            String remainingHeader = response.header("X-RateLimit-Remaining");
            String resetHeader = response.header("X-RateLimit-Reset");
            String retryAfterHeader = response.header("Retry-After");

            if (limitHeader != null || remainingHeader != null || retryAfterHeader != null) {
                log("Rate limit headers for tokenId=" + tokenId
                        + ": limit=" + limitHeader
                        + ", remaining=" + remainingHeader
                        + ", reset=" + resetHeader
                        + ", retry-after=" + retryAfterHeader);
            }

            // 处理 Retry-After（服务端明确要求等待）
            if (retryAfterHeader != null) {
                try {
                    long retryAfterSecs = Long.parseLong(retryAfterHeader);
                    TokenBucket bucket = getOrCreateBucket(tokenId);
                    bucket.lock.lock();
                    try {
                        // 将 tokens 置为 0，强制限流
                        bucket.tokens = 0.0;
                        // 增加连续失败次数以触发退避
                        bucket.consecutiveFailures = Math.max(bucket.consecutiveFailures,
                                (int) (retryAfterSecs / (minTokenIntervalMs / 1000L)));
                        log("Retry-After received for tokenId=" + tokenId
                                + ": " + retryAfterSecs + "s");
                    } finally {
                        bucket.lock.unlock();
                    }
                } catch (NumberFormatException e) {
                    logError("Failed to parse Retry-After header", e);
                }
            }

            // 处理 X-RateLimit-Remaining（服务端剩余配额）
            if (remainingHeader != null) {
                try {
                    int remaining = Integer.parseInt(remainingHeader);
                    // 如果服务端显示剩余很少，调整本地桶状态
                    if (remaining < 5) {
                        TokenBucket bucket = getOrCreateBucket(tokenId);
                        bucket.lock.lock();
                        try {
                            refillBucket(bucket);
                            // 将本地令牌数调整为与服务端一致
                            bucket.tokens = Math.min(bucket.tokens, remaining);
                        } finally {
                            bucket.lock.unlock();
                        }
                    }
                } catch (NumberFormatException e) {
                    logError("Failed to parse X-RateLimit-Remaining header", e);
                }
            }

            // 处理 X-RateLimit-Reset（服务端配额重置时间）
            if (resetHeader != null) {
                try {
                    long resetUnix = Long.parseLong(resetHeader);
                    long resetMs = resetUnix * 1000L;
                    if (resetMs > System.currentTimeMillis() && resetMs < dailyResetTime) {
                        dailyResetTime = resetMs;
                        log("Daily reset time updated from response headers: " + resetMs);
                    }
                } catch (NumberFormatException e) {
                    logError("Failed to parse X-RateLimit-Reset header", e);
                }
            }
        } catch (Exception e) {
            logError("Failed to update rate limit from response", e);
        }
    }

    /**
     * 重置每日配额计数器。
     * <p>
     * 通常在每日配额重置时由内部定时逻辑调用，也可由外部手动触发。
     */
    public void resetDailyQuota() {
        dailyResetLock.lock();
        try {
            dailyRequestCount.set(0);
            dailyResetTime = calculateDailyResetTime();
            log("Daily quota reset. Next reset at: " + dailyResetTime);
        } finally {
            dailyResetLock.unlock();
        }
    }

    /**
     * 获取当前每日请求计数。
     *
     * @return 当前已使用的请求数
     */
    public int getDailyRequestCount() {
        return dailyRequestCount.get();
    }

    /**
     * 获取每日最大请求数配置。
     *
     * @return 每日最大请求数
     */
    public int getDailyMaxRequests() {
        return dailyMaxRequests;
    }

    /**
     * 获取当前配置的快照，以 JSON 格式返回。
     *
     * @return 包含当前配置的 JSON 字符串
     */
    public String getConfigAsJson() {
        try {
            JSONObject config = new JSONObject();
            config.put("minTokenIntervalMs", minTokenIntervalMs);
            config.put("maxTokenIntervalMs", maxTokenIntervalMs);
            config.put("dailyMaxRequests", dailyMaxRequests);
            config.put("jitterPercent", jitterPercent);
            config.put("backoffStrategy", backoffStrategy.name());
            config.put("backoffBaseMs", backoffBaseMs);
            config.put("bucketCapacity", bucketCapacity);
            return config.toString();
        } catch (Exception e) {
            logError("Failed to serialize config", e);
            return "{}";
        }
    }

    /**
     * 获取当前所有桶的状态快照，以 JSON 格式返回。
     *
     * @return 包含所有桶状态的 JSON 字符串
     */
    public String getBucketsAsJson() {
        try {
            JSONObject bucketsJson = new JSONObject();
            for (ConcurrentMap.Entry<String, TokenBucket> entry : buckets.entrySet()) {
                TokenBucket bucket = entry.getValue();
                bucket.lock.lock();
                try {
                    refillBucket(bucket);
                    JSONObject b = new JSONObject();
                    b.put("tokens", bucket.tokens);
                    b.put("maxTokens", bucket.maxTokens);
                    b.put("lastRefillTimeMs", bucket.lastRefillTimeMs.get());
                    b.put("lastAccessTimeMs", bucket.lastAccessTimeMs.get());
                    b.put("consecutiveFailures", bucket.consecutiveFailures);
                    b.put("currentIntervalMs", bucket.currentIntervalMs);
                    bucketsJson.put(entry.getKey(), b);
                } finally {
                    bucket.lock.unlock();
                }
            }

            JSONObject result = new JSONObject();
            result.put("buckets", bucketsJson);
            result.put("dailyRequestCount", dailyRequestCount.get());
            result.put("dailyMaxRequests", dailyMaxRequests);
            result.put("dailyResetTime", dailyResetTime);

            // 添加配置信息
            result.put("config", new JSONObject(getConfigAsJson()));

            return result.toString(2);
        } catch (Exception e) {
            logError("Failed to serialize buckets", e);
            return "{}";
        }
    }

    /**
     * 从远程端点同步配额信息。
     * <p>
     * 向 AWS Kiro 配额端点发送请求，获取最新的配额信息并更新本地状态。
     * 此方法仅供内部使用，在 OkHttpClient 不可用时静默失败。
     *
     * @param tokenId 令牌标识符
     * @param accessToken 用于认证的访问令牌
     */
    public void syncQuotaFromRemote(String tokenId, String accessToken) {
        if (tokenId == null || accessToken == null) {
            return;
        }

        try {
            Request request = new Request.Builder()
                    .url(QUOTA_ENDPOINT + "?tokenId=" + tokenId)
                    .header("Authorization", "Bearer " + accessToken)
                    .header("Accept", "application/json")
                    .build();

            try (Response response = httpClient.newCall(request).execute()) {
                if (response.isSuccessful() && response.body() != null) {
                    String body = response.body().string();
                    JSONObject json = new JSONObject(body);

                    if (json.has("remaining")) {
                        int remaining = json.getInt("remaining");
                        TokenBucket bucket = getOrCreateBucket(tokenId);
                        bucket.lock.lock();
                        try {
                            bucket.tokens = Math.min(bucket.tokens, remaining);
                        } finally {
                            bucket.lock.unlock();
                        }
                    }

                    if (json.has("dailyLimit")) {
                        // 如果服务端返回的每日限制不同，记录日志
                        int serverLimit = json.getInt("dailyLimit");
                        if (serverLimit != dailyMaxRequests) {
                            log("Server daily limit differs: local=" + dailyMaxRequests
                                    + ", server=" + serverLimit);
                        }
                    }

                    if (json.has("resetTime")) {
                        long serverResetTime = json.getLong("resetTime");
                        if (serverResetTime > dailyResetTime) {
                            dailyResetTime = serverResetTime;
                        }
                    }

                    log("Quota synced from remote for tokenId=" + tokenId);
                }
            }
        } catch (Exception e) {
            logError("Failed to sync quota from remote for tokenId=" + tokenId, e);
        }
    }

    // ================================================================
    //  内部方法
    // ================================================================

    /**
     * 获取或创建一个令牌桶。
     * <p>
     * 如果指定 tokenId 的桶已存在则直接返回，否则创建一个新的桶。
     * 新桶的初始令牌数为 {@link #bucketCapacity}，初始补充间隔为
     * {@link #minTokenIntervalMs}。
     *
     * @param tokenId 令牌标识符
     * @return 对应的 TokenBucket 实例
     */
    private TokenBucket getOrCreateBucket(String tokenId) {
        TokenBucket existing = buckets.get(tokenId);
        if (existing != null) {
            return existing;
        }

        long initialInterval = minTokenIntervalMs
                + (long) ((maxTokenIntervalMs - minTokenIntervalMs) * random.nextDouble());
        TokenBucket newBucket = new TokenBucket(tokenId, bucketCapacity, initialInterval);
        TokenBucket old = buckets.putIfAbsent(tokenId, newBucket);
        if (old != null) {
            return old;
        }
        log("Created new token bucket for tokenId=" + tokenId
                + ", capacity=" + bucketCapacity);
        return newBucket;
    }

    /**
     * 补充令牌桶中的令牌。
     * <p>
     * 根据上次补充时间到现在的流逝时间，计算应补充的令牌数。
     * 补充间隔使用抖动计算，每次补充后重新计算下一次的间隔。
     * 补充的令牌数不超过桶的容量上限。
     *
     * @param bucket 要补充的令牌桶
     */
    private void refillBucket(TokenBucket bucket) {
        long now = System.currentTimeMillis();
        long lastRefill = bucket.lastRefillTimeMs.get();
        long elapsed = now - lastRefill;

        if (elapsed <= 0) {
            return;
        }

        // 计算应补充的令牌数
        double tokensToAdd = (double) elapsed / bucket.currentIntervalMs;

        if (tokensToAdd > 0) {
            bucket.tokens = Math.min(bucket.tokens + tokensToAdd, bucket.maxTokens);

            // 更新上次补充时间
            bucket.lastRefillTimeMs.set(now);

            // 重新计算下一次的补充间隔（含抖动）
            bucket.currentIntervalMs = calculateRefillInterval();

            log("Refilled bucket for tokenId=" + bucket.tokenId
                    + ": added=" + String.format("%.2f", tokensToAdd)
                    + ", total=" + String.format("%.2f", bucket.tokens)
                    + ", nextInterval=" + bucket.currentIntervalMs + "ms");
        }
    }

    /**
     * 计算带抖动的令牌补充间隔。
     * <p>
     * 公式：baseInterval × (1.0 + jitterPercent × (random × 2 - 1))
     * 其中 baseInterval 在 minTokenIntervalMs 和 maxTokenIntervalMs 之间随机选取。
     *
     * @return 下一次补充间隔（毫秒），始终为正值
     */
    private long calculateRefillInterval() {
        // 在最小和最大间隔之间随机选取基准值
        double base = minTokenIntervalMs
                + (maxTokenIntervalMs - minTokenIntervalMs) * random.nextDouble();

        // 应用抖动：±jitterPercent
        double jitter = 1.0 + jitterPercent * (random.nextDouble() * 2.0 - 1.0);

        long interval = (long) (base * jitter);

        // 确保间隔不小于一个合理的下限（1ms）
        return Math.max(1L, interval);
    }

    /**
     * 根据退避策略和连续失败次数计算退避等待时间。
     *
     * @param consecutiveFailures 连续失败次数
     * @return 建议的退避等待时间（毫秒）
     */
    private long calculateBackoffWait(int consecutiveFailures) {
        if (consecutiveFailures <= 0) {
            return 0L;
        }

        long waitMs;
        switch (backoffStrategy) {
            case EXPONENTIAL:
                waitMs = (long) (backoffBaseMs * Math.pow(2, consecutiveFailures - 1));
                break;
            case LINEAR:
                waitMs = backoffBaseMs * consecutiveFailures;
                break;
            case FIXED:
                waitMs = backoffBaseMs;
                break;
            default:
                waitMs = backoffBaseMs * consecutiveFailures;
                break;
        }

        // 应用抖动：±jitterPercent
        double jitter = 1.0 + jitterPercent * (random.nextDouble() * 2.0 - 1.0);
        waitMs = (long) (waitMs * jitter);

        // 限制最大退避时间
        return Math.min(waitMs, MAX_BACKOFF_WAIT_MS);
    }

    /**
     * 计算综合建议等待时间。
     * <p>
     * 综合考虑令牌补充时间和退避策略，返回调用方应等待的时间。
     *
     * @param bucket     令牌桶
     * @param backoffWait 退避计算出的等待时间
     * @return 建议等待时间（毫秒）
     */
    private long computeRecommendedWait(TokenBucket bucket, long backoffWait) {
        long now = System.currentTimeMillis();
        long lastRefill = bucket.lastRefillTimeMs.get();

        // 计算下次补充前还需等待的时间
        long timeSinceLastRefill = now - lastRefill;
        long timeUntilNextRefill = Math.max(0L, bucket.currentIntervalMs - timeSinceLastRefill);

        // 实际等待时间 = max(补充等待, 退避等待)
        long wait = Math.max(timeUntilNextRefill, backoffWait);

        // 如果每日配额已用完，等待到重置时间
        if (isDailyQuotaExceeded()) {
            long waitUntilReset = Math.max(0L, dailyResetTime - now);
            wait = Math.max(wait, waitUntilReset);
        }

        return wait;
    }

    /**
     * 检查每日配额是否已用完。
     * <p>
     * 如果当前时间已超过配额重置时间，自动重置计数器。
     *
     * @return true 如果每日配额已用完
     */
    private boolean isDailyQuotaExceeded() {
        long now = System.currentTimeMillis();

        // 检查是否需要重置每日配额
        if (now >= dailyResetTime) {
            dailyResetLock.lock();
            try {
                if (now >= dailyResetTime) {
                    dailyRequestCount.set(0);
                    dailyResetTime = calculateDailyResetTime();
                    log("Daily quota auto-reset. Next reset at: " + dailyResetTime);
                }
            } finally {
                dailyResetLock.unlock();
            }
        }

        return dailyRequestCount.get() >= dailyMaxRequests;
    }

    /**
     * 计算下一次每日配额重置时间。
     * <p>
     * 从当前时间开始，计算下一个整点的配额重置时间（24 小时后）。
     *
     * @return 重置时间戳（epoch millis）
     */
    private long calculateDailyResetTime() {
        return System.currentTimeMillis() + DAILY_RESET_PERIOD_MS;
    }

    // ================================================================
    //  日志辅助方法
    // ================================================================

    private void log(String msg) {
        Log.d(TAG, msg);
    }

    private void logError(String msg, Throwable t) {
        Log.e(TAG, msg, t);
    }

    // ================================================================
    //  Builder
    // ================================================================

    /**
     * KiroRateLimiter 的配置构建器。
     * <p>
     * 使用 Builder 模式创建 {@link KiroRateLimiter} 实例，
     * 所有配置项均有合理的默认值。
     * <p>
     * 示例：
     * <pre>
     * KiroRateLimiter limiter = new KiroRateLimiter.Builder()
     *     .setMinTokenInterval(500, TimeUnit.MILLISECONDS)
     *     .setMaxTokenInterval(1500, TimeUnit.MILLISECONDS)
     *     .setDailyMaxRequests(1000)
     *     .setJitterPercent(0.2)
     *     .setBackoffStrategy(BackoffStrategy.EXPONENTIAL)
     *     .build();
     * </pre>
     */
    public static class Builder {
        private long minTokenIntervalMs = DEFAULT_MIN_TOKEN_INTERVAL_MS;
        private long maxTokenIntervalMs = DEFAULT_MAX_TOKEN_INTERVAL_MS;
        private int dailyMaxRequests = DEFAULT_DAILY_MAX_REQUESTS;
        private double jitterPercent = DEFAULT_JITTER_PERCENT;
        private BackoffStrategy backoffStrategy = DEFAULT_BACKOFF_STRATEGY;
        private long backoffBaseMs = DEFAULT_BACKOFF_BASE_MS;
        private double bucketCapacity = DEFAULT_BUCKET_CAPACITY;

        /**
         * 设置最小令牌发放间隔。默认 1000ms。
         *
         * @param interval 间隔值
         * @param unit     时间单位
         * @return this Builder
         * @throws IllegalArgumentException 如果 interval 小于等于 0
         */
        public Builder setMinTokenInterval(long interval, TimeUnit unit) {
            if (interval <= 0) {
                throw new IllegalArgumentException("minTokenInterval must be > 0");
            }
            this.minTokenIntervalMs = unit.toMillis(interval);
            return this;
        }

        /**
         * 设置最大令牌发放间隔。默认 2000ms。
         *
         * @param interval 间隔值
         * @param unit     时间单位
         * @return this Builder
         * @throws IllegalArgumentException 如果 interval 小于等于 0 或小于 minTokenInterval
         */
        public Builder setMaxTokenInterval(long interval, TimeUnit unit) {
            if (interval <= 0) {
                throw new IllegalArgumentException("maxTokenInterval must be > 0");
            }
            this.maxTokenIntervalMs = unit.toMillis(interval);
            return this;
        }

        /**
         * 设置每日最大请求数。默认 500。
         *
         * @param dailyMaxRequests 每日最大请求数
         * @return this Builder
         * @throws IllegalArgumentException 如果 dailyMaxRequests 小于等于 0
         */
        public Builder setDailyMaxRequests(int dailyMaxRequests) {
            if (dailyMaxRequests <= 0) {
                throw new IllegalArgumentException("dailyMaxRequests must be > 0");
            }
            this.dailyMaxRequests = dailyMaxRequests;
            // 容量不能超过每日限制
            this.bucketCapacity = Math.min(this.bucketCapacity, dailyMaxRequests);
            return this;
        }

        /**
         * 设置抖动百分比。默认 0.3（±30%）。
         * <p>
         * 抖动用于在令牌补充间隔和退避等待时间中引入随机性，
         * 防止多个客户端同步请求导致"惊群"效应。
         *
         * @param jitterPercent 抖动百分比，范围 0.0 ~ 1.0
         * @return this Builder
         * @throws IllegalArgumentException 如果 jitterPercent 不在 [0.0, 1.0] 范围内
         */
        public Builder setJitterPercent(double jitterPercent) {
            if (jitterPercent < 0.0 || jitterPercent > 1.0) {
                throw new IllegalArgumentException("jitterPercent must be in [0.0, 1.0], got " + jitterPercent);
            }
            this.jitterPercent = jitterPercent;
            return this;
        }

        /**
         * 设置退避策略。默认 {@link BackoffStrategy#EXPONENTIAL}。
         *
         * @param backoffStrategy 退避策略
         * @return this Builder
         * @throws IllegalArgumentException 如果 backoffStrategy 为 null
         */
        public Builder setBackoffStrategy(BackoffStrategy backoffStrategy) {
            if (backoffStrategy == null) {
                throw new IllegalArgumentException("backoffStrategy must not be null");
            }
            this.backoffStrategy = backoffStrategy;
            return this;
        }

        /**
         * 设置退避基础等待时间。默认 1000ms。
         * <p>
         * 此基础值用于退避策略的计算：
         * <ul>
         *   <li>EXPONENTIAL：base × 2^(failures-1)</li>
         *   <li>LINEAR：base × failures</li>
         *   <li>FIXED：base</li>
         * </ul>
         *
         * @param backoffBaseMs 基础等待时间（毫秒）
         * @return this Builder
         * @throws IllegalArgumentException 如果 backoffBaseMs 小于等于 0
         */
        public Builder setBackoffBaseMs(long backoffBaseMs) {
            if (backoffBaseMs <= 0) {
                throw new IllegalArgumentException("backoffBaseMs must be > 0");
            }
            this.backoffBaseMs = backoffBaseMs;
            return this;
        }

        /**
         * 设置每个令牌桶的最大容量。默认 5.0。
         * <p>
         * 桶容量决定了在完全不使用的情况下，最多可以累积多少个令牌。
         * 容量越大，短时间内的突发请求能力越强。
         *
         * @param bucketCapacity 桶容量
         * @return this Builder
         * @throws IllegalArgumentException 如果 bucketCapacity 小于等于 0
         */
        public Builder setBucketCapacity(double bucketCapacity) {
            if (bucketCapacity <= 0) {
                throw new IllegalArgumentException("bucketCapacity must be > 0");
            }
            this.bucketCapacity = Math.min(bucketCapacity, dailyMaxRequests);
            return this;
        }

        /**
         * 构建 KiroRateLimiter 实例。
         * <p>
         * 构建前会验证配置的有效性：
         * <ul>
         *   <li>maxTokenInterval 必须 >= minTokenInterval</li>
         *   <li>所有数值配置必须为正值</li>
         *   <li>jitterPercent 必须在 [0.0, 1.0] 范围内</li>
         * </ul>
         *
         * @return 新的 KiroRateLimiter 实例
         * @throws IllegalStateException 如果配置验证失败
         */
        public KiroRateLimiter build() {
            // 验证配置
            if (maxTokenIntervalMs < minTokenIntervalMs) {
                throw new IllegalStateException(
                        "maxTokenInterval (" + maxTokenIntervalMs + "ms) must be >= "
                                + "minTokenInterval (" + minTokenIntervalMs + "ms)");
            }
            if (minTokenIntervalMs <= 0) {
                throw new IllegalStateException("minTokenInterval must be > 0");
            }
            if (dailyMaxRequests <= 0) {
                throw new IllegalStateException("dailyMaxRequests must be > 0");
            }
            if (jitterPercent < 0.0 || jitterPercent > 1.0) {
                throw new IllegalStateException(
                        "jitterPercent must be in [0.0, 1.0]");
            }

            return new KiroRateLimiter(this);
        }
    }
}