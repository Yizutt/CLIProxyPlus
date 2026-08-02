package com.cliproxy.plus.auth;

import android.util.Log;

import com.cliproxy.plus.auth.oauth.OAuthProvider;
import com.cliproxy.plus.auth.oauth.OAuthProvider.TokenData;
import com.cliproxy.plus.auth.oauth.OAuthProvider.OAuthException;

import org.json.JSONObject;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

/**
 * TokenRefresher - 自动令牌刷新管理器
 * <p>
 * 使用 {@link ScheduledExecutorService} 定期检查所有已注册 OAuth 提供者的令牌过期时间。
 * 当令牌剩余有效期小于 5 分钟时，自动调用 {@link OAuthProvider#refreshTokens(String)}
 * 刷新令牌，并更新本地缓存的令牌数据。
 * <p>
 * 支持动态添加/移除提供者、启动/停止刷新调度，以及查询下次刷新时间。
 * 线程安全，可在多线程环境下使用。
 * <p>
 * 对应原版 CLIProxyAPIPlus/internal/auth/ 中的令牌刷新逻辑。
 */
public class TokenRefresher {

    private static final String TAG = "TokenRefresher";

    /** 提前刷新阈值：5 分钟（毫秒） */
    private static final long REFRESH_THRESHOLD_MS = 5 * 60 * 1000L;

    /** 默认检查间隔：30 秒（毫秒） */
    private static final long DEFAULT_CHECK_INTERVAL_MS = 30_000L;

    /** 刷新失败后的重试延迟基数（毫秒） */
    private static final long RETRY_BASE_DELAY_MS = 10_000L;

    /** 最大连续失败次数，超过后暂停该提供者的刷新 */
    private static final int MAX_CONSECUTIVE_FAILURES = 5;

    /** OkHttp 客户端，用于直接令牌验证请求 */
    private static final OkHttpClient HTTP_CLIENT = new OkHttpClient.Builder()
            .connectTimeout(15, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .writeTimeout(15, TimeUnit.SECONDS)
            .build();

    /** 提供者注册表：provider name -> ProviderEntry */
    private final ConcurrentHashMap<String, ProviderEntry> providers = new ConcurrentHashMap<>();

    /** 调度器 */
    private ScheduledExecutorService scheduler;

    /** 定时刷新任务的 Future */
    private ScheduledFuture<?> refreshTask;

    /** 并发控制锁 */
    private final ReentrantLock lock = new ReentrantLock();

    /** 运行状态 */
    private volatile boolean running = false;

    /** 下次刷新时间（毫秒时间戳），0 表示未调度 */
    private volatile long nextRefreshTime = 0;

    // ============================================================
    //  内部类：ProviderEntry
    // ============================================================

    /**
     * 提供者条目，记录每个 OAuth 提供者的令牌状态和刷新元数据。
     */
    private static class ProviderEntry {
        final OAuthProvider provider;
        final String name;

        /** 当前 refresh token */
        volatile String refreshToken;

        /** 当前 access token 过期时间（毫秒时间戳） */
        volatile long expireAt;

        /** 上次成功刷新时间（毫秒时间戳） */
        volatile long lastRefreshTime;

        /** 刷新次数累计 */
        volatile int refreshCount;

        /** 连续失败次数 */
        volatile int consecutiveFailures;

        /** 上次错误消息 */
        volatile String lastError;

        /** 是否暂停刷新（连续失败过多后暂停） */
        volatile boolean paused;

        /** 暂停恢复时间（毫秒时间戳） */
        volatile long pausedUntil;

        /**
         * 构造提供者条目。
         *
         * @param provider OAuth 提供者实例
         */
        ProviderEntry(OAuthProvider provider) {
            this.provider = provider;
            this.name = provider.getClass().getSimpleName();
            this.refreshToken = "";
            this.expireAt = 0;
            this.lastRefreshTime = 0;
            this.refreshCount = 0;
            this.consecutiveFailures = 0;
            this.lastError = "";
            this.paused = false;
            this.pausedUntil = 0;
        }

        /**
         * 判断令牌是否即将过期（在 REFRESH_THRESHOLD_MS 内）。
         *
         * @return true 如果令牌即将过期
         */
        boolean isExpiringSoon() {
            if (expireAt <= 0) {
                return false;
            }
            return System.currentTimeMillis() + REFRESH_THRESHOLD_MS >= expireAt;
        }

        /**
         * 判断令牌是否已过期。
         *
         * @return true 如果令牌已过期
         */
        boolean isExpired() {
            return expireAt > 0 && System.currentTimeMillis() >= expireAt;
        }

        /**
         * 判断是否应跳过本次刷新检查。
         *
         * @return true 如果应跳过检查
         */
        boolean shouldSkipCheck() {
            if (paused) {
                if (System.currentTimeMillis() >= pausedUntil) {
                    paused = false;
                    pausedUntil = 0;
                    return false;
                }
                return true;
            }
            if (refreshToken == null || refreshToken.isEmpty()) {
                return true;
            }
            return false;
        }

        /**
         * 记录刷新成功。
         *
         * @param newTokenData 新的令牌数据
         */
        void recordSuccess(TokenData newTokenData) {
            this.refreshToken = newTokenData.refreshToken != null
                    ? newTokenData.refreshToken : this.refreshToken;
            this.expireAt = newTokenData.expireAt > 0
                    ? newTokenData.expireAt : this.expireAt;
            this.lastRefreshTime = System.currentTimeMillis();
            this.refreshCount++;
            this.consecutiveFailures = 0;
            this.lastError = "";
            this.paused = false;
            this.pausedUntil = 0;
        }

        /**
         * 记录刷新失败。
         *
         * @param errorMessage 错误消息
         */
        void recordFailure(String errorMessage) {
            this.consecutiveFailures++;
            this.lastError = errorMessage;
            if (this.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
                this.paused = true;
                this.pausedUntil = System.currentTimeMillis()
                        + Math.min(300_000L, this.consecutiveFailures * 60_000L);
                Log.w(TAG, name + ": paused until " + new Date(pausedUntil)
                        + " after " + consecutiveFailures + " consecutive failures");
            }
        }

        /**
         * 获取令牌剩余有效时间（毫秒）。
         *
         * @return 剩余毫秒数，已过期或未设置则返回 0
         */
        long getRemainingMs() {
            if (expireAt <= 0) return 0;
            long remaining = expireAt - System.currentTimeMillis();
            return Math.max(remaining, 0);
        }

        /**
         * 获取提供者状态摘要。
         */
        String getStatusSummary() {
            StringBuilder sb = new StringBuilder(name);
            sb.append(" [expireAt=").append(expireAt > 0 ? new Date(expireAt) : "N/A");
            sb.append(", remaining=").append(getRemainingMs() / 1000).append("s");
            sb.append(", refreshCount=").append(refreshCount);
            sb.append(", failures=").append(consecutiveFailures);
            if (paused) {
                sb.append(", PAUSED");
            }
            if (lastError != null && !lastError.isEmpty()) {
                sb.append(", lastError=").append(lastError);
            }
            sb.append("]");
            return sb.toString();
        }
    }

    // ============================================================
    //  构造方法
    // ============================================================

    /**
     * 创建一个新的 TokenRefresher 实例。
     * <p>
     * 初始状态为未启动，需调用 {@link #start()} 开始定期刷新检查。
     */
    public TokenRefresher() {
        Log.d(TAG, "TokenRefresher created");
    }

    // ============================================================
    //  公开 API
    // ============================================================

    /**
     * 注册一个 OAuth 提供者。
     * <p>
     * 提供者添加后，需通过 {@link #updateToken(String, String, long)} 设置初始令牌数据，
     * 刷新器才会执行检查。提供者名称默认使用类简单名（如 "KimiOAuth"、"ClaudeOAuth"）。
     * <p>
     * 如果同名提供者已存在，将被替换。
     *
     * @param provider OAuth 提供者实例，不能为 null
     * @throws IllegalArgumentException 如果 provider 为 null
     */
    public void addProvider(OAuthProvider provider) {
        if (provider == null) {
            throw new IllegalArgumentException("provider must not be null");
        }

        ProviderEntry entry = new ProviderEntry(provider);
        ProviderEntry previous = providers.put(entry.name, entry);

        if (previous != null) {
            Log.d(TAG, "Provider replaced: " + entry.name);
        } else {
            Log.d(TAG, "Provider added: " + entry.name);
        }

        // 如果正在运行，重新调度以立即考虑新提供者
        if (running) {
            reschedule();
        }
    }

    /**
     * 移除指定名称的 OAuth 提供者。
     * <p>
     * 移除后，该提供者将不再参与令牌刷新检查。
     *
     * @param providerName 提供者名称（类简单名），不能为 null 或空
     * @return true 如果找到并移除了该提供者
     * @throws IllegalArgumentException 如果 providerName 为 null 或空
     */
    public boolean removeProvider(String providerName) {
        if (providerName == null || providerName.trim().isEmpty()) {
            throw new IllegalArgumentException("providerName must not be null or empty");
        }

        ProviderEntry removed = providers.remove(providerName.trim());
        if (removed != null) {
            Log.d(TAG, "Provider removed: " + providerName
                    + " (refreshed " + removed.refreshCount + " times)");
            return true;
        } else {
            Log.w(TAG, "Provider not found for removal: " + providerName);
            return false;
        }
    }

    /**
     * 更新指定提供者的令牌数据。
     * <p>
     * 首次添加提供者后，需调用此方法设置初始令牌数据。
     * 刷新器内部也会在每次成功刷新后自动更新令牌数据。
     * <p>
     * 如果 {@code expireAt} 为 0 或负值，表示令牌永不过期（不触发自动刷新）。
     *
     * @param providerName 提供者名称
     * @param refreshToken 新的 refresh token，传 null 或空字符串则不更新
     * @param expireAt     access token 过期时间（毫秒时间戳），传 0 表示不更新或不检查
     * @return true 如果找到并更新了该提供者
     */
    public boolean updateToken(String providerName, String refreshToken, long expireAt) {
        ProviderEntry entry = providers.get(providerName);
        if (entry == null) {
            Log.w(TAG, "Provider not found for token update: " + providerName);
            return false;
        }

        if (refreshToken != null && !refreshToken.isEmpty()) {
            entry.refreshToken = refreshToken;
        }
        if (expireAt > 0) {
            entry.expireAt = expireAt;
        }
        entry.lastRefreshTime = System.currentTimeMillis();

        Log.d(TAG, "Token updated for " + providerName + ": "
                + "expireAt=" + (expireAt > 0 ? new Date(expireAt) : "unchanged"));
        return true;
    }

    /**
     * 启动定期令牌刷新调度。
     * <p>
     * 使用 {@link ScheduledExecutorService} 以固定频率检查所有已注册提供者的令牌状态。
     * 如果已在运行，调用无效果。
     * <p>
     * 首次启动时会立即执行一次检查。
     */
    public void start() {
        lock.lock();
        try {
            if (running) {
                Log.d(TAG, "TokenRefresher already running");
                return;
            }

            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "token-refresher");
                t.setDaemon(true);
                return t;
            });

            // 立即执行一次检查，然后按固定间隔调度
            refreshTask = scheduler.scheduleWithFixedDelay(
                    this::performRefreshCheck,
                    0,
                    DEFAULT_CHECK_INTERVAL_MS,
                    TimeUnit.MILLISECONDS
            );

            running = true;
            nextRefreshTime = System.currentTimeMillis() + DEFAULT_CHECK_INTERVAL_MS;

            Log.i(TAG, "TokenRefresher started (check interval: "
                    + DEFAULT_CHECK_INTERVAL_MS + "ms, "
                    + "providers: " + providers.size() + ")");
        } finally {
            lock.unlock();
        }
    }

    /**
     * 停止定期令牌刷新调度。
     * <p>
     * 取消所有待执行的刷新任务，关闭调度器。
     * 停止后可通过 {@link #start()} 重新启动。
     * <p>
     * 安全：等待当前正在执行的刷新任务完成后再返回。
     */
    public void stop() {
        lock.lock();
        try {
            if (!running) {
                Log.d(TAG, "TokenRefresher already stopped");
                return;
            }

            running = false;
            nextRefreshTime = 0;

            // 取消定时任务
            if (refreshTask != null && !refreshTask.isCancelled()) {
                refreshTask.cancel(false); // 不中断正在执行的任务
                refreshTask = null;
            }

            // 关闭调度器
            if (scheduler != null && !scheduler.isShutdown()) {
                scheduler.shutdown();
                try {
                    if (!scheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                        scheduler.shutdownNow();
                    }
                } catch (InterruptedException e) {
                    scheduler.shutdownNow();
                    Thread.currentThread().interrupt();
                }
                scheduler = null;
            }

            Log.i(TAG, "TokenRefresher stopped");
        } finally {
            lock.unlock();
        }
    }

    /**
     * 获取下次计划刷新时间。
     * <p>
     * 如果刷新器未运行或没有需要刷新的提供者，返回 0。
     *
     * @return 下次刷新时间的毫秒时间戳，0 表示未调度
     */
    public long getNextRefreshTime() {
        return nextRefreshTime;
    }

    // ============================================================
    //  内部逻辑
    // ============================================================

    /**
     * 执行一次刷新检查。
     * <p>
     * 遍历所有提供者，检查令牌是否即将过期（5 分钟内），
     * 如果是则调用 {@link OAuthProvider#refreshTokens(String)} 刷新。
     * 此方法由调度器在后台线程中调用。
     */
    private void performRefreshCheck() {
        if (!running) {
            return;
        }

        Log.d(TAG, "Performing refresh check for " + providers.size() + " providers");

        long earliestExpiry = Long.MAX_VALUE;
        boolean hasPending = false;

        for (ProviderEntry entry : providers.values()) {
            if (entry.shouldSkipCheck()) {
                continue;
            }

            if (entry.isExpiringSoon()) {
                hasPending = true;
                refreshProvider(entry);
            }

            // 计算下次检查时间
            if (entry.expireAt > 0) {
                long refreshPoint = entry.expireAt - REFRESH_THRESHOLD_MS;
                if (refreshPoint < earliestExpiry) {
                    earliestExpiry = refreshPoint;
                }
            }
        }

        // 更新下次刷新时间
        if (hasPending || earliestExpiry < Long.MAX_VALUE) {
            long now = System.currentTimeMillis();
            long nextCheck = hasPending
                    ? now + DEFAULT_CHECK_INTERVAL_MS
                    : Math.max(now + DEFAULT_CHECK_INTERVAL_MS,
                    earliestExpiry - now > 0 ? earliestExpiry : now + DEFAULT_CHECK_INTERVAL_MS);
            nextRefreshTime = nextCheck;
        } else {
            nextRefreshTime = 0;
        }

        logProviderStatus();
    }

    /**
     * 刷新指定提供者的令牌。
     *
     * @param entry 提供者条目
     */
    private void refreshProvider(ProviderEntry entry) {
        String name = entry.name;
        String refreshToken = entry.refreshToken;

        Log.d(TAG, "Refreshing token for " + name
                + " (remaining: " + entry.getRemainingMs() / 1000 + "s)");

        try {
            TokenData newTokenData = entry.provider.refreshTokens(refreshToken);

            if (newTokenData == null) {
                throw new OAuthException("refresh_failed",
                        "Provider returned null token data");
            }

            if (newTokenData.accessToken == null || newTokenData.accessToken.isEmpty()) {
                throw new OAuthException("refresh_failed",
                        "Provider returned empty access token");
            }

            // 更新令牌数据
            entry.recordSuccess(newTokenData);

            // 同步更新 AuthManager 中的凭证状态
            notifyAuthManagerSuccess(name);

            Log.i(TAG, "Token refreshed successfully for " + name
                    + " (expireAt: " + (newTokenData.expireAt > 0
                    ? new Date(newTokenData.expireAt) : "N/A")
                    + ", refreshCount: " + entry.refreshCount + ")");

        } catch (OAuthException e) {
            handleRefreshError(entry, e);
        } catch (Exception e) {
            handleRefreshError(entry, new OAuthException("refresh_error",
                    "Unexpected error during token refresh: " + e.getMessage(), e));
        }
    }

    /**
     * 处理刷新错误。
     *
     * @param entry 提供者条目
     * @param error 刷新异常
     */
    private void handleRefreshError(ProviderEntry entry, OAuthException error) {
        String name = entry.name;
        entry.recordFailure(error.getMessage());

        // 通知 AuthManager 标记失败
        notifyAuthManagerFailure(name);

        if (entry.consecutiveFailures >= MAX_CONSECUTIVE_FAILURES) {
            Log.e(TAG, "Token refresh suspended for " + name
                    + " after " + entry.consecutiveFailures
                    + " consecutive failures: " + error.getMessage());
        } else {
            Log.e(TAG, "Token refresh failed for " + name
                    + " (attempt " + entry.consecutiveFailures + "): "
                    + error.getMessage());
        }
    }

    /**
     * 重新调度刷新任务。
     * <p>
     * 在添加/移除提供者后调用，使调度器立即考虑变更。
     */
    private void reschedule() {
        lock.lock();
        try {
            if (!running || scheduler == null || scheduler.isShutdown()) {
                return;
            }

            // 取消当前任务
            if (refreshTask != null && !refreshTask.isCancelled()) {
                refreshTask.cancel(false);
            }

            // 重新调度
            refreshTask = scheduler.scheduleWithFixedDelay(
                    this::performRefreshCheck,
                    0,
                    DEFAULT_CHECK_INTERVAL_MS,
                    TimeUnit.MILLISECONDS
            );

            nextRefreshTime = System.currentTimeMillis() + DEFAULT_CHECK_INTERVAL_MS;
            Log.d(TAG, "Refresh task rescheduled");
        } finally {
            lock.unlock();
        }
    }

    // ============================================================
    //  AuthManager 集成
    // ============================================================

    /**
     * 通知 AuthManager 刷新成功（重置失败计数）。
     */
    private void notifyAuthManagerSuccess(String providerName) {
        try {
            AuthManager authManager = AuthManager.getInstance();
            // 查找该提供者名下所有凭证并标记成功
            for (AuthManager.AuthCredential cred : authManager.listCredentialsByProvider(providerName)) {
                authManager.markSuccess(cred.id);
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to notify AuthManager of success for " + providerName, e);
        }
    }

    /**
     * 通知 AuthManager 刷新失败。
     */
    private void notifyAuthManagerFailure(String providerName) {
        try {
            AuthManager authManager = AuthManager.getInstance();
            for (AuthManager.AuthCredential cred : authManager.listCredentialsByProvider(providerName)) {
                authManager.markFailure(cred.id);
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to notify AuthManager of failure for " + providerName, e);
        }
    }

    // ============================================================
    //  查询与工具方法
    // ============================================================

    /**
     * 检查刷新器是否正在运行。
     *
     * @return true 如果正在运行
     */
    public boolean isRunning() {
        return running;
    }

    /**
     * 获取已注册的提供者数量。
     *
     * @return 提供者数量
     */
    public int getProviderCount() {
        return providers.size();
    }

    /**
     * 获取所有已注册的提供者名称列表。
     *
     * @return 不可修改的提供者名称列表
     */
    public List<String> getProviderNames() {
        return Collections.unmodifiableList(new ArrayList<>(providers.keySet()));
    }

    /**
     * 获取指定提供者的令牌状态摘要。
     *
     * @param providerName 提供者名称
     * @return 状态摘要字符串，提供者不存在则返回 null
     */
    public String getProviderStatus(String providerName) {
        ProviderEntry entry = providers.get(providerName);
        if (entry == null) {
            return null;
        }
        return entry.getStatusSummary();
    }

    /**
     * 获取所有提供者的状态摘要。
     *
     * @return 状态摘要字符串列表
     */
    public List<String> getAllProviderStatus() {
        List<String> statuses = new ArrayList<>();
        for (ProviderEntry entry : providers.values()) {
            statuses.add(entry.getStatusSummary());
        }
        return statuses;
    }

    /**
     * 立即对指定提供者强制执行一次令牌刷新。
     * <p>
     * 忽略提前刷新阈值检查，直接调用刷新。
     *
     * @param providerName 提供者名称
     * @return true 如果刷新请求已发起
     */
    public boolean forceRefresh(String providerName) {
        ProviderEntry entry = providers.get(providerName);
        if (entry == null) {
            Log.w(TAG, "Provider not found for force refresh: " + providerName);
            return false;
        }
        if (entry.refreshToken == null || entry.refreshToken.isEmpty()) {
            Log.w(TAG, "Cannot force refresh " + providerName + ": no refresh token");
            return false;
        }

        Log.i(TAG, "Force refreshing token for " + providerName);
        refreshProvider(entry);
        return true;
    }

    /**
     * 使用 OkHttp 直接验证 access token 的有效性。
     * <p>
     * 向指定端点发送带有 Bearer Token 的 GET 请求，检查响应状态。
     * 如果返回 401/403，表示令牌已失效。
     *
     * @param token       access token
     * @param verifyUrl   验证端点 URL
     * @return true 如果令牌有效（2xx 响应）
     */
    public boolean verifyTokenDirect(String token, String verifyUrl) {
        if (token == null || token.isEmpty() || verifyUrl == null || verifyUrl.isEmpty()) {
            return false;
        }

        Request request = new Request.Builder()
                .url(verifyUrl)
                .header("Authorization", "Bearer " + token)
                .header("Accept", "application/json")
                .build();

        try (Response response = HTTP_CLIENT.newCall(request).execute()) {
            int code = response.code();
            if (code >= 200 && code < 300) {
                Log.d(TAG, "Token verification succeeded: HTTP " + code);
                return true;
            } else if (code == 401 || code == 403) {
                Log.w(TAG, "Token verification failed: HTTP " + code + " (token expired/invalid)");
                return false;
            } else {
                Log.w(TAG, "Token verification returned unexpected status: HTTP " + code);
                return false;
            }
        } catch (IOException e) {
            Log.e(TAG, "Token verification request failed", e);
            return false;
        }
    }

    /**
     * 使用 OkHttp 解析令牌端点返回的 JSON 响应，提取过期时间。
     * <p>
     * 向令牌信息端点发送 GET 请求，解析 JSON 中的 expires_in 或 exp 字段。
     *
     * @param tokenInfoUrl 令牌信息端点 URL
     * @param bearerToken  Bearer token
     * @return 过期时间（毫秒时间戳），解析失败返回 0
     */
    public long fetchTokenExpiryFromEndpoint(String tokenInfoUrl, String bearerToken) {
        if (tokenInfoUrl == null || tokenInfoUrl.isEmpty()
                || bearerToken == null || bearerToken.isEmpty()) {
            return 0;
        }

        Request request = new Request.Builder()
                .url(tokenInfoUrl)
                .header("Authorization", "Bearer " + bearerToken)
                .header("Accept", "application/json")
                .build();

        try (Response response = HTTP_CLIENT.newCall(request).execute()) {
            if (!response.isSuccessful() || response.body() == null) {
                Log.w(TAG, "Token info request failed: HTTP " + response.code());
                return 0;
            }

            String json = response.body().string();
            JSONObject obj = new JSONObject(json);

            // 尝试多种字段名
            long expiresIn = 0;
            if (obj.has("expires_in")) {
                expiresIn = obj.optLong("expires_in", 0);
            } else if (obj.has("exp")) {
                // exp 是 Unix 时间戳（秒）
                long exp = obj.optLong("exp", 0);
                if (exp > 0) {
                    return exp * 1000L;
                }
            }

            if (expiresIn > 0) {
                return System.currentTimeMillis() + (expiresIn * 1000L);
            }

            return 0;
        } catch (IOException | org.json.JSONException e) {
            Log.e(TAG, "Failed to fetch token expiry from endpoint", e);
            return 0;
        }
    }

    // ============================================================
    //  日志辅助
    // ============================================================

    /**
     * 记录所有提供者的状态摘要。
     */
    private void logProviderStatus() {
        if (!Log.isLoggable(TAG, Log.DEBUG)) {
            return;
        }
        for (ProviderEntry entry : providers.values()) {
            Log.d(TAG, "Provider status: " + entry.getStatusSummary());
        }
    }

    // ============================================================
    //  清理
    // ============================================================

    /**
     * 释放所有资源。
     * <p>
     * 停止刷新调度，清空提供者注册表。
     * 调用后此实例不再可用，应丢弃。
     */
    public void destroy() {
        stop();
        providers.clear();
        Log.d(TAG, "TokenRefresher destroyed");
    }
}