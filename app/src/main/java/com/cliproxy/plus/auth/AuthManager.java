package com.cliproxy.plus.auth;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * AuthManager - 账号池管理器
 * 管理所有认证凭证（OAuth + API Key）
 * 支持多账号负载均衡（round-robin、weighted-round-robin、fill-first）
 * 对应原版 internal/auth/ 和 internal/cmd/auth_manager.go
 */
public class AuthManager {

    private static final String TAG = "AuthManager";

    // 单例
    private static AuthManager instance;

    // 账号池
    private final Map<String, AuthCredential> credentials = new ConcurrentHashMap<>();

    // 按提供商分组的账号
    private final Map<String, List<String>> providerGroups = new ConcurrentHashMap<>();

    // Round-robin 计数器
    private final Map<String, AtomicInteger> roundRobinCounters = new ConcurrentHashMap<>();

    // 路由策略
    private volatile RoutingStrategy strategy = RoutingStrategy.ROUND_ROBIN;

    public enum RoutingStrategy {
        ROUND_ROBIN,
        WEIGHTED_ROUND_ROBIN,
        FILL_FIRST
    }

    /**
     * 认证凭证
     */
    public static class AuthCredential {
        public String id;
        public String provider;      // gemini, claude, codex, xai, kiro, antigravity, etc.
        public String prefix;        // 模型命名空间前缀
        public String fileName;      // 凭证文件路径
        public String label;         // 显示标签
        public AuthType type;        // OAUTH 或 API_KEY
        public volatile boolean disabled;
        public volatile boolean unavailable;
        public int weight;           // 权重（用于 weighted-round-robin）
        public int priority;         // 优先级
        public String proxyUrl;      // 代理覆盖
        public Map<String, String> metadata = new HashMap<>();
        public volatile long lastUsed;
        public volatile int failureCount;
        public volatile long cooldownUntil;

        public enum AuthType {
            OAUTH,
            API_KEY
        }

        public boolean isAvailable() {
            return !disabled && !unavailable && System.currentTimeMillis() >= cooldownUntil;
        }
    }

    private AuthManager() {}

    public static synchronized AuthManager getInstance() {
        if (instance == null) {
            instance = new AuthManager();
        }
        return instance;
    }

    /**
     * 注册凭证
     */
    public void registerCredential(AuthCredential credential) {
        credentials.put(credential.id, credential);
        providerGroups.computeIfAbsent(credential.provider, k -> new ArrayList<>()).add(credential.id);
    }

    /**
     * 移除凭证
     */
    public void removeCredential(String id) {
        AuthCredential cred = credentials.remove(id);
        if (cred != null) {
            List<String> group = providerGroups.get(cred.provider);
            if (group != null) {
                group.remove(id);
                if (group.isEmpty()) {
                    providerGroups.remove(cred.provider);
                }
            }
        }
    }

    /**
     * 选择可用账号（Round-Robin）
     */
    public AuthCredential selectCredential(String provider) {
        List<String> authIds = providerGroups.get(provider);
        if (authIds == null || authIds.isEmpty()) {
            return null;
        }

        switch (strategy) {
            case ROUND_ROBIN:
                return selectRoundRobin(provider, authIds);
            case WEIGHTED_ROUND_ROBIN:
                return selectWeighted(provider, authIds);
            case FILL_FIRST:
                return selectFillFirst(authIds);
            default:
                return selectRoundRobin(provider, authIds);
        }
    }

    private AuthCredential selectRoundRobin(String provider, List<String> authIds) {
        AtomicInteger counter = roundRobinCounters.computeIfAbsent(provider, k -> new AtomicInteger(0));
        int size = authIds.size();
        for (int i = 0; i < size; i++) {
            int idx = Math.abs(counter.getAndIncrement()) % size;
            AuthCredential cred = credentials.get(authIds.get(idx));
            if (cred != null && cred.isAvailable()) {
                cred.lastUsed = System.currentTimeMillis();
                return cred;
            }
        }
        return null;
    }

    private AuthCredential selectWeighted(String provider, List<String> authIds) {
        // 加权轮询
        List<AuthCredential> available = new ArrayList<>();
        for (String id : authIds) {
            AuthCredential cred = credentials.get(id);
            if (cred != null && cred.isAvailable()) {
                available.add(cred);
            }
        }
        if (available.isEmpty()) return null;

        int totalWeight = available.stream().mapToInt(c -> Math.max(c.weight, 1)).sum();
        int point = Math.abs(new java.util.Random().nextInt()) % totalWeight;

        for (AuthCredential cred : available) {
            point -= Math.max(cred.weight, 1);
            if (point < 0) {
                cred.lastUsed = System.currentTimeMillis();
                return cred;
            }
        }
        return available.get(0);
    }

    private AuthCredential selectFillFirst(List<String> authIds) {
        for (String id : authIds) {
            AuthCredential cred = credentials.get(id);
            if (cred != null && cred.isAvailable()) {
                cred.lastUsed = System.currentTimeMillis();
                return cred;
            }
        }
        return null;
    }

    /**
     * 标记认证失败（触发冷却）
     */
    public void markFailure(String id) {
        AuthCredential cred = credentials.get(id);
        if (cred != null) {
            cred.failureCount++;
            cred.cooldownUntil = System.currentTimeMillis() + Math.min(60000, cred.failureCount * 10000);
        }
    }

    /**
     * 标记认证成功（重置失败计数）
     */
    public void markSuccess(String id) {
        AuthCredential cred = credentials.get(id);
        if (cred != null) {
            cred.failureCount = 0;
            cred.cooldownUntil = 0;
        }
    }

    public void setStrategy(RoutingStrategy strategy) {
        this.strategy = strategy;
    }

    public RoutingStrategy getStrategy() {
        return strategy;
    }

    public List<AuthCredential> listCredentials() {
        return new ArrayList<>(credentials.values());
    }

    public List<AuthCredential> listCredentialsByProvider(String provider) {
        List<AuthCredential> result = new ArrayList<>();
        List<String> ids = providerGroups.get(provider);
        if (ids != null) {
            for (String id : ids) {
                AuthCredential cred = credentials.get(id);
                if (cred != null) {
                    result.add(cred);
                }
            }
        }
        return result;
    }

    public int getActiveCount() {
        return (int) credentials.values().stream().filter(AuthCredential::isAvailable).count();
    }

    public int getTotalCount() {
        return credentials.size();
    }
}