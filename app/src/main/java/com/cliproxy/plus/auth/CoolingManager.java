package com.cliproxy.plus.auth;

import android.content.Context;
import android.util.Log;

import org.json.JSONObject;
import org.json.JSONException;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * CoolingManager - 认证冷却管理器
 * 管理失败认证凭证的冷却/退避状态
 * 实现指数退避策略，防止短时间内重复使用失败凭证
 * 支持将冷却状态持久化为 .cds 文件
 * 对应原版 internal/auth/cooling.go
 */
public class CoolingManager {

    private static final String TAG = "CoolingManager";

    /** 冷却状态文件扩展名 */
    private static final String COOLING_FILE_EXT = ".cds";

    /** 冷却状态文件目录名 */
    private static final String COOLING_DIR = "cooling";

    /** 指数退避级别（毫秒）：10s, 30s, 60s, 5min, 15min, 30min, 1h */
    private static final long[] BACKOFF_LEVELS = {
        10_000L,        // 第1次失败
        30_000L,        // 第2次失败
        60_000L,        // 第3次失败
        300_000L,       // 第4次失败
        900_000L,       // 第5次失败
        1_800_000L,     // 第6次失败
        3_600_000L      // 第7次及以后失败
    };

    /** 冷却状态文件版本 */
    private static final int CDS_VERSION = 1;

    /** 单例 */
    private static CoolingManager instance;

    /** 应用上下文 */
    private final Context context;

    /** 冷却状态存储：authId -> CoolingEntry */
    private final ConcurrentMap<String, CoolingEntry> coolingMap = new ConcurrentHashMap<>();

    /** 冷却文件缓存目录 */
    private final File coolingDir;

    /**
     * 冷却条目 - 记录失败次数和冷却过期时间
     */
    private static class CoolingEntry {
        /** 失败次数 */
        int failureCount;
        /** 冷却过期时间戳（毫秒） */
        long cooldownUntil;

        CoolingEntry(int failureCount, long cooldownUntil) {
            this.failureCount = failureCount;
            this.cooldownUntil = cooldownUntil;
        }

        /**
         * 判断是否仍在冷却中
         */
        boolean isCooling() {
            return System.currentTimeMillis() < cooldownUntil;
        }

        /**
         * 获取剩余冷却时间（毫秒）
         */
        long getRemaining() {
            long remaining = cooldownUntil - System.currentTimeMillis();
            return Math.max(0, remaining);
        }
    }

    /**
     * 私有构造函数
     * @param context 应用上下文
     */
    private CoolingManager(Context context) {
        this.context = context.getApplicationContext();
        this.coolingDir = new File(this.context.getFilesDir(), COOLING_DIR);
        ensureCoolingDir();
        loadAllCoolingStates();
        Log.i(TAG, "CoolingManager initialized, " + coolingMap.size() + " persisted states loaded");
    }

    /**
     * 获取 CoolingManager 单例
     * @param context 应用上下文
     * @return CoolingManager 实例
     */
    public static synchronized CoolingManager getInstance(Context context) {
        if (instance == null) {
            instance = new CoolingManager(context);
        }
        return instance;
    }

    /**
     * 获取 CoolingManager 单例（需先初始化）
     * @return CoolingManager 实例
     * @throws IllegalStateException 如果尚未初始化
     */
    public static CoolingManager getInstance() {
        if (instance == null) {
            throw new IllegalStateException("CoolingManager not initialized. Call getInstance(Context) first.");
        }
        return instance;
    }

    /**
     * 确保冷却状态目录存在
     */
    private void ensureCoolingDir() {
        if (!coolingDir.exists()) {
            boolean created = coolingDir.mkdirs();
            if (!created) {
                Log.w(TAG, "Failed to create cooling directory: " + coolingDir.getAbsolutePath());
            }
        }
    }

    /**
     * 记录认证失败，应用指数退避冷却
     * <p>
     * 退避级别：10s -> 30s -> 60s -> 5min -> 15min -> 30min -> 1h
     * 超过 7 次失败后维持在 1h
     * </p>
     * @param authId 认证凭证标识
     */
    public void recordFailure(String authId) {
        if (authId == null || authId.isEmpty()) {
            Log.w(TAG, "recordFailure called with null or empty authId");
            return;
        }

        CoolingEntry entry = coolingMap.get(authId);
        int newCount;
        long cooldownDuration;

        if (entry == null) {
            // 首次失败
            newCount = 1;
            cooldownDuration = getBackoffDuration(0);
            Log.d(TAG, "First failure for " + authId + ", cooldown: " + (cooldownDuration / 1000) + "s");
        } else {
            newCount = entry.failureCount + 1;
            cooldownDuration = getBackoffDuration(newCount - 1);
            Log.d(TAG, "Failure #" + newCount + " for " + authId + ", cooldown: " + (cooldownDuration / 1000) + "s");
        }

        long cooldownUntil = System.currentTimeMillis() + cooldownDuration;
        coolingMap.put(authId, new CoolingEntry(newCount, cooldownUntil));

        // 持久化冷却状态
        persistCoolingState(authId);
        Log.i(TAG, "Cooling activated for " + authId + " until " + cooldownUntil + " (failure #" + newCount + ")");
    }

    /**
     * 记录认证成功，重置冷却状态
     * @param authId 认证凭证标识
     */
    public void recordSuccess(String authId) {
        if (authId == null || authId.isEmpty()) {
            Log.w(TAG, "recordSuccess called with null or empty authId");
            return;
        }

        CoolingEntry removed = coolingMap.remove(authId);
        if (removed != null) {
            // 删除持久化冷却文件
            deleteCoolingFile(authId);
            Log.i(TAG, "Cooling cleared for " + authId + " (had " + removed.failureCount + " failures)");
        } else {
            Log.d(TAG, "No cooling state to clear for " + authId);
        }
    }

    /**
     * 检查指定凭证是否处于冷却中
     * @param authId 认证凭证标识
     * @return true 如果正在冷却中
     */
    public boolean isCooling(String authId) {
        if (authId == null || authId.isEmpty()) {
            return false;
        }

        CoolingEntry entry = coolingMap.get(authId);
        if (entry == null) {
            return false;
        }

        if (entry.isCooling()) {
            return true;
        }

        // 冷却已过期，自动清理
        coolingMap.remove(authId);
        deleteCoolingFile(authId);
        return false;
    }

    /**
     * 获取冷却剩余时间
     * @param authId 认证凭证标识
     * @return 剩余冷却时间（毫秒），0 表示未冷却
     */
    public long getCooldownRemaining(String authId) {
        if (authId == null || authId.isEmpty()) {
            return 0;
        }

        CoolingEntry entry = coolingMap.get(authId);
        if (entry == null) {
            return 0;
        }

        if (entry.isCooling()) {
            return entry.getRemaining();
        }

        // 冷却已过期，自动清理
        coolingMap.remove(authId);
        deleteCoolingFile(authId);
        return 0;
    }

    /**
     * 重置所有冷却状态
     */
    public void resetAll() {
        coolingMap.clear();
        clearAllCoolingFiles();
        Log.i(TAG, "All cooling states have been reset");
    }

    /**
     * 获取当前冷却中的凭证数量
     * @return 冷却中数量
     */
    public int getCoolingCount() {
        // 清理过期的冷却条目
        long now = System.currentTimeMillis();
        int count = 0;
        for (ConcurrentMap.Entry<String, CoolingEntry> entry : coolingMap.entrySet()) {
            if (entry.getValue().cooldownUntil > now) {
                count++;
            }
        }
        return count;
    }

    /**
     * 获取所有冷却中的凭证 ID 列表
     * @return 冷却中的 authId 列表
     */
    public String[] getCoolingAuthIds() {
        long now = System.currentTimeMillis();
        return coolingMap.entrySet().stream()
            .filter(e -> e.getValue().cooldownUntil > now)
            .map(ConcurrentMap.Entry::getKey)
            .toArray(String[]::new);
    }

    /**
     * 获取指定凭证的失败次数
     * @param authId 认证凭证标识
     * @return 失败次数，未冷却返回 0
     */
    public int getFailureCount(String authId) {
        if (authId == null || authId.isEmpty()) {
            return 0;
        }
        CoolingEntry entry = coolingMap.get(authId);
        return (entry != null) ? entry.failureCount : 0;
    }

    /**
     * 根据失败索引获取退避时长
     * @param failureIndex 失败索引（0-based）
     * @return 退避时长（毫秒）
     */
    private long getBackoffDuration(int failureIndex) {
        if (failureIndex < 0) {
            return BACKOFF_LEVELS[0];
        }
        if (failureIndex >= BACKOFF_LEVELS.length) {
            return BACKOFF_LEVELS[BACKOFF_LEVELS.length - 1];
        }
        return BACKOFF_LEVELS[failureIndex];
    }

    // ==================== 持久化 ====================

    /**
     * 获取指定 authId 的冷却状态文件
     * @param authId 认证凭证标识
     * @return 冷却状态文件
     */
    private File getCoolingFile(String authId) {
        // 对 authId 进行安全文件名编码
        String safeName = encodeFileName(authId);
        return new File(coolingDir, safeName + COOLING_FILE_EXT);
    }

    /**
     * 将 authId 编码为安全的文件名
     * 替换不适合文件系统的字符
     */
    private String encodeFileName(String authId) {
        return authId.replaceAll("[^a-zA-Z0-9._-]", "_")
                     .replaceAll("_{2,}", "_");
    }

    /**
     * 持久化冷却状态到 .cds 文件
     * @param authId 认证凭证标识
     */
    private void persistCoolingState(String authId) {
        CoolingEntry entry = coolingMap.get(authId);
        if (entry == null) {
            return;
        }

        ensureCoolingDir();
        File file = getCoolingFile(authId);

        try {
            JSONObject json = new JSONObject();
            json.put("version", CDS_VERSION);
            json.put("authId", authId);
            json.put("failureCount", entry.failureCount);
            json.put("cooldownUntil", entry.cooldownUntil);
            json.put("timestamp", System.currentTimeMillis());

            try (FileWriter writer = new FileWriter(file)) {
                writer.write(json.toString(2));
                writer.flush();
            }
            Log.d(TAG, "Cooling state persisted for " + authId);
        } catch (IOException e) {
            Log.e(TAG, "Failed to persist cooling state for " + authId, e);
        } catch (JSONException e) {
            Log.e(TAG, "Failed to build cooling state JSON for " + authId, e);
        }
    }

    /**
     * 从 .cds 文件加载冷却状态
     * @param file 冷却状态文件
     */
    private void loadCoolingState(File file) {
        if (!file.exists() || !file.isFile()) {
            return;
        }

        try (FileReader reader = new FileReader(file)) {
            StringBuilder sb = new StringBuilder();
            char[] buffer = new char[4096];
            int bytesRead;
            while ((bytesRead = reader.read(buffer)) != -1) {
                sb.append(buffer, 0, bytesRead);
            }

            JSONObject json = new JSONObject(sb.toString());
            String authId = json.optString("authId", null);
            if (authId == null || authId.isEmpty()) {
                Log.w(TAG, "Skipping invalid cooling file: " + file.getName());
                return;
            }

            int failureCount = json.optInt("failureCount", 0);
            long cooldownUntil = json.optLong("cooldownUntil", 0);

            // 如果冷却已过期，删除文件
            if (cooldownUntil <= System.currentTimeMillis()) {
                boolean deleted = file.delete();
                if (deleted) {
                    Log.d(TAG, "Removed expired cooling state for " + authId);
                }
                return;
            }

            coolingMap.put(authId, new CoolingEntry(failureCount, cooldownUntil));
            Log.d(TAG, "Loaded cooling state for " + authId + " (failureCount=" + failureCount
                + ", remaining=" + ((cooldownUntil - System.currentTimeMillis()) / 1000) + "s)");
        } catch (IOException e) {
            Log.e(TAG, "Failed to read cooling file: " + file.getName(), e);
        } catch (JSONException e) {
            Log.e(TAG, "Failed to parse cooling file: " + file.getName(), e);
        }
    }

    /**
     * 加载所有持久化冷却状态
     */
    private void loadAllCoolingStates() {
        File[] files = coolingDir.listFiles((dir, name) -> name.endsWith(COOLING_FILE_EXT));
        if (files == null || files.length == 0) {
            return;
        }

        int loaded = 0;
        for (File file : files) {
            loadCoolingState(file);
            loaded++;
        }
        Log.i(TAG, "Loaded " + loaded + " cooling state files");
    }

    /**
     * 删除指定 authId 的冷却文件
     * @param authId 认证凭证标识
     */
    private void deleteCoolingFile(String authId) {
        File file = getCoolingFile(authId);
        if (file.exists()) {
            boolean deleted = file.delete();
            if (!deleted) {
                Log.w(TAG, "Failed to delete cooling file for " + authId);
            }
        }
    }

    /**
     * 清理所有冷却文件
     */
    private void clearAllCoolingFiles() {
        File[] files = coolingDir.listFiles((dir, name) -> name.endsWith(COOLING_FILE_EXT));
        if (files == null) {
            return;
        }
        for (File file : files) {
            boolean deleted = file.delete();
            if (!deleted) {
                Log.w(TAG, "Failed to delete cooling file: " + file.getName());
            }
        }
        Log.i(TAG, "Cleared " + files.length + " cooling state files");
    }

    /**
     * 获取冷却状态文件目录
     * @return 冷却目录
     */
    public File getCoolingDirectory() {
        return coolingDir;
    }

    /**
     * 获取冷却状态文件版本
     * @return 版本号
     */
    public static int getCdsVersion() {
        return CDS_VERSION;
    }
}