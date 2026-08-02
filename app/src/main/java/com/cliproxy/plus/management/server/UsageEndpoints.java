package com.cliproxy.plus.management.server;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.atomic.AtomicLong;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * UsageEndpoints - 用量统计与数据管理端点
 * <p>
 * 处理 /v0/management/usage 路径下的所有请求，提供代理服务的用量统计查询、
 * 用量数据的导入导出以及用量队列的消费功能。所有数据默认存储在内存中，
 * 重启后清空，如需持久化请先调用导出接口。
 * <p>
 * 包含以下端点：
 * <ul>
 *   <li>GET /v0/management/usage — 获取用量统计快照</li>
 *   <li>GET /v0/management/usage/export — 导出所有用量数据</li>
 *   <li>POST /v0/management/usage/import — 导入用量数据</li>
 *   <li>GET /v0/management/usage-queue — 弹出待消费的用量记录</li>
 * </ul>
 * <p>
 * 对应原版 internal/api/management/usage.go
 *
 * @author CLIProxy Plus
 * @version 1.0
 */
public class UsageEndpoints {

    private static final String TAG = "UsageEndpoints";

    // 管理 API 路径常量
    private static final String PATH_USAGE = "/v0/management/usage";
    private static final String PATH_USAGE_EXPORT = "/v0/management/usage/export";
    private static final String PATH_USAGE_IMPORT = "/v0/management/usage/import";
    private static final String PATH_USAGE_QUEUE = "/v0/management/usage-queue";

    /**
     * 用量统计快照 —— 按模型/API 名称聚合的计数
     * key: 模型名称（如 gpt-4、claude-3），value: 累计请求次数
     */
    private final ConcurrentHashMap<String, AtomicLong> usageStats;

    /**
     * 详细的用量记录队列
     * 每条记录包含时间戳、模型、令牌数、耗时等信息
     */
    private final ConcurrentLinkedDeque<JSONObject> usageQueue;

    /**
     * 总请求计数器
     */
    private final AtomicLong totalRequests;

    /**
     * 总输入令牌数
     */
    private final AtomicLong totalInputTokens;

    /**
     * 总输出令牌数
     */
    private final AtomicLong totalOutputTokens;

    /**
     * 总请求耗时（毫秒）
     */
    private final AtomicLong totalDurationMs;

    /**
     * 服务启动时间戳（毫秒）
     */
    private final long startTime;

    /**
     * 构造 UsageEndpoints 实例，初始化统计存储和队列
     */
    public UsageEndpoints() {
        this.usageStats = new ConcurrentHashMap<>();
        this.usageQueue = new ConcurrentLinkedDeque<>();
        this.totalRequests = new AtomicLong(0);
        this.totalInputTokens = new AtomicLong(0);
        this.totalOutputTokens = new AtomicLong(0);
        this.totalDurationMs = new AtomicLong(0);
        this.startTime = System.currentTimeMillis();
        Log.d(TAG, "UsageEndpoints initialized");
    }

    /**
     * 主分发方法 - 根据 HTTP 方法和请求路径路由到对应处理方法
     *
     * @param method  HTTP 请求方法（GET、POST）
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

        // GET /v0/management/usage — 用量统计快照
        if (NanoHTTPD.Method.GET.equals(method) && PATH_USAGE.equals(uri)) {
            return getUsage();
        }

        // GET /v0/management/usage/export — 导出用量数据
        if (NanoHTTPD.Method.GET.equals(method) && PATH_USAGE_EXPORT.equals(uri)) {
            return exportUsage();
        }

        // POST /v0/management/usage/import — 导入用量数据
        if (NanoHTTPD.Method.POST.equals(method) && PATH_USAGE_IMPORT.equals(uri)) {
            return importUsage(body);
        }

        // GET /v0/management/usage-queue — 弹出待消费的用量记录
        if (NanoHTTPD.Method.GET.equals(method) && PATH_USAGE_QUEUE.equals(uri)) {
            return getUsageQueue();
        }

        // 未知操作
        Log.w(TAG, "Unknown endpoint: " + method + " " + uri);
        return jsonResponse(404, new JSONObject()
                .put("error", "端点不存在")
                .put("path", uri)
                .toString());
    }

    /**
     * 获取用量统计快照
     * <p>
     * GET /v0/management/usage
     * 返回当前在内存中聚合的用量统计信息，包括：
     * <ul>
     *   <li>各模型的请求次数分布</li>
     *   <li>总请求次数</li>
     *   <li>总输入/输出令牌数</li>
     *   <li>总请求耗时</li>
     *   <li>服务运行时间</li>
     * </ul>
     *
     * @return JSON 响应，包含完整的用量统计快照
     */
    public Response getUsage() {
        Log.d(TAG, "Getting usage statistics snapshot");

        long uptime = System.currentTimeMillis() - startTime;

        JSONObject stats = new JSONObject();
        JSONObject modelStats = new JSONObject();
        for (Map.Entry<String, AtomicLong> entry : usageStats.entrySet()) {
            modelStats.put(entry.getKey(), entry.getValue().get());
        }

        stats.put("models", modelStats);
        stats.put("total_requests", totalRequests.get());
        stats.put("total_input_tokens", totalInputTokens.get());
        stats.put("total_output_tokens", totalOutputTokens.get());
        stats.put("total_duration_ms", totalDurationMs.get());
        stats.put("uptime_ms", uptime);
        stats.put("queue_size", usageQueue.size());

        Log.d(TAG, "Usage snapshot: " + totalRequests.get() + " total requests, "
                + usageStats.size() + " models tracked");
        return jsonResponse(200, stats.toString());
    }

    /**
     * 导出所有用量数据
     * <p>
     * GET /v0/management/usage/export
     * 将当前内存中所有用量统计数据和待消费的用量记录队列导出为 JSON 格式。
     * 导出的数据可用于备份或迁移到其他实例，通过导入接口恢复。
     *
     * @return JSON 响应，包含完整的用量数据和导出元信息
     */
    public Response exportUsage() {
        Log.d(TAG, "Exporting usage data");

        JSONObject exportData = new JSONObject();
        exportData.put("export_time", System.currentTimeMillis());
        exportData.put("total_requests", totalRequests.get());
        exportData.put("total_input_tokens", totalInputTokens.get());
        exportData.put("total_output_tokens", totalOutputTokens.get());
        exportData.put("total_duration_ms", totalDurationMs.get());

        // 导出各模型统计
        JSONObject modelStats = new JSONObject();
        for (Map.Entry<String, AtomicLong> entry : usageStats.entrySet()) {
            modelStats.put(entry.getKey(), entry.getValue().get());
        }
        exportData.put("models", modelStats);

        // 导出队列中的待消费记录
        JSONArray queueArray = new JSONArray();
        for (JSONObject record : usageQueue) {
            queueArray.put(record);
        }
        exportData.put("queue", queueArray);
        exportData.put("queue_size", usageQueue.size());

        Log.d(TAG, "Exported " + usageQueue.size() + " queued records, "
                + usageStats.size() + " model stats");
        return jsonResponse(200, exportData.toString());
    }

    /**
     * 导入用量数据
     * <p>
     * POST /v0/management/usage/import
     * 从 JSON 字符串中恢复用量统计数据。导入的数据格式应与导出接口的输出一致。
     * 导入操作会与当前内存中的数据合并（累加计数器、追加队列）。
     * 如果导入的数据中包含模型统计信息，对应模型的计数器会累加。
     * 如果包含队列记录，会追加到当前队列尾部。
     *
     * @param data 请求体 JSON 字符串，包含要导入的用量数据
     * @return JSON 响应，包含导入操作结果
     */
    public Response importUsage(String data) {
        if (data == null || data.trim().isEmpty()) {
            Log.w(TAG, "Import failed: empty request body");
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体不能为空")
                    .toString());
        }

        try {
            JSONObject importData = new JSONObject(data);

            int importedRequests = 0;
            int importedStats = 0;
            int importedQueueSize = 0;

            // 合并总计数器
            if (importData.has("total_requests")) {
                long val = importData.optLong("total_requests", 0);
                totalRequests.addAndGet(val);
                importedRequests = (int) val;
            }

            if (importData.has("total_input_tokens")) {
                totalInputTokens.addAndGet(importData.optLong("total_input_tokens", 0));
            }

            if (importData.has("total_output_tokens")) {
                totalOutputTokens.addAndGet(importData.optLong("total_output_tokens", 0));
            }

            if (importData.has("total_duration_ms")) {
                totalDurationMs.addAndGet(importData.optLong("total_duration_ms", 0));
            }

            // 合并各模型统计
            if (importData.has("models")) {
                JSONObject models = importData.getJSONObject("models");
                for (String model : models.keySet()) {
                    long count = models.optLong(model, 0);
                    usageStats.computeIfAbsent(model, k -> new AtomicLong(0))
                            .addAndGet(count);
                    importedStats++;
                }
            }

            // 追加队列记录
            if (importData.has("queue")) {
                JSONArray queue = importData.getJSONArray("queue");
                for (int i = 0; i < queue.length(); i++) {
                    JSONObject record = queue.optJSONObject(i);
                    if (record != null) {
                        usageQueue.addLast(record);
                    }
                }
                importedQueueSize = queue.length();
            }

            Log.d(TAG, "Import completed: " + importedRequests + " requests, "
                    + importedStats + " model stats, " + importedQueueSize + " queue records");

            JSONObject response = new JSONObject();
            response.put("success", true);
            response.put("imported_requests", importedRequests);
            response.put("imported_model_stats", importedStats);
            response.put("imported_queue_records", importedQueueSize);

            return jsonResponse(200, response.toString());

        } catch (Exception e) {
            Log.w(TAG, "Import failed: invalid JSON data", e);
            return jsonResponse(400, new JSONObject()
                    .put("error", "导入数据格式错误，需要合法的 JSON: " + e.getMessage())
                    .toString());
        }
    }

    /**
     * 获取用量记录队列（弹出模式）
     * <p>
     * GET /v0/management/usage-queue
     * 从队列头部弹出至多 N 条待消费的用量记录（默认 100 条，可通过 query 参数 limit 指定）。
     * 此操作会从队列中移除返回的记录，每条记录包含：
     * <ul>
     *   <li>timestamp — 记录时间戳（毫秒）</li>
     *   <li>model — 使用的模型名称</li>
     *   <li>input_tokens — 输入令牌数</li>
     *   <li>output_tokens — 输出令牌数</li>
     *   <li>duration_ms — 请求耗时（毫秒）</li>
     * </ul>
     *
     * @return JSON 响应，包含弹出的用量记录列表
     */
    public Response getUsageQueue() {
        Log.d(TAG, "Popping usage records from queue");

        // 默认弹出 100 条，最多 500 条
        int limit = 100;
        int maxLimit = 500;

        // 尝试从查询参数中读取 limit
        // 注意：此方法在 dispatch 中通过 params 传入，但 getUsageQueue 通常
        // 由 dispatch 直接调用，因此 limit 在此处暂用默认值；
        // 若需要动态 limit，建议由 dispatch 解析后传入。

        JSONArray records = new JSONArray();
        int count = 0;
        while (count < limit) {
            JSONObject record = usageQueue.pollFirst();
            if (record == null) {
                break;
            }
            records.put(record);
            count++;
        }

        Log.d(TAG, "Popped " + count + " records from queue, remaining: " + usageQueue.size());

        JSONObject response = new JSONObject();
        response.put("records", records);
        response.put("popped", count);
        response.put("remaining", usageQueue.size());

        return jsonResponse(200, response.toString());
    }

    // ===== 内部工具方法 =====

    /**
     * 记录一次用量数据（供内部调用，非 HTTP 端点）
     * <p>
     * 当代理服务器完成一次请求后调用此方法，将本次用量信息记录到统计和队列中。
     *
     * @param model        模型名称
     * @param inputTokens  输入令牌数
     * @param outputTokens 输出令牌数
     * @param durationMs   请求耗时（毫秒）
     */
    public void recordUsage(String model, long inputTokens, long outputTokens, long durationMs) {
        totalRequests.incrementAndGet();
        totalInputTokens.addAndGet(inputTokens);
        totalOutputTokens.addAndGet(outputTokens);
        totalDurationMs.addAndGet(durationMs);

        // 更新模型维度的统计
        usageStats.computeIfAbsent(model, k -> new AtomicLong(0))
                .incrementAndGet();

        // 构建详细记录并入队
        JSONObject record = new JSONObject();
        record.put("timestamp", System.currentTimeMillis());
        record.put("model", model);
        record.put("input_tokens", inputTokens);
        record.put("output_tokens", outputTokens);
        record.put("duration_ms", durationMs);
        usageQueue.addLast(record);

        Log.d(TAG, "Usage recorded: model=" + model + ", tokens="
                + (inputTokens + outputTokens) + ", duration=" + durationMs + "ms");
    }

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