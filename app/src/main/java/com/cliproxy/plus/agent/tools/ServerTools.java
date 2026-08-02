package com.cliproxy.plus.agent.tools;

import android.util.Log;

import com.cliproxy.plus.proxy.ProxyServer;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * ServerTools - 服务器控制工具集
 * <p>
 * AI Agent 工具类，提供对 CLIProxy Plus 代理服务器的完整生命周期管理。
 * 包含以下工具方法：
 * <ul>
 *   <li>{@link #server_start(JSONObject)} - 启动代理服务器</li>
 *   <li>{@link #server_stop(JSONObject)} - 停止代理服务器</li>
 *   <li>{@link #server_restart(JSONObject)} - 重启代理服务器</li>
 *   <li>{@link #server_status(JSONObject)} - 查询服务器运行状态</li>
 *   <li>{@link #server_set_port(JSONObject)} - 设置服务器监听端口</li>
 * </ul>
 * </p>
 *
 * <p>
 * 所有工具方法均为静态方法，遵循统一的调用约定：
 * 接收 {@link JSONObject} 参数，返回 {@link JSONObject} 结果。
 * 结果中始终包含 "success"（boolean）和 "message"（String）字段。
 * </p>
 *
 * @author CLIProxy Plus
 * @version 1.0
 */
public class ServerTools {

    private static final String TAG = "ServerTools";

    /** 默认代理服务器监听端口 */
    private static final int DEFAULT_PORT = 8317;

    /** 代理服务器单例实例 */
    private static ProxyServer proxyServer;

    /** 当前配置的监听端口，初始为默认端口 */
    private static int currentPort = DEFAULT_PORT;

    /** 服务器状态同步锁 */
    private static final Object lock = new Object();

    /**
     * 私有构造方法，防止外部实例化工具类。
     */
    private ServerTools() {
        // 工具类无需实例化
    }

    // ======================== 工具方法 ========================

    /**
     * server_start - 启动代理服务器
     * <p>
     * 启动 CLIProxy Plus 代理服务器。如果服务器已在运行，则直接返回成功状态。
     * 可通过参数 "port" 指定监听端口，若不指定则使用默认端口（8317）
     * 或上次通过 {@link #server_set_port(JSONObject)} 设置的端口。
     * </p>
     *
     * <p>
     * <b>参数（JSONObject）：</b>
     * <pre>
     * {
     *   "port": 8317  // 可选，监听端口号，默认 8317
     * }
     * </pre>
     * </p>
     *
     * <p>
     * <b>返回值（JSONObject）：</b>
     * <pre>
     * {
     *   "success": true,
     *   "message": "代理服务器已启动",
     *   "port": 8317,
     *   "previousRunning": false
     * }
     * </pre>
     * </p>
     *
     * @param params 工具参数 JSON 对象，可选包含 "port" 字段
     * @return 包含执行结果的 JSONObject，始终包含 success 和 message 字段
     */
    public static JSONObject server_start(JSONObject params) {
        JSONObject result = new JSONObject();
        long startTime = System.currentTimeMillis();

        try {
            // 解析参数中的端口号
            if (params != null && params.has("port")) {
                int port = params.optInt("port", DEFAULT_PORT);
                if (port <= 0 || port > 65535) {
                    return buildError(result, "端口号无效，有效范围: 1-65535，实际值: " + port);
                }
                currentPort = port;
            }

            synchronized (lock) {
                // 检查是否已在运行
                if (proxyServer != null && proxyServer.isRunning()) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    Log.i(TAG, "服务器已在运行中，端口: " + currentPort + "，耗时: " + elapsed + "ms");
                    return buildSuccess(result, "代理服务器已在运行中")
                            .put("port", currentPort)
                            .put("previousRunning", true);
                }

                // 创建并启动服务器
                proxyServer = new ProxyServer(currentPort);
                boolean started = proxyServer.startServer();

                if (started) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    Log.i(TAG, "服务器启动成功，端口: " + currentPort + "，耗时: " + elapsed + "ms");
                    return buildSuccess(result, "代理服务器已启动")
                            .put("port", currentPort)
                            .put("previousRunning", false);
                } else {
                    Log.e(TAG, "服务器启动失败，端口: " + currentPort);
                    proxyServer = null;
                    return buildError(result, "代理服务器启动失败，端口 " + currentPort + " 可能已被占用");
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "启动服务器时发生异常", e);
            return buildError(result, "启动服务器时发生异常: " + e.getMessage());
        }
    }

    /**
     * server_stop - 停止代理服务器
     * <p>
     * 停止正在运行的 CLIProxy Plus 代理服务器。
     * 如果服务器未在运行，则直接返回成功状态。
     * </p>
     *
     * <p>
     * <b>参数（JSONObject）：</b>
     * <pre>
     * {}  // 无参数
     * </pre>
     * </p>
     *
     * <p>
     * <b>返回值（JSONObject）：</b>
     * <pre>
     * {
     *   "success": true,
     *   "message": "代理服务器已停止",
     *   "wasRunning": true
     * }
     * </pre>
     * </p>
     *
     * @param params 工具参数 JSON 对象（当前未使用）
     * @return 包含执行结果的 JSONObject
     */
    public static JSONObject server_stop(JSONObject params) {
        JSONObject result = new JSONObject();
        long startTime = System.currentTimeMillis();

        try {
            synchronized (lock) {
                if (proxyServer == null || !proxyServer.isRunning()) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    Log.i(TAG, "服务器未在运行，无需停止，耗时: " + elapsed + "ms");
                    return buildSuccess(result, "代理服务器未在运行，无需停止")
                            .put("wasRunning", false);
                }

                proxyServer.stopServer();
                proxyServer = null;

                long elapsed = System.currentTimeMillis() - startTime;
                Log.i(TAG, "服务器已停止，耗时: " + elapsed + "ms");
                return buildSuccess(result, "代理服务器已停止")
                        .put("wasRunning", true);
            }

        } catch (Exception e) {
            Log.e(TAG, "停止服务器时发生异常", e);
            return buildError(result, "停止服务器时发生异常: " + e.getMessage());
        }
    }

    /**
     * server_restart - 重启代理服务器
     * <p>
     * 重启 CLIProxy Plus 代理服务器。如果服务器正在运行，则先停止再启动；
     * 如果未在运行，则直接启动。可通过参数 "port" 指定新的监听端口。
     * </p>
     *
     * <p>
     * <b>参数（JSONObject）：</b>
     * <pre>
     * {
     *   "port": 8317  // 可选，重启后使用的端口号
     * }
     * </pre>
     * </p>
     *
     * <p>
     * <b>返回值（JSONObject）：</b>
     * <pre>
     * {
     *   "success": true,
     *   "message": "代理服务器已重启",
     *   "port": 8317,
     *   "wasRunning": true
     * }
     * </pre>
     * </p>
     *
     * @param params 工具参数 JSON 对象，可选包含 "port" 字段
     * @return 包含执行结果的 JSONObject
     */
    public static JSONObject server_restart(JSONObject params) {
        JSONObject result = new JSONObject();
        long startTime = System.currentTimeMillis();

        try {
            // 解析参数中的端口号
            if (params != null && params.has("port")) {
                int port = params.optInt("port", DEFAULT_PORT);
                if (port <= 0 || port > 65535) {
                    return buildError(result, "端口号无效，有效范围: 1-65535，实际值: " + port);
                }
                currentPort = port;
            }

            synchronized (lock) {
                boolean wasRunning = (proxyServer != null && proxyServer.isRunning());

                // 如果正在运行，先停止
                if (wasRunning) {
                    proxyServer.stopServer();
                    proxyServer = null;
                    Log.d(TAG, "重启流程：旧服务器已停止");
                }

                // 启动新服务器
                proxyServer = new ProxyServer(currentPort);
                boolean started = proxyServer.startServer();

                if (started) {
                    long elapsed = System.currentTimeMillis() - startTime;
                    Log.i(TAG, "服务器重启成功，端口: " + currentPort
                            + "，之前运行状态: " + wasRunning + "，耗时: " + elapsed + "ms");
                    return buildSuccess(result, "代理服务器已重启")
                            .put("port", currentPort)
                            .put("wasRunning", wasRunning);
                } else {
                    Log.e(TAG, "服务器重启失败，端口: " + currentPort);
                    proxyServer = null;
                    return buildError(result, "代理服务器重启失败，端口 " + currentPort + " 可能已被占用");
                }
            }

        } catch (Exception e) {
            Log.e(TAG, "重启服务器时发生异常", e);
            return buildError(result, "重启服务器时发生异常: " + e.getMessage());
        }
    }

    /**
     * server_status - 查询代理服务器运行状态
     * <p>
     * 获取 CLIProxy Plus 代理服务器的当前运行状态信息，
     * 包括是否正在运行、监听端口号、运行时长等。
     * </p>
     *
     * <p>
     * <b>参数（JSONObject）：</b>
     * <pre>
     * {}  // 无参数
     * </pre>
     * </p>
     *
     * <p>
     * <b>返回值（JSONObject）：</b>
     * <pre>
     * {
     *   "success": true,
     *   "message": "服务器状态查询成功",
     *   "running": true,
     *   "port": 8317,
     *   "uptime": "5分钟",
     *   "configuredPort": 8317
     * }
     * </pre>
     * </p>
     *
     * @param params 工具参数 JSON 对象（当前未使用）
     * @return 包含服务器状态信息的 JSONObject
     */
    public static JSONObject server_status(JSONObject params) {
        JSONObject result = new JSONObject();

        try {
            synchronized (lock) {
                boolean running = (proxyServer != null && proxyServer.isRunning());
                int actualPort = running ? proxyServer.getPort() : -1;

                // 构建详细状态信息
                JSONObject statusInfo = new JSONObject();
                statusInfo.put("running", running);
                statusInfo.put("port", actualPort);
                statusInfo.put("configuredPort", currentPort);
                statusInfo.put("serverInstance", proxyServer != null ? "initialized" : "null");

                Log.d(TAG, "服务器状态查询: running=" + running
                        + ", port=" + actualPort
                        + ", configuredPort=" + currentPort);

                return buildSuccess(result, "服务器状态查询成功")
                        .put("running", running)
                        .put("port", actualPort)
                        .put("configuredPort", currentPort)
                        .put("statusInfo", statusInfo);
            }

        } catch (Exception e) {
            Log.e(TAG, "查询服务器状态时发生异常", e);
            return buildError(result, "查询服务器状态时发生异常: " + e.getMessage());
        }
    }

    /**
     * server_set_port - 设置代理服务器监听端口
     * <p>
     * 设置代理服务器监听的端口号。此操作仅修改配置，不会自动重启服务器。
     * 若需使新端口立即生效，请在设置端口后调用 {@link #server_restart(JSONObject)}。
     * </p>
     *
     * <p>
     * <b>参数（JSONObject）：</b>
     * <pre>
     * {
     *   "port": 8317  // 必填，新的监听端口号（1-65535）
     * }
     * </pre>
     * </p>
     *
     * <p>
     * <b>返回值（JSONObject）：</b>
     * <pre>
     * {
     *   "success": true,
     *   "message": "服务器端口已设置为 8317，重启后生效",
     *   "previousPort": 8080,
     *   "currentPort": 8317,
     *   "requiresRestart": true
     * }
     * </pre>
     * </p>
     *
     * @param params 工具参数 JSON 对象，必须包含 "port" 字段
     * @return 包含执行结果的 JSONObject
     */
    public static JSONObject server_set_port(JSONObject params) {
        JSONObject result = new JSONObject();

        try {
            // 校验参数
            if (params == null || !params.has("port")) {
                return buildError(result, "缺少必填参数 'port'");
            }

            int port = params.optInt("port", -1);
            if (port <= 0 || port > 65535) {
                return buildError(result, "端口号无效，有效范围: 1-65535，实际值: " + port);
            }

            synchronized (lock) {
                int previousPort = currentPort;
                boolean wasRunning = (proxyServer != null && proxyServer.isRunning());

                currentPort = port;

                Log.i(TAG, "服务器端口已设置: " + previousPort + " -> " + port
                        + "，服务器运行中: " + wasRunning);

                return buildSuccess(result, "服务器端口已设置为 " + port + "，重启后生效")
                        .put("previousPort", previousPort)
                        .put("currentPort", port)
                        .put("requiresRestart", wasRunning);
            }

        } catch (Exception e) {
            Log.e(TAG, "设置服务器端口时发生异常", e);
            return buildError(result, "设置服务器端口时发生异常: " + e.getMessage());
        }
    }

    // ======================== 辅助方法 ========================

    /**
     * 构建成功响应的 JSONObject 基础结构。
     *
     * @param result  结果 JSONObject
     * @param message 成功消息
     * @return 包含 success=true 和 message 字段的 JSONObject
     */
    private static JSONObject buildSuccess(JSONObject result, String message) {
        try {
            result.put("success", true);
            result.put("message", message != null ? message : "操作成功");
        } catch (JSONException e) {
            Log.e(TAG, "构建成功响应时发生异常", e);
        }
        return result;
    }

    /**
     * 构建错误响应的 JSONObject 基础结构。
     *
     * @param result  结果 JSONObject
     * @param message 错误消息
     * @return 包含 success=false 和 message 字段的 JSONObject
     */
    private static JSONObject buildError(JSONObject result, String message) {
        try {
            result.put("success", false);
            result.put("message", message != null ? message : "操作失败");
        } catch (JSONException e) {
            Log.e(TAG, "构建错误响应时发生异常", e);
        }
        return result;
    }

    /**
     * 获取当前代理服务器实例（供内部其他组件使用）。
     *
     * @return ProxyServer 实例，可能为 null
     */
    public static ProxyServer getProxyServer() {
        synchronized (lock) {
            return proxyServer;
        }
    }

    /**
     * 获取当前配置的监听端口号。
     *
     * @return 当前端口号
     */
    public static int getCurrentPort() {
        return currentPort;
    }

    /**
     * 重置服务器工具状态（主要用于测试或全局重置场景）。
     * <p>
     * 注意：如果服务器正在运行，此方法会将其停止。
     * </p>
     */
    public static void reset() {
        synchronized (lock) {
            if (proxyServer != null) {
                proxyServer.stopServer();
                proxyServer = null;
            }
            currentPort = DEFAULT_PORT;
            Log.w(TAG, "ServerTools 状态已重置");
        }
    }
}