package com.cliproxy.plus.proxy;

import android.content.Context;
import android.util.Log;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * ServerManager - 管理 rootfs 中 Go 服务器的生命周期
 * 负责启动/停止/监控 cliproxy-server 进程
 */
public class ServerManager {

    private static final String TAG = "ServerManager";
    private static final String BINARY_NAME = "cliproxy-server";
    private static final int SERVER_PORT = 8317;

    private final Context context;
    private final File binDir;
    private final File configFile;
    private Process serverProcess;
    private final AtomicBoolean running = new AtomicBoolean(false);
    private Thread monitorThread;

    public ServerManager(Context context) {
        this.context = context.getApplicationContext();
        this.binDir = new File(context.getFilesDir(), "server");
        this.configFile = new File(binDir, "config.yaml");
    }

    /**
     * 初始化服务器环境：解压二进制和配置文件
     */
    public boolean initialize() {
        try {
            if (!binDir.exists()) binDir.mkdirs();

            // 解压二进制
            File binaryFile = new File(binDir, BINARY_NAME);
            if (!binaryFile.exists()) {
                try (InputStream in = context.getAssets().open(BINARY_NAME);
                     FileOutputStream out = new FileOutputStream(binaryFile)) {
                    byte[] buf = new byte[8192];
                    int len;
                    while ((len = in.read(buf)) != -1) {
                        out.write(buf, 0, len);
                    }
                }
                binaryFile.setExecutable(true);
                Log.i(TAG, "Binary extracted: " + binaryFile.getAbsolutePath());
            }

            // 创建默认配置
            if (!configFile.exists()) {
                createDefaultConfig();
            }

            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to initialize server", e);
            return false;
        }
    }

    /**
     * 启动服务器
     */
    public boolean startServer() {
        if (running.get()) return true;

        try {
            if (!initialize()) return false;

            File binaryFile = new File(binDir, BINARY_NAME);

            ProcessBuilder pb = new ProcessBuilder(
                    binaryFile.getAbsolutePath(),
                    "--config", configFile.getAbsolutePath(),
                    "--port", String.valueOf(SERVER_PORT)
            );
            pb.directory(binDir);
            pb.environment().put("HOME", binDir.getAbsolutePath());
            pb.redirectErrorStream(true);

            serverProcess = pb.start();

            // 监控进程
            monitorThread = new Thread(() -> {
                try {
                    BufferedReader reader = new BufferedReader(
                            new FileReader(serverProcess.getInputStream()));
                    String line;
                    while ((line = reader.readLine()) != null) {
                        Log.d(TAG, "[server] " + line);
                    }
                    int exitCode = serverProcess.waitFor();
                    running.set(false);
                    Log.i(TAG, "Server exited with code: " + exitCode);
                } catch (Exception e) {
                    Log.e(TAG, "Server monitor error", e);
                }
            });
            monitorThread.setDaemon(true);
            monitorThread.start();

            running.set(true);
            Log.i(TAG, "Server started on port " + SERVER_PORT);
            return true;

        } catch (IOException e) {
            Log.e(TAG, "Failed to start server", e);
            return false;
        }
    }

    /**
     * 停止服务器
     */
    public void stopServer() {
        if (serverProcess != null && running.get()) {
            serverProcess.destroy();
            try {
                serverProcess.waitFor(5000, java.util.concurrent.TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                serverProcess.destroyForcibly();
            }
            running.set(false);
            Log.i(TAG, "Server stopped");
        }
    }

    public boolean isRunning() {
        return running.get() && serverProcess != null && serverProcess.isAlive();
    }

    public int getPort() {
        return SERVER_PORT;
    }

    public String getServerUrl() {
        return "http://127.0.0.1:" + SERVER_PORT;
    }

    private void createDefaultConfig() throws IOException {
        String config = "host: 127.0.0.1\n" +
                        "port: " + SERVER_PORT + "\n" +
                        "debug: false\n" +
                        "incognito-browser: true\n" +
                        "request-retry: 3\n" +
                        "max-retry-interval: 30\n" +
                        "usage-statistics-enabled: true\n" +
                        "auth-dir: '" + new File(binDir, "auths").getAbsolutePath() + "'\n" +
                        "routing:\n" +
                        "  strategy: round-robin\n" +
                        "  session-affinity: false\n";
        java.io.FileWriter writer = new java.io.FileWriter(configFile);
        writer.write(config);
        writer.close();
        Log.i(TAG, "Default config created");
    }
}