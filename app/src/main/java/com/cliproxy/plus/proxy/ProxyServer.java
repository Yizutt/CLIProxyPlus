package com.cliproxy.plus.proxy;

import android.util.Log;

import java.io.IOException;

import fi.iki.elonen.NanoHTTPD;

/**
 * ProxyServer - 内嵌 HTTP 代理服务器
 * 监听端口 8317，处理所有 AI API 请求
 * 对应原版 cmd/server/main.go
 */
public class ProxyServer extends NanoHTTPD {

    private static final String TAG = "ProxyServer";
    private static final int DEFAULT_PORT = 8317;

    private RequestRouter router;
    private volatile boolean isRunning;

    public ProxyServer() {
        super(DEFAULT_PORT);
        this.router = new RequestRouter();
    }

    public ProxyServer(int port) {
        super(port);
        this.router = new RequestRouter();
    }

    @Override
    public Response serve(IHTTPSession session) {
        String uri = session.getUri();
        Method method = session.getMethod();
        Map<String, String> headers = session.getHeaders();
        Map<String, String> params = session.getParms();
        String queryString = session.getQueryParameterString();

        Log.d(TAG, method + " " + uri);

        // 读取请求体
        String body = null;
        try {
            Map<String, String> files = new java.util.HashMap<>();
            session.parseBody(files);
            if (files.containsKey("postData")) {
                body = files.get("postData");
            }
        } catch (IOException | ResponseException e) {
            Log.w(TAG, "Failed to parse body: " + e.getMessage());
        }

        // 路由到对应处理器
        try {
            return router.dispatch(method, uri, headers, params, queryString, body);
        } catch (Exception e) {
            Log.e(TAG, "Request failed: " + uri, e);
            return RequestRouter.jsonResponse(500,
                    "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    public boolean startServer() {
        try {
            start(NanoHTTPD.SOCKET_READ_TIMEOUT, false);
            isRunning = true;
            Log.i(TAG, "ProxyServer started on port " + getPort());
            return true;
        } catch (IOException e) {
            Log.e(TAG, "Failed to start server", e);
            isRunning = false;
            return false;
        }
    }

    public void stopServer() {
        if (isRunning) {
            stop();
            isRunning = false;
            Log.i(TAG, "ProxyServer stopped");
        }
    }

    public boolean isRunning() {
        return isRunning;
    }

    public int getPort() {
        return getListeningPort();
    }
}