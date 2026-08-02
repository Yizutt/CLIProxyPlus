package com.cliproxy.plus.proxy;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;

import com.cliproxy.plus.proxy.handlers.ClaudeHandler;
import com.cliproxy.plus.proxy.handlers.GeminiHandler;
import com.cliproxy.plus.proxy.handlers.OpenAIHandler;
import com.cliproxy.plus.proxy.middleware.AuthMiddleware;

/**
 * RequestRouter - 请求路由分发
 * 根据请求路径和方法路由到对应协议处理器
 * 对应原版 internal/api/server_routes.go
 */
public class RequestRouter {

    private final OpenAIHandler openAIHandler;
    private final ClaudeHandler claudeHandler;
    private final GeminiHandler geminiHandler;
    private final AuthMiddleware authMiddleware;

    // 协议识别常量
    private static final String PREFIX_OPENAI = "/v1/chat/completions";
    private static final String PREFIX_OPENAI_MODELS = "/v1/models";
    private static final String PREFIX_CLAUDE = "/v1/messages";
    private static final String PREFIX_GEMINI = "/v1beta";
    private static final String PREFIX_CODEX = "/backend-api/codex";
    private static final String PREFIX_OPENAI_VIDEOS = "/openai/v1/videos";
    private static final String PREFIX_MANAGEMENT = "/v0/management";

    public RequestRouter() {
        this.openAIHandler = new OpenAIHandler();
        this.claudeHandler = new ClaudeHandler();
        this.geminiHandler = new GeminiHandler();
        this.authMiddleware = new AuthMiddleware();
    }

    public Response dispatch(NanoHTTPD.Method method, String uri,
                                        Map<String, String> headers,
                                        Map<String, String> params,
                                        String queryString, String body) {

        // 健康检查
        if (uri.equals("/healthz") || uri.equals("/health")) {
            return jsonResponse(200, "{\"status\":\"ok\",\"version\":\"6.9.45\"}");
        }

        // CORS OPTIONS 预检
        if (method == NanoHTTPD.Method.OPTIONS) {
            return jsonResponse(200, "{}");
        }

        // 管理 API
        if (uri.startsWith(PREFIX_MANAGEMENT)) {
            return jsonResponse(200, "{\"message\":\"Management API not yet implemented\"}");
        }

        // 模型列表
        if (uri.equals(PREFIX_OPENAI_MODELS)) {
            return jsonResponse(200, "{\"object\":\"list\",\"data\":[{\"id\":\"gpt-4\"," +
                    "\"object\":\"model\",\"created\":1700000000,\"owned_by\":\"cliproxy\"}]}");
        }

        // OpenAI 聊天完成
        if (uri.equals(PREFIX_OPENAI) || uri.equals("/v1/chat/completions")) {
            return openAIHandler.handleChatCompletion(headers, body);
        }

        // 其他协议暂存
        if (uri.equals(PREFIX_CLAUDE) || uri.startsWith(PREFIX_CLAUDE + "/")) {
            return claudeHandler.handleMessage(headers, body);
        }

        if (uri.startsWith(PREFIX_GEMINI)) {
            return geminiHandler.handleRequest(uri, headers, body);
        }

        if (uri.startsWith(PREFIX_CODEX)) {
            return jsonResponse(501, "{\"error\":\"Codex handler not yet implemented\"}");
        }

        if (uri.startsWith(PREFIX_OPENAI_VIDEOS)) {
            return jsonResponse(501, "{\"error\":\"Video handler not yet implemented\"}");
        }

        // 默认：返回根信息
        if (uri.equals("/")) {
            return jsonResponse(200, "{\"service\":\"CLIProxy Plus\",\"version\":\"6.9.45\"}");
        }

        return jsonResponse(404, "{\"error\":\"Not Found\"}");
    }

    /**
     * 创建 JSON 响应
     */
    public static Response jsonResponse(int statusCode, String json) {
        Response.Status status = Response.Status.lookup(statusCode);
        InputStream in = new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));
        Response response = NanoHTTPD.newChunkedResponse(status, "application/json", in);
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return response;
    }

    /**
     * 创建 SSE 流式响应
     */
    public static Response sseResponse(String initialData) {
        InputStream in = new ByteArrayInputStream(initialData.getBytes(StandardCharsets.UTF_8));
        Response response = NanoHTTPD.newChunkedResponse(Response.Status.OK, "text/event-stream", in);
        response.addHeader("Cache-Control", "no-cache");
        response.addHeader("Connection", "keep-alive");
        response.addHeader("Access-Control-Allow-Origin", "*");
        return response;
    }
}