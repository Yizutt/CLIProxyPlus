package com.cliproxy.plus.proxy;

import java.util.Map;

import fi.iki.elonen.NanoHTTPD;

import com.cliproxy.plus.proxy.handlers.OpenAIHandler;
import com.cliproxy.plus.proxy.middleware.AuthMiddleware;

/**
 * RequestRouter - 请求路由分发
 * 根据请求路径和方法路由到对应协议处理器
 * 对应原版 internal/api/server_routes.go
 */
public class RequestRouter {

    private final OpenAIHandler openAIHandler;
    private final AuthMiddleware authMiddleware;

    // 协议识别常量
    private static final String PREFIX_OPENAI = "/v1/chat/completions";
    private static final String PREFIX_OPENAI_COMPLETIONS = "/v1/completions";
    private static final String PREFIX_OPENAI_MODELS = "/v1/models";
    private static final String PREFIX_OPENAI_IMAGES = "/v1/images";
    private static final String PREFIX_OPENAI_RESPONSES = "/v1/responses";
    private static final String PREFIX_OPENAI_VIDEOS = "/v1/videos";
    private static final String PREFIX_CLAUDE = "/v1/messages";
    private static final String PREFIX_GEMINI = "/v1beta";
    private static final String PREFIX_CODEX = "/backend-api/codex";
    private static final String PREFIX_OPENAI_VIDEOS = "/openai/v1/videos";
    private static final String PREFIX_LIVE = "/v1/live";
    private static final String PREFIX_REALTIME = "/v1/realtime";
    private static final String PREFIX_ALPHA_SEARCH = "/v1/alpha/search";
    private static final String PREFIX_MANAGEMENT = "/v0/management";
    private static final String PREFIX_HEALTH = "/healthz";

    public RequestRouter() {
        this.openAIHandler = new OpenAIHandler();
        this.authMiddleware = new AuthMiddleware();
    }

    public NanoHTTPD.Response dispatch(NanoHTTPD.Method method, String uri,
                                        Map<String, String> headers,
                                        Map<String, String> params,
                                        String queryString, String body) {

        // 健康检查
        if (uri.equals(PREFIX_HEALTH) || uri.equals("/health")) {
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
        if (uri.equals(PREFIX_CLAUDE) || uri.startsWith(PREFIX_CLAUDE)) {
            return handleClaudeMessage(method, headers, body);
        }

        if (uri.startsWith(PREFIX_GEMINI)) {
            return handleGeminiRequest(method, uri, headers, body);
        }

        if (uri.startsWith(PREFIX_CODEX)) {
            return handleCodexRequest(method, uri, headers, body);
        }

        if (uri.startsWith(PREFIX_OPENAI_VIDEOS)) {
            return handleVideoRequest(method, uri, headers, body);
        }

        // 默认：返回根信息
        if (uri.equals("/")) {
            return jsonResponse(200, "{\"service\":\"CLIProxy Plus\",\"version\":\"6.9.45\"}");
        }

        return jsonResponse(404, "{\"error\":\"Not Found\"}");
    }

    private NanoHTTPD.Response handleOpenAIChat(NanoHTTPD.Method method, Map<String, String> headers, String body) {
        // 暂存 - 等待 OpenAIHandler 实现
        return jsonResponse(501, "{\"error\":\"OpenAI handler not yet implemented\"}");
    }

    private NanoHTTPD.Response handleClaudeMessage(NanoHTTPD.Method method, Map<String, String> headers, String body) {
        return jsonResponse(501, "{\"error\":\"Claude handler not yet implemented\"}");
    }

    private NanoHTTPD.Response handleGeminiRequest(NanoHTTPD.Method method, String uri, Map<String, String> headers, String body) {
        return jsonResponse(501, "{\"error\":\"Gemini handler not yet implemented\"}");
    }

    private NanoHTTPD.Response handleCodexRequest(NanoHTTPD.Method method, String uri, Map<String, String> headers, String body) {
        return jsonResponse(501, "{\"error\":\"Codex handler not yet implemented\"}");
    }

    private NanoHTTPD.Response handleVideoRequest(NanoHTTPD.Method method, String uri, Map<String, String> headers, String body) {
        return jsonResponse(501, "{\"error\":\"Video handler not yet implemented\"}");
    }

    /**
     * 创建 JSON 响应
     */
    public static NanoHTTPD.Response jsonResponse(int statusCode, String json) {
        NanoHTTPD.Response.Status status = NanoHTTPD.Response.Status.lookup(statusCode);
        NanoHTTPD.Response response = new NanoHTTPD.Response(status, "application/json", json);
        response.addHeader("Access-Control-Allow-Origin", "*");
        response.addHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, PATCH, OPTIONS");
        response.addHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
        return response;
    }

    /**
     * 创建 SSE 流式响应
     */
    public static NanoHTTPD.Response sseResponse(String initialData) {
        NanoHTTPD.Response response = NanoHTTPD.newChunkedResponse(NanoHTTPD.Response.Status.OK, "text/event-stream", null);
        response.addHeader("Cache-Control", "no-cache");
        response.addHeader("Connection", "keep-alive");
        response.addHeader("Access-Control-Allow-Origin", "*");
        return response;
    }
}