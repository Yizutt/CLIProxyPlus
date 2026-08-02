package com.cliproxy.plus.management.server;

import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import fi.iki.elonen.NanoHTTPD;
import fi.iki.elonen.NanoHTTPD.Response;

import org.json.JSONArray;
import org.json.JSONObject;

/**
 * AuthFileEndpoints - 凭证文件管理端点
 * <p>
 * 处理 /v0/management/auth-files 路径下的所有请求，提供凭证文件（API Key、Token 等）
 * 的增删改查功能。每个凭证文件以名称标识，内容为 JSON 格式的认证凭据数据。
 * 支持禁用/启用状态切换，用于在不删除文件的情况下临时停用某个认证配置。
 * <p>
 * 对应原版 internal/api/management/authfile.go
 *
 * @author CLIProxy Plus
 * @version 1.0
 */
public class AuthFileEndpoints {

    private static final String TAG = "AuthFileEndpoints";

    // 管理 API 路径前缀
    private static final String PREFIX_AUTH_FILES = "/v0/management/auth-files";
    private static final String PATH_AUTH_FILES_MODELS = "/v0/management/auth-files/models";

    /**
     * 内存中存储的凭证文件映射表
     * key: 文件名，value: 文件内容（JSON 字符串）
     */
    private final ConcurrentHashMap<String, String> authFiles;

    /**
     * 凭证文件禁用状态映射表
     * key: 文件名，value: 是否禁用
     */
    private final ConcurrentHashMap<String, Boolean> disabledStatus;

    /**
     * 凭证文件关联的模型列表
     * key: 文件名，value: 模型名称数组（JSON 字符串）
     */
    private final ConcurrentHashMap<String, String> fileModels;

    /**
     * 构造 AuthFileEndpoints 实例，初始化内部存储
     */
    public AuthFileEndpoints() {
        this.authFiles = new ConcurrentHashMap<>();
        this.disabledStatus = new ConcurrentHashMap<>();
        this.fileModels = new ConcurrentHashMap<>();
        Log.d(TAG, "AuthFileEndpoints initialized");
    }

    /**
     * 主分发方法 - 根据 HTTP 方法和请求路径路由到对应处理方法
     *
     * @param method  HTTP 请求方法（GET、POST、DELETE、PATCH）
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

        // GET /v0/management/auth-files/models — 返回每个凭证文件关联的模型
        if (NanoHTTPD.Method.GET.equals(method) && PATH_AUTH_FILES_MODELS.equals(uri)) {
            return getAuthFileModels();
        }

        // GET /v0/management/auth-files — 列出所有凭证文件
        if (NanoHTTPD.Method.GET.equals(method) && PREFIX_AUTH_FILES.equals(uri)) {
            return listAuthFiles();
        }

        // POST /v0/management/auth-files — 上传新的凭证文件
        if (NanoHTTPD.Method.POST.equals(method) && PREFIX_AUTH_FILES.equals(uri)) {
            String name = params != null ? params.get("name") : null;
            return uploadAuthFile(name, body);
        }

        // DELETE /v0/management/auth-files — 删除凭证文件
        if (NanoHTTPD.Method.DELETE.equals(method) && PREFIX_AUTH_FILES.equals(uri)) {
            String name = params != null ? params.get("name") : null;
            return deleteAuthFile(name);
        }

        // PATCH /v0/management/auth-files — 切换凭证文件禁用状态
        if (NanoHTTPD.Method.PATCH.equals(method) && PREFIX_AUTH_FILES.equals(uri)) {
            return handleToggleAuthFile(body);
        }

        // 未知操作
        Log.w(TAG, "Unknown endpoint: " + method + " " + uri);
        return jsonResponse(404, new JSONObject()
                .put("error", "端点不存在")
                .put("path", uri)
                .toString());
    }

    /**
     * 列出所有凭证文件
     * <p>
     * GET /v0/management/auth-files
     * 返回当前所有已存储的凭证文件名称列表，包含每个文件的禁用状态。
     *
     * @return JSON 响应，包含文件列表和状态信息
     */
    public Response listAuthFiles() {
        Log.d(TAG, "Listing all auth files");

        JSONArray filesArray = new JSONArray();
        for (String name : authFiles.keySet()) {
            JSONObject fileObj = new JSONObject();
            fileObj.put("name", name);
            fileObj.put("disabled", disabledStatus.getOrDefault(name, false));
            // 不返回具体内容，仅返回元信息
            fileObj.put("size", authFiles.get(name).length());
            filesArray.put(fileObj);
        }

        JSONObject response = new JSONObject();
        response.put("files", filesArray);
        response.put("total", authFiles.size());

        Log.d(TAG, "Found " + authFiles.size() + " auth files");
        return jsonResponse(200, response.toString());
    }

    /**
     * 获取每个凭证文件关联的模型列表
     * <p>
     * GET /v0/management/auth-files/models
     * 返回每个凭证文件所支持的模型名称列表，用于前端展示文件与模型的对应关系。
     *
     * @return JSON 响应，包含每个文件对应的模型列表
     */
    public Response getAuthFileModels() {
        Log.d(TAG, "Getting auth file models");

        JSONObject modelsByFile = new JSONObject();
        for (String name : authFiles.keySet()) {
            String modelsJson = fileModels.get(name);
            if (modelsJson != null) {
                try {
                    modelsByFile.put(name, new JSONArray(modelsJson));
                } catch (Exception e) {
                    Log.w(TAG, "Failed to parse models for file: " + name, e);
                    modelsByFile.put(name, new JSONArray());
                }
            } else {
                // 如果未显式配置模型，尝试从文件内容中推断
                modelsByFile.put(name, inferModelsFromContent(name));
            }
        }

        JSONObject response = new JSONObject();
        response.put("models", modelsByFile);
        response.put("total_files", authFiles.size());

        Log.d(TAG, "Models retrieved for " + authFiles.size() + " files");
        return jsonResponse(200, response.toString());
    }

    /**
     * 上传（创建或更新）凭证文件
     * <p>
     * POST /v0/management/auth-files
     * 请求参数 name 指定文件名，请求体为凭证文件内容（JSON 格式）。
     * 如果文件已存在则覆盖更新，否则创建新文件。
     *
     * @param name 凭证文件名（由 query 参数传入）
     * @param data 凭证文件内容（请求体 JSON 字符串）
     * @return JSON 响应，包含操作结果
     */
    public Response uploadAuthFile(String name, String data) {
        if (name == null || name.trim().isEmpty()) {
            Log.w(TAG, "Upload failed: missing file name");
            return jsonResponse(400, new JSONObject()
                    .put("error", "缺少文件名参数 name")
                    .toString());
        }

        if (data == null || data.trim().isEmpty()) {
            Log.w(TAG, "Upload failed: empty data for file: " + name);
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体不能为空")
                    .toString());
        }

        // 校验数据是否为合法 JSON
        try {
            new JSONObject(data);
        } catch (Exception e) {
            Log.w(TAG, "Upload failed: invalid JSON for file: " + name, e);
            return jsonResponse(400, new JSONObject()
                    .put("error", "凭证文件内容必须是合法的 JSON 格式")
                    .toString());
        }

        boolean isNew = !authFiles.containsKey(name);
        authFiles.put(name, data);

        // 新文件默认启用
        if (isNew) {
            disabledStatus.put(name, false);
        }

        // 尝试从内容中提取模型信息
        extractModelsFromContent(name, data);

        Log.d(TAG, "Auth file " + (isNew ? "created" : "updated") + ": " + name);

        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("name", name);
        response.put("action", isNew ? "created" : "updated");

        return jsonResponse(200, response.toString());
    }

    /**
     * 删除指定的凭证文件
     * <p>
     * DELETE /v0/management/auth-files
     * 从内存中移除指定名称的凭证文件及其关联的模型和状态信息。
     *
     * @param name 要删除的凭证文件名（由 query 参数传入）
     * @return JSON 响应，包含操作结果
     */
    public Response deleteAuthFile(String name) {
        if (name == null || name.trim().isEmpty()) {
            Log.w(TAG, "Delete failed: missing file name");
            return jsonResponse(400, new JSONObject()
                    .put("error", "缺少文件名参数 name")
                    .toString());
        }

        if (!authFiles.containsKey(name)) {
            Log.w(TAG, "Delete failed: file not found: " + name);
            return jsonResponse(404, new JSONObject()
                    .put("error", "凭证文件不存在: " + name)
                    .toString());
        }

        authFiles.remove(name);
        disabledStatus.remove(name);
        fileModels.remove(name);

        Log.d(TAG, "Auth file deleted: " + name);

        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("name", name);
        response.put("action", "deleted");

        return jsonResponse(200, response.toString());
    }

    /**
     * 切换凭证文件的禁用状态
     * <p>
     * PATCH /v0/management/auth-files
     * 请求体为 JSON 格式，包含 name 和 disabled 字段。
     * 用于临时启用或禁用某个凭证文件，禁用后该文件不会被用于认证。
     *
     * @param name     凭证文件名
     * @param disabled 是否禁用（true 为禁用，false 为启用）
     * @return JSON 响应，包含操作结果
     */
    public Response toggleAuthFile(String name, boolean disabled) {
        if (name == null || name.trim().isEmpty()) {
            Log.w(TAG, "Toggle failed: missing file name");
            return jsonResponse(400, new JSONObject()
                    .put("error", "缺少文件名参数 name")
                    .toString());
        }

        if (!authFiles.containsKey(name)) {
            Log.w(TAG, "Toggle failed: file not found: " + name);
            return jsonResponse(404, new JSONObject()
                    .put("error", "凭证文件不存在: " + name)
                    .toString());
        }

        disabledStatus.put(name, disabled);

        Log.d(TAG, "Auth file '" + name + "' disabled status set to: " + disabled);

        JSONObject response = new JSONObject();
        response.put("success", true);
        response.put("name", name);
        response.put("disabled", disabled);

        return jsonResponse(200, response.toString());
    }

    /**
     * 处理 PATCH 请求体并解析参数后调用 toggleAuthFile
     *
     * @param body 请求体 JSON 字符串
     * @return NanoHTTPD Response 对象
     */
    private Response handleToggleAuthFile(String body) {
        if (body == null || body.trim().isEmpty()) {
            Log.w(TAG, "Toggle failed: empty request body");
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体不能为空")
                    .toString());
        }

        try {
            JSONObject json = new JSONObject(body);
            String name = json.optString("name", null);
            boolean disabled = json.optBoolean("disabled", true);
            return toggleAuthFile(name, disabled);
        } catch (Exception e) {
            Log.w(TAG, "Toggle failed: invalid JSON body", e);
            return jsonResponse(400, new JSONObject()
                    .put("error", "请求体格式错误，需要合法的 JSON")
                    .toString());
        }
    }

    /**
     * 从凭证文件内容中推断支持的模型列表
     * <p>
     * 根据文件内容中的 api_base、model 等字段自动推断该文件支持的模型。
     * 如果无法推断，返回空数组。
     *
     * @param name 凭证文件名
     * @return JSONArray 模型名称列表
     */
    private JSONArray inferModelsFromContent(String name) {
        String content = authFiles.get(name);
        if (content == null) {
            return new JSONArray();
        }

        try {
            JSONObject json = new JSONObject(content);
            JSONArray models = new JSONArray();

            // 如果内容中显式指定了 model 字段
            if (json.has("model")) {
                String model = json.optString("model", "");
                if (!model.isEmpty()) {
                    models.put(model);
                    return models;
                }
            }

            // 如果内容中指定了多个 models
            if (json.has("models")) {
                Object modelsRaw = json.get("models");
                if (modelsRaw instanceof JSONArray) {
                    return (JSONArray) modelsRaw;
                }
            }

            return models;
        } catch (Exception e) {
            Log.w(TAG, "Failed to infer models from file: " + name, e);
            return new JSONArray();
        }
    }

    /**
     * 从上传内容中提取模型信息并缓存
     *
     * @param name 凭证文件名
     * @param data 文件内容 JSON 字符串
     */
    private void extractModelsFromContent(String name, String data) {
        try {
            JSONObject json = new JSONObject(data);
            if (json.has("models")) {
                Object modelsRaw = json.get("models");
                if (modelsRaw instanceof JSONArray) {
                    fileModels.put(name, ((JSONArray) modelsRaw).toString());
                    return;
                }
            }
            // 单个 model 字段也存入
            if (json.has("model")) {
                JSONArray models = new JSONArray();
                models.put(json.optString("model", ""));
                fileModels.put(name, models.toString());
                return;
            }
            // 清除旧缓存
            fileModels.remove(name);
        } catch (Exception e) {
            Log.w(TAG, "Failed to extract models from file: " + name, e);
            fileModels.remove(name);
        }
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