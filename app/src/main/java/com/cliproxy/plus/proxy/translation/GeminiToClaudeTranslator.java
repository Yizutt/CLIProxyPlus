package com.cliproxy.plus.proxy.translation;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * GeminiToClaudeTranslator - Gemini 协议格式转 Claude 协议格式
 * <p>
 * 将 Google Gemini API (/v1beta/models/{model}:generateContent) 的请求/响应格式转换为
 * Anthropic Claude API (/v1/messages) 格式。此转换器是协议转换层的一部分，
 * 用于将上游 Gemini 兼容 API 的请求透明地转发到 Claude 兼容的 API 后端。
 * </p>
 *
 * <h3>字段映射表</h3>
 * <pre>
 * Gemini (/v1beta)                 →  Claude (/v1/messages)
 * ─────────────────────────────────────────────────────────────
 * contents                         →  messages（角色映射：user/model → user/assistant）
 * systemInstruction                →  system（从嵌套结构提取文本）
 * generationConfig.temperature     →  temperature
 * generationConfig.maxOutputTokens →  max_tokens
 * generationConfig.topP            →  top_p
 * generationConfig.topK            →  top_k
 * generationConfig.stopSequences   →  stop_sequences
 * safetySettings                   →  safety_filters（威胁级别映射）
 * tools                            →  tools（functionDeclarations 格式转换）
 * </pre>
 *
 * <h3>使用示例</h3>
 * <pre>
 * GeminiToClaudeTranslator translator = new GeminiToClaudeTranslator();
 * String claudeRequest = translator.translate(geminiJson, headers);
 * String geminiResponse = translator.translateResponse(claudeResponseBody);
 * </pre>
 *
 * 对应原版 internal/api/translator/gemini.go
 *
 * @author CLIProxy Plus Team
 * @version 1.0.0
 */
public class GeminiToClaudeTranslator implements FormatTranslator {

    private static final String TAG = "GeminiToClaude";

    /**
     * Gemini → Claude 模型名称映射表
     * 将 Gemini 的模型标识符映射为 Claude 兼容的模型标识符
     */
    private static final Map<String, String> MODEL_MAP = new HashMap<>();

    static {
        // Gemini 2.0 系列 → Claude Sonnet
        MODEL_MAP.put("gemini-2.0-flash", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gemini-2.0-flash-lite", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gemini-2.0-pro", "claude-opus-4-20250514");
        MODEL_MAP.put("gemini-2.0-pro-exp", "claude-opus-4-20250514");

        // Gemini 1.5 系列
        MODEL_MAP.put("gemini-1.5-pro", "claude-3-5-sonnet-20241022");
        MODEL_MAP.put("gemini-1.5-flash", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gemini-1.5-flash-8b", "claude-3-5-haiku-20241022");

        // Gemini 1.0 系列
        MODEL_MAP.put("gemini-1.0-pro", "claude-3-haiku-20240307");

        // 通配符兜底
        MODEL_MAP.put("gemini-2.0", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gemini-1.5", "claude-3-5-sonnet-20241022");
        MODEL_MAP.put("gemini-1.0", "claude-3-haiku-20240307");
        MODEL_MAP.put("gemini-flash", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gemini-pro", "claude-3-5-sonnet-20241022");
    }

    /**
     * Gemini 安全阈值 → Claude 安全级别映射表
     */
    private static final Map<String, String> SAFETY_THRESHOLD_MAP = new HashMap<>();

    static {
        SAFETY_THRESHOLD_MAP.put("BLOCK_ONLY_HIGH", "high");
        SAFETY_THRESHOLD_MAP.put("BLOCK_MEDIUM_AND_ABOVE", "medium");
        SAFETY_THRESHOLD_MAP.put("BLOCK_LOW_AND_ABOVE", "low");
        SAFETY_THRESHOLD_MAP.put("BLOCK_NONE", "none");
        SAFETY_THRESHOLD_MAP.put("HARM_BLOCK_THRESHOLD_UNSPECIFIED", "default");
    }

    /**
     * Gemini 危害类别 → Claude 安全过滤器类别映射
     */
    private static final Map<String, String> HARM_CATEGORY_MAP = new HashMap<>();

    static {
        HARM_CATEGORY_MAP.put("HARM_CATEGORY_HARASSMENT", "harassment");
        HARM_CATEGORY_MAP.put("HARM_CATEGORY_HATE_SPEECH", "hate_speech");
        HARM_CATEGORY_MAP.put("HARM_CATEGORY_SEXUALLY_EXPLICIT", "sexual");
        HARM_CATEGORY_MAP.put("HARM_CATEGORY_DANGEROUS_CONTENT", "dangerous");
        HARM_CATEGORY_MAP.put("HARM_CATEGORY_CIVIC_INTEGRITY", "civic_integrity");
    }

    /**
     * 将 Gemini /v1beta 请求体转换为 Claude /v1/messages 请求体
     * <p>
     * 实现 {@link FormatTranslator#translate(String, Map)} 接口方法。
     * 执行完整的字段映射：模型名称、消息结构（contents → messages）、
     * 系统指令（systemInstruction → system）、生成参数（generationConfig → 顶层参数）、
     * 安全设置（safetySettings → safety_filters）、工具（tools → tools）。
     * </p>
     *
     * @param sourceJson Gemini 格式的请求体 JSON 字符串
     * @param headers    请求头信息（用于日志和调试）
     * @return Claude 格式的请求体 JSON 字符串
     * @throws FormatTranslator.TranslationException 转换失败时抛出，包含错误代码和详细信息
     */
    @Override
    public String translate(String sourceJson, Map<String, String> headers) throws FormatTranslator.TranslationException {
        if (sourceJson == null || sourceJson.isEmpty()) {
            Log.w(TAG, "translate: empty request body");
            throw new FormatTranslator.TranslationException(
                    FormatTranslator.TranslationException.ERROR_EMPTY_BODY, "Request body is empty");
        }

        try {
            JSONObject geminiRequest = new JSONObject(sourceJson);
            JSONObject claudeRequest = new JSONObject();

            // 1. 模型名称映射
            translateModel(geminiRequest, claudeRequest);

            // 2. 消息转换：Gemini contents → Claude messages
            translateContents(geminiRequest, claudeRequest);

            // 3. 系统指令转换：systemInstruction → system
            translateSystemInstruction(geminiRequest, claudeRequest);

            // 4. 生成参数转换：generationConfig → 顶层参数
            translateGenerationConfig(geminiRequest, claudeRequest);

            // 5. 安全设置转换：safetySettings → safety_filters
            translateSafetySettings(geminiRequest, claudeRequest);

            // 6. 工具转换：Gemini functionDeclarations → Claude tools
            translateTools(geminiRequest, claudeRequest);

            Log.d(TAG, "translate: successfully converted Gemini request to Claude format");
            return claudeRequest.toString();

        } catch (JSONException e) {
            Log.e(TAG, "translate: failed to translate request", e);
            throw new FormatTranslator.TranslationException(
                    FormatTranslator.TranslationException.ERROR_PARSE,
                    "Failed to parse or convert Gemini request: " + e.getMessage(), e);
        }
    }

    /**
     * 将 Claude /v1/messages 响应体反向转换为 Gemini /v1beta 响应体
     * <p>
     * 此方法不在 {@link FormatTranslator} 接口中，但作为公共辅助方法提供，
     * 用于在收到后端 Claude 格式的响应后，将其转换回 Gemini 格式返回给客户端。
     * </p>
     *
     * @param claudeResponseBody Claude 格式的响应体 JSON 字符串
     * @return Gemini 格式的响应体 JSON 字符串，转换失败时返回原始响应体
     */
    public String translateResponse(String claudeResponseBody) {
        if (claudeResponseBody == null || claudeResponseBody.isEmpty()) {
            Log.w(TAG, "translateResponse: empty response body");
            return claudeResponseBody;
        }

        try {
            JSONObject claudeResponse = new JSONObject(claudeResponseBody);
            JSONObject geminiResponse = new JSONObject();

            // 1. candidates 数组构建
            JSONArray candidates = new JSONArray();
            JSONObject candidate = new JSONObject();
            JSONObject content = new JSONObject();
            JSONArray parts = new JSONArray();

            // 从 Claude response 提取内容
            String role = claudeResponse.optString("role", "model");
            content.put("role", "assistant".equals(role) ? "model" : role);

            JSONArray contentArray = claudeResponse.optJSONArray("content");
            if (contentArray != null && contentArray.length() > 0) {
                for (int i = 0; i < contentArray.length(); i++) {
                    JSONObject block = contentArray.getJSONObject(i);
                    String blockType = block.optString("type", "text");

                    if ("text".equals(blockType)) {
                        JSONObject textPart = new JSONObject();
                        textPart.put("text", block.optString("text", ""));
                        parts.put(textPart);
                    } else if ("tool_use".equals(blockType)) {
                        // Claude tool_use → Gemini functionCall
                        JSONObject functionCallPart = new JSONObject();
                        JSONObject functionCall = new JSONObject();
                        functionCall.put("name", block.optString("name", ""));
                        functionCall.put("args", block.optJSONObject("input"));
                        functionCallPart.put("functionCall", functionCall);
                        parts.put(functionCallPart);
                    }
                }
            } else {
                // 兜底：空内容
                JSONObject emptyPart = new JSONObject();
                emptyPart.put("text", "");
                parts.put(emptyPart);
            }

            content.put("parts", parts);
            candidate.put("content", content);

            // 2. finishReason 映射
            String stopReason = claudeResponse.optString("stop_reason", "end_turn");
            candidate.put("finishReason", mapStopReasonToFinishReason(stopReason));

            // 3. safetyRatings（固定为默认值，因为 Claude 不提供细粒度安全评分）
            candidate.put("safetyRatings", new JSONArray());

            // 4. index
            candidate.put("index", 0);

            candidates.put(candidate);
            geminiResponse.put("candidates", candidates);

            // 5. usageMetadata 映射
            if (claudeResponse.has("usage")) {
                JSONObject claudeUsage = claudeResponse.getJSONObject("usage");
                JSONObject usageMetadata = new JSONObject();
                usageMetadata.put("promptTokenCount", claudeUsage.optInt("input_tokens", 0));
                usageMetadata.put("candidatesTokenCount", claudeUsage.optInt("output_tokens", 0));
                usageMetadata.put("totalTokenCount",
                        claudeUsage.optInt("input_tokens", 0) + claudeUsage.optInt("output_tokens", 0));
                geminiResponse.put("usageMetadata", usageMetadata);
            }

            // 6. modelVersion
            geminiResponse.put("modelVersion", claudeResponse.optString("model", "unknown"));

            Log.d(TAG, "translateResponse: successfully converted Claude response to Gemini format");
            return geminiResponse.toString();

        } catch (JSONException e) {
            Log.e(TAG, "translateResponse: failed to translate response", e);
            return claudeResponseBody;
        }
    }

    // ==================== 请求转换 - 内部辅助方法 ====================

    /**
     * 转换模型名称：根据 MODEL_MAP 将 Gemini 模型名映射为 Claude 模型名
     * <p>
     * Gemini 的模型名称可能以 "models/" 为前缀，此方法会自动去除前缀进行匹配。
     * 支持精确匹配、前缀匹配和关键词匹配三种策略。
     * </p>
     */
    private void translateModel(JSONObject geminiRequest, JSONObject claudeRequest) throws JSONException {
        String geminiModel = geminiRequest.optString("model", "gemini-2.0-flash");

        // 去除 "models/" 前缀
        if (geminiModel.startsWith("models/")) {
            geminiModel = geminiModel.substring(7);
        }

        String claudeModel = mapModel(geminiModel);
        claudeRequest.put("model", claudeModel);
        Log.d(TAG, "translateModel: " + geminiModel + " → " + claudeModel);
    }

    /**
     * 转换消息：将 Gemini 的 contents 数组转换为 Claude 的 messages 数组
     * <p>
     * Gemini 的 contents 包含 role（user/model）和 parts（文本/多模态内容块），
     * Claude 的 messages 包含 role（user/assistant）和 content（字符串或内容块数组）。
     * </p>
     *
     * <h3>角色映射</h3>
     * <ul>
     *   <li>Gemini "user" → Claude "user"</li>
     *   <li>Gemini "model" → Claude "assistant"</li>
     * </ul>
     *
     * <h3>内容转换</h3>
     * <ul>
     *   <li>Gemini text part → Claude 文本内容块</li>
     *   <li>Gemini inlineData part → Claude image 内容块（base64）</li>
     *   <li>Gemini functionCall → Claude tool_use 内容块</li>
     *   <li>Gemini functionResponse → Claude tool_result 内容块</li>
     * </ul>
     */
    private void translateContents(JSONObject geminiRequest, JSONObject claudeRequest) throws JSONException {
        if (!geminiRequest.has("contents")) {
            Log.w(TAG, "translateContents: no contents in request");
            return;
        }

        JSONArray geminiContents = geminiRequest.getJSONArray("contents");
        JSONArray claudeMessages = new JSONArray();

        for (int i = 0; i < geminiContents.length(); i++) {
            JSONObject geminiContent = geminiContents.getJSONObject(i);
            String geminiRole = geminiContent.optString("role", "user");

            // 角色映射：model → assistant
            String claudeRole;
            if ("model".equals(geminiRole)) {
                claudeRole = "assistant";
            } else if ("user".equals(geminiRole)) {
                claudeRole = "user";
            } else {
                claudeRole = "user";
                Log.d(TAG, "translateContents: unknown role '" + geminiRole + "', defaulting to 'user'");
            }

            JSONArray parts = geminiContent.optJSONArray("parts");
            if (parts == null || parts.length() == 0) {
                Log.w(TAG, "translateContents: content at index " + i + " has no parts, skipping");
                continue;
            }

            // 检查 whether this is a function response (tool_result) or regular content
            boolean isFunctionResponse = false;
            JSONArray functionResponseParts = new JSONArray();

            for (int j = 0; j < parts.length(); j++) {
                JSONObject part = parts.getJSONObject(j);
                if (part.has("functionResponse")) {
                    isFunctionResponse = true;
                }
            }

            if (isFunctionResponse) {
                // 将 functionResponse 转换为 tool_result 消息（每条作为独立消息）
                for (int j = 0; j < parts.length(); j++) {
                    JSONObject part = parts.getJSONObject(j);
                    if (part.has("functionResponse")) {
                        JSONObject functionResponse = part.getJSONObject("functionResponse");
                        JSONObject toolResultMsg = new JSONObject();
                        toolResultMsg.put("role", "user");

                        JSONArray toolResultContent = new JSONArray();
                        JSONObject toolResultBlock = new JSONObject();
                        toolResultBlock.put("type", "tool_result");
                        toolResultBlock.put("tool_use_id", functionResponse.optString("id",
                                "toolu_" + System.currentTimeMillis()));
                        toolResultBlock.put("content", functionResponse.optString("response", "{}"));
                        toolResultContent.put(toolResultBlock);

                        toolResultMsg.put("content", toolResultContent);
                        claudeMessages.put(toolResultMsg);
                    }
                }
                continue;
            }

            // 常规内容处理
            JSONObject claudeMsg = new JSONObject();
            claudeMsg.put("role", claudeRole);

            // 确定是否有多内容块需要作为数组传递
            boolean hasNonTextParts = false;
            boolean hasFunctionCall = false;
            for (int j = 0; j < parts.length(); j++) {
                JSONObject part = parts.getJSONObject(j);
                if (part.has("inlineData") || part.has("fileData")) {
                    hasNonTextParts = true;
                }
                if (part.has("functionCall")) {
                    hasFunctionCall = true;
                }
            }

            if (hasFunctionCall) {
                // 将 functionCall 转换为 tool_use 内容块
                JSONArray contentBlocks = new JSONArray();

                // 首先收集文本内容
                StringBuilder textContent = new StringBuilder();
                for (int j = 0; j < parts.length(); j++) {
                    JSONObject part = parts.getJSONObject(j);
                    if (part.has("text")) {
                        if (textContent.length() > 0) {
                            textContent.append("\n");
                        }
                        textContent.append(part.optString("text", ""));
                    }
                }

                if (textContent.length() > 0) {
                    JSONObject textBlock = new JSONObject();
                    textBlock.put("type", "text");
                    textBlock.put("text", textContent.toString());
                    contentBlocks.put(textBlock);
                }

                // 转换 functionCall → tool_use
                for (int j = 0; j < parts.length(); j++) {
                    JSONObject part = parts.getJSONObject(j);
                    if (part.has("functionCall")) {
                        JSONObject functionCall = part.getJSONObject("functionCall");
                        JSONObject toolUseBlock = new JSONObject();
                        toolUseBlock.put("type", "tool_use");
                        toolUseBlock.put("id", functionCall.optString("id",
                                "toolu_" + System.currentTimeMillis()));
                        toolUseBlock.put("name", functionCall.optString("name", ""));
                        JSONObject args = functionCall.optJSONObject("args");
                        toolUseBlock.put("input", args != null ? args : new JSONObject());
                        contentBlocks.put(toolUseBlock);
                    }
                }

                claudeMsg.put("content", contentBlocks);

            } else if (hasNonTextParts || parts.length() > 1) {
                // 多内容块：包含文本、图片等
                JSONArray contentBlocks = new JSONArray();

                for (int j = 0; j < parts.length(); j++) {
                    JSONObject part = parts.getJSONObject(j);

                    if (part.has("text")) {
                        JSONObject textBlock = new JSONObject();
                        textBlock.put("type", "text");
                        textBlock.put("text", part.optString("text", ""));
                        contentBlocks.put(textBlock);

                    } else if (part.has("inlineData")) {
                        // 内联图片数据 → Claude image 内容块
                        JSONObject inlineData = part.getJSONObject("inlineData");
                        String mimeType = inlineData.optString("mimeType", "image/png");
                        String data = inlineData.optString("data", "");

                        JSONObject imageBlock = new JSONObject();
                        imageBlock.put("type", "image");
                        imageBlock.put("source", new JSONObject());
                        imageBlock.getJSONObject("source").put("type", "base64");
                        imageBlock.getJSONObject("source").put("media_type", mimeType);
                        imageBlock.getJSONObject("source").put("data", data);
                        contentBlocks.put(imageBlock);

                    } else if (part.has("fileData")) {
                        // 文件数据：转换为文本引用（Claude 不支持直接 fileData）
                        JSONObject fileData = part.getJSONObject("fileData");
                        String fileUri = fileData.optString("fileUri", "");
                        String mimeType = fileData.optString("mimeType", "");

                        JSONObject textBlock = new JSONObject();
                        textBlock.put("type", "text");
                        textBlock.put("text", "[File: " + fileUri + " (" + mimeType + ")]");
                        contentBlocks.put(textBlock);
                        Log.d(TAG, "translateContents: fileData converted to text reference: " + fileUri);
                    }
                }

                claudeMsg.put("content", contentBlocks);

            } else {
                // 单文本内容
                JSONObject firstPart = parts.getJSONObject(0);
                String text = firstPart.optString("text", "");
                claudeMsg.put("content", text);
            }

            claudeMessages.put(claudeMsg);
        }

        claudeRequest.put("messages", claudeMessages);
        Log.d(TAG, "translateContents: converted " + geminiContents.length() + " contents to messages");
    }

    /**
     * 转换系统指令：将 Gemini 的 systemInstruction 转换为 Claude 的 system 字段
     * <p>
     * Gemini 的 systemInstruction 格式为：
     * <pre>
     * {"parts": [{"text": "You are a helpful assistant..."}]}
     * </pre>
     * Claude 的 system 字段为顶层字符串，直接提取文本内容。
     * </p>
     */
    private void translateSystemInstruction(JSONObject geminiRequest, JSONObject claudeRequest) throws JSONException {
        if (!geminiRequest.has("systemInstruction")) {
            return;
        }

        JSONObject systemInstruction = geminiRequest.getJSONObject("systemInstruction");
        JSONArray parts = systemInstruction.optJSONArray("parts");

        if (parts != null && parts.length() > 0) {
            StringBuilder systemText = new StringBuilder();

            for (int i = 0; i < parts.length(); i++) {
                JSONObject part = parts.getJSONObject(i);
                if (part.has("text")) {
                    if (systemText.length() > 0) {
                        systemText.append("\n");
                    }
                    systemText.append(part.optString("text", ""));
                }
            }

            if (systemText.length() > 0) {
                claudeRequest.put("system", systemText.toString());
                Log.d(TAG, "translateSystemInstruction: extracted system prompt, length=" + systemText.length());
            }
        }
    }

    /**
     * 转换生成参数：将 Gemini 的 generationConfig 映射为 Claude 的顶层参数
     * <p>
     * 字段映射明细：
     * <ul>
     *   <li>temperature → temperature（直接映射）</li>
     *   <li>maxOutputTokens → max_tokens（重命名）</li>
     *   <li>topP → top_p（重命名）</li>
     *   <li>topK → top_k（直接映射）</li>
     *   <li>stopSequences → stop_sequences（重命名）</li>
     *   <li>candidateCount → 移除（Claude 不支持多候选，记录日志）</li>
     *   <li>presencePenalty → 移除（Claude 不支持，记录日志）</li>
     *   <li>frequencyPenalty → 移除（Claude 不支持，记录日志）</li>
     * </ul>
     * </p>
     */
    private void translateGenerationConfig(JSONObject geminiRequest, JSONObject claudeRequest) throws JSONException {
        if (!geminiRequest.has("generationConfig")) {
            return;
        }

        JSONObject generationConfig = geminiRequest.getJSONObject("generationConfig");

        // temperature 直接映射
        if (generationConfig.has("temperature")) {
            claudeRequest.put("temperature", generationConfig.getDouble("temperature"));
        }

        // maxOutputTokens → max_tokens
        if (generationConfig.has("maxOutputTokens")) {
            claudeRequest.put("max_tokens", generationConfig.getInt("maxOutputTokens"));
        }

        // topP → top_p
        if (generationConfig.has("topP")) {
            claudeRequest.put("top_p", generationConfig.getDouble("topP"));
        }

        // topK → top_k
        if (generationConfig.has("topK")) {
            claudeRequest.put("top_k", generationConfig.getInt("topK"));
        }

        // stopSequences → stop_sequences
        if (generationConfig.has("stopSequences")) {
            claudeRequest.put("stop_sequences", generationConfig.get("stopSequences"));
        }

        // candidateCount 移除（Claude 不支持）
        if (generationConfig.has("candidateCount")) {
            Log.d(TAG, "translateGenerationConfig: candidateCount is not supported by Claude, dropping");
        }

        // presencePenalty 移除（Claude 不支持）
        if (generationConfig.has("presencePenalty")) {
            Log.d(TAG, "translateGenerationConfig: presencePenalty is not supported by Claude, dropping");
        }

        // frequencyPenalty 移除（Claude 不支持）
        if (generationConfig.has("frequencyPenalty")) {
            Log.d(TAG, "translateGenerationConfig: frequencyPenalty is not supported by Claude, dropping");
        }

        // responseMimeType 移除（Claude 不支持结构化输出控制）
        if (generationConfig.has("responseMimeType")) {
            Log.d(TAG, "translateGenerationConfig: responseMimeType is not supported by Claude, dropping");
        }

        // seed 移除（Claude 不支持）
        if (generationConfig.has("seed")) {
            Log.d(TAG, "translateGenerationConfig: seed is not supported by Claude, dropping");
        }

        Log.d(TAG, "translateGenerationConfig: generationConfig parameters mapped successfully");
    }

    /**
     * 转换安全设置：将 Gemini 的 safetySettings 转换为 Claude 的 safety_filters
     * <p>
     * Gemini 的 safetySettings 格式为：
     * <pre>
     * [{"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}]
     * </pre>
     * Claude 的 safety_filters 格式为：
     * <pre>
     * [{"type": "harassment", "level": "medium"}]
     * </pre>
     * </p>
     */
    private void translateSafetySettings(JSONObject geminiRequest, JSONObject claudeRequest) throws JSONException {
        if (!geminiRequest.has("safetySettings")) {
            return;
        }

        JSONArray geminiSafetySettings = geminiRequest.getJSONArray("safetySettings");
        if (geminiSafetySettings.length() == 0) {
            return;
        }

        JSONArray claudeSafetyFilters = new JSONArray();

        for (int i = 0; i < geminiSafetySettings.length(); i++) {
            JSONObject safetySetting = geminiSafetySettings.getJSONObject(i);

            String category = safetySetting.optString("category", "");
            String threshold = safetySetting.optString("threshold", "HARM_BLOCK_THRESHOLD_UNSPECIFIED");

            // 映射危害类别
            String claudeType = mapHarmCategory(category);
            if (claudeType == null) {
                Log.d(TAG, "translateSafetySettings: unknown category '" + category + "', skipping");
                continue;
            }

            // 映射阈值级别
            String claudeLevel = mapSafetyThreshold(threshold);

            JSONObject filter = new JSONObject();
            filter.put("type", claudeType);
            filter.put("level", claudeLevel);
            claudeSafetyFilters.put(filter);

            Log.d(TAG, "translateSafetySettings: " + category + "(" + threshold + ") → "
                    + claudeType + "(" + claudeLevel + ")");
        }

        if (claudeSafetyFilters.length() > 0) {
            claudeRequest.put("safety_filters", claudeSafetyFilters);
        }
    }

    /**
     * 转换工具：将 Gemini 的 tools 转换为 Claude 的 tools 格式
     * <p>
     * Gemini 的 tools 格式为：
     * <pre>
     * [{"functionDeclarations": [{"name": "...", "description": "...", "parameters": {...}}]}]
     * </pre>
     * Claude 的 tools 格式为：
     * <pre>
     * [{"name": "...", "description": "...", "input_schema": {...}}]
     * </pre>
     * 注意：Gemini 的 tools 是一个数组，每个元素包含 functionDeclarations 数组；
     * 而 Claude 的 tools 是扁平的工具对象数组。此方法会展开 Gemini 的嵌套结构。
     * </p>
     */
    private void translateTools(JSONObject geminiRequest, JSONObject claudeRequest) throws JSONException, FormatTranslator.TranslationException {
        if (!geminiRequest.has("tools")) {
            return;
        }

        JSONArray geminiTools = geminiRequest.getJSONArray("tools");
        JSONArray claudeTools = new JSONArray();

        for (int i = 0; i < geminiTools.length(); i++) {
            JSONObject tool = geminiTools.getJSONObject(i);

            // Gemini 的 tools 可能包含 functionDeclarations 数组
            JSONArray functionDeclarations = tool.optJSONArray("functionDeclarations");
            if (functionDeclarations != null) {
                for (int j = 0; j < functionDeclarations.length(); j++) {
                    JSONObject funcDecl = functionDeclarations.getJSONObject(j);
                    JSONObject claudeTool = new JSONObject();

                    claudeTool.put("name", funcDecl.optString("name", "unknown_function_" + j));
                    claudeTool.put("description", funcDecl.optString("description", ""));

                    // 将 Gemini 的 parameters 映射为 Claude 的 input_schema
                    JSONObject parameters = funcDecl.optJSONObject("parameters");
                    if (parameters != null) {
                        claudeTool.put("input_schema", parameters);
                    } else {
                        // 提供默认空 schema
                        JSONObject defaultSchema = new JSONObject();
                        defaultSchema.put("type", "object");
                        defaultSchema.put("properties", new JSONObject());
                        defaultSchema.put("required", new JSONArray());
                        claudeTool.put("input_schema", defaultSchema);
                    }

                    claudeTools.put(claudeTool);
                }
            }

            // 也支持 Gemini 直接使用 codeExecution 工具（转换为 Claude 不支持的日志）
            if (tool.has("codeExecution")) {
                Log.d(TAG, "translateTools: codeExecution tool is not supported by Claude, skipping");
            }

            // 支持 Google Search 工具（记录日志，Claude 不支持）
            if (tool.has("googleSearch")) {
                Log.d(TAG, "translateTools: googleSearch tool is not supported by Claude, skipping");
            }

            // 支持 Google Search Retrieval 工具（记录日志，Claude 不支持）
            if (tool.has("googleSearchRetrieval")) {
                Log.d(TAG, "translateTools: googleSearchRetrieval tool is not supported by Claude, skipping");
            }
        }

        if (claudeTools.length() > 0) {
            claudeRequest.put("tools", claudeTools);
            Log.d(TAG, "translateTools: converted " + geminiTools.length() + " Gemini tools to "
                    + claudeTools.length() + " Claude tools");
        }
    }

    // ==================== 响应转换 - 内部辅助方法 ====================

    /**
     * 将 Claude stop_reason 映射为 Gemini finishReason
     */
    private String mapStopReasonToFinishReason(String stopReason) {
        if (stopReason == null) {
            return "STOP";
        }
        switch (stopReason) {
            case "end_turn":
                return "STOP";
            case "max_tokens":
                return "MAX_TOKENS";
            case "tool_use":
                return "TOOL_CALL";
            case "content_filtered":
                return "SAFETY";
            case "stop_sequence":
                return "STOP";
            default:
                return stopReason.toUpperCase();
        }
    }

    // ==================== 通用辅助方法 ====================

    /**
     * 模型名称查找：支持精确匹配和前缀匹配
     *
     * @param geminiModel Gemini 模型名称（已去除 "models/" 前缀）
     * @return 对应的 Claude 模型名称
     */
    static String mapModel(String geminiModel) {
        if (geminiModel == null || geminiModel.isEmpty()) {
            return "claude-sonnet-4-20250514";
        }

        // 精确匹配
        String mapped = MODEL_MAP.get(geminiModel);
        if (mapped != null) {
            return mapped;
        }

        // 前缀匹配：例如 gemini-2.0-flash-001 可以匹配 gemini-2.0-flash 通配
        for (Map.Entry<String, String> entry : MODEL_MAP.entrySet()) {
            if (geminiModel.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }

        // 尝试匹配系列关键词
        String lowerModel = geminiModel.toLowerCase();
        if (lowerModel.contains("gemini-2.0") || lowerModel.contains("gemini2.0")) {
            return "claude-sonnet-4-20250514";
        } else if (lowerModel.contains("gemini-1.5") || lowerModel.contains("gemini1.5")) {
            return "claude-3-5-sonnet-20241022";
        } else if (lowerModel.contains("gemini-1.0") || lowerModel.contains("gemini1.0")) {
            return "claude-3-haiku-20240307";
        } else if (lowerModel.contains("gemini-pro") || lowerModel.contains("gemini ult")) {
            return "claude-3-5-sonnet-20241022";
        } else if (lowerModel.contains("gemini-flash") || lowerModel.contains("gemini flash")) {
            return "claude-3-5-haiku-20241022";
        }

        // 默认回退
        Log.w(TAG, "mapModel: unknown model '" + geminiModel + "', falling back to claude-sonnet-4-20250514");
        return "claude-sonnet-4-20250514";
    }

    /**
     * 映射 Gemini 危害类别到 Claude 安全过滤器类型
     *
     * @param category Gemini 危害类别名称
     * @return Claude 安全过滤器类型，未知类别时返回 null
     */
    private String mapHarmCategory(String category) {
        if (category == null || category.isEmpty()) {
            return null;
        }
        return HARM_CATEGORY_MAP.get(category);
    }

    /**
     * 映射 Gemini 安全阈值到 Claude 安全级别
     *
     * @param threshold Gemini 安全阈值
     * @return Claude 安全级别，未知阈值时返回 "default"
     */
    private String mapSafetyThreshold(String threshold) {
        if (threshold == null || threshold.isEmpty()) {
            return "default";
        }
        String mapped = SAFETY_THRESHOLD_MAP.get(threshold);
        return mapped != null ? mapped : "default";
    }
}