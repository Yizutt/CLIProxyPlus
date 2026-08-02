package com.cliproxy.plus.proxy.translation;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * ClaudeToOpenAITranslator - Claude 协议格式转 OpenAI 协议格式
 * <p>
 * 将 Claude API (/v1/messages) 的请求/响应格式转换为 OpenAI 聊天完成格式 (/v1/chat/completions)。
 * 此转换器是协议转换层的一部分，用于将上游 Claude 兼容 API 的请求透明地转发到
 * OpenAI 兼容的 API 后端。
 * </p>
 *
 * <h3>字段映射表</h3>
 * <pre>
 * Claude (/v1/messages)          →  OpenAI (/v1/chat/completions)
 * ─────────────────────────────────────────────────────────────
 * model                          →  model（通过模型映射表）
 * messages[].role                →  messages[].role（user/assistant）
 * messages[].content             →  messages[].content
 * system                         →  messages[0] {role: "system", content: "..."}
 * max_tokens                     →  max_tokens
 * stop_sequences                 →  stop
 * stream                         →  stream
 * tools                          →  tools
 * thinking.budget_tokens         →  reasoning_effort (low/medium/high)
 * metadata.user_id               →  user
 * </pre>
 *
 * 对应原版 internal/api/translator/claude.go
 */
public class ClaudeToOpenAITranslator implements FormatTranslator {

    private static final String TAG = "ClaudeToOpenAI";

    /**
     * Claude → OpenAI 模型名称映射表
     * 将 Claude 的模型标识符映射为 OpenAI 兼容的模型标识符
     */
    private static final Map<String, String> MODEL_MAP = new HashMap<>();

    static {
        // Claude 3.5 系列
        MODEL_MAP.put("claude-sonnet-4-20250514", "gpt-4-turbo");
        MODEL_MAP.put("claude-sonnet-4", "gpt-4-turbo");
        MODEL_MAP.put("claude-3-5-sonnet-20241022", "gpt-4-turbo");
        MODEL_MAP.put("claude-3-5-sonnet-20240620", "gpt-4-turbo");
        MODEL_MAP.put("claude-3-5-haiku-20241022", "gpt-4-turbo");

        // Claude 3 系列
        MODEL_MAP.put("claude-opus-4-20250514", "gpt-4");
        MODEL_MAP.put("claude-opus-4", "gpt-4");
        MODEL_MAP.put("claude-3-opus-20240229", "gpt-4");
        MODEL_MAP.put("claude-3-sonnet-20240229", "gpt-4");
        MODEL_MAP.put("claude-3-haiku-20240307", "gpt-3.5-turbo");

        // Claude 2 系列
        MODEL_MAP.put("claude-2.1", "gpt-3.5-turbo-16k");
        MODEL_MAP.put("claude-2.0", "gpt-3.5-turbo-16k");
        MODEL_MAP.put("claude-instant-1.2", "gpt-3.5-turbo");

        // 通配符兜底
        MODEL_MAP.put("claude-sonnet", "gpt-4-turbo");
        MODEL_MAP.put("claude-opus", "gpt-4");
        MODEL_MAP.put("claude-haiku", "gpt-3.5-turbo");
    }

    /**
     * Claude thinking budget_tokens → OpenAI reasoning_effort 映射
     * 根据预算 token 数量自动选择推理力度
     */
    private static final int THINKING_BUDGET_LOW_MAX = 4096;
    private static final int THINKING_BUDGET_MEDIUM_MAX = 16384;

    /**
     * 将 Claude /v1/messages 请求体转换为 OpenAI /v1/chat/completions 请求体
     * <p>
     * 实现 {@link FormatTranslator#translate(String, Map)} 接口方法。
     * 执行完整的字段映射：模型名称、消息结构、参数（max_tokens、stop_sequences、
     * stream、tools、thinking 等）从 Claude 格式到 OpenAI 格式。
     * </p>
     *
     * @param sourceJson Claude 格式的请求体 JSON 字符串
     * @param headers    请求头信息（用于日志和调试）
     * @return OpenAI 格式的请求体 JSON 字符串
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
            JSONObject claudeRequest = new JSONObject(sourceJson);
            JSONObject openaiRequest = new JSONObject();

            // 1. 模型名称映射
            translateModel(claudeRequest, openaiRequest);

            // 2. 消息转换：将 Claude messages + system 合并为 OpenAI messages
            translateMessages(claudeRequest, openaiRequest);

            // 3. max_tokens 直接映射
            if (claudeRequest.has("max_tokens")) {
                openaiRequest.put("max_tokens", claudeRequest.getInt("max_tokens"));
            }

            // 4. stop_sequences → stop
            if (claudeRequest.has("stop_sequences")) {
                openaiRequest.put("stop", claudeRequest.get("stop_sequences"));
            }

            // 5. stream 直接映射
            if (claudeRequest.has("stream")) {
                openaiRequest.put("stream", claudeRequest.getBoolean("stream"));
            }

            // 6. tools 直接映射
            if (claudeRequest.has("tools")) {
                openaiRequest.put("tools", claudeRequest.get("tools"));
            }

            // 7. tool_choice 直接映射
            if (claudeRequest.has("tool_choice")) {
                openaiRequest.put("tool_choice", claudeRequest.get("tool_choice"));
            }

            // 8. temperature 直接映射
            if (claudeRequest.has("temperature")) {
                openaiRequest.put("temperature", claudeRequest.getDouble("temperature"));
            }

            // 9. top_p 直接映射
            if (claudeRequest.has("top_p")) {
                openaiRequest.put("top_p", claudeRequest.getDouble("top_p"));
            }

            // 10. top_k 移除（OpenAI 不支持），仅记录日志
            if (claudeRequest.has("top_k")) {
                Log.d(TAG, "translate: top_k is not supported by OpenAI, dropping");
            }

            // 11. thinking → reasoning_effort
            translateThinking(claudeRequest, openaiRequest);

            // 12. metadata.user_id → user
            if (claudeRequest.has("metadata")) {
                JSONObject metadata = claudeRequest.getJSONObject("metadata");
                if (metadata.has("user_id")) {
                    openaiRequest.put("user", metadata.getString("user_id"));
                }
            }

            Log.d(TAG, "translate: successfully converted Claude request to OpenAI format");
            return openaiRequest.toString();

        } catch (JSONException e) {
            Log.e(TAG, "translate: failed to translate request", e);
            throw new FormatTranslator.TranslationException(
                    FormatTranslator.TranslationException.ERROR_PARSE,
                    "Failed to parse or convert Claude request: " + e.getMessage(), e);
        }
    }

    /**
     * 将 OpenAI /v1/chat/completions 响应体反向转换为 Claude /v1/messages 响应体
     * <p>
     * 此方法不在 {@link FormatTranslator} 接口中，但作为公共辅助方法提供，
     * 用于在收到后端 OpenAI 格式的响应后，将其转换回 Claude 格式返回给客户端。
     * </p>
     *
     * @param openaiResponseBody OpenAI 格式的响应体 JSON 字符串
     * @return Claude 格式的响应体 JSON 字符串，转换失败时返回原始响应体
     */
    public String translateResponse(String openaiResponseBody) {
        if (openaiResponseBody == null || openaiResponseBody.isEmpty()) {
            Log.w(TAG, "translateResponse: empty response body");
            return openaiResponseBody;
        }

        try {
            JSONObject openaiResponse = new JSONObject(openaiResponseBody);
            JSONObject claudeResponse = new JSONObject();

            // 1. id 映射
            String openaiId = openaiResponse.optString("id", "msg_cliproxy_" + System.currentTimeMillis());
            claudeResponse.put("id", openaiId.replace("chatcmpl-", "msg_"));

            // 2. model 保留原始值
            claudeResponse.put("model", openaiResponse.optString("model", "unknown"));

            // 3. type 固定为 message
            claudeResponse.put("type", "message");

            // 4. role 固定为 assistant
            claudeResponse.put("role", "assistant");

            // 5. content 数组转换
            JSONArray choices = openaiResponse.optJSONArray("choices");
            if (choices != null && choices.length() > 0) {
                JSONObject firstChoice = choices.getJSONObject(0);
                JSONObject message = firstChoice.optJSONObject("message");

                JSONArray contentArray = new JSONArray();
                JSONObject contentBlock = new JSONObject();

                if (message != null && message.has("content") && !message.isNull("content")) {
                    String content = message.getString("content");
                    if (content.isEmpty()) {
                        contentBlock.put("type", "text");
                        contentBlock.put("text", "");
                    } else {
                        contentBlock.put("type", "text");
                        contentBlock.put("text", content);
                    }
                } else {
                    contentBlock.put("type", "text");
                    contentBlock.put("text", "");
                }
                contentArray.put(contentBlock);

                // 处理工具调用（tool_calls → tool_use）
                if (message != null && message.has("tool_calls")) {
                    JSONArray toolCalls = message.getJSONArray("tool_calls");
                    for (int i = 0; i < toolCalls.length(); i++) {
                        JSONObject toolCall = toolCalls.getJSONObject(i);
                        JSONObject toolUseBlock = new JSONObject();
                        toolUseBlock.put("type", "tool_use");
                        toolUseBlock.put("id", toolCall.getString("id"));
                        toolUseBlock.put("name", toolCall.getJSONObject("function").getString("name"));
                        toolUseBlock.put("input", new JSONObject(
                                toolCall.getJSONObject("function").getString("arguments")));
                        contentArray.put(toolUseBlock);
                    }
                }

                claudeResponse.put("content", contentArray);

                // 6. stop_reason 映射
                String finishReason = firstChoice.optString("finish_reason", "end_turn");
                claudeResponse.put("stop_reason", mapFinishReason(finishReason));

                // 7. stop_sequence 处理
                if (firstChoice.has("stop_sequence") && !firstChoice.isNull("stop_sequence")) {
                    claudeResponse.put("stop_sequence", firstChoice.getString("stop_sequence"));
                }
            }

            // 8. usage 映射
            if (openaiResponse.has("usage")) {
                JSONObject openaiUsage = openaiResponse.getJSONObject("usage");
                JSONObject claudeUsage = new JSONObject();
                claudeUsage.put("input_tokens", openaiUsage.optInt("prompt_tokens", 0));
                claudeUsage.put("output_tokens", openaiUsage.optInt("completion_tokens", 0));
                claudeResponse.put("usage", claudeUsage);
            }

            Log.d(TAG, "translateResponse: successfully converted OpenAI response to Claude format");
            return claudeResponse.toString();

        } catch (JSONException e) {
            Log.e(TAG, "translateResponse: failed to translate response", e);
            return openaiResponseBody;
        }
    }

    // ==================== 内部辅助方法 ====================

    /**
     * 转换模型名称：根据 MODEL_MAP 将 Claude 模型名映射为 OpenAI 模型名
     */
    private void translateModel(JSONObject claudeRequest, JSONObject openaiRequest) throws JSONException {
        String claudeModel = claudeRequest.optString("model", "claude-sonnet-4");
        String openaiModel = mapModel(claudeModel);
        openaiRequest.put("model", openaiModel);
        Log.d(TAG, "translateModel: " + claudeModel + " → " + openaiModel);
    }

    /**
     * 转换消息：将 Claude 的 messages + system 合并为 OpenAI 的 messages
     * <p>
     * Claude 的 system 提示位于顶层字段，而 OpenAI 将其作为 role=system 的消息
     * 插入到消息列表的开头。Claude 的 messages 数组中的 role 为 "user"/"assistant"，
     * 与 OpenAI 兼容，直接复制。
     * </p>
     */
    private void translateMessages(JSONObject claudeRequest, JSONObject openaiRequest) throws JSONException {
        JSONArray openaiMessages = new JSONArray();

        // 1. 处理 system 提示：Claude 顶层 system → OpenAI messages[0] role=system
        if (claudeRequest.has("system")) {
            Object systemValue = claudeRequest.get("system");
            Log.d(TAG, "translateMessages: processing system prompt");

            if (systemValue instanceof String) {
                // 纯文本 system
                String systemText = (String) systemValue;
                if (!systemText.isEmpty()) {
                    JSONObject systemMsg = new JSONObject();
                    systemMsg.put("role", "system");
                    systemMsg.put("content", systemText);
                    openaiMessages.put(systemMsg);
                }
            } else if (systemValue instanceof JSONArray) {
                // 多内容块 system（Claude 3+ 支持）
                JSONArray systemBlocks = (JSONArray) systemValue;
                StringBuilder systemText = new StringBuilder();
                for (int i = 0; i < systemBlocks.length(); i++) {
                    JSONObject block = systemBlocks.getJSONObject(i);
                    String type = block.optString("type", "text");
                    if ("text".equals(type)) {
                        if (systemText.length() > 0) {
                            systemText.append("\n");
                        }
                        systemText.append(block.optString("text", ""));
                    }
                }
                if (systemText.length() > 0) {
                    JSONObject systemMsg = new JSONObject();
                    systemMsg.put("role", "system");
                    systemMsg.put("content", systemText.toString());
                    openaiMessages.put(systemMsg);
                }
            }
        }

        // 2. 处理 messages 数组
        if (claudeRequest.has("messages")) {
            JSONArray claudeMessages = claudeRequest.getJSONArray("messages");
            for (int i = 0; i < claudeMessages.length(); i++) {
                JSONObject claudeMsg = claudeMessages.getJSONObject(i);
                JSONObject openaiMsg = new JSONObject();

                // 角色映射：Claude 使用 user/assistant，OpenAI 兼容
                String role = claudeMsg.optString("role", "user");
                openaiMsg.put("role", role);

                // 内容处理：Claude 支持字符串或内容块数组
                Object content = claudeMsg.get("content");
                if (content instanceof String) {
                    String contentStr = (String) content;
                    if (!contentStr.isEmpty()) {
                        openaiMsg.put("content", contentStr);
                    } else {
                        openaiMsg.put("content", "");
                    }
                } else if (content instanceof JSONArray) {
                    // 将 Claude 内容块数组转换为 OpenAI 单文本消息
                    JSONArray contentBlocks = (JSONArray) content;
                    StringBuilder combinedText = new StringBuilder();
                    for (int j = 0; j < contentBlocks.length(); j++) {
                        JSONObject block = contentBlocks.getJSONObject(j);
                        String blockType = block.optString("type", "text");
                        if ("text".equals(blockType)) {
                            if (combinedText.length() > 0) {
                                combinedText.append("\n");
                            }
                            combinedText.append(block.optString("text", ""));
                        } else if ("tool_use".equals(blockType)) {
                            // Claude tool_use → OpenAI tool_calls（在 assistant 消息中）
                            JSONArray toolCalls = openaiMsg.optJSONArray("tool_calls");
                            if (toolCalls == null) {
                                toolCalls = new JSONArray();
                                openaiMsg.put("tool_calls", toolCalls);
                            }
                            JSONObject toolCall = new JSONObject();
                            toolCall.put("id", block.optString("id", ""));
                            toolCall.put("type", "function");
                            JSONObject function = new JSONObject();
                            function.put("name", block.optString("name", ""));
                            function.put("arguments", block.optJSONObject("input").toString());
                            toolCall.put("function", function);
                            toolCalls.put(toolCall);
                        } else if ("tool_result".equals(blockType)) {
                            // Claude tool_result → OpenAI tool 角色消息
                            JSONObject toolMsg = new JSONObject();
                            toolMsg.put("role", "tool");
                            toolMsg.put("tool_call_id", block.optString("tool_use_id", ""));
                            Object blockContent = block.get("content");
                            if (blockContent instanceof String) {
                                toolMsg.put("content", blockContent);
                            } else if (blockContent instanceof JSONArray) {
                                JSONArray innerBlocks = (JSONArray) blockContent;
                                StringBuilder innerText = new StringBuilder();
                                for (int k = 0; k < innerBlocks.length(); k++) {
                                    JSONObject innerBlock = innerBlocks.getJSONObject(k);
                                    if ("text".equals(innerBlock.optString("type", "text"))) {
                                        if (innerText.length() > 0) {
                                            innerText.append("\n");
                                        }
                                        innerText.append(innerBlock.optString("text", ""));
                                    }
                                }
                                toolMsg.put("content", innerText.toString());
                            }
                            // tool_result 作为独立消息插入，而不是当前消息的一部分
                            openaiMessages.put(toolMsg);
                            continue;
                        }
                    }
                    String combined = combinedText.toString();
                    if (!combined.isEmpty()) {
                        openaiMsg.put("content", combined);
                    } else if (!openaiMsg.has("tool_calls")) {
                        openaiMsg.put("content", "");
                    }
                }

                openaiMessages.put(openaiMsg);
            }
        }

        openaiRequest.put("messages", openaiMessages);
    }

    /**
     * 转换 thinking 配置：Claude thinking → OpenAI reasoning_effort
     * <p>
     * Claude 的 thinking 字段包含 type 和 budget_tokens，
     * OpenAI 的 reasoning_effort 为字符串枚举（low/medium/high）。
     * 根据 budget_tokens 自动映射：
     * <ul>
     *   <li>budget_tokens ≤ 4096 → low</li>
     *   <li>4096 < budget_tokens ≤ 16384 → medium</li>
     *   <li>budget_tokens > 16384 → high</li>
     * </ul>
     * </p>
     */
    private void translateThinking(JSONObject claudeRequest, JSONObject openaiRequest) throws JSONException {
        if (!claudeRequest.has("thinking")) {
            return;
        }

        JSONObject thinking = claudeRequest.getJSONObject("thinking");
        String thinkingType = thinking.optString("type", "enabled");

        if ("disabled".equals(thinkingType)) {
            Log.d(TAG, "translateThinking: thinking is disabled, skipping");
            return;
        }

        int budgetTokens = thinking.optInt("budget_tokens", 4096);
        String reasoningEffort;

        if (budgetTokens <= THINKING_BUDGET_LOW_MAX) {
            reasoningEffort = "low";
        } else if (budgetTokens <= THINKING_BUDGET_MEDIUM_MAX) {
            reasoningEffort = "medium";
        } else {
            reasoningEffort = "high";
        }

        openaiRequest.put("reasoning_effort", reasoningEffort);
        Log.d(TAG, "translateThinking: budget_tokens=" + budgetTokens + " → reasoning_effort=" + reasoningEffort);
    }

    /**
     * 模型名称查找：支持精确匹配和前缀匹配
     *
     * @param claudeModel Claude 模型名称
     * @return 对应的 OpenAI 模型名称
     */
    static String mapModel(String claudeModel) {
        if (claudeModel == null || claudeModel.isEmpty()) {
            return "gpt-4-turbo";
        }

        // 精确匹配
        String mapped = MODEL_MAP.get(claudeModel);
        if (mapped != null) {
            return mapped;
        }

        // 前缀匹配：例如 claude-sonnet-4-20250514 可以匹配 claude-sonnet 通配
        for (Map.Entry<String, String> entry : MODEL_MAP.entrySet()) {
            if (claudeModel.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }

        // 尝试匹配系列前缀
        if (claudeModel.contains("sonnet")) {
            return "gpt-4-turbo";
        } else if (claudeModel.contains("opus")) {
            return "gpt-4";
        } else if (claudeModel.contains("haiku")) {
            return "gpt-3.5-turbo";
        }

        // 默认回退
        Log.w(TAG, "mapModel: unknown model '" + claudeModel + "', falling back to gpt-4-turbo");
        return "gpt-4-turbo";
    }

    /**
     * 将 OpenAI finish_reason 映射为 Claude stop_reason
     */
    private String mapFinishReason(String finishReason) {
        if (finishReason == null) {
            return "end_turn";
        }
        switch (finishReason) {
            case "stop":
                return "end_turn";
            case "length":
                return "max_tokens";
            case "tool_calls":
                return "tool_use";
            case "content_filter":
                return "content_filtered";
            default:
                return finishReason;
        }
    }
}