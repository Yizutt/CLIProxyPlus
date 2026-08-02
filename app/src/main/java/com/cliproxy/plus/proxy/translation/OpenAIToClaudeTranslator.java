package com.cliproxy.plus.proxy.translation;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

/**
 * OpenAIToClaudeTranslator - OpenAI 协议格式转 Claude 协议格式
 * <p>
 * 将 OpenAI 聊天完成格式 (/v1/chat/completions) 的请求/响应格式转换为
 * Claude API (/v1/messages) 格式。此转换器是协议转换层的一部分，
 * 用于将上游 OpenAI 兼容 API 的请求透明地转发到 Claude 兼容的 API 后端。
 * </p>
 *
 * <h3>字段映射表</h3>
 * <pre>
 * OpenAI (/v1/chat/completions)  →  Claude (/v1/messages)
 * ─────────────────────────────────────────────────────────────
 * model                          →  model（通过模型映射表）
 * messages[].role                →  messages[].role（user/assistant）
 * messages[0] {role:"system"}    →  system（顶层字段）
 * messages[].tool_calls          →  messages[].content tool_use 块
 * messages[].role:"tool"         →  messages[].content tool_result 块
 * max_tokens                     →  max_tokens
 * temperature                    →  temperature
 * top_p                          →  top_p
 * stop                           →  stop_sequences
 * stream                         →  stream
 * tools                          →  tools（格式转换）
 * tool_choice                    →  tool_choice
 * user                           →  metadata.user_id
 * reasoning_effort               →  thinking（反向映射）
 * response_format                →  thinking（json_object/json_schema 模式）
 * </pre>
 *
 * 对应原版 internal/api/translator/openai.go
 *
 * @author CLIProxy Plus Team
 * @version 1.0.0
 */
public class OpenAIToClaudeTranslator implements FormatTranslator {

    private static final String TAG = "OpenAIToClaude";

    /**
     * OpenAI → Claude 模型名称映射表
     * 将 OpenAI 的模型标识符映射为 Claude 兼容的模型标识符
     */
    private static final Map<String, String> MODEL_MAP = new HashMap<>();

    static {
        // GPT-4 系列 → Claude Sonnet/Opus
        MODEL_MAP.put("gpt-4-turbo", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gpt-4-turbo-preview", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gpt-4-0125-preview", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gpt-4-1106-preview", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gpt-4", "claude-opus-4-20250514");
        MODEL_MAP.put("gpt-4-0613", "claude-opus-4-20250514");
        MODEL_MAP.put("gpt-4-32k", "claude-opus-4-20250514");
        MODEL_MAP.put("gpt-4-32k-0613", "claude-opus-4-20250514");

        // GPT-3.5 系列 → Claude Haiku
        MODEL_MAP.put("gpt-3.5-turbo", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gpt-3.5-turbo-0125", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gpt-3.5-turbo-1106", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gpt-3.5-turbo-16k", "claude-2.1");
        MODEL_MAP.put("gpt-3.5-turbo-0613", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gpt-3.5-turbo-16k-0613", "claude-2.1");

        // GPT-4o 系列 → Claude Sonnet
        MODEL_MAP.put("gpt-4o", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gpt-4o-2024-05-13", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gpt-4o-mini", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gpt-4o-mini-2024-07-18", "claude-3-5-haiku-20241022");

        // o1 系列 → Claude Opus with thinking
        MODEL_MAP.put("o1-preview", "claude-opus-4-20250514");
        MODEL_MAP.put("o1-mini", "claude-3-5-sonnet-20241022");
        MODEL_MAP.put("o1", "claude-opus-4-20250514");

        // 通配符兜底
        MODEL_MAP.put("gpt-4", "claude-sonnet-4-20250514");
        MODEL_MAP.put("gpt-3.5", "claude-3-5-haiku-20241022");
        MODEL_MAP.put("gpt-4o", "claude-sonnet-4-20250514");
    }

    /**
     * reasoning_effort → thinking budget_tokens 映射常量
     */
    private static final int THINKING_BUDGET_LOW = 2048;
    private static final int THINKING_BUDGET_MEDIUM = 8192;
    private static final int THINKING_BUDGET_HIGH = 16384;

    /**
     * 将 OpenAI /v1/chat/completions 请求体转换为 Claude /v1/messages 请求体
     * <p>
     * 实现 {@link FormatTranslator#translate(String, Map)} 接口方法。
     * 执行完整的字段映射：模型名称、消息结构、参数（max_tokens、stop、stream、
     * tools、response_format、reasoning_effort 等）从 OpenAI 格式到 Claude 格式。
     * </p>
     *
     * @param sourceJson OpenAI 格式的请求体 JSON 字符串
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
            JSONObject openaiRequest = new JSONObject(sourceJson);
            JSONObject claudeRequest = new JSONObject();

            // 1. 模型名称映射
            translateModel(openaiRequest, claudeRequest);

            // 2. 消息转换：将 OpenAI messages 拆分为 Claude system + messages
            translateMessages(openaiRequest, claudeRequest);

            // 3. max_tokens 直接映射
            if (openaiRequest.has("max_tokens")) {
                claudeRequest.put("max_tokens", openaiRequest.getInt("max_tokens"));
            }

            // 4. temperature 直接映射
            if (openaiRequest.has("temperature")) {
                claudeRequest.put("temperature", openaiRequest.getDouble("temperature"));
            }

            // 5. top_p 直接映射
            if (openaiRequest.has("top_p")) {
                claudeRequest.put("top_p", openaiRequest.getDouble("top_p"));
            }

            // 6. stop → stop_sequences
            if (openaiRequest.has("stop")) {
                claudeRequest.put("stop_sequences", openaiRequest.get("stop"));
            }

            // 7. stream 直接映射
            if (openaiRequest.has("stream")) {
                claudeRequest.put("stream", openaiRequest.getBoolean("stream"));
            }

            // 8. tools 转换：OpenAI function 格式 → Claude tool 格式
            if (openaiRequest.has("tools")) {
                claudeRequest.put("tools", translateTools(openaiRequest.getJSONArray("tools")));
            }

            // 9. tool_choice 直接映射
            if (openaiRequest.has("tool_choice")) {
                claudeRequest.put("tool_choice", openaiRequest.get("tool_choice"));
            }

            // 10. user → metadata.user_id
            if (openaiRequest.has("user")) {
                JSONObject metadata = new JSONObject();
                metadata.put("user_id", openaiRequest.getString("user"));
                claudeRequest.put("metadata", metadata);
            }

            // 11. response_format → thinking
            if (openaiRequest.has("response_format")) {
                translateResponseFormat(openaiRequest, claudeRequest);
            }

            // 12. reasoning_effort → thinking
            if (openaiRequest.has("reasoning_effort")) {
                translateReasoningEffort(openaiRequest, claudeRequest);
            }

            // 13. frequency_penalty 移除（Claude 不支持），仅记录日志
            if (openaiRequest.has("frequency_penalty")) {
                Log.d(TAG, "translate: frequency_penalty is not supported by Claude, dropping");
            }

            // 14. presence_penalty 移除（Claude 不支持），仅记录日志
            if (openaiRequest.has("presence_penalty")) {
                Log.d(TAG, "translate: presence_penalty is not supported by Claude, dropping");
            }

            // 15. logit_bias 移除（Claude 不支持），仅记录日志
            if (openaiRequest.has("logit_bias")) {
                Log.d(TAG, "translate: logit_bias is not supported by Claude, dropping");
            }

            // 16. seed 移除（Claude 不支持），仅记录日志
            if (openaiRequest.has("seed")) {
                Log.d(TAG, "translate: seed is not supported by Claude, dropping");
            }

            Log.d(TAG, "translate: successfully converted OpenAI request to Claude format");
            return claudeRequest.toString();

        } catch (JSONException e) {
            Log.e(TAG, "translate: failed to translate request", e);
            throw new FormatTranslator.TranslationException(
                    FormatTranslator.TranslationException.ERROR_PARSE,
                    "Failed to parse or convert OpenAI request: " + e.getMessage(), e);
        }
    }

    /**
     * 将 Claude /v1/messages 响应体反向转换为 OpenAI /v1/chat/completions 响应体
     * <p>
     * 此方法不在 {@link FormatTranslator} 接口中，但作为公共辅助方法提供，
     * 用于在收到后端 Claude 格式的响应后，将其转换回 OpenAI 格式返回给客户端。
     * </p>
     *
     * @param claudeResponseBody Claude 格式的响应体 JSON 字符串
     * @return OpenAI 格式的响应体 JSON 字符串，转换失败时返回原始响应体
     */
    public String translateResponse(String claudeResponseBody) {
        if (claudeResponseBody == null || claudeResponseBody.isEmpty()) {
            Log.w(TAG, "translateResponse: empty response body");
            return claudeResponseBody;
        }

        try {
            JSONObject claudeResponse = new JSONObject(claudeResponseBody);
            JSONObject openaiResponse = new JSONObject();

            // 1. id 映射
            String claudeId = claudeResponse.optString("id", "chatcmpl-cliproxy-" + System.currentTimeMillis());
            openaiResponse.put("id", claudeId.replace("msg_", "chatcmpl-"));

            // 2. object 固定为 chat.completion
            openaiResponse.put("object", "chat.completion");

            // 3. created 时间戳
            openaiResponse.put("created", System.currentTimeMillis() / 1000);

            // 4. model 保留原始值
            openaiResponse.put("model", claudeResponse.optString("model", "unknown"));

            // 5. choices 数组转换
            JSONArray choices = new JSONArray();
            JSONObject choice = new JSONObject();
            JSONObject message = new JSONObject();

            message.put("role", "assistant");

            // 5a. content 提取
            JSONArray contentArray = claudeResponse.optJSONArray("content");
            StringBuilder contentText = new StringBuilder();
            JSONArray toolCalls = new JSONArray();

            if (contentArray != null) {
                for (int i = 0; i < contentArray.length(); i++) {
                    JSONObject block = contentArray.getJSONObject(i);
                    String blockType = block.optString("type", "text");

                    if ("text".equals(blockType)) {
                        if (contentText.length() > 0) {
                            contentText.append("\n");
                        }
                        contentText.append(block.optString("text", ""));
                    } else if ("tool_use".equals(blockType)) {
                        // Claude tool_use → OpenAI tool_calls
                        JSONObject toolCall = new JSONObject();
                        toolCall.put("id", block.optString("id", ""));
                        toolCall.put("type", "function");
                        JSONObject function = new JSONObject();
                        function.put("name", block.optString("name", ""));
                        function.put("arguments", block.optJSONObject("input").toString());
                        toolCall.put("function", function);
                        toolCalls.put(toolCall);
                    }
                }
            }

            message.put("content", contentText.length() > 0 ? contentText.toString() : "");

            if (toolCalls.length() > 0) {
                message.put("tool_calls", toolCalls);
            }

            choice.put("index", 0);
            choice.put("message", message);

            // 5b. finish_reason 映射
            String stopReason = claudeResponse.optString("stop_reason", "stop");
            choice.put("finish_reason", mapStopReason(stopReason));

            // 5c. logprobs 固定为 null
            choice.put("logprobs", JSONObject.NULL);

            choices.put(choice);
            openaiResponse.put("choices", choices);

            // 6. usage 映射
            if (claudeResponse.has("usage")) {
                JSONObject claudeUsage = claudeResponse.getJSONObject("usage");
                JSONObject openaiUsage = new JSONObject();
                openaiUsage.put("prompt_tokens", claudeUsage.optInt("input_tokens", 0));
                openaiUsage.put("completion_tokens", claudeUsage.optInt("output_tokens", 0));
                openaiUsage.put("total_tokens",
                        claudeUsage.optInt("input_tokens", 0) + claudeUsage.optInt("output_tokens", 0));
                openaiResponse.put("usage", openaiUsage);
            }

            // 7. system_fingerprint 固定值
            openaiResponse.put("system_fingerprint", "fp_claude_proxy");

            Log.d(TAG, "translateResponse: successfully converted Claude response to OpenAI format");
            return openaiResponse.toString();

        } catch (JSONException e) {
            Log.e(TAG, "translateResponse: failed to translate response", e);
            return claudeResponseBody;
        }
    }

    // ==================== 内部辅助方法 ====================

    /**
     * 转换模型名称：根据 MODEL_MAP 将 OpenAI 模型名映射为 Claude 模型名
     */
    private void translateModel(JSONObject openaiRequest, JSONObject claudeRequest) throws JSONException {
        String openaiModel = openaiRequest.optString("model", "gpt-4-turbo");
        String claudeModel = mapModel(openaiModel);
        claudeRequest.put("model", claudeModel);
        Log.d(TAG, "translateModel: " + openaiModel + " → " + claudeModel);
    }

    /**
     * 转换消息：将 OpenAI 的 messages 拆分为 Claude 的 system（顶层）+ messages
     * <p>
     * OpenAI 的 system 提示位于 messages 数组中 role=system 的消息，
     * 而 Claude 将其提取为顶层 system 字段。OpenAI 的 tool_calls 和 tool 角色消息
     * 需要转换为 Claude 的 tool_use 和 tool_result 内容块。
     * </p>
     */
    private void translateMessages(JSONObject openaiRequest, JSONObject claudeRequest) throws JSONException {
        if (!openaiRequest.has("messages")) {
            Log.w(TAG, "translateMessages: no messages in request");
            return;
        }

        JSONArray openaiMessages = openaiRequest.getJSONArray("messages");
        JSONArray claudeMessages = new JSONArray();
        StringBuilder systemContent = new StringBuilder();

        for (int i = 0; i < openaiMessages.length(); i++) {
            JSONObject openaiMsg = openaiMessages.getJSONObject(i);
            String role = openaiMsg.optString("role", "user");

            // 处理 system 角色：提取到顶层 system 字段
            if ("system".equals(role)) {
                Object content = openaiMsg.get("content");
                String text = extractTextContent(content);
                if (text != null && !text.isEmpty()) {
                    if (systemContent.length() > 0) {
                        systemContent.append("\n");
                    }
                    systemContent.append(text);
                }
                continue;
            }

            // 处理 tool 角色：转换为 Claude tool_result 内容块
            if ("tool".equals(role)) {
                JSONObject toolMsg = new JSONObject();
                toolMsg.put("role", "user");

                JSONArray contentBlocks = new JSONArray();
                JSONObject toolResultBlock = new JSONObject();
                toolResultBlock.put("type", "tool_result");
                toolResultBlock.put("tool_use_id", openaiMsg.optString("tool_call_id", ""));
                toolResultBlock.put("content", openaiMsg.optString("content", ""));
                if (openaiMsg.has("is_error")) {
                    toolResultBlock.put("is_error", openaiMsg.getBoolean("is_error"));
                }
                contentBlocks.put(toolResultBlock);
                toolMsg.put("content", contentBlocks);
                claudeMessages.put(toolMsg);
                continue;
            }

            // 处理 user/assistant 角色
            JSONObject claudeMsg = new JSONObject();
            claudeMsg.put("role", role);

            Object content = openaiMsg.opt("content");

            // 检查是否有 tool_calls（仅 assistant 消息）
            boolean hasToolCalls = openaiMsg.has("tool_calls");

            if (hasToolCalls) {
                // assistant 消息包含 tool_calls 时，使用内容块数组
                JSONArray contentBlocks = new JSONArray();

                // 如果有文本内容，添加 text 块
                if (content instanceof String && !((String) content).isEmpty()) {
                    JSONObject textBlock = new JSONObject();
                    textBlock.put("type", "text");
                    textBlock.put("text", content);
                    contentBlocks.put(textBlock);
                } else if (content instanceof JSONArray) {
                    // 传递已有的内容块
                    contentBlocks = (JSONArray) content;
                }

                // 转换 tool_calls → tool_use 内容块
                JSONArray toolCalls = openaiMsg.getJSONArray("tool_calls");
                for (int j = 0; j < toolCalls.length(); j++) {
                    JSONObject openaiToolCall = toolCalls.getJSONObject(j);
                    JSONObject toolUseBlock = new JSONObject();
                    toolUseBlock.put("type", "tool_use");
                    toolUseBlock.put("id", openaiToolCall.optString("id", ""));
                    toolUseBlock.put("name", openaiToolCall.getJSONObject("function").getString("name"));
                    String argumentsStr = openaiToolCall.getJSONObject("function").optString("arguments", "{}");
                    try {
                        toolUseBlock.put("input", new JSONObject(argumentsStr));
                    } catch (JSONException e) {
                        toolUseBlock.put("input", argumentsStr);
                    }
                    contentBlocks.put(toolUseBlock);
                }

                claudeMsg.put("content", contentBlocks);

            } else if (content instanceof JSONArray) {
                // 传递已有的内容块数组
                claudeMsg.put("content", content);
            } else if (content instanceof String) {
                // 纯文本内容
                String text = (String) content;
                if (!text.isEmpty()) {
                    claudeMsg.put("content", text);
                } else {
                    claudeMsg.put("content", "");
                }
            } else {
                claudeMsg.put("content", "");
            }

            claudeMessages.put(claudeMsg);
        }

        // 设置顶层 system 字段
        if (systemContent.length() > 0) {
            claudeRequest.put("system", systemContent.toString());
            Log.d(TAG, "translateMessages: extracted system prompt, length=" + systemContent.length());
        }

        claudeRequest.put("messages", claudeMessages);
    }

    /**
     * 转换 tools：将 OpenAI function 工具格式转换为 Claude 工具格式
     * <p>
     * OpenAI 格式：
     * <pre>
     * {"type": "function", "function": {"name": "...", "description": "...", "parameters": {...}}}
     * </pre>
     * Claude 格式：
     * <pre>
     * {"name": "...", "description": "...", "input_schema": {...}}
     * </pre>
     * </p>
     */
    private JSONArray translateTools(JSONArray openaiTools) throws JSONException, FormatTranslator.TranslationException {
        JSONArray claudeTools = new JSONArray();

        for (int i = 0; i < openaiTools.length(); i++) {
            JSONObject openaiTool = openaiTools.getJSONObject(i);
            String toolType = openaiTool.optString("type", "function");

            if (!"function".equals(toolType)) {
                Log.w(TAG, "translateTools: unsupported tool type '" + toolType + "', skipping");
                continue;
            }

            JSONObject openaiFunction = openaiTool.optJSONObject("function");
            if (openaiFunction == null) {
                Log.w(TAG, "translateTools: tool missing 'function' field, skipping index " + i);
                continue;
            }

            JSONObject claudeTool = new JSONObject();
            claudeTool.put("name", openaiFunction.optString("name", "unknown_function"));
            claudeTool.put("description", openaiFunction.optString("description", ""));

            // 将 OpenAI 的 parameters 映射为 Claude 的 input_schema
            JSONObject parameters = openaiFunction.optJSONObject("parameters");
            if (parameters != null) {
                claudeTool.put("input_schema", parameters);
            } else {
                // 没有 parameters 时提供一个默认的空 schema
                JSONObject defaultSchema = new JSONObject();
                defaultSchema.put("type", "object");
                defaultSchema.put("properties", new JSONObject());
                defaultSchema.put("required", new JSONArray());
                claudeTool.put("input_schema", defaultSchema);
            }

            claudeTools.put(claudeTool);
        }

        Log.d(TAG, "translateTools: converted " + openaiTools.length() + " OpenAI tools to " + claudeTools.length() + " Claude tools");
        return claudeTools;
    }

    /**
     * 转换 response_format：OpenAI response_format → Claude thinking
     * <p>
     * OpenAI 的 response_format 支持 json_object 和 json_schema 模式。
     * 当指定 json_object 或 json_schema 时，在 Claude 中通过启用 thinking
     * 并设置较低的 budget_tokens 来模拟结构化输出，同时记录日志提示
     * json_schema 的差异。
     * </p>
     */
    private void translateResponseFormat(JSONObject openaiRequest, JSONObject claudeRequest) throws JSONException {
        JSONObject responseFormat = openaiRequest.getJSONObject("response_format");
        String formatType = responseFormat.optString("type", "text");

        if ("json_object".equals(formatType)) {
            // 启用 thinking 以鼓励结构化 JSON 输出
            JSONObject thinking = new JSONObject();
            thinking.put("type", "enabled");
            thinking.put("budget_tokens", THINKING_BUDGET_LOW);
            claudeRequest.put("thinking", thinking);
            Log.d(TAG, "translateResponseFormat: json_object → thinking with budget_tokens=" + THINKING_BUDGET_LOW);

            // 在 system prompt 中追加 JSON 输出指令（如果已有 system 字段）
            String jsonInstruction = "You must respond with valid JSON only. " +
                    "Do not include any explanatory text outside the JSON object.";
            String existingSystem = claudeRequest.optString("system", "");
            if (!existingSystem.isEmpty()) {
                claudeRequest.put("system", existingSystem + "\n\n" + jsonInstruction);
            } else {
                claudeRequest.put("system", jsonInstruction);
            }

        } else if ("json_schema".equals(formatType)) {
            // json_schema 模式：启用 thinking 并尝试传递 schema 信息
            JSONObject thinking = new JSONObject();
            thinking.put("type", "enabled");
            thinking.put("budget_tokens", THINKING_BUDGET_MEDIUM);
            claudeRequest.put("thinking", thinking);

            // 将 schema 信息以 system prompt 方式传递
            JSONObject schema = responseFormat.optJSONObject("schema");
            if (schema != null) {
                String schemaInstruction = "You must respond with a valid JSON object that conforms to the " +
                        "following JSON schema:\n" + schema.toString(2);
                String existingSystem = claudeRequest.optString("system", "");
                if (!existingSystem.isEmpty()) {
                    claudeRequest.put("system", existingSystem + "\n\n" + schemaInstruction);
                } else {
                    claudeRequest.put("system", schemaInstruction);
                }
            }

            Log.d(TAG, "translateResponseFormat: json_schema → thinking with budget_tokens=" + THINKING_BUDGET_MEDIUM
                    + (schema != null ? " (schema included in system prompt)" : ""));

        } else {
            Log.d(TAG, "translateResponseFormat: unsupported response_format type '" + formatType + "', skipping");
        }
    }

    /**
     * 转换 reasoning_effort：OpenAI reasoning_effort → Claude thinking
     * <p>
     * OpenAI 的 reasoning_effort 为字符串枚举（low/medium/high），
     * Claude 的 thinking 字段包含 type 和 budget_tokens。
     * 根据 reasoning_effort 自动映射 budget_tokens：
     * <ul>
     *   <li>low → 2048</li>
     *   <li>medium → 8192</li>
     *   <li>high → 16384</li>
     * </ul>
     * </p>
     */
    private void translateReasoningEffort(JSONObject openaiRequest, JSONObject claudeRequest) throws JSONException {
        String reasoningEffort = openaiRequest.optString("reasoning_effort", "medium");
        int budgetTokens;

        switch (reasoningEffort) {
            case "low":
                budgetTokens = THINKING_BUDGET_LOW;
                break;
            case "medium":
                budgetTokens = THINKING_BUDGET_MEDIUM;
                break;
            case "high":
                budgetTokens = THINKING_BUDGET_HIGH;
                break;
            default:
                Log.w(TAG, "translateReasoningEffort: unknown reasoning_effort '" + reasoningEffort
                        + "', defaulting to medium");
                budgetTokens = THINKING_BUDGET_MEDIUM;
                break;
        }

        JSONObject thinking = new JSONObject();
        thinking.put("type", "enabled");
        thinking.put("budget_tokens", budgetTokens);
        claudeRequest.put("thinking", thinking);

        Log.d(TAG, "translateReasoningEffort: reasoning_effort=" + reasoningEffort
                + " → thinking budget_tokens=" + budgetTokens);
    }

    /**
     * 从 OpenAI 消息的 content 字段中提取文本内容
     * <p>
     * content 可以是字符串或内容块数组，此方法统一提取文本部分。
     * </p>
     *
     * @param content content 字段值
     * @return 提取的文本内容，无文本时返回 null
     */
    private String extractTextContent(Object content) {
        if (content == null) {
            return null;
        }
        if (content instanceof String) {
            String text = (String) content;
            return text.isEmpty() ? null : text;
        }
        if (content instanceof JSONArray) {
            JSONArray blocks = (JSONArray) content;
            StringBuilder text = new StringBuilder();
            for (int i = 0; i < blocks.length(); i++) {
                JSONObject block = blocks.optJSONObject(i);
                if (block != null && "text".equals(block.optString("type", "text"))) {
                    if (text.length() > 0) {
                        text.append("\n");
                    }
                    text.append(block.optString("text", ""));
                }
            }
            return text.length() > 0 ? text.toString() : null;
        }
        return null;
    }

    /**
     * 模型名称查找：支持精确匹配和前缀匹配
     *
     * @param openaiModel OpenAI 模型名称
     * @return 对应的 Claude 模型名称
     */
    static String mapModel(String openaiModel) {
        if (openaiModel == null || openaiModel.isEmpty()) {
            return "claude-sonnet-4-20250514";
        }

        // 精确匹配
        String mapped = MODEL_MAP.get(openaiModel);
        if (mapped != null) {
            return mapped;
        }

        // 前缀匹配：例如 gpt-4-turbo-2024-04-09 可以匹配 gpt-4-turbo 通配
        for (Map.Entry<String, String> entry : MODEL_MAP.entrySet()) {
            if (openaiModel.startsWith(entry.getKey())) {
                return entry.getValue();
            }
        }

        // 尝试匹配系列关键词
        String lowerModel = openaiModel.toLowerCase();
        if (lowerModel.contains("gpt-4o") || lowerModel.contains("gpt4o")) {
            return "claude-sonnet-4-20250514";
        } else if (lowerModel.contains("gpt-4") || lowerModel.contains("gpt4")) {
            return "claude-opus-4-20250514";
        } else if (lowerModel.contains("gpt-3.5") || lowerModel.contains("gpt3.5") || lowerModel.contains("gpt-35")) {
            return "claude-3-5-haiku-20241022";
        } else if (lowerModel.contains("o1") || lowerModel.contains("o3")) {
            return "claude-opus-4-20250514";
        }

        // 默认回退
        Log.w(TAG, "mapModel: unknown model '" + openaiModel + "', falling back to claude-sonnet-4-20250514");
        return "claude-sonnet-4-20250514";
    }

    /**
     * 将 Claude stop_reason 映射为 OpenAI finish_reason
     */
    private String mapStopReason(String stopReason) {
        if (stopReason == null) {
            return "stop";
        }
        switch (stopReason) {
            case "end_turn":
                return "stop";
            case "max_tokens":
                return "length";
            case "tool_use":
                return "tool_calls";
            case "content_filtered":
                return "content_filter";
            case "stop_sequence":
                return "stop";
            default:
                return stopReason;
        }
    }
}