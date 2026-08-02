package com.cliproxy.plus.agent.llm;

import android.util.Log;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.List;

/**
 * LLMClient - AI Agent 所使用的 LLM 客户端接口
 * <p>
 * 定义了大语言模型调用的统一抽象，所有具体 LLM 提供商（如 OpenAI、Claude、Gemini 等）
 * 均需实现本接口，以支持 AI Agent 的对话生成与流式输出功能。
 * </p>
 *
 * @see StreamCallback
 */
public interface LLMClient {

    String TAG = "LLMClient";

    /**
     * 生成非流式响应 —— 发送系统提示词和用户消息到 LLM，返回完整回复文本。
     * <p>
     * 调用方将阻塞等待完整响应返回。适用于不需要实时逐 Token 输出的场景，
     * 例如工具调用（Function Calling）结果解析或短文本生成。
     * </p>
     *
     * @param systemPrompt 系统级提示词，用于设定 LLM 的角色和行为准则
     * @param userMessage  用户输入的消息内容
     * @param tools        可供 LLM 调用的工具列表（每个工具名称作为字符串元素），
     *                     若无需工具可为空列表或 null
     * @return LLM 生成的完整回复文本，失败时返回 null
     * @throws Exception 当网络请求失败、API 返回错误或 JSON 解析异常时抛出
     */
    String generateResponse(String systemPrompt, String userMessage, List<String> tools) throws Exception;

    /**
     * 生成流式响应 —— 通过回调逐 Token 接收 LLM 输出的同时，最终返回完整文本。
     * <p>
     * 适用于需要在 UI 上实时展示生成内容的场景，如聊天机器人逐字输出效果。
     * 流式请求期间通过 {@link StreamCallback} 通知调用方每个 Token、
     * 完成事件或错误信息。
     * </p>
     *
     * @param systemPrompt 系统级提示词，用于设定 LLM 的角色和行为准则
     * @param userMessage  用户输入的消息内容
     * @param tools        可供 LLM 调用的工具列表（每个工具名称作为字符串元素），
     *                     若无需工具可为空列表或 null
     * @param callback     流式回调接口，用于接收 Token、完成通知和错误通知
     * @return LLM 生成的完整回复文本（流式结束后拼接而成），失败时返回 null
     * @throws Exception 当网络请求失败、API 返回错误或 JSON 解析异常时抛出
     */
    String generateStreaming(String systemPrompt, String userMessage, List<String> tools,
                             StreamCallback callback) throws Exception;

    /**
     * StreamCallback - 流式响应回调接口
     * <p>
     * 用于接收 LLM 流式输出过程中的逐 Token 增量、完成事件和错误事件。
     * 实现类通常持有 UI 引用以更新界面，或持有 StringBuilder 以拼接完整结果。
     * </p>
     *
     * <p>
     * 回调方法调用时序约定：<br>
     * <ul>
     *   <li>正常情况：{@link #onToken(String)} 被调用零次或多次，最后调用 {@link #onComplete(String)}</li>
     *   <li>异常情况：{@link #onToken(String)} 被调用零次或多次后，调用 {@link #onError(Exception)}</li>
     *   <li>一旦调用 {@link #onComplete(String)} 或 {@link #onError(Exception)}，后续不再有回调</li>
     * </ul>
     * </p>
     */
    interface StreamCallback {

        /**
         * 收到一个响应 Token 时调用。
         * <p>
         * 每次调用携带一个文本片段，调用方通常将其追加到当前输出缓冲区，
         * 并更新 UI 以展示实时生成效果。
         * </p>
         *
         * @param token 本次收到的文本片段（Token），可能包含空格或标点。不会为 null。
         */
        void onToken(String token);

        /**
         * 流式响应完成时调用。
         * <p>
         * 表示 LLM 已输出完整回复，流式传输结束。
         * 调用方应在此方法中清理临时状态，并将完整结果提交给后续处理流程。
         * </p>
         *
         * @param fullResponse 所有 Token 拼接而成的完整回复文本。不会为 null。
         */
        void onComplete(String fullResponse);

        /**
         * 流式响应过程中发生错误时调用。
         * <p>
         * 表示流式传输因网络异常、API 错误或数据解析失败而中断。
         * 调用方应在此方法中处理错误状态（如显示错误提示、重试或记录日志）。
         * </p>
         *
         * @param e 描述错误原因的异常对象。不会为 null。
         */
        void onError(Exception e);
    }
}