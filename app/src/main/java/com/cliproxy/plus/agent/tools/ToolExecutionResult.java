package com.cliproxy.plus.agent.tools;

/**
 * ToolExecutionResult - 工具执行结果
 * <p>
 * 封装 AI Agent 工具执行的结果，包含执行状态、返回数据等。
 * </p>
 */
public class ToolExecutionResult {

    private final boolean success;
    private final String result;
    private final String error;

    /**
     * 构造成功执行结果
     *
     * @param result 执行结果数据
     */
    public ToolExecutionResult(String result) {
        this.success = true;
        this.result = result;
        this.error = null;
    }

    /**
     * 构造执行结果（成功或失败）
     *
     * @param success 是否成功
     * @param result  执行结果数据
     * @param error   错误信息（失败时）
     */
    public ToolExecutionResult(boolean success, String result, String error) {
        this.success = success;
        this.result = result;
        this.error = error;
    }

    /**
     * 获取执行结果数据
     *
     * @return 结果字符串
     */
    public String getResult() {
        return result;
    }

    /**
     * 判断执行是否成功
     *
     * @return true 表示成功
     */
    public boolean isSuccess() {
        return success;
    }

    /**
     * 获取错误信息
     *
     * @return 错误信息，无错误时返回 null
     */
    public String getError() {
        return error;
    }
}