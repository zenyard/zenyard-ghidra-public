package com.zenyard.decompai.ghidra.copilot.tools;

/**
 * Exception thrown by tools for user-facing errors.
 * Mirrors IDA's ToolUserError pattern.
 * 
 * This exception is caught by LangChain4j and converted to error messages
 * in the conversation, allowing the agent to continue execution.
 */
public class ToolExecutionException extends RuntimeException {
    
    public ToolExecutionException(String message) {
        super(message);
    }
    
    public ToolExecutionException(String message, Throwable cause) {
        super(message, cause);
    }
}

