package com.zenyard.decompai.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;

/**
 * Tool to set a function's prototype/signature.
 */
public class SetFunctionPrototypeTool {
    
    private final CopilotToolContext context;
    
    public SetFunctionPrototypeTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Sets a function's prototype. Provide a C-style function prototype (e.g., 'int foo(int x, char *y);')")
    public void setFunctionPrototype(String address, String newPrototype) {
        try {
            context.checkCancelled();
            
            Program program = context.getProgram();
            if (program == null) {
                throw new ToolExecutionException("No program is currently loaded");
            }
            
            Function function = ToolUtils.getFunction(program, address);
            if (function == null) {
                throw new ToolExecutionException("Failed to retrieve function from address: " + address);
            }
            
            // Ensure prototype ends with semicolon
            if (!newPrototype.trim().endsWith(";")) {
                newPrototype = newPrototype.trim() + ";";
            }
            
            // Use transaction for program modification
            int transactionId = program.startTransaction("DecompAI: Set function prototype");
            try {
                // Get DataTypeQueryService from tool if available
                // In Ghidra 12.0, DataTypeQueryService may be in a different package
                Object queryService = null;
                if (context.getTool() != null) {
                    try {
                        // Try to get DataTypeQueryService from tool
                        Class<?> queryServiceClass = Class.forName("ghidra.app.services.DataTypeQueryService");
                        queryService = context.getTool().getService(queryServiceClass);
                    } catch (ClassNotFoundException e) {
                        // DataTypeQueryService may not exist or be in a different package
                    }
                }
                
                // Parse the string prototype to FunctionSignature using FunctionSignatureParser
                // FunctionSignatureParser requires DataTypeManager and DataTypeQueryService
                ghidra.app.util.parser.FunctionSignatureParser parser;
                if (queryService != null) {
                    // Use reflection to create parser with queryService
                    java.lang.reflect.Constructor<?> constructor = 
                        ghidra.app.util.parser.FunctionSignatureParser.class.getConstructor(
                            ghidra.program.model.data.DataTypeManager.class,
                            queryService.getClass()
                        );
                    parser = (ghidra.app.util.parser.FunctionSignatureParser) constructor.newInstance(
                        program.getDataTypeManager(),
                        queryService
                    );
                } else {
                    // Fallback: try to create parser with just DataTypeManager
                    // This may work if DataTypeQueryService is optional or has a default
                    try {
                        // Try constructor with just DataTypeManager
                        java.lang.reflect.Constructor<?> constructor = 
                            ghidra.app.util.parser.FunctionSignatureParser.class.getConstructor(
                                ghidra.program.model.data.DataTypeManager.class
                            );
                        parser = (ghidra.app.util.parser.FunctionSignatureParser) constructor.newInstance(
                            program.getDataTypeManager()
                        );
                    } catch (Exception e) {
                        throw new ToolExecutionException("Cannot create FunctionSignatureParser: " + e.getMessage());
                    }
                }
                
                // Parse the signature - FunctionSignatureParser.parse() takes existing signature and new prototype string
                // Function.getSignature() returns FunctionSignature from ghidra.program.model.listing package
                ghidra.program.model.listing.FunctionSignature signature = 
                    parser.parse(function.getSignature(), newPrototype);
                
                // Use ApplyFunctionSignatureCmd to apply the parsed signature
                ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    function.getEntryPoint(),
                    signature,
                    SourceType.USER_DEFINED
                );
                cmd.applyTo(program);
            } finally {
                program.endTransaction(transactionId, true);
            }
        } catch (ToolExecutionException e) {
            throw e;
        } catch (Exception e) {
            throw new ToolExecutionException("Failed to set function prototype: " + e.getMessage(), e);
        }
    }
}

