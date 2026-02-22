package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;

/**
 * Tool to disassemble a function to assembly code.
 */
public class DisassembleFunctionTool {
    
    private final CopilotToolContext context;
    
    public DisassembleFunctionTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Return instruction-level disassembly for one function. Input requires `address`: a function entry address or any address inside the function.")
    public String disassembleFunction(
            @P("Function address in the current program (hex like `0x401000`). This can be the function entry point or any instruction address within the function.") String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "disassemble_function", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Address addr = ToolUtils.parseAddress(program, address);
                if (addr == null) {
                    throw new ToolExecutionException("Invalid address: " + address);
                }

                // Get function containing or at this address
                ghidra.program.model.listing.Function function = ToolUtils.getFunctionContaining(program, address);
                if (function == null) {
                    function = ToolUtils.getFunction(program, address);
                }
                
                if (function == null) {
                    throw new ToolExecutionException("No function found at or containing address: " + address);
                }

                Listing listing = program.getListing();
                Address start = function.getEntryPoint();
                Address end = function.getBody().getMaxAddress();

                StringBuilder result = new StringBuilder();
                InstructionIterator instructions = listing.getInstructions(start, true);
                
                while (instructions.hasNext()) {
                    context.checkCancelled();
                    
                    Instruction instr = instructions.next();
                    if (instr.getAddress().compareTo(end) > 0) {
                        break; // Stop if we've gone past the end of the function
                    }
                    
                    String comment = listing.getComment(CommentType.EOL, instr.getAddress());
                    comment = (comment != null) ? " ; " + comment : "";

                    result.append(String.format("%s: %s%s\n", 
                        ToolUtils.formatAddress(instr.getAddress()), 
                        instr.toString(),
                        comment));
                }

                return result.toString();
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to disassemble function: " + e.getMessage(), e);
            }
        });
    }
}
