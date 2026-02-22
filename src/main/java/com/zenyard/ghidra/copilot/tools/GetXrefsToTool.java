package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;

import com.zenyard.ghidra.copilot.tools.models.Xref;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to get all references TO an address.
 */
public class GetXrefsToTool {
    
    private final CopilotToolContext context;
    
    public GetXrefsToTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Return all references TO a target address (calls, data references, and other ref types).")
    public ToolOutput getXrefsTo(
            @P("Target address (hex like `0x401000`).") String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "get_xrefs_to", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Address targetAddress = ToolUtils.parseAddress(program, address);
                if (targetAddress == null) {
                    throw new ToolExecutionException("Invalid address: " + address);
                }

                ReferenceManager refManager = program.getReferenceManager();
                ReferenceIterator refIter = refManager.getReferencesTo(targetAddress);
                
                List<Xref> allXrefs = new ArrayList<>();
                FunctionManager functionManager = program.getFunctionManager();
                
                while (refIter.hasNext()) {
                    context.checkCancelled();
                    
                    Reference ref = refIter.next();
                    Address fromAddress = ref.getFromAddress();
                    
                    // Get context (function name if in a function)
                    Function fromFunc = functionManager.getFunctionContaining(fromAddress);
                    String contextStr = fromFunc != null ? fromFunc.getName() : "";
                    
                    String refType = ref.getReferenceType().getName();
                    
                    allXrefs.add(new Xref(
                        ToolUtils.formatAddress(fromAddress),
                        ToolUtils.formatAddress(targetAddress),
                        refType,
                        contextStr
                    ));
                }
                
                StringBuilder output = new StringBuilder();
                for (Xref xref : allXrefs) {
                    output.append(xref.getFromAddress())
                        .append(" -> ")
                        .append(xref.getToAddress())
                        .append(" ")
                        .append(xref.getReferenceType())
                        .append(" ")
                        .append(xref.getContext())
                        .append("\n");
                }
                return ToolUtils.persistLargeOutput(context, "xrefs-to", output.toString(), allXrefs.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get xrefs to address: " + e.getMessage(), e);
            }
        });
    }
}
