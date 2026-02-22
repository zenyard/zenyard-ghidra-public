package com.zenyard.ghidra.copilot.tools;

import java.util.ArrayList;
import java.util.List;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

import com.zenyard.ghidra.copilot.tools.models.Xref;
import com.zenyard.ghidra.copilot.tools.models.ToolOutput;

/**
 * Tool to get all references FROM an address.
 */
public class GetXrefsFromTool {
    
    private final CopilotToolContext context;
    
    public GetXrefsFromTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Return all references FROM a source address (calls, data references, and other ref types).")
    public ToolOutput getXrefsFrom(
            @P("Source address (hex like `0x401000`).") String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "get_xrefs_from", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Address fromAddress = ToolUtils.parseAddress(program, address);
                if (fromAddress == null) {
                    throw new ToolExecutionException("Invalid address: " + address);
                }

                ReferenceManager refManager = program.getReferenceManager();
                Reference[] references = refManager.getReferencesFrom(fromAddress);
                
                List<Xref> allXrefs = new ArrayList<>();
                FunctionManager functionManager = program.getFunctionManager();
                
                for (Reference ref : references) {
                    context.checkCancelled();
                    
                    Address toAddress = ref.getToAddress();
                    
                    // Get context (target function name or data label)
                    String contextStr = "";
                    Function toFunc = functionManager.getFunctionAt(toAddress);
                    if (toFunc != null) {
                        contextStr = toFunc.getName();
                    } else {
                        Data data = program.getListing().getDataAt(toAddress);
                        if (data != null && data.getLabel() != null) {
                            contextStr = data.getLabel();
                        }
                    }
                    
                    String refType = ref.getReferenceType().getName();
                    
                    allXrefs.add(new Xref(
                        ToolUtils.formatAddress(fromAddress),
                        ToolUtils.formatAddress(toAddress),
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
                return ToolUtils.persistLargeOutput(context, "xrefs-from", output.toString(), allXrefs.size());
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get xrefs from address: " + e.getMessage(), e);
            }
        });
    }
}
