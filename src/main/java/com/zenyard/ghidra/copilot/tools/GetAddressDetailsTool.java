package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import com.zenyard.ghidra.copilot.tools.models.AddressDetails;

/**
 * Tool to get comprehensive information about an address.
 */
public class GetAddressDetailsTool {
    
    private final CopilotToolContext context;
    
    public GetAddressDetailsTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Returns comprehensive information about the given address, including " +
          "whether it's in a function, data, code, symbol name, data type, comments, etc.")
    public AddressDetails getAddressDetails(String address) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        return ToolUtils.executeTool(context, "get_address_details", args, () -> {
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

                Listing listing = program.getListing();
                SymbolTable symbolTable = program.getSymbolTable();
                
                String addressType = "unknown";
                String label = null;
                String dataType = null;
                String functionName = null;
                String comment = null;
                String value = null;
                
                // Check if it's in a function
                Function function = program.getFunctionManager().getFunctionContaining(addr);
                if (function != null) {
                    addressType = "function";
                    functionName = function.getName();
                }
                
                // Check if it's data
                Data data = listing.getDataAt(addr);
                if (data != null) {
                    if (addressType.equals("unknown")) {
                        addressType = "data";
                    }
                    DataType dt = data.getDataType();
                    if (dt != null) {
                        dataType = dt.getName();
                    }
                    try {
                        Object valueObj = data.getValue();
                        if (valueObj != null) {
                            value = valueObj.toString();
                        }
                    } catch (Exception e) {
                        // Ignore if we can't read the value
                    }
                }
                
                // Check if it's code (instruction)
                Instruction instruction = listing.getInstructionAt(addr);
                if (instruction != null) {
                    if (addressType.equals("unknown")) {
                        addressType = "code";
                    }
                }
                
                // Get symbol/label
                Symbol primarySymbol = symbolTable.getPrimarySymbol(addr);
                if (primarySymbol != null) {
                    label = primarySymbol.getName();
                }
                
                // Get comment (prefer EOL comment, fall back to PRE comment)
                comment = listing.getComment(CommentType.EOL, addr);
                if (comment == null || comment.isEmpty()) {
                    comment = listing.getComment(CommentType.PRE, addr);
                }
                
                return new AddressDetails(
                    ToolUtils.formatAddress(addr),
                    addressType,
                    label,
                    dataType,
                    functionName,
                    comment,
                    value
                );
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to get address details: " + e.getMessage(), e);
            }
        });
    }
}
