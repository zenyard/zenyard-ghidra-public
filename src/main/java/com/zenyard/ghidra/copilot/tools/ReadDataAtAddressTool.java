package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;

/**
 * Tool to read raw data/bytes at an address.
 */
public class ReadDataAtAddressTool {
    
    private final CopilotToolContext context;
    
    public ReadDataAtAddressTool(CopilotToolContext context) {
        this.context = context;
    }
    
    @Tool("Read data and raw bytes starting at an address. Returns detected data type/value (if defined) plus a hexdump.")
    public String readDataAtAddress(
            @P("Start address to read from (hex like `0x401000`).") String address,
            @P(value = "Optional number of bytes to read. Defaults to 16 and is capped at 256.", required = false) Integer length) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        if (length != null) {
            args.put("length", length);
        }
        return ToolUtils.executeTool(context, "read_data_at_address", args, () -> {
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
                Memory memory = program.getMemory();
                
                StringBuilder result = new StringBuilder();
                
                // Try to get defined data first
                Data data = listing.getDataAt(addr);
                if (data != null) {
                    DataType dt = data.getDataType();
                    String typeName = dt != null ? dt.getName() : "unknown";
                    String valueRepr = "";
                    try {
                        valueRepr = data.getDefaultValueRepresentation();
                    } catch (Exception e) {
                        valueRepr = "(unreadable)";
                    }
                    
                    result.append(String.format("Type: %s\n", typeName));
                    result.append(String.format("Value: %s\n", valueRepr));
                }
                
                // Read raw bytes
                int readLength = (length != null && length > 0) ? length : 16; // Default 16 bytes
                if (readLength > 256) {
                    readLength = 256; // Limit to 256 bytes
                }
                
                try {
                    byte[] bytes = new byte[readLength];
                    int bytesRead = memory.getBytes(addr, bytes);
                    
                    result.append(String.format("Raw bytes (%d bytes):\n", bytesRead));
                    result.append(formatBytes(bytes, bytesRead, addr));
                } catch (MemoryAccessException e) {
                    result.append("Error reading memory: " + e.getMessage());
                }
                
                return result.toString();
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException("Failed to read data at address: " + e.getMessage(), e);
            }
        });
    }
    
    /**
     * Format bytes in hexdump style.
     */
    private String formatBytes(byte[] bytes, int length, Address baseAddress) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i += 16) {
            Address currentAddr = baseAddress.add(i);
            sb.append(String.format("%s: ", ToolUtils.formatAddress(currentAddr)));
            
            // Hex bytes
            for (int j = 0; j < 16 && (i + j) < length; j++) {
                sb.append(String.format("%02x ", bytes[i + j]));
            }
            
            // ASCII representation
            sb.append(" |");
            for (int j = 0; j < 16 && (i + j) < length; j++) {
                byte b = bytes[i + j];
                char c = (b >= 32 && b < 127) ? (char) b : '.';
                sb.append(c);
            }
            sb.append("|\n");
        }
        return sb.toString();
    }
}
