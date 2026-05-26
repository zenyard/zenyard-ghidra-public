package com.zenyard.ghidra.copilot.tools;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.FunctionRenameOption;
import ghidra.app.util.parser.FunctionSignatureParser;
import com.zenyard.ghidra.util.FunctionPointerTypeSupport;
import com.zenyard.ghidra.util.HeadlessDataTypeQueryService;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * Tool to set a function's prototype/signature.
 */
public class SetFunctionPrototypeTool {

    private final CopilotToolContext context;

    private static final Set<String> C_KEYWORDS = Set.of(
        "void", "char", "short", "int", "long", "float", "double",
        "unsigned", "signed", "const", "volatile", "struct", "union",
        "enum", "typedef", "static", "extern", "register", "auto",
        "bool", "size_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
        "int8_t", "int16_t", "int32_t", "int64_t", "uchar", "uint",
        "ulong", "ushort", "byte", "word", "dword", "qword",
        "undefined", "undefined1", "undefined2", "undefined4", "undefined8",
        "pointer", "addr", "longlong", "ulonglong"
    );

    public SetFunctionPrototypeTool(CopilotToolContext context) {
        this.context = context;
    }

    @Tool("Set a function signature using a C-style prototype. This tool updates return type, parameter types/names, varargs, and preserves the current calling convention/noreturn settings, but it does not rename the function symbol. Inputs: `address` (target function location) and `new_prototype` (for example `int foo(int x, char *y);`). Custom types must already exist in the program data type manager.")
    public String setFunctionPrototype(
            @P("Function address in the current program (hex like `0x401000`).") String address,
            @P("Full C-style function prototype to apply. Include parameter names where possible; trailing semicolon is optional.") String newPrototype) {
        java.util.Map<String, Object> args = new java.util.HashMap<>();
        args.put("address", address);
        args.put("new_prototype", newPrototype);
        return ToolUtils.executeTool(context, "set_function_prototype", args, () -> {
            try {
                context.checkCancelled();

                Program program = context.getProgram();
                if (program == null) {
                    throw new ToolExecutionException("No program is currently loaded");
                }

                Function function = ToolUtils.getFunction(program, address);
                if (function == null) {
                    throw new ToolExecutionException(
                        "Failed to retrieve function from address: " + address);
                }

                String prototype = newPrototype.trim();
                if (prototype.endsWith(";")) {
                    prototype = prototype.substring(0, prototype.length() - 1).trim();
                }

                int transactionId = program.startTransaction(
                    "Zenyard: Set function prototype");
                boolean commit = false;
                try {
                    DataTypeManager dtm = program.getDataTypeManager();
                    prototype = FunctionPointerTypeSupport.preprocessPrototypeForSignatureParser(
                        program, prototype);

                    FunctionSignatureParser parser = new FunctionSignatureParser(
                        dtm, new HeadlessDataTypeQueryService(dtm));

                    FunctionDefinitionDataType signature;
                    try {
                        signature = parser.parse(
                            function.getSignature(), prototype);
                    } catch (Exception parseError) {
                        String parseMsg = parseError.getMessage();
                        if (parseMsg == null) {
                            parseMsg = parseError.getClass().getSimpleName();
                        }
                        String typeHints = suggestTypes(dtm, prototype);
                        throw new ToolExecutionException(
                            "Failed to parse prototype '" + prototype + "': "
                            + parseMsg
                            + ". All custom/struct types must exist in the "
                            + "program's data type manager."
                            + typeHints
                            + " Call getLocalTypes to see all available types.");
                    }

                    try {
                        signature.setCategoryPath(FunctionPointerTypeSupport.ZENYARD_PROTOTYPES_CATEGORY);
                    } catch (Exception e) {
                        Msg.warn(SetFunctionPrototypeTool.class,
                            "Could not set prototype category to /zenyard/prototypes: " + e.getMessage());
                    }

                    // The parser only reconstructs the textual signature fields.
                    // Preserve attributes edited outside the raw prototype text.
                    signature.setNoReturn(function.hasNoReturn());
                    try {
                        signature.setCallingConvention(function.getCallingConventionName());
                    } catch (Exception ignored) {
                        // Leave calling convention unchanged if Ghidra rejects the current value.
                    }

                    ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                        function.getEntryPoint(),
                        signature,
                        SourceType.USER_DEFINED,
                        false,
                        false,
                        null,
                        FunctionRenameOption.NO_CHANGE
                    );
                    boolean success = cmd.applyTo(program);
                    if (!success) {
                        String statusMsg = cmd.getStatusMsg();
                        throw new ToolExecutionException(
                            "Failed to apply signature: "
                            + (statusMsg != null ? statusMsg : "unknown error"));
                    }
                    commit = true;
                } finally {
                    program.endTransaction(transactionId, commit);
                }
                String currentFunctionName = function.getName();
                if (currentFunctionName.equals(signatureNameFromPrototype(prototype))) {
                    return "Successfully set prototype for function at " + address
                        + " to: " + prototype
                        + ". Symbol name was unchanged.";
                }
                return "Successfully set prototype for function at " + address
                    + " to: " + prototype
                    + ". Note: function symbol name remains '" + currentFunctionName
                    + "'. If you also want to rename it to '"
                    + signatureNameFromPrototype(prototype)
                    + "', call renameSymbol separately.";
            } catch (ToolExecutionException e) {
                throw e;
            } catch (Exception e) {
                throw new ToolExecutionException(
                    "Failed to set function prototype: " + e.getMessage(), e);
            }
        });
    }

    // ----------------------------------------------------------------
    // Error diagnostics helpers
    // ----------------------------------------------------------------

    /**
     * Identifies non-primitive type names in the prototype, checks whether
     * they exist in the DTM, and produces a hint string for the agent.
     */
    private String suggestTypes(DataTypeManager dtm, String prototype) {
        List<String> unknownTypes = new ArrayList<>();
        List<String> suggestions = new ArrayList<>();

        String returnAndName = prototype.contains("(")
            ? prototype.substring(0, prototype.indexOf('('))
            : prototype;
        String params = prototype.contains("(") && prototype.contains(")")
            ? prototype.substring(
                prototype.indexOf('(') + 1, prototype.lastIndexOf(')'))
            : "";

        checkTypeTokens(dtm, returnAndName.trim(), unknownTypes, suggestions);

        if (!params.isBlank()) {
            for (String param : params.split(",")) {
                checkTypeTokens(dtm, param.trim(), unknownTypes, suggestions);
            }
        }

        if (unknownTypes.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        sb.append(" Unknown type(s): ")
          .append(String.join(", ", unknownTypes)).append(".");
        if (!suggestions.isEmpty()) {
            sb.append(" Similar types found: ")
              .append(String.join(", ", suggestions)).append(".");
        }
        return sb.toString();
    }

    private String signatureNameFromPrototype(String prototype) {
        int parenIndex = prototype.indexOf('(');
        if (parenIndex < 0) {
            return prototype;
        }
        String beforeParen = prototype.substring(0, parenIndex).trim();
        int lastSpace = beforeParen.lastIndexOf(' ');
        if (lastSpace < 0) {
            return beforeParen;
        }
        return beforeParen.substring(lastSpace + 1).trim();
    }

    private void checkTypeTokens(DataTypeManager dtm, String fragment,
            List<String> unknownTypes, List<String> suggestions) {
        String cleaned = fragment.replaceAll("[*&\\[\\];]", " ")
            .replaceAll(
                "\\b(const|volatile|struct|union|enum|unsigned|signed)\\b",
                "")
            .trim();
        String[] tokens = cleaned.split("\\s+");
        if (tokens.length == 0) {
            return;
        }

        for (int i = 0; i < tokens.length - 1; i++) {
            String token = tokens[i].trim();
            if (token.isEmpty()
                    || C_KEYWORDS.contains(token.toLowerCase())) {
                continue;
            }
            List<DataType> found = new ArrayList<>();
            dtm.findDataTypes(token, found);
            if (found.isEmpty() && !unknownTypes.contains(token)) {
                unknownTypes.add(token);
                List<String> similar = findSimilarTypeNames(dtm, token);
                suggestions.addAll(similar);
            }
        }
    }

    private List<String> findSimilarTypeNames(
            DataTypeManager dtm, String name) {
        List<String> similar = new ArrayList<>();
        String lowerName = name.toLowerCase();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            String dtName = dt.getName();
            if (dtName != null) {
                String lowerDtName = dtName.toLowerCase();
                if (lowerDtName.contains(lowerName)
                        || lowerName.contains(lowerDtName)) {
                    if (!similar.contains(dtName)) {
                        similar.add(dtName);
                    }
                    if (similar.size() >= 5) {
                        break;
                    }
                }
            }
        }
        return similar;
    }
}
