package com.zenyard.ghidra.util;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.GZIPOutputStream;

import ghidra.framework.model.DomainFile;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Utility class for serializing Ghidra Program to binary data (gzip-compressed).
 * 
 * NOTE: mirrors zenyard_ida/binary.py read_compressed_input_file() logic
 */
public class BinarySerializer {
    
    /**
     * Result of binary serialization.
     */
    public static class SerializedBinary {
        private final String name;
        private final byte[] data;
        private final String type;
        
        public SerializedBinary(String name, byte[] data, String type) {
            this.name = name;
            this.data = data;
            this.type = type;
        }
        
        public String getName() {
            return name;
        }
        
        public byte[] getData() {
            return data;
        }
        
        public String getType() {
            return type;
        }
    }
    
    /**
     * Serialize the program's binary file to gzip-compressed data.
     * 
     * Prefers original binary file, falls back to Ghidra project file.
     * 
     * @param program The program to serialize
     * @return Serialized binary with name, data, and type
     * @throws IOException if file cannot be read or compressed
     */
    public static SerializedBinary serializeBinary(Program program) throws IOException {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null");
        }
        
        // Check if it's an Apple dyld cache
        String fileType = getFileType(program);
        if (fileType != null && fileType.toLowerCase().contains("apple dyld cache")) {
            // For dyld cache, return empty data
            return new SerializedBinary("dyld", new byte[0], "dyld");
        }
        
        // Prefer original binary file
        Path inputPath = getBinaryPath(program);
        String name = "binary.gz";
        String fileTypeStr = "binary";
        
        if (inputPath == null || !Files.exists(inputPath)) {
            // Fallback to Ghidra project file
            inputPath = getProjectPath(program);
            if (inputPath != null) {
                name = "idb.gz";
                fileTypeStr = "idb";
            }
        }
        
        if (inputPath == null || !Files.exists(inputPath)) {
            throw new IOException("No input file found for program: " + program.getName());
        }
        
        // Read and compress file
        byte[] compressedData = compressGzip(inputPath);
        
        return new SerializedBinary(name, compressedData, fileTypeStr);
    }

    /**
     * Resolve input file size in bytes.
     *
     * Prefers original binary file, falls back to Ghidra project file.
     *
     * @param program The program whose source file size should be measured
     * @return Size in bytes
     * @throws IOException if input file cannot be resolved
     */
    public static long getInputFileSizeBytes(Program program) throws IOException {
        if (program == null) {
            throw new IllegalArgumentException("Program cannot be null");
        }

        Path inputPath = getBinaryPath(program);
        if (inputPath == null || !Files.exists(inputPath)) {
            inputPath = getProjectPath(program);
        }

        if (inputPath == null || !Files.exists(inputPath)) {
            throw new IOException("No input file found for program: " + program.getName());
        }

        return Files.size(inputPath);
    }
    
    /**
     * Get the original binary file path.
     */
    private static Path getBinaryPath(Program program) {
        try {
            // Try to get executable path from program
            String executablePath = program.getExecutablePath();
            if (executablePath != null && !executablePath.isEmpty()) {
                Path path = Paths.get(executablePath);
                if (Files.exists(path)) {
                    return path;
                }
            }
            
            // Try to get from domain file
            DomainFile domainFile = program.getDomainFile();
            if (domainFile != null) {
                // In Ghidra 12.0, use getPathname() instead of getFile()
                String pathname = domainFile.getPathname();
                if (pathname != null && !pathname.isEmpty()) {
                    File file = new File(pathname);
                    if (file.exists()) {
                        return file.toPath();
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(BinarySerializer.class, "Failed to get binary path: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Get the Ghidra project file path.
     */
    private static Path getProjectPath(Program program) {
        try {
            DomainFile domainFile = program.getDomainFile();
            if (domainFile != null) {
                // In Ghidra 12.0, use getPathname() instead of getFile()
                String pathname = domainFile.getPathname();
                if (pathname != null && !pathname.isEmpty()) {
                    File file = new File(pathname);
                    if (file.exists()) {
                        return file.toPath();
                    }
                }
            }
        } catch (Exception e) {
            Msg.debug(BinarySerializer.class, "Failed to get project path: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Get the file type name from the program.
     */
    private static String getFileType(Program program) {
        try {
            // Try to get format name
            String format = program.getExecutableFormat();
            if (format != null) {
                return format;
            }
            
            // Try to get from domain file
            DomainFile domainFile = program.getDomainFile();
            if (domainFile != null) {
                return domainFile.getContentType();
            }
        } catch (Exception e) {
            Msg.debug(BinarySerializer.class, "Failed to get file type: " + e.getMessage());
        }
        
        return null;
    }
    
    /**
     * Compress a file using gzip.
     */
    private static byte[] compressGzip(Path filePath) throws IOException {
        ByteArrayOutputStream compressedBuffer = new ByteArrayOutputStream();
        
        try (GZIPOutputStream gzipOut = new GZIPOutputStream(compressedBuffer);
             FileInputStream fileIn = new FileInputStream(filePath.toFile())) {
            
            byte[] buffer = new byte[8192];
            int bytesRead;
            while ((bytesRead = fileIn.read(buffer)) != -1) {
                gzipOut.write(buffer, 0, bytesRead);
            }
        }
        
        return compressedBuffer.toByteArray();
    }
}

