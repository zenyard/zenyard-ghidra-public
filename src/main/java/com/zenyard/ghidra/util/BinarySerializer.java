package com.zenyard.ghidra.util;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.Comparator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.zip.GZIPOutputStream;

import ghidra.framework.model.DomainFile;
import ghidra.program.database.mem.FileBytes;
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

        // Prefer reconstructing from Ghidra's stored original bytes to avoid filesystem
        // path issues on platforms where executable path format is not directly usable.
        byte[] reconstructed = compressFromProgramFileBytes(program);
        if (reconstructed != null) {
            return new SerializedBinary("binary.gz", reconstructed, "binary");
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

        Long ghidraSize = getSizeFromProgramFileBytes(program);
        if (ghidraSize != null && ghidraSize > 0) {
            return ghidraSize.longValue();
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
     * Resolve input file size from Ghidra's stored FileBytes metadata.
     * Uses the maximum covered source-file extent across all file-byte segments.
     */
    private static Long getSizeFromProgramFileBytes(Program program) {
        try {
            List<FileBytes> fileBytesList = program.getMemory().getAllFileBytes();
            if (fileBytesList == null || fileBytesList.isEmpty()) {
                return null;
            }

            long maxEnd = 0;
            for (FileBytes fileBytes : fileBytesList) {
                if (fileBytes == null) {
                    continue;
                }
                long segmentSize = fileBytes.getSize();
                if (segmentSize <= 0) {
                    continue;
                }
                long segmentOffset = fileBytes.getFileOffset();
                long segmentEnd;
                try {
                    segmentEnd = Math.addExact(segmentOffset, segmentSize);
                } catch (ArithmeticException ignored) {
                    segmentEnd = Long.MAX_VALUE;
                }
                if (segmentEnd > maxEnd) {
                    maxEnd = segmentEnd;
                }
            }

            return maxEnd > 0 ? Long.valueOf(maxEnd) : null;
        } catch (Exception e) {
            Msg.debug(BinarySerializer.class,
                "Failed to get input size from program file bytes: " + e.getMessage());
            return null;
        }
    }

    /**
     * Reconstruct and gzip original file bytes from Ghidra metadata.
     * Returns null if no suitable file-bytes source can be resolved.
     */
    private static byte[] compressFromProgramFileBytes(Program program) {
        try {
            List<FileBytes> sourceSegments = selectPrimaryFileBytesSegments(program);
            if (sourceSegments.isEmpty()) {
                return null;
            }

            ByteArrayOutputStream compressedBuffer = new ByteArrayOutputStream();
            try (GZIPOutputStream gzipOut = new GZIPOutputStream(compressedBuffer)) {
                byte[] buffer = new byte[8192];
                long writtenEnd = Long.MIN_VALUE;

                for (FileBytes segment : sourceSegments) {
                    long segmentStart = Math.max(0L, segment.getFileOffset());
                    long segmentSize = segment.getSize();
                    if (segmentSize <= 0) {
                        continue;
                    }

                    long readStart = segmentStart;
                    if (writtenEnd != Long.MIN_VALUE && segmentStart < writtenEnd) {
                        readStart = writtenEnd; // overlap: skip already written range
                    }
                    if (readStart >= segmentStart + segmentSize) {
                        continue;
                    }

                    long localOffset = readStart - segmentStart;
                    long remaining = (segmentStart + segmentSize) - readStart;
                    while (remaining > 0) {
                        int chunkSize = (int) Math.min(buffer.length, remaining);
                        int read = segment.getOriginalBytes(localOffset, buffer, 0, chunkSize);
                        if (read <= 0) {
                            throw new IOException("Failed to reconstruct bytes from Ghidra file bytes");
                        }
                        gzipOut.write(buffer, 0, read);
                        localOffset += read;
                        remaining -= read;
                    }

                    writtenEnd = Math.max(writtenEnd, segmentStart + segmentSize);
                }
            }

            byte[] compressed = compressedBuffer.toByteArray();
            return compressed.length > 0 ? compressed : null;
        } catch (Exception e) {
            Msg.debug(BinarySerializer.class,
                "Failed to reconstruct binary from program file bytes: " + e.getMessage());
            return null;
        }
    }

    /**
     * Select a primary file-bytes source by grouping segments by source filename and
     * choosing the group with the largest aggregate size.
     */
    private static List<FileBytes> selectPrimaryFileBytesSegments(Program program) {
        List<FileBytes> all = program.getMemory().getAllFileBytes();
        if (all == null || all.isEmpty()) {
            return List.of();
        }

        Map<String, Long> sizeByName = new HashMap<>();
        for (FileBytes segment : all) {
            if (segment == null) {
                continue;
            }
            long size = segment.getSize();
            if (size <= 0) {
                continue;
            }
            String name = normalizeSegmentName(segment.getFilename());
            Long current = sizeByName.get(name);
            long updated = (current != null ? current.longValue() : 0L) + size;
            sizeByName.put(name, updated);
        }
        if (sizeByName.isEmpty()) {
            return List.of();
        }

        String selectedName = null;
        long maxSize = Long.MIN_VALUE;
        for (Map.Entry<String, Long> entry : sizeByName.entrySet()) {
            if (entry.getValue() > maxSize) {
                selectedName = entry.getKey();
                maxSize = entry.getValue();
            }
        }
        if (selectedName == null) {
            return List.of();
        }

        List<FileBytes> selected = new ArrayList<>();
        for (FileBytes segment : all) {
            if (segment == null || segment.getSize() <= 0) {
                continue;
            }
            if (selectedName.equals(normalizeSegmentName(segment.getFilename()))) {
                selected.add(segment);
            }
        }
        selected.sort(Comparator.comparingLong(FileBytes::getFileOffset));
        return selected;
    }

    private static String normalizeSegmentName(String name) {
        return name == null ? "" : name;
    }
    
    /**
     * Get the original binary file path.
     */
    private static Path getBinaryPath(Program program) {
        try {
            // Try to get executable path from program
            String executablePath = program.getExecutablePath();
            if (executablePath != null && !executablePath.isEmpty()) {
                Path path = resolveExistingPath(executablePath);
                if (path != null) {
                    return path;
                }
            }
        } catch (Exception e) {
            Msg.debug(BinarySerializer.class, "Failed to read executable path: " + e.getMessage());
        }
            
        try {
            // Try to get from domain file
            DomainFile domainFile = program.getDomainFile();
            if (domainFile != null) {
                // In Ghidra 12.0, use getPathname() instead of getFile()
                String pathname = domainFile.getPathname();
                if (pathname != null && !pathname.isEmpty()) {
                    Path path = resolveExistingPath(pathname);
                    if (path != null) {
                        return path;
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
                    Path path = resolveExistingPath(pathname);
                    if (path != null) {
                        return path;
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
     * Resolve a path string that may be a filesystem path or file:// URI.
     */
    private static Path resolveExistingPath(String value) {
        if (value == null) {
            return null;
        }
        String candidate = value.trim();
        if (candidate.isEmpty()) {
            return null;
        }

        Path directPath = parsePath(candidate);
        if (directPath != null && Files.exists(directPath)) {
            return directPath;
        }

        Path uriPath = parseFileUriPath(candidate);
        if (uriPath != null && Files.exists(uriPath)) {
            return uriPath;
        }

        return null;
    }

    private static Path parsePath(String value) {
        try {
            return Paths.get(value);
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static Path parseFileUriPath(String value) {
        if (!value.regionMatches(true, 0, "file:", 0, 5)) {
            return null;
        }
        try {
            URI uri = URI.create(value);
            if (!"file".equalsIgnoreCase(uri.getScheme())) {
                return null;
            }
            return Paths.get(uri);
        } catch (RuntimeException e) {
            return null;
        }
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

