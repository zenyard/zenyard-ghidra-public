package com.zenyard.decompai.ghidra.util;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.FileAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.config.LoggerConfig;
import org.apache.logging.log4j.core.layout.PatternLayout;

import ghidra.util.Msg;

/**
 * Logger utility that creates per-project or per-binary log files.
 * 
 * Uses Log4j2 (which Ghidra uses) for file logging, with per-program log files.
 * 
 * NOTE: mirrors decompai_ida/logger.py which opens per-IDB log files,
 * but uses Log4j2 to match Ghidra's logging infrastructure.
 */
public class LoggerUtil {
    
    private static final String LOG_DIR = "logs/decompai";
    private static final String LOGGER_NAME = "com.zenyard.decompai";
    
    /**
     * Configure logging for a specific program/project.
     * 
     * Creates a per-program log file using Log4j2, which is compatible with Ghidra's logging system.
     * 
     * @param programName The name of the program (used for log file naming)
     * @param logLevel The log level (e.g., "DEBUG", "INFO", "WARN", "ERROR")
     */
    public static void configureForProgram(String programName, String logLevel) {
        try {
            // Get Log4j2 LoggerContext (Ghidra uses Log4j2)
            LoggerContext loggerContext = (LoggerContext) LogManager.getContext(false);
            Configuration config = loggerContext.getConfiguration();
            
            // Create log directory
            Path logDir = Paths.get(System.getProperty("user.home"), ".ghidra", LOG_DIR);
            File logDirFile = logDir.toFile();
            if (!logDirFile.exists()) {
                logDirFile.mkdirs();
            }
            
            // Create log file path
            Path logFile = logDir.resolve(sanitizeFileName(programName) + ".log");
            
            // Create pattern layout
            PatternLayout layout = PatternLayout.newBuilder()
                .withPattern("%d{yyyy-MM-dd HH:mm:ss.SSS} [%t] %-5level %logger{36} - %msg%n")
                .withConfiguration(config)
                .build();
            
            // Create file appender
            FileAppender fileAppender = FileAppender.newBuilder()
                .setName("DecompAI-" + sanitizeFileName(programName))
                .withFileName(logFile.toString())
                .setLayout(layout)
                .setConfiguration(config)
                .build();
            
            fileAppender.start();
            config.addAppender(fileAppender);
            
            // Configure logger for our package
            LoggerConfig loggerConfig = config.getLoggerConfig(LOGGER_NAME);
            if (loggerConfig == null || loggerConfig.getName().equals(LOGGER_NAME)) {
                loggerConfig = new LoggerConfig(LOGGER_NAME, 
                    org.apache.logging.log4j.Level.toLevel(logLevel, org.apache.logging.log4j.Level.INFO), 
                    true);
                config.addLogger(LOGGER_NAME, loggerConfig);
            }
            
            loggerConfig.addAppender(fileAppender, 
                org.apache.logging.log4j.Level.toLevel(logLevel, org.apache.logging.log4j.Level.INFO), 
                null);
            loggerConfig.setLevel(org.apache.logging.log4j.Level.toLevel(logLevel, org.apache.logging.log4j.Level.INFO));
            
            loggerContext.updateLoggers();
            
            // Log initialization message
            Logger logger = LogManager.getLogger(LOGGER_NAME);
            logger.info("DecompAI logging initialized for program: {}", programName);
            logger.info("Log file: {}", logFile);
            
        } catch (Exception e) {
            // Fallback: use Ghidra's Msg API if Log4j2 configuration fails
            Msg.warn(LoggerUtil.class, "Failed to configure custom logging for program " + programName + 
                ": " + e.getMessage() + ". Using Ghidra's default logging.", e);
        }
    }
    
    /**
     * Sanitize a file name to remove invalid characters.
     */
    private static String sanitizeFileName(String fileName) {
        if (fileName == null) {
            return "unknown";
        }
        // Replace invalid file name characters with underscores
        return fileName.replaceAll("[^a-zA-Z0-9._-]", "_");
    }
    
    /**
     * Get a Logger instance for the DecompAI package.
     * Use this instead of creating new loggers directly.
     */
    public static Logger getLogger() {
        return LogManager.getLogger(LOGGER_NAME);
    }
    
    /**
     * Get a Logger instance for a specific class.
     */
    public static Logger getLogger(Class<?> clazz) {
        return LogManager.getLogger(clazz);
    }
}

