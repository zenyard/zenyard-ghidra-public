package com.zenyard.ghidra.status;

import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.InputStream;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import javax.imageio.ImageIO;
import javax.swing.Icon;
import javax.swing.ImageIcon;

import ghidra.util.Msg;

/**
 * Load and cache scaled icons for status bar UI.
 */
public class IconRegistry {
    private final Map<String, Icon> cache = new ConcurrentHashMap<>();

    public Icon loadIcon(String resourcePath, int width, int height, String fallbackText) {
        String cacheKey = resourcePath + ":" + width + "x" + height;
        return cache.computeIfAbsent(cacheKey, key -> {
            try (InputStream iconStream = getClass().getClassLoader().getResourceAsStream(resourcePath)) {
                if (iconStream == null) {
                    return new ImageIcon();
                }
                BufferedImage image = ImageIO.read(iconStream);
                if (image == null) {
                    return new ImageIcon();
                }
                Image scaledImage = image.getScaledInstance(width, height, Image.SCALE_SMOOTH);
                return new ImageIcon(scaledImage);
            } catch (Exception e) {
                Msg.warn(this, "Could not load icon: " + resourcePath + " (" + e.getMessage() + ")");
                return new ImageIcon();
            }
        });
    }
}
