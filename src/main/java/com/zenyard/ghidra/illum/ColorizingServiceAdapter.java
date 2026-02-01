package com.zenyard.ghidra.illum;

import java.awt.Color;
import java.util.Optional;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.util.Msg;

/**
 * Adapter for ColorizingService across Ghidra versions.
 */
public final class ColorizingServiceAdapter {
    private final ColorizingService service;

    private ColorizingServiceAdapter(ColorizingService service) {
        this.service = service;
    }

    public static Optional<ColorizingServiceAdapter> forTool(PluginTool tool) {
        if (tool == null) {
            return Optional.empty();
        }
        ColorizingService service = tool.getService(ColorizingService.class);
        if (service == null) {
            return Optional.empty();
        }
        return Optional.of(new ColorizingServiceAdapter(service));
    }

    public void setBackground(Address address, Color color) {
        try {
            service.setBackgroundColor(address, address, color);
        } catch (Exception e) {
            Msg.warn(this, "Failed to set background color: " + e.getMessage(), e);
        }
    }

    public void clearBackground(Address address) {
        try {
            service.clearBackgroundColor(address, address);
        } catch (Exception e) {
            Msg.warn(this, "Failed to clear background color: " + e.getMessage(), e);
        }
    }

    public void setBackground(AddressSetView set, Color color) {
        try {
            service.setBackgroundColor(set, color);
        } catch (Exception e) {
            Msg.warn(this, "Failed to set background color: " + e.getMessage(), e);
        }
    }

    public void clearBackground(AddressSetView set) {
        try {
            service.clearBackgroundColor(set);
        } catch (Exception e) {
            Msg.warn(this, "Failed to clear background color: " + e.getMessage(), e);
        }
    }
}
