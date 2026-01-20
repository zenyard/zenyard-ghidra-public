package com.zenyard.decompai.ghidra.copilot;

import java.awt.BorderLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;

import docking.ComponentProvider;
import ghidra.framework.plugintool.PluginTool;

/**
 * A ComponentProvider dockable window implementing the Copilot chat UI.
 * 
 * NOTE: mirrors functionality in decompai_ida/ui/copilot.py
 */
public class CopilotProvider extends ComponentProvider {
    
    private JTextArea chatArea;
    private JTextField inputField;
    private JButton sendButton;
    private CopilotController controller;
    
    public CopilotProvider(PluginTool tool, CopilotController controller) {
        super(tool, "DecompAI Copilot", "DecompAI");
        this.controller = controller;
        
        buildComponent();
    }
    
    public void setController(CopilotController controller) {
        this.controller = controller;
    }
    
    private void buildComponent() {
        JPanel mainPanel = new JPanel(new BorderLayout());
        
        // Chat area
        chatArea = new JTextArea(20, 50);
        chatArea.setEditable(false);
        chatArea.setLineWrap(true);
        chatArea.setWrapStyleWord(true);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        mainPanel.add(scrollPane, BorderLayout.CENTER);
        
        // Input panel
        JPanel inputPanel = new JPanel(new BorderLayout());
        inputField = new JTextField();
        sendButton = new JButton("Send");
        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });
        
        inputPanel.add(inputField, BorderLayout.CENTER);
        inputPanel.add(sendButton, BorderLayout.EAST);
        mainPanel.add(inputPanel, BorderLayout.SOUTH);
        
        // In Ghidra 12.0, ComponentProvider may require getComponent() method
        // Store component and provide getComponent() implementation
        this.component = mainPanel;
    }
    
    private JPanel component;
    
    // In Ghidra 12.0, ComponentProvider requires getComponent() method returning JComponent
    @Override
    public javax.swing.JComponent getComponent() {
        return component;
    }
    
    private void sendMessage() {
        if (controller == null) {
            appendMessage("Error: Copilot not initialized. Please configure DecompAI API key.");
            return;
        }
        
        String message = inputField.getText().trim();
        if (message.isEmpty()) {
            return;
        }
        
        // Add user message to chat
        appendMessage("You: " + message);
        inputField.setText("");
        
        // Send to controller
        controller.sendMessage(message);
    }
    
    public void appendMessage(String message) {
        chatArea.append(message + "\n");
        chatArea.setCaretPosition(chatArea.getDocument().getLength());
    }
    
    @Override
    public void componentShown() {
        // Component is shown
    }
    
    @Override
    public void componentHidden() {
        // Component is hidden
    }
}

