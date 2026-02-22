package com.zenyard.ghidra.copilot;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

class CopilotViewModelTodoStateTest {

    @Test
    void todoStatuses_reflectPendingAndInProgress() {
        CopilotViewModel model = new CopilotViewModel();

        model.setTodos(List.of("Inspect xrefs", "Rename symbol"));
        model.setActiveTodo("Inspect xrefs");

        Map<String, String> statuses = model.getTodoStatuses();
        assertEquals("in_progress", statuses.get("Inspect xrefs"));
        assertEquals("pending", statuses.get("Rename symbol"));
    }

    @Test
    void finalizeTodos_marksRemainingAsCompleted() {
        CopilotViewModel model = new CopilotViewModel();

        model.setTodos(List.of("Step A", "Step B"));
        model.setActiveTodo("Step A");
        model.finalizeTodos(null);

        Map<String, String> statuses = model.getTodoStatuses();
        assertEquals("completed", statuses.get("Step A"));
        assertEquals("completed", statuses.get("Step B"));
    }

    @Test
    void markFailedTodos_marksOutstandingAsFailed() {
        CopilotViewModel model = new CopilotViewModel();

        model.setTodos(List.of("Step A", "Step B"));
        model.setActiveTodo("Step A");
        model.markFailedTodos(null);

        Map<String, String> statuses = model.getTodoStatuses();
        assertEquals("failed", statuses.get("Step A"));
        assertEquals("failed", statuses.get("Step B"));
    }
}
