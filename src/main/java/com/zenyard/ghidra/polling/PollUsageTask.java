package com.zenyard.ghidra.polling;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import com.zenyard.ghidra.ZenyardService;
import com.zenyard.ghidra.api.generated.ApiException;
import com.zenyard.ghidra.api.generated.api.UserApi;
import com.zenyard.ghidra.api.generated.model.UsageResponse;
import com.zenyard.ghidra.events.EventDispatcher;
import com.zenyard.ghidra.events.ZenyardEvent;
import com.zenyard.ghidra.tasks.EventAwareTask;
import com.zenyard.ghidra.usage.UsageState;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

public class PollUsageTask extends EventAwareTask {
    private static final int POLL_INTERVAL_MS = 5000;

    private final UserApi userApi;
    private final ZenyardService services;
    private volatile boolean shouldStop = false;
    private volatile UsageState lastPublishedUsageState;
    private volatile boolean hasPublishedUsageState = false;

    public PollUsageTask(UserApi userApi, ZenyardService services, EventDispatcher eventDispatcher) {
        super("Poll Usage", true, false, false, eventDispatcher);
        this.userApi = userApi;
        this.services = services;
    }

    @Override
    public Set<ZenyardEvent.EventType> getSubscribedEventTypes() {
        return Set.of(ZenyardEvent.EventType.PROGRAM_DEACTIVATED);
    }

    @Override
    public void handleEvent(ZenyardEvent event) {
        if (event.getType() == ZenyardEvent.EventType.PROGRAM_DEACTIVATED) {
            shouldStop = true;
        }
    }

    @Override
    protected void doRun(TaskMonitor monitor) {
        if (userApi == null) {
            return;
        }
        while (!shouldStop && !monitor.isCancelled()) {
            try {
                UsageResponse response = userApi.getUserPlansUsage();
                UsageState usageState = UsageState.fromUsageResponse(response);
                publishUsageStateIfChanged(usageState);
            } catch (ApiException e) {
                Msg.warn(this, "Failed to fetch usage: " + e.getMessage());
            } catch (Exception e) {
                Msg.warn(this, "Unexpected error while fetching usage: " + e.getMessage());
            }

            try {
                Thread.sleep(POLL_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void publishUsageStateIfChanged(UsageState usageState) {
        if (hasPublishedUsageState && usageStatesEqual(lastPublishedUsageState, usageState)) {
            return;
        }
        if (services != null) {
            services.setUsageState(usageState);
        }
        Map<String, Object> payload = new HashMap<>();
        payload.put("usageState", usageState);
        publishEvent(new ZenyardEvent(ZenyardEvent.EventType.USAGE_UPDATED, getTaskTitle(), payload));
        lastPublishedUsageState = usageState;
        hasPublishedUsageState = true;
    }

    private boolean usageStatesEqual(UsageState lhs, UsageState rhs) {
        if (lhs == null || rhs == null) {
            return false;
        }
        return lhs.getKind() == rhs.getKind()
            && Objects.equals(lhs.getUsagePercentage(), rhs.getUsagePercentage())
            && Objects.equals(lhs.getExpiration(), rhs.getExpiration());
    }
}
