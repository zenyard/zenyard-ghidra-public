package com.zenyard.ghidra.status;

/**
 * Actions that the status bar UI can invoke.
 */
public interface StatusBarActions {
    void onRerun();
    void onInitialUpload();
    void onReviewTerms();
    void onUsageDetails();
}
