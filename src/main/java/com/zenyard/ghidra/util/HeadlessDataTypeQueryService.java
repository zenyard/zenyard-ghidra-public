package com.zenyard.ghidra.util;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;

import ghidra.app.services.DataTypeQueryService;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypePath;
import ghidra.util.task.TaskMonitor;

/**
 * Non-interactive {@link DataTypeQueryService} that resolves type names by searching the
 * program's {@link DataTypeManager} across all categories.
 *
 * <p>GUI-based services may show a type-chooser on the Swing EDT when multiple matches exist,
 * which deadlocks when called from a non-EDT thread. This implementation never shows dialogs.
 */
public class HeadlessDataTypeQueryService implements DataTypeQueryService {

    private final DataTypeManager dtm;

    public HeadlessDataTypeQueryService(DataTypeManager dtm) {
        this.dtm = dtm;
    }

    @Override
    public DataType getDataType(String filterText) {
        return promptForDataType(filterText);
    }

    @Override
    public DataType promptForDataType(String filterText) {
        if (filterText == null || filterText.isBlank()) {
            return null;
        }

        DataType rootMatch = dtm.getDataType(CategoryPath.ROOT, filterText);
        if (rootMatch != null) {
            return rootMatch;
        }

        List<DataType> matches = new ArrayList<>();
        dtm.findDataTypes(filterText, matches);

        if (matches.isEmpty()) {
            return null;
        }
        if (matches.size() == 1) {
            return matches.get(0);
        }

        for (DataType dt : matches) {
            if (dt.getSourceArchive() != null
                    && dt.getSourceArchive().getArchiveType() == ArchiveType.PROGRAM) {
                return dt;
            }
        }
        return matches.get(0);
    }

    @Override
    public List<DataType> getSortedDataTypeList() {
        List<DataType> all = new ArrayList<>();
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            all.add(iter.next());
        }
        all.sort((a, b) -> a.getName().compareToIgnoreCase(b.getName()));
        return all;
    }

    @Override
    public List<CategoryPath> getSortedCategoryPathList() {
        return Collections.emptyList();
    }

    @Override
    public List<DataType> findDataTypes(String name, TaskMonitor monitor) {
        List<DataType> results = new ArrayList<>();
        dtm.findDataTypes(name, results);
        return results;
    }

    @Override
    public List<DataType> getDataTypesByPath(DataTypePath path) {
        if (path == null) {
            return Collections.emptyList();
        }
        DataType dt = dtm.getDataType(path);
        return dt != null ? List.of(dt) : Collections.emptyList();
    }

    @Override
    public DataType getProgramDataTypeByPath(DataTypePath path) {
        if (path == null) {
            return null;
        }
        return dtm.getDataType(path);
    }
}
