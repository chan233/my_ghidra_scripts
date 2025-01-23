// @category Extra.Functions
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class FunctionReferenceSorter extends GhidraScript {
    private Map<Function, Integer> functionCallCounts = new HashMap<>();

    @Override
    protected void run() throws Exception {
        // 获取用户输入的显示数量
        int limit = askInt("Function Limit", "Enter the number of top functions to display:");

        // 获取所有的函数
        FunctionManager functionManager = currentProgram.getFunctionManager();
        FunctionIterator functionIterator = functionManager.getFunctions(true);

        // 遍历所有函数，统计每个函数的引用次数
        while (functionIterator.hasNext()) {
            Function function = functionIterator.next();
            traceReferences(function);
        }

        // 排序并打印引用次数最多的函数
        printSortedFunctions(limit);
    }

    private void traceReferences(Function function) {
        // 获取所有引用此函数的交叉引用 (Xrefs)
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator references = refManager.getReferencesTo(function.getEntryPoint());

        for (Reference ref : references) {
            Address fromAddr = ref.getFromAddress();
            Function caller = getFunctionContaining(fromAddr);

            if (caller != null) {
                functionCallCounts.put(caller, functionCallCounts.getOrDefault(caller, 0) + 1);
            }
        }
    }

    private void printSortedFunctions(int limit) {
        // 将函数按引用次数从多到少排序
        List<Map.Entry<Function, Integer>> sortedList = new ArrayList<>(functionCallCounts.entrySet());
        sortedList.sort((a, b) -> Integer.compare(b.getValue(), a.getValue()));

        // 打印排序后的函数及其引用次数
        println("\nTop " + limit + " most referenced functions:");
        int count = 0;
        for (Map.Entry<Function, Integer> entry : sortedList) {
            if (count++ >= limit) break;
            println(entry.getKey().getName() + " (" + entry.getKey().getEntryPoint() + ") - Calls: " + entry.getValue());
        }
    }
}
