
// @category Extra.Functions
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;

import java.util.*;

public class FunctionCallTracer extends GhidraScript {
    private Set<Function> visitedFunctions = new HashSet<>();
    
    @Override
    protected void run() throws Exception {
        // 获取用户输入的函数地址
        String inputAddr = askString("Function Address", "Enter function address (e.g., 0x1001000):");
        Address functionAddr = currentProgram.getAddressFactory().getAddress(inputAddr);

        // 查找目标函数
        Function targetFunction = getFunctionAt(functionAddr);
        if (targetFunction == null) {
            println("[ERROR] Invalid function address or function not found!");
            return;
        }

        println("Tracing calls to: " + targetFunction.getName());
        traceCallers(targetFunction, "", 0);
    }

    private void traceCallers(Function function, String indent, int depth) {
        if (visitedFunctions.contains(function)) {
            return;
        }
        visitedFunctions.add(function);

        // 获取所有引用此函数的交叉引用 (Xrefs)
        ReferenceManager refManager = currentProgram.getReferenceManager();
        ReferenceIterator references = refManager.getReferencesTo(function.getEntryPoint());
        
        for (Reference ref : references) {
            Address fromAddr = ref.getFromAddress();
            Function caller = getFunctionContaining(fromAddr);

            if (caller != null) {
                println(indent + "|-- " + caller.getName() + " (" + caller.getEntryPoint() + ")");
                traceCallers(caller, indent + "    |", depth + 1); // 递归追溯上层调用者
            }
        }
    }
}
