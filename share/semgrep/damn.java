public class Test {
    // bad1：直接将用户输入传入ProcessBuilder命令，存在OSCI（操作系统命令注入）漏洞
    public void bad1(String userData) {
        ProcessBuilder pb = new ProcessBuilder(); // 修正原代码变量声明顺序（先声明后使用）
        pb.command("sh", "/c", userData); // 核心风险：用户输入直接作为命令参数
    }

    // bad2：用户输入先赋值给中间变量，再传入命令，仍存在OSCI漏洞
    public void bad2(ProcessBuilder builder, CustomClass userData) { // 修正参数格式（合并行）
        String input = userData; // 用户输入赋值给中间变量input
        builder.command("bash", input); // 核心风险：中间变量携带用户输入传入命令
    }

    // bad_fn：用户输入经trim处理后传入命令，trim仅去空白，无法消除OSCI漏洞
    public void bad_fn(String userData) {
        ProcessBuilder pb = new ProcessBuilder();
        String shell = "sh"; // 修正语法（补充分号）
        String arg = "/c";   // 修正语法（补充分号）
        String cmd = trim(userData); // 用户输入经trim处理（仅去首尾空白，无安全过滤）
        pb.command(shell, arg, cmd); // 核心风险：处理后的用户输入仍传入命令执行
    }

    // // 补充trim方法占位（原代码未定义，保证语法完整）
    // private String trim(String str) {
    //     return str == null ? "" : str.trim();
    // }

    // // 补充CustomClass类占位（原代码引用但未定义，保证语法完整）
    // static class CustomClass {
    //     // 模拟用户输入载体类，实际场景中可能是任意传递用户输入的自定义类型
    // }
}