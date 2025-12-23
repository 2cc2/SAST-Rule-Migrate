public class Test {
    // bad1：直接将用户输入传入ProcessBuilder命令，存在OSCI（操作系统命令注入）漏洞
    public void bad1(String userData) {
        // ProcessBuilder pb = new ProcessBuilder(); // 修正原代码变量声明顺序（先声明后使用）
        pb.command("sh", "/c", userData); // 核心风险：用户输入直接作为命令参数
    }
}