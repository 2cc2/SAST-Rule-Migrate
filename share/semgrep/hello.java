public class Test {
    // bad1：直接将用户输入传入ProcessBuilder命令，存在OSCI（操作系统命令注入）漏洞
    public void Hello() {
       print("hello")
    }
}