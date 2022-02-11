package my.tool;

import java.util.Scanner;

public class CTRUtil {
    public static void main(String[] args) {
        // write your code here
        while (true){
            SM7CTR();
        }
        //System.out.println(C_ArrayToString("0x43,0x68,0x69,0x6e,0x65,0x73,0x65,0x20,0x49,0x42,0x45,0x20,0x73,0x74,0x61,0x6e,0x64,0x61,0x72,0x64"));
    }

    //txt内容批量转换，并按c代码格式输出
    public static void SM7CTR(){
        System.out.println("Enter Your Code:");
        Scanner sc = new Scanner(System.in);
        StringBuffer stringBuffer=new StringBuffer();
        int i=5;
        while (i-->0){
            //读取字符串型输入
            String str = sc.nextLine();
            String code=str.substring(str.indexOf('=')+1).trim();

            if (str.contains("明文") && !str.contains("明文长度")){
                stringBuffer.append("unsigned char input[]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
                stringBuffer.append("int in_len=").append(code.length()/2).append(";\n");
            }else if (str.contains("IV")){
                stringBuffer.append("unsigned char IV[]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
            }else if (str.contains("密钥")){
                stringBuffer.append("unsigned char key[]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
                stringBuffer.append("int key_len=").append(code.length()/2).append(";\n");
            }else if (str.contains("密文") && !str.contains("密文长度")){
                stringBuffer.append("unsigned char cipher[]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
                //stringBuffer.append("int cipher_len=").append(code.length()/2).append(";\n");
            }
        }
        System.out.println(stringBuffer);
        ClipBoardUtil.SetClipboardString(stringBuffer.toString());
        System.out.println("The results has been copied to the clipboard!");
    }
}
