package my.tool;

import java.util.Scanner;

public class SM9Util {
    public static void main(String[] args) {
        // write your code here
        while (true){
            Sm9DealAll();
        }
        //System.out.println(C_ArrayToString("0x43,0x68,0x69,0x6e,0x65,0x73,0x65,0x20,0x49,0x42,0x45,0x20,0x73,0x74,0x61,0x6e,0x64,0x61,0x72,0x64"));
    }
    //txt内容批量转换，并按c代码格式输出
    public static void Sm9DealAll(){
        System.out.println("Enter Your Code:");
        Scanner sc = new Scanner(System.in);
        StringBuffer stringBuffer=new StringBuffer();
        int i=5;
        while (i-->0){
            //读取字符串型输入
            String str = sc.nextLine();
            String code=str.substring(str.indexOf('=')+1).trim();

            if (str.contains("随机数r")){
                stringBuffer.append("unsigned char rand["+code.length()/2+"]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
            }else if (str.contains("用户标识")){
                //stringBuffer.append("unsigned char *IDB=");
                //stringBuffer.append(HexStringUtil.HexStr2Str(code)).append(";\n");
                stringBuffer.append("unsigned char IDB1["+code.length()/2+"]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
            }else if (str.contains("公钥")){
                stringBuffer.append("unsigned char Ppub["+code.length()/2+"]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
            }else if (str.contains("加密方式")){
                stringBuffer.append("int EncID="+code.trim()+";\n");
            }else if (str.contains("明文字符串")){
                //stringBuffer.append("unsigned char *std_message=");
                //stringBuffer.append(HexStringUtil.HexStr2Str(code)).append(";\n");
                stringBuffer.append("unsigned char std_message1["+code.length()/2+"]=");
                stringBuffer.append(CString2Array.C_StringToArray(code));
            }
        }
        System.out.println(stringBuffer);
        ClipBoardUtil.SetClipboardString(stringBuffer.toString());
        System.out.println("The results has been copied to the clipboard!");
    }
}
