package my.tool;

import java.util.Scanner;

public class CString2Array {

    public static void main(String[] args) {
	    // write your code here
        DealOneString2Array();
        //DealOneArray2String();
       // System.out.println(C_ArrayToString("0x4c,0xa0,0xda,0x50,0x8f,0x66,0xf9,0x42,0xa9,0x88,0xaa,0xe7,0x9f,0x28,0x08,0x01"));
    }

    public static void DealOneString2Array(){
        Scanner sc = new Scanner(System.in);
        while (true){
            System.out.println("Enter Your Code:");
            //读取字符串型输入
            String code = sc.nextLine();
            code=code.replaceAll("\\s","");
            System.out.println("Length: "+code.length()/2);
            String result=C_StringToArray(code);
            System.out.println(result);
            ClipBoardUtil.SetClipboardString(result);
            System.out.println("The results has been copied to the clipboard!");
        }
    }
    public static void DealOneArray2String(){
        Scanner sc = new Scanner(System.in);
        while (true){
            System.out.println("Enter Your Code:");
            //读取字符串型输入
            String code = sc.nextLine();
            code=code.replaceAll("\\s","");
            String result=C_ArrayToString(code);
            System.out.println(result);
            ClipBoardUtil.SetClipboardString(result);
            System.out.println("The results has been copied to the clipboard!");
        }
    }

    //为16进制字符串加上0x和,
    public static String C_StringToArray(String s){
        return C_StringToArray(s,16);
    }
    public static String C_StringToArray(String s,int lineLength){
        StringBuffer sb=new StringBuffer();
        sb.append("{\n    ");
        int i=0;
        while(i<s.length()){
            sb.append("0x").append(s.charAt(i)).append(s.charAt(i + 1));;
            i=i+2;
            if (i<s.length()){
                sb.append(',');
            }
            if ((i/2)%lineLength==0){
                sb.append("\n    ");
            }
        }
        sb.append("};\n");
        return sb.toString();
    }

    //去掉,0x,换行等
    public static String C_ArrayToString(String arrayString){
        return arrayString.replaceAll(",|0x|\\s+","");
    }

}
