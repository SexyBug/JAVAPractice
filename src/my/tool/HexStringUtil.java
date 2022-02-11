package my.tool;

public class HexStringUtil {

    public static void main(String[] args){
        System.out.println(Integer.toOctalString( 10 ));
        String s="0010";
        int s2= Integer.valueOf(s,16);
        System.out.println(s2);
    }

    /**
     * 字符串转换成为16进制编码(无需Unicode编码)
     * @param str
     * @return
     */
    public static String Str2HexStr(String str) {
        char[] chars = "0123456789ABCDEF".toCharArray();
        StringBuilder sb = new StringBuilder("");
        byte[] bs = str.getBytes();
        int bit;
        for (int i = 0; i < bs.length; i++) {
            bit = (bs[i] & 0x0f0) >> 4;
            sb.append(chars[bit]);
            bit = bs[i] & 0x0f;
            sb.append(chars[bit]);
            // sb.append(' ');
        }
        return sb.toString().trim();
    }

    /**
     * 16进制编码直接转换成为字符串(无需Unicode解码)
     * @param hexStr
     * @return
     */
    public static String HexStr2Str(String hexStr) {
        String str = "0123456789ABCDEF";
        char[] hexs = hexStr.toCharArray();
        byte[] bytes = new byte[hexStr.length() / 2];
        int n;
        for (int i = 0; i < bytes.length; i++) {
            n = str.indexOf(hexs[2 * i]) * 16;
            n += str.indexOf(hexs[2 * i + 1]);
            bytes[i] = (byte) (n & 0xff);
        }
        return new String(bytes);
    }
}
