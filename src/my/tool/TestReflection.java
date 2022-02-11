package my.tool;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;

//反射实践，参考：https://www.sczyh30.com/posts/Java/java-reflection-1/
public class TestReflection {

    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        //加载类
        String className="my.tool.A";
        Class<?> c= Class.forName(className);

        //获取构造函数
        Constructor constructor1=c.getConstructor();
        //使用构造函数实例化对象
        Object obj1=constructor1.newInstance();
        System.out.println(obj1);

        //获取构造函数
        Constructor constructor2=c.getConstructor(Integer.class);
        //使用构造函数实例化对象
        Object obj2=constructor2.newInstance(1);
        System.out.println(obj2);
    }
}
