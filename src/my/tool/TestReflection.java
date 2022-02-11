package my.tool;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

//反射实践，参考：https://www.sczyh30.com/posts/Java/java-reflection-1/
public class TestReflection {

    public static void main(String[] args) throws ClassNotFoundException, NoSuchMethodException, InvocationTargetException, InstantiationException, IllegalAccessException {
        //加载类
        String className="my.tool.A";
        Class<?> c= Class.forName(className);

        //获取构造函数
        Constructor<?> constructor1=c.getConstructor();
        //使用构造函数实例化对象
        Object a1=constructor1.newInstance();
        System.out.println(a1);

        //获取构造函数
        Constructor<?> constructor2=c.getConstructor(Integer.class);
        //使用构造函数实例化对象
        Object a2=constructor2.newInstance(2);
        System.out.println(a2);

        //获取某个类的所有公用（public）方法，包括其继承类的公用方法。
        Method method1=c.getMethod("setV",Integer.class);
        Method method2=c.getMethod("getV");

        //指定对象，调用方法
        method1.invoke(a1,1);
        Object obj3=method2.invoke(a1);
        System.out.println(obj3);

        method1.invoke(a2,22);
        Object obj4=method2.invoke(a2);
        System.out.println(obj4);


    }
}
