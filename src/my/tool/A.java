package my.tool;

public class A {
    private Integer v;

    public A(){}

    public A(Integer vv){
        v=vv;
    }
    public Integer getV(){
        return v;
    }
    public void setV(Integer newV){
        v=newV;
    }

    @Override
    public String toString() {
        return "A{" +
                "v=" + v +
                '}';
    }
}
