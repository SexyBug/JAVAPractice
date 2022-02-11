
#include <sys/time.h>
#include "sm9_common.h"
#include "SM4.h"

unsigned char SM9_q[32] =  {
	0xB6,0x40,0x00,0x00,0x02,0xA3,0xA6,0xF1,0xD6,0x03,0xAB,0x4F,0xF5,0x8E,0xC7,0x45,
	0x21,0xF2,0x93,0x4B,0x1A,0x7A,0xEE,0xDB,0xE5,0x6F,0x9B,0x27,0xE3,0x51,0x45,0x7D
};

unsigned char SM9_N[32] =  {
	0xB6,0x40,0x00,0x00,0x02,0xA3,0xA6,0xF1,0xD6,0x03,0xAB,0x4F,0xF5,0x8E,0xC7,0x44,
	0x49,0xF2,0x93,0x4B,0x18,0xEA,0x8B,0xEE,0xE5,0x6E,0xE1,0x9C,0xD6,0x9E,0xCF,0x25
};

unsigned char SM9_P1x[32]= {
	0x93,0xDE,0x05,0x1D,0x62,0xBF,0x71,0x8F,0xF5,0xED,0x07,0x04,0x48,0x7D,0x01,0xD6,
	0xE1,0xE4,0x08,0x69,0x09,0xDC,0x32,0x80,0xE8,0xC4,0xE4,0x81,0x7C,0x66,0xDD,0xDD
};

unsigned char SM9_P1y[32]= {
	0x21,0xFE,0x8D,0xDA,0x4F,0x21,0xE6,0x07,0x63,0x10,0x65,0x12,0x5C,0x39,0x5B,0xBC,
	0x1C,0x1C,0x00,0xCB,0xFA,0x60,0x24,0x35,0x0C,0x46,0x4C,0xD7,0x0A,0x3E,0xA6,0x16
};

unsigned char SM9_P2[128]= {
	0x85,0xAE,0xF3,0xD0,0x78,0x64,0x0C,0x98,0x59,0x7B,0x60,0x27,0xB4,0x41,0xA0,0x1F,
	0xF1,0xDD,0x2C,0x19,0x0F,0x5E,0x93,0xC4,0x54,0x80,0x6C,0x11,0xD8,0x80,0x61,0x41,
	0x37,0x22,0x75,0x52,0x92,0x13,0x0B,0x08,0xD2,0xAA,0xB9,0x7F,0xD3,0x4E,0xC1,0x20,
	0xEE,0x26,0x59,0x48,0xD1,0x9C,0x17,0xAB,0xF9,0xB7,0x21,0x3B,0xAF,0x82,0xD6,0x5B,
	0x17,0x50,0x9B,0x09,0x2E,0x84,0x5C,0x12,0x66,0xBA,0x0D,0x26,0x2C,0xBE,0xE6,0xED,
	0x07,0x36,0xA9,0x6F,0xA3,0x47,0xC8,0xBD,0x85,0x6D,0xC7,0x6B,0x84,0xEB,0xEB,0x96,
	0xA7,0xCF,0x28,0xD5,0x19,0xBE,0x3D,0xA6,0x5F,0x31,0x70,0x15,0x3D,0x27,0x8F,0xF2,
	0x47,0xEF,0xBA,0x98,0xA7,0x1A,0x08,0x11,0x62,0x15,0xBB,0xA5,0xC9,0x99,0xA7,0xC7
};

unsigned char SM9_t[32] =  {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x60,0x00,0x00,0x00,0x00,0x58,0xF9,0x8A
};

unsigned char SM9_a[32] =  {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

unsigned char SM9_b[32] =  {
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x05
};
//extern unsigned char SM9_q[32];
//extern unsigned char SM9_N[32];
//extern unsigned char SM9_P1x[32];
//extern unsigned char SM9_P1y[32];
//extern unsigned char SM9_P2[128];
//extern unsigned char SM9_t[32];
//extern unsigned char SM9_a[32];
//extern unsigned char SM9_b[32];

extern miracl* mip;
extern epoint *P;
extern ecn2 P2;
extern big N;  //order of group, N(t)
extern big para_a,para_b,para_t,para_q;
extern zzn2 X;

#define DEBUG_PRINT 0
//#define PRINT



/****************************************************************

Function:		bytes128_to_ecn2
Description:    convert 128 bytes into ecn2
Calls:          MIRACL functions
Called By:      SM9_Init,SM9_Decrypt
Input:          Ppubs[]
Output:         ecn2 *res
Return:         FALSE: execution error
                TRUE: execute correctly
Others:
****************************************************************/
BOOL bytes128_to_ecn2(unsigned char Ppubs[],ecn2 *res)
{
	BOOL ret;
	zzn2 x, y;
	big a,b;
	ecn2 r;

	init_ecn2(&r);
	init_zzn2(&x);
	init_zzn2(&y);
	a=mirvar(0);
	b=mirvar(0);

	bytes_to_big(BNLEN,Ppubs,b);
	bytes_to_big(BNLEN,Ppubs+BNLEN,a);
	zzn2_from_bigs(a,b,&x);
	bytes_to_big(BNLEN,Ppubs+BNLEN*2,b);
	bytes_to_big(BNLEN,Ppubs+BNLEN*3,a);
	zzn2_from_bigs(a,b,&y);

	ret = ecn2_set( &x,&y,res);

	mirkill(a);
	mirkill(b);
	release_ecn2(&r);
	release_zzn2(&x);
	release_zzn2(&y);

	return ret;
}

/****************************************************************
F
Function:		LinkCharZzn12
Description:    link two different types(unsigned char and zzn12)to one(unsigned char)
Calls:          MIRACL functions
Called By:      SM9_Encrypt,SM9_Decrypt
Input:          message:
				len:	length of message
                w:      zzn12 element

Output:			Z:		the characters array stored message and w
                Zlen:   length of Z
Return:         NULL
Others:

****************************************************************/
void LinkCharZzn12(unsigned char *message,int len,zzn12 w,unsigned char *Z,int Zlen)
{
	big tmp;

	tmp=mirvar(0);

	memcpy(Z,message,len);
	redc(w.c.b.b,tmp);
	big_to_bytes(BNLEN,tmp,Z+len,1);
	redc(w.c.b.a,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN,1);
	redc(w.c.a.b,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*2,1);
	redc(w.c.a.a,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*3,1);
	redc(w.b.b.b,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*4,1);
	redc(w.b.b.a,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*5,1);
	redc(w.b.a.b,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*6,1);
	redc(w.b.a.a,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*7,1);
	redc(w.a.b.b,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*8,1);
	redc(w.a.b.a,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*9,1);
	redc(w.a.a.b,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*10,1);
	redc(w.a.a.a,tmp);
	big_to_bytes(BNLEN,tmp,Z+len+BNLEN*11,1);

	mirkill(tmp);
}

/****************************************************************

Function:		Test_Point
Description:    test if the given point is on SM9 curve
Calls:
Called By:     	SM9_Decrypt
Input:          point
Output:         null
Return:         0: success
                1: not a valid point on curve
Others:

****************************************************************/
int Test_Point(epoint* point)
{
	int ret = 0;
	big x,y,x_3,tmp;
	epoint *buf;

	x=mirvar(0);
	y=mirvar(0);
	x_3=mirvar(0);
	tmp=mirvar(0);
	buf=epoint_init();

	//test if y^2=x^3+b
	epoint_get(point,x,y);
	power(x, 3, para_q, x_3);	//x_3=x^3 mod p
	multiply (x, para_a,x);
	divide (x, para_q, tmp);
	add(x_3,x,x);				//x=x^3+ax+b
	add(x,para_b,x);
	divide(x,para_q,tmp);		//x=x^3+ax+b mod p
	power(y, 2,para_q, y);		//y=y^2 mod p
	if(mr_compare(x,y)!=0)
	{
		ret = 1;
		goto RETURN;
	}

	//test infinity
	ecurve_mult(N,point,buf);
	if(point_at_infinity(buf)==FALSE)
	{
		ret = 1;
		goto RETURN;
	}


RETURN:
	mirkill(x);
	mirkill(y);
	mirkill(x_3);
	mirkill(tmp);
	epoint_free(buf);
	return ret;
}




/****************************************************************

Function:		SM9_Enc_MAC
Description:    MAC in SM9 standard 5.4.5
Calls:          SM3_256
Called By:      SM9_Encrypt,SM9_Decrypt
Input:			K:key
                Klen:the length of K
                M:message
                Mlen:the length of message
Output:			C=MAC(K,Z)
Return: 		0: success;
                1: asking for memory error
Others:

****************************************************************/
int SM9_Enc_MAC(unsigned char *K,int Klen,unsigned char *M,int Mlen,unsigned char C[])
{
	unsigned char *Z=NULL;
	int len=Klen+Mlen;
	int C_len;
	Z=(char *)malloc(sizeof(char)*(len+1));
	if(Z==NULL)
		return SM9_ASK_MEMORY_ERR;
	memcpy(Z,M,Mlen);
	memcpy(Z+Mlen,K,Klen);
	//SM3_256(Z,len,C);

	SM3Hash(Z,len,C,&C_len);
	free(Z);
	return 0;
}

/***************************************************************

Function:		SM4_Block_Encrypt
Description:    encrypt the message with padding,according to PKS#5
Calls:          SM4_Encrypt
Called By:      SM9_Encrypt
Input:			key:	the key of SM4
				message:data to be encrypted
				mlen:	the length of message
Output:			cipher: ciphertext
                cipher_len:the length of ciphertext
Return:         NULL
Others:

****************************************************************/
static void SM4_Block_Encrypt(unsigned char key[],unsigned char * message,
			int mlen,unsigned char *cipher,int * cipher_len)
{
	unsigned char mess[16];
	int i,rem=mlen%16;

	for(i=0;i<mlen/16;i++)
		SM4_Encrypt(key,&message[i*16],&cipher[i*16]);


	//encrypt the last block
	memset(mess,16-rem,16);
	if(rem)
		memcpy(mess,&message[i*16],rem);
	SM4_Encrypt(key,mess,&cipher[i*16]);
}

/***************************************************************

Function:		SM4_Block_Decrypt
Description:	decrypt the cipher with padding,according to PKS#5
Calls:			SM4_Decrypt
Called By:		SM9_Decrypt
Input:			key:	the key of SM4
				cipher: ciphertext
				mlen:	the length of ciphertext
Output: 		plain: plaintext
				plain_len:the length of plaintext
Return: 		NULL
Others:

****************************************************************/
static void SM4_Block_Decrypt(unsigned char key[],unsigned char *cipher,
				int len,unsigned char *plain,int *plain_len)
{
	int i;
	for(i=0;i<len/16;i++)
		SM4_Decrypt(key,cipher+i*16,plain+i*16);
	*plain_len=len-plain[len-1];
}

int SM9_H1_ver(unsigned char Z[],int Zlen,big n,big h1)
{
     int hlen,i,ZHlen;
     big hh,i256,tmp,n1;
     unsigned char *ZH=NULL,*ha=NULL;

     hh=mirvar(0);i256=mirvar(0);
     tmp=mirvar(0);n1=mirvar(0);
     convert(1,i256);
     ZHlen=Zlen+1+4;

     hlen=(int)ceil((5.0*logb2(n))/32.0);
     decr(n,1,n1);
     ZH=(unsigned char *)malloc(sizeof(char)*(ZHlen+1));
     if(ZH==NULL) return SM9_ASK_MEMORY_ERR;
     memcpy(ZH+1,Z,Zlen);
     ZH[0]=0x01;
     ha=(unsigned char *)malloc(sizeof(char)*(hlen+1));
     if(ha==NULL) return SM9_ASK_MEMORY_ERR;
     SM3_KDF(ZH,ZHlen,hlen,ha);

	for(i=hlen-1;i>=0;i--)//key[从大到小]
	{
		premult(i256,ha[i],tmp);
        add(hh,tmp,hh);
        premult(i256,256,i256);
        divide(i256,n1,tmp);
        divide(hh,n1,tmp);
	}
    incr(hh,1,h1);
    free(ZH);free(ha);
    return 0;
}



int SM9_H1(unsigned char *ID,int IDlen,unsigned char hid,big h1)
{
	unsigned char *buf = NULL;

	buf = (unsigned char *)calloc(IDlen +1 +1 +4,sizeof(unsigned char));
	if (NULL == buf)
	{
		return SM9_ASK_MEMORY_ERR;
	}

	buf[0] = 0x01;
	memcpy(buf+1,ID,IDlen);
	buf[1+IDlen] = hid;
	return SM9_H(buf,IDlen +1 +1 +4,N,h1);
}

int SM9_Init()
{
	big P1_x, P1_y;

	mip=mirsys(1000, 16);
	mip->IOBASE=16;

	para_q=mirvar(0);
	N=mirvar(0);
	P1_x=mirvar(0);
	P1_y=mirvar(0);
	para_a=mirvar(0);
	para_b=mirvar(0);
	para_t=mirvar(0);

	init_zzn2(&X);
	init_ecn2(&P2);
	P=epoint_init();

	bytes_to_big(BNLEN,SM9_q,para_q);
	bytes_to_big(BNLEN,SM9_P1x,P1_x);
	bytes_to_big(BNLEN,SM9_P1y,P1_y);
	bytes_to_big(BNLEN,SM9_a,para_a);
	bytes_to_big(BNLEN,SM9_b,para_b);
	bytes_to_big(BNLEN,SM9_N,N);
	bytes_to_big(BNLEN,SM9_t,para_t);

	mip->TWIST=MR_SEXTIC_M;
	ecurve_init(para_a,para_b,para_q,MR_PROJECTIVE);
	//Initialises GF(q) elliptic curve
	//MR_PROJECTIVE specifying projective coordinates

	if(!epoint_set(P1_x,P1_y,0,P))
		return SM9_G1BASEPOINT_SET_ERR;

	if(!(bytes128_to_ecn2(SM9_P2,&P2)))
			return SM9_G2BASEPOINT_SET_ERR;



	set_frobenius_constant();

	mirkill(P1_x);
	mirkill(P1_y);

	return 0;

}

void SM9_release()
{
	mirkill(para_a);
	mirkill(para_b);
	mirkill(para_t);
	mirkill(para_q);
	mirkill(N);

	release_zzn2(&X);
	release_ecn2(&P2);
	epoint_free(P);

	mirexit();
}


/***************************************************************

Function:		SM9_GenerateEncryptKey
Description:    Generate encryption keys(public key and private key)
Calls:          MIRACL functions,SM9_H1,xgcd,ecn2_Bytes128_Print
Called By:      SM9_SelfCheck
Input:          ID:identification
                IDlen:the length of ID
                ke:master private key used to generate encryption public key and private key
Output:         Ppubs:encryption public key
                deB: encryption private key
Return:         0: success;
                1: asking for memory error
Others:

****************************************************************/
int SM9_GenerateEncryptKey(unsigned char *ID,int IDlen,unsigned char KE[],unsigned char Ppubs[],unsigned char deB[])
{
	big h1,t1,t2,rem,xPpub,yPpub,tmp,ke;
	ke=mirvar(0);
	bytes_to_big(32,KE,ke);
	int ret = 0;
	ecn2 dEB;
	epoint *Ppub;

	h1=mirvar(0);
	t1=mirvar(0);
	t2=mirvar(0);
	rem=mirvar(0);
	tmp=mirvar(0);
	xPpub=mirvar(0);
	yPpub=mirvar(0);
	Ppub=epoint_init();
	init_ecn2(&dEB);

	ret=SM9_H1(ID,IDlen,HID_ENCRYPT,h1);
	if (0 != ret)
	{
		printf("SM9_H1 error!\n");
		goto RETURN;
	}



	add(h1,ke,t1);		/* t1=h1 + ke ;t1=H1(IDA||hid,N)+ks */
	xgcd(t1,N,t1,t1,t1);/* t1=t1(-1)\BC\C6\CB\E3\C1\BD\B8\F6\B4\F3\CA\FD\B5\C4\C0\A9չ\D7\EE\B4\F3\B9\ABԼ\CA\FD xgcd(x, p, x, x, x,); // x = 1/x mod p (p is prime)	*/
	multiply(ke,t1,t2); /* t2=ke*t1 */
	divide(t2,N,rem);	/* x=x mod y,z=x/y t2=ks*t1(-1) */
	ecurve_mult(ke,P,Ppub);/* Ppub=[ke]P2 ppub=ke*p1 \BD\AB\CD\D6Բ\C7\FA\CF\DF\C9ϵĵ\E3p1*ke,\B1\B6\CA\FDPpub\BC\B4\CA\C7˽Կ */

	//deB=[t2]P2
	ecn2_copy(&P2,&dEB);
	ecn2_mul(t2,&dEB);

	//printf("\n**************The private key deB = (xdeB, ydeB) ：*********************\n");
	//ecn2_Bytes128_Print(dEB);
	//printf("\n**********************PublicKey Ppubs=[ke]P1 ：*************************\n");
	epoint_get(Ppub,xPpub,yPpub);
	epoint_get(Ppub,xPpub,yPpub);
	big_to_bytes(BNLEN,xPpub,Ppubs,1);
	big_to_bytes(BNLEN,yPpub,Ppubs+BNLEN,1);

	redc(dEB.x.b,tmp);
	big_to_bytes(BNLEN,tmp,deB,1);
	redc(dEB.x.a,tmp);
	big_to_bytes(BNLEN,tmp,deB+BNLEN,1);
	redc(dEB.y.b,tmp);
	big_to_bytes(BNLEN,tmp,deB+BNLEN*2,1);
	redc(dEB.y.a,tmp);
	big_to_bytes(BNLEN,tmp,deB+BNLEN*3,1);


RETURN:
	mirkill(h1);
	mirkill(t1);
	mirkill(t2);
	mirkill(rem);
	mirkill(xPpub);
	mirkill(yPpub);
	mirkill(tmp);
	release_ecn2(&dEB);
	epoint_free(Ppub);

	return ret;



}

int SM9_Encrypt(unsigned char *ID,int ID_len,unsigned char *data_in,int data_in_len,unsigned char *C,int *C_len,unsigned char *rand,unsigned char *Ppub,int isblockorstream,int macKeylen)
{
	int ret = 0;
	big h,x,y,r;
	zzn12 g,w;
	epoint *Ppube,*QB,*C1;
	unsigned char *Z=NULL,*K=NULL,*C2=NULL,C3[SM3_len/8];
	int i=0,j=0,Zlen,buf,C2_len;
	int klen;
	int k1_len = 16; // key length for sm4
	int k2_len = macKeylen;

	h=mirvar(0);
	r=mirvar(0);
	x=mirvar(0);
	y=mirvar(0);
	QB=epoint_init();
	Ppube=epoint_init();
	C1=epoint_init();
	init_zzn12(&g);

	bytes_to_big(BNLEN,Ppub,x);
	bytes_to_big(BNLEN,Ppub+BNLEN,y);
	epoint_set(x,y,0,Ppube);

	/* Step1:calculate QB=[H1(IDB||hid,N)]P1+Ppube
		Z[0] = H1id(0x01) 4:sizeof(ct) */
	ret = SM9_H1(ID,ID_len,HID_ENCRYPT,h);
	if (ret != 0)
	{
		goto RETURN;
	}

	ecurve_mult(h,P,QB);
	ecurve_add(Ppube,QB);

	epoint_get(QB,x,y);
#if DEBUG_PRINT
	printf("\n*******************QB:=[H1(IDB||hid,N)]P1+Ppube*****************\n");
	cotnum(x,stdout);
	cotnum(y,stdout);
#endif

	//Step2:randnom
	bytes_to_big(BNLEN,rand,r);
#if DEBUG_PRINT
	printf("\n*******************r*****************\n");
	cotnum(r,stdout);
#endif

	//Step3:C1=[r]QB
	ecurve_mult(r,QB,C1);
	epoint_get(C1,x,y);
#if DEBUG_PRINT
	printf("\n*******************:C1=[r]QB*****************\n");
	cotnum(x,stdout);
	cotnum(y,stdout);
#endif

	big_to_bytes(BNLEN,x,C,1);
	big_to_bytes(BNLEN,y,C+BNLEN,1);

	//Step4:g = e(P2, Ppub-e)
	if(!ecap(P2, Ppube, para_t, X, &g))
	{
		ret = SM9_MY_ECAP_12A_ERR;
		goto RETURN;
	}

#if DEBUG_PRINT
		printf("\n*******************:g=e(P2,Ppube*****************\n");
		zzn12_ElementPrint(g);
#endif


	//test if a ZZn12 element is of order q
	if(!member(g, para_t, X))
	{
		ret = SM9_MEMBER_ERR;
		goto RETURN;
	}

	//Step5:calculate w=g^r
	w = zzn12_pow(g,r);
#if DEBUG_PRINT
       printf("\n*******************:w=g^r*****************\n");
		zzn12_ElementPrint(w);
#endif

	//Step6:calculate C2
	if(0 == isblockorstream)
	{
		C2_len=data_in_len;
		*C_len=BNLEN*2+SM3_len/8+C2_len;

		//Step:6-1: calculate K=KDF(C1||w||IDB,klen)
		klen=data_in_len+k2_len;
		Zlen=ID_len+BNLEN*14;
		Z=(char *)malloc(sizeof(char)*(Zlen+4));
		K=(char *)malloc(sizeof(char)*(klen+1));
		C2=(char *)malloc(sizeof(char)*(data_in_len+1));
		if(Z==NULL|| K==NULL|| C2==NULL)
		{
			ret = SM9_ASK_MEMORY_ERR;
			release_zzn12(&w);
			goto RETURN;
		}

		LinkCharZzn12( C,BNLEN*2,w,Z,(Zlen-ID_len));

		release_zzn12(&w);
		memcpy(Z+BNLEN*14,ID,ID_len);

		SM3_KDF(Z,Zlen+4,klen,K);

		/* Step:6-2: calculate C2=M^K1,and test if K1==0 */
		for(i=0;i<data_in_len;i++)
		{
			if(K[i]==0)
				j=j+1;
			C2[i]=data_in[i]^K[i];
		}


		if(j == data_in_len)
		{
			ret = SM9_ERR_K1_ZERO;
			goto RETURN;
		}

		//Step7:calculate C3=MAC(K2,C2)
		ret = SM9_Enc_MAC(K+data_in_len,k2_len,C2,data_in_len,C3);
		if (ret != 0)
		{
			goto RETURN;
		}
		memcpy(C+BNLEN*2,C3,SM3_len/8);
		memcpy(C+BNLEN*2+SM3_len/8,C2,C2_len);

	}
	else
	{
		C2_len=(data_in_len/16+1)*16;
		*C_len=BNLEN*2+SM3_len/8+C2_len;

		//Step:6-1: calculate K=KDF(C1||w||IDB,klen)
		klen=k1_len+k2_len;
		Zlen=ID_len+BNLEN*14;
		Z=(char *)malloc(sizeof(char)*(Zlen+4));
		K=(char *)malloc(sizeof(char)*(klen+1));
		C2=(char *)malloc(sizeof(char)*(C2_len+1));
		if(Z==NULL|| K==NULL|| C2==NULL)
		{
			ret = SM9_ASK_MEMORY_ERR;
			release_zzn12(&w);
			goto RETURN;
		}


		LinkCharZzn12(C,BNLEN*2,w,Z,Zlen-ID_len);
//  printf("\n******************************LinkCharZzn12 --> Z:************************************\n");
//    for(i=0;i<Zlen-strlen(ID);i++)
//      printf("%02x",Z[i]);

		release_zzn12(&w);
		memcpy(Z+BNLEN*14,ID,ID_len);
//		printf("\n******************************Z:************************************\n");
//        for(i=0;i<Zlen;i++)
//          printf("%02x",Z[i]);
		SM3_KDF(Z,Zlen+4,klen,K);

		//Step:6-2: calculate C2=Enc(K1,M),and also test if K1==0?
		for(i=0;i<k1_len;i++)
		{
			if(K[i]==0)
				j=j+1;
		}
		if(j==k1_len)
		{
			ret = SM9_ERR_K1_ZERO;
			goto RETURN;
		}
//printf("\n******************************data_in:************************************\n");
//for(i=0;i<data_in_len;i++)
//  printf("%02x",data_in[i]);
//
//printf("\n******************************K:************************************\n");
//for(i=0;i<klen+data_in_len;i++)
//  printf("%02x",K[i]);

		SM4_Block_Encrypt(K,data_in,data_in_len,C2,&C2_len);

//printf("\n******************************C2:************************************\n");
//for(i=0;i<C2_len;i++)
//  printf("%02x",C2[i]);

		//Step7:calculate C3=MAC(K2,C2)
		SM9_Enc_MAC(K+k1_len,k2_len,C2,C2_len,C3);

		memcpy(C+BNLEN*2,C3,SM3_len/8);
		memcpy(C+BNLEN*2+SM3_len/8,C2,C2_len);
	}



RETURN:
	mirkill(h);
	mirkill(r);
	mirkill(x);
	mirkill(y);
	epoint_free(Ppube);
	epoint_free(QB);
	epoint_free(C1);
	release_zzn12(&g);
	if (Z != NULL)
	{
		free(Z);
		Z = NULL;
	}
	if (K != NULL)
	{
		free(K);
		K = NULL;
	}
	if (C2 != NULL)
	{
		free(C2);
		C2 = NULL;
	}

	return ret;

}

/****************************************************************

Function:		SM9_Decrypt
Description:	SM9 Decryption algorithm
Calls:			MIRACL functions,zzn12_init(),Test_Point(), ecap(),
			member(),zzn12_ElementPrint(),LinkCharZzn12(),SM3_KDF(),
			SM9_Enc_MAC(),SM4_Block_Decrypt(),bytes128_to_ecn2()
Called By:		SM9_SelfCheck()
Input:			C		//cipher C1||C3||C2
			C_len		//the byte length of C
			deB 		//private key of user B
			IDB 		//identification of userB
			EncID		//encryption identification,0:stream cipher1:block cipher
			k2_len		//the byte length of K2 in MAC algorithm
Output: 		M			//message
			Mlen:		//the length of message
Return: 		0: success
			1: asking for memory error
			2: element is out of order q
			3: R-ate calculation error
			4: test if C1 is on G1
			A: K1 equals 0
			B: compare error of C3
Others:

****************************************************************/
int SM9_Decrypt (unsigned char C[],int C_len,unsigned char *deB,unsigned char *ID,int ID_len,int isblockorstream,
			int macKeylen,unsigned char M[],int * Mlen)
{
	big x,y;
	epoint *C1;
	zzn12 w;
	ecn2 dEB;
	int mlen,klen,Zlen,i,number=0,ret=0;
	int k1_len = 16;
	int k2_len = macKeylen;
	unsigned char *Z=NULL,*K=NULL,*K1=NULL,u[SM3_len/8];

	x=mirvar(0);
	y=mirvar(0);
	init_ecn2(&dEB);
	C1=epoint_init();
	init_zzn12(&w);

	bytes_to_big(BNLEN,C,x);
	bytes_to_big(BNLEN,C+BNLEN,y);
	bytes128_to_ecn2(deB,&dEB);

	//Step1:get C1,and test if C1 is on G1
	epoint_set(x,y,1,C1);
	if(Test_Point(C1))
	{
		ret = SM9_C1_NOT_VALID_G1;
		goto RETURN;
	}

	//Step2:w = e(C1, deB)
	if(!ecap(dEB, C1, para_t, X, &w))
	{
		ret = SM9_MY_ECAP_12A_ERR;
		goto RETURN;
	}

	//test if a ZZn12 element is of order q
	if(!member(w, para_t, X))
	{
		ret = SM9_MEMBER_ERR;
		goto RETURN;
	}
#if DEBUG_PRINT
	printf("\n*********************** w = e(C1, deB):****************************\n");
	zzn12_ElementPrint(w);
#endif

	mlen=C_len-BNLEN*2-SM3_len/8;
	if (0 == isblockorstream)
	{
		//Step3-1:calculate K=KDF(C1||w||IDB,klen)
		klen=mlen+k2_len;
		Zlen=ID_len+BNLEN*14;
		Z=(char *)malloc(sizeof(char)*(Zlen+4));
		K=(char *)malloc(sizeof(char)*(klen+1));
		if(Z==NULL || K==NULL)
		{
			ret = SM9_ASK_MEMORY_ERR;
			goto RETURN;
		}
		LinkCharZzn12(C,BNLEN*2,w,Z,Zlen-ID_len);
		memcpy(Z+BNLEN*14,ID,ID_len);
		SM3_KDF(Z,Zlen+4,klen,K);

#if DEBUG_PRINT
		printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
		for(i=0;i<klen;i++)
			printf("%02x",K[i]);
		printf("\n");
#endif
		//Step:3-2: calculate M=C2^K1,and test if K1==0?
		for(i=0;i<mlen;i++)
		{
			if(K[i]==0)
				number+=1;
			M[i]=C[i+C_len-mlen]^K[i];
		}
		if(number==mlen)
		{
			ret = SM9_ERR_K1_ZERO;
			goto RETURN;
		}
		*Mlen=mlen;

		//Step4:calculate u=MAC(K2,C2)
		SM9_Enc_MAC(K+mlen,k2_len,&C[C_len-mlen],mlen,u);

#if DEBUG_PRINT
		printf("*****************************u:***********************\n");
		for (i=0;i<sizeof(u);i++)
			printf("%02x",u[i]);
#endif

		if(memcmp(u,&C[BNLEN*2],SM3_len/8))
		{
			ret = SM9_C3_MEMCMP_ERR;
			goto RETURN;
		}

#if DEBUG_PRINT
		printf("\n****************************** M:******************************\n");
		for(i=0;i<mlen;i++)
			printf("%02x",M[i]);
#endif



	}
	else
	{
		//Step:3-1: calculate K=KDF(C1||w||IDB,klen)
		klen=k1_len+k2_len;
		Zlen=ID_len+BNLEN*14;
		Z=(char *)malloc(sizeof(char)*(Zlen+4));
		K=(char *)malloc(sizeof(char)*(klen+1));
		K1=(char *)malloc(sizeof(char)*(k1_len+1));
		if(Z==NULL|| K==NULL|| K1==NULL)
		{
			ret = SM9_ASK_MEMORY_ERR;
			goto RETURN;
		}
		LinkCharZzn12(C,BNLEN*2,w,Z,Zlen-ID_len);
		memcpy(Z+BNLEN*14,ID,ID_len);
		SM3_KDF(Z,Zlen+4,klen,K);

#if DEBUG_PRINT
		printf("\n*****************K=KDF(C1||w||IDB,klen):***********************\n");
		for(i=0;i<klen;i++)
			printf("%02x",K[i]);
#endif
		//Step:3-2: calculate M=dec(K1,C2),and test if K1==0?
		for(i=0;i<k1_len;i++)
		{
			if(K[i]==0)
				number+=1;
			K1[i]=K[i];
		}
		if(number==k1_len)
		{
			ret = SM9_ERR_K1_ZERO;
			goto RETURN;
		}
		SM4_Block_Decrypt(K1,&C[C_len-mlen],mlen,M,Mlen);

		//Step4:calculate u=MAC(K2,C2)
		SM9_Enc_MAC(K+k1_len,k2_len,&C[C_len-mlen],mlen,u);
		if(memcmp(u,&C[BNLEN*2],SM3_len/8))
		{
			ret = SM9_C3_MEMCMP_ERR;
			goto RETURN;
		}
	}

RETURN:
	mirkill(x);
	mirkill(y);
	epoint_free(C1);
	release_ecn2(&dEB);
	release_zzn12(&w);
	if (Z == NULL)
	{
		free(Z);
		Z = NULL;
	}
	if (K == NULL)
	{
		free(K);
		K = NULL;
	}
	if (K1 == NULL)
	{
		free(K1);
		K1 = NULL;
	}

	return ret;
}


int SM9_GenerateSignKey(unsigned char *ID,int IDlen,unsigned char dA[],unsigned char Ppubs[],unsigned char dsa[])
{
    big h1,t1,t2,rem,xdSA,ydSA,tmp,ks;
    ks=mirvar(0);
    bytes_to_big(32,dA,ks);
//    unsigned char *Z=NULL;
//    int Zlen=IDlen+1;
    int buf;
    ecn2 Ppub;
    epoint *dSA;
    h1=mirvar(0);
    t1=mirvar(0);
    t2=mirvar(0);
    rem=mirvar(0);
    tmp=mirvar(0);
    xdSA=mirvar(0);
    ydSA=mirvar(0);
    dSA=epoint_init();
    init_ecn2(&Ppub);
//    Z=(char *)malloc(sizeof(char)*(Zlen+1));
//    memcpy(Z,ID,IDlen);
//    memcpy(Z+IDlen,HID_SIGN,1);
    buf=SM9_H1(ID,IDlen,HID_SIGN,h1);
    if(buf!=0) return buf;
    add(h1,ks,t1);//t1=H1(IDA||hid,N)+ks
    xgcd(t1,N,t1,t1,t1);//t1=t1(-1)
    multiply(ks,t1,t2);
    divide(t2,N,rem);//t2=ks*t1(-1)
    //dSA=[t2]P1
    ecurve_mult(t2,P,dSA);
    //Ppub=[ks]P2
    ecn2_copy(&P2,&Ppub);
    ecn2_mul(ks,&Ppub);
//    printf("\n*********************The signed key = (xdA, ydA)： *********************\n");
    epoint_get(dSA,xdSA,ydSA);
//    cotnum(xdSA,stdout);cotnum(ydSA,stdout);
//    printf("\n**********************PublicKey Ppubs=[ks]P2： *************************\n");
//    ecn2_Bytes128_Print(Ppub);
    epoint_get(dSA,xdSA,ydSA);
    big_to_bytes(BNLEN,xdSA,dsa,1);
    big_to_bytes(BNLEN,ydSA,dsa+BNLEN,1);
    redc(Ppub.x.b,tmp);
    big_to_bytes(BNLEN,tmp,Ppubs,1);
    redc(Ppub.x.a,tmp);
    big_to_bytes(BNLEN,tmp,Ppubs+BNLEN,1);
    redc(Ppub.y.b,tmp);
    big_to_bytes(BNLEN,tmp,Ppubs+BNLEN*2,1);
    redc(Ppub.y.a,tmp);
    big_to_bytes(BNLEN,tmp,Ppubs+BNLEN*3,1);
//    free(Z);

    return 0;
}
/****************************************************************
Function: SM9_Sign
Description: SM9 signature algorithm
Calls: MIRACL functions,zzn12_init(),ecap(),member(),zzn12_ElementPrint(),
zzn12_pow(),LinkCharZzn12(),SM9_H2()
Called By: SM9_SelfCheck()
Input:
hid:0x01
IDA //identification of userA
message //the message to be signed
len //the length of message
rand //a random number K lies in [1,N-1]
dSA //signature private key
Ppubs //signature public key
Output: H,S //signature result
Return: 0: success
1: asking for memory error
4: element is out of order q
5: R-ate calculation error
9: parameter L error
Others:
****************************************************************/
int SM9_Sign (unsigned char *IDA,unsigned char *message,int len,unsigned char rand[],unsigned char dsa[],unsigned char Ppub[],unsigned char H[],unsigned char S[])
{
    big h1,r,h,l,xdSA,ydSA;
    big xS,yS,tmp,zero;
    zzn12 g,w;
    epoint *s,*dSA,*QB;
    ecn2 Ppubs;
    int Zlen,buf,i;
    unsigned char *Z=NULL;
    //initiate
    h1=mirvar(0);
    h1=mirvar(0);
    r=mirvar(0);
    h=mirvar(0);
    l=mirvar(0);
    tmp=mirvar(0);
    zero=mirvar(0);
    xS=mirvar(0);yS=mirvar(0);
    xdSA=mirvar(0);ydSA=mirvar(0);
    s=epoint_init();dSA=epoint_init();

    init_ecn2(&Ppubs);
    zzn12_init(&g);
    zzn12_init(&w);
    bytes_to_big(BNLEN,rand,r);
    bytes_to_big(BNLEN,dsa,xdSA);
    bytes_to_big(BNLEN,dsa+BNLEN,ydSA);
    epoint_set(xdSA,ydSA,0,dSA);
    bytes128_to_ecn2(Ppub,&Ppubs);
////    //Step1:g = e(P1, Ppub-s)
    if(!ecap(Ppubs, P, para_t, X, &g))
    return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if(!member(g, para_t, X))
    return SM9_MEMBER_ERR;
//    printf("\n***********************g=e(P1,Ppubs):****************************\n");
//    zzn12_ElementPrint(g);
    //Step2:calculate w=g(r)
//    printf("\n***********************randnum r:********************************\n");
//    cotnum(r,stdout);
    w=zzn12_pow(g,r);
//    printf("\n***************************w=gr:**********************************\n");
//    zzn12_ElementPrint(w);
    //Step3:calculate h=H2(M||w,N)
    Zlen=len+32*12;
    Z=(char *)malloc(sizeof(char)*(Zlen+1));
    if(Z==NULL)
    return SM9_ASK_MEMORY_ERR;
    LinkCharZzn12(message,len,w,Z,Zlen);
//    for (i=0; i<Zlen+1; i++)
//    {
//        printf("0x%02x,", Z[i]);
//    }
    buf=SM9_H2(Z,Zlen,N,h);if(buf!=0)
    return buf;
//    printf("\n****************************N:*************************************\n");
//    cotnum(N,stdout);
//    printf("\n****************************h:*************************************\n");
//    cotnum(h,stdout);
    //Step4:l=(r-h)mod N
    subtract(r,h,l);
    divide(l,N,tmp);
    while(mr_compare(l,zero)<0)
    add(l,N,l);
    if(mr_compare(l,zero)==0)
    return SM9_L_error;
//    printf("\n**************************l=(r-h)mod N:****************************\n");
//    cotnum(l,stdout);
    //Step5:S=[l]dSA=(xS,yS)
    ecurve_mult(l,dSA,s);
    epoint_get(s,xS,yS);
//    printf("\n**************************S=[l]dSA=(xS,yS):*************************\n");
//    cotnum(xS,stdout);cotnum(yS,stdout);
    big_to_bytes(32,h,H,1);
    big_to_bytes(32,xS,S,1);
    big_to_bytes(32,yS,S+32,1);
    free(Z);
    return 0;
}
/****************************************************************
Function: SM9_Verify
Description: SM9 signature verification algorithm
Calls: MIRACL functions,zzn12_init(),Test_Range(),Test_Point(),
ecap(),member(),zzn12_ElementPrint(),SM9_H1(),SM9_H2()
Called By: SM9_SelfCheck()
Input:
H,S //signature result used to be verified
hid //identification
IDA //identification of userA
message //the message to be signed
len //the length of message
Ppubs //signature public key
Output: NULL
Return: 0: success1: asking for memory error
2: H is not in the range[1,N-1]
6: S is not on the SM9 curve
4: element is out of order q
5: R-ate calculation error
3: h2!=h,comparison error
Others:
****************************************************************/
int SM9_Verify (unsigned char H[],unsigned char S[],unsigned char *IDA,unsigned char *message,int len,
unsigned char Ppub[])
{
    big h,xS,yS,h1,h2;
    epoint *S1;
    zzn12 g,t,u,w;
    ecn2 P1,Ppubs;
    int Zlen1,Zlen2,buf;
    unsigned char * Z1=NULL,*Z2=NULL;
    unsigned char hid[]={0x01};
    h=mirvar(0);
    h1=mirvar(0);
    h2=mirvar(0);
    xS=mirvar(0);
    yS=mirvar(0);
    init_ecn2(&P1);
     init_ecn2(&Ppubs);
//    P1.x.a=mirvar(0);
//    P1.x.b=mirvar(0);
//    P1.y.a=mirvar(0);
//    P1.y.b=mirvar(0);
//    P1.z.a=mirvar(0);
//    P1.z.b=mirvar(0);
//    P1.marker=MR_EPOINT_INFINITY;
//    Ppubs.x.a=mirvar(0);
//    Ppubs.x.b=mirvar(0);
//    Ppubs.y.a=mirvar(0);
//    Ppubs.y.b=mirvar(0);
//    Ppubs.z.a=mirvar(0);
//    Ppubs.z.b=mirvar(0);
//    Ppubs.marker=MR_EPOINT_INFINITY;
    S1=epoint_init();
    zzn12_init(&g);
    zzn12_init(&t);
    zzn12_init(&u);
    zzn12_init(&w);
    bytes_to_big(BNLEN,H,h);
    bytes_to_big(BNLEN,S,xS);
    bytes_to_big(BNLEN,S+BNLEN,yS);
    bytes128_to_ecn2(Ppub,&Ppubs);
    //Step 1:test if h in the rangge [1,N-1]
    if(Test_Range(h))
    return SM9_H_OUTRANGE;
    //Step 2:test if S is on G1
    epoint_set(xS,yS,0,S1);
    if(Test_Point(S1))
    return SM9_S_NOT_VALID_G1;
    //Step3:g = e(P1, Ppub-s)
    if(!ecap(Ppubs, P, para_t, X, &g))
    return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if(!member(g, para_t, X))
    return SM9_MEMBER_ERR;
//    printf("\n***********************g=e(P1,Ppubs):****************************\n");
//    zzn12_ElementPrint(g);
    //Step4:calculate t=g(h)
    t=zzn12_pow(g,h);
//    printf("\n***************************w=gh:**********************************\n");
//    zzn12_ElementPrint(t);
    //Step5:calculate h1=H1(IDA||hid,N)
    Zlen1=strlen(IDA)+1;
    Z1=(char *)malloc(sizeof(char)*(Zlen1+1));
    if(Z1==NULL) return SM9_ASK_MEMORY_ERR;
    memcpy(Z1,IDA,strlen(IDA));
    memcpy(Z1+strlen(IDA),hid,1);
//int i;
//printf(" \n================Z1==================\n");
//        for (i=0; i<Zlen1+1; i++)
//    {
//        printf("0x%02x,", Z1[i]);
//    }
    buf=SM9_H1_ver(Z1,Zlen1,N,h1);
    if(buf!=0) return buf;
//    printf("\n****************************h1:**********************************\n");
//    cotnum(h1,stdout);
    //Step6:P=[h1]P2+Ppubs
    ecn2_copy(&P2,&P1);
    ecn2_mul(h1,&P1);
    ecn2_add(&Ppubs,&P1);//Step7:u=e(S1,P)
    if(!ecap(P1, S1, para_t, X, &u)) return SM9_MY_ECAP_12A_ERR;
    //test if a ZZn12 element is of order q
    if(!member(u, para_t, X)) return SM9_MEMBER_ERR;
//    printf("\n************************** u=e(S1,P):*****************************\n");
//    zzn12_ElementPrint(u);
    //Step8:w=u*t
    zzn12_mul(u,t,&w);
//    printf("\n************************* w=u*t: **********************************\n");
//    zzn12_ElementPrint(w);
    //Step9:h2=H2(M||w,N)
    Zlen2=len+32*12;
    Z2=(char *)malloc(sizeof(char)*(Zlen2+1));
    if(Z2==NULL)
    return SM9_ASK_MEMORY_ERR;
    LinkCharZzn12(message,len,w,Z2,Zlen2);
    buf=SM9_H2(Z2,Zlen2,N,h2);
    if(buf!=0) return buf;
    printf("\n**************************** h2:***********************************\n");
    cotnum(h2,stdout);
    free(Z1);
    free(Z2);
    if(mr_compare(h2,h)!=0)
    return SM9_DATA_MEMCMP_ERR;
    return 0;
}
// SM9签名验签方法
//        6.Test_Range           //test if the big x belong to the range[1,N-1]
//        9.SM9_H2               //function H2 in SM9 standard 5.4.2.3
//        10.SM9_GenerateSignKey //generate signed private and public key
//        11.SM9_Sign            //SM9 signature algorithm
//        12.SM9_Verify          //SM9 verification
//        13.SM9_sign_verify_SelfCheck()     //SM9 slef-check
/****************************************************************
  Function:       Test_Range
  Description:    test if the big x belong to the range[1,n-1]
  Calls:
  Called By:      SM9_Verify
  Input:          big x    ///a miracl data type
  Output:         null
  Return:         0: success
                  1: x==n,fail/////////////////////////////////////////////////////
  Others:
****************************************************************/
int Test_Range(big x)
{
    big one,decr_n;

    one=mirvar(0);
    decr_n=mirvar(0);

    convert(1,one);
    decr(N,1,decr_n);

    if( (mr_compare(x,one) < 0)| (mr_compare(x,decr_n)>0) )
        return 1;
    return 0;
}

/****************************************************************
  Function:       SM9_H2
  Description:    function H2 in SM9 standard 5.4.2.3
  Calls:          MIRACL functions,SM3_KDF
  Called By:      SM9_Sign,SM9_Verify
  Input:          Z:
                  Zlen:the length of Z
                  n:Frobniues constant X
  Output:         h2=H2(Z,Zlen)
  Return:         0: success;
                  1: asking for memory error
  Others:
****************************************************************/
int SM9_H2(unsigned char Z[],int Zlen,big n,big h2)
{
     int hlen,ZHlen,i;
     big hh,i256,tmp,n1;
     unsigned char *ZH=NULL,*ha=NULL;

     hh=mirvar(0);i256=mirvar(0);
     tmp=mirvar(0);n1=mirvar(0);
     convert(1,i256);
     ZHlen=Zlen+1+4;

     hlen=(int)ceil((5.0*logb2(n))/32.0);
     decr(n,1,n1);
     ZH=(unsigned char *)malloc(sizeof(char)*(ZHlen+1));
     if(ZH==NULL) return SM9_ASK_MEMORY_ERR;
     memcpy(ZH+1,Z,Zlen);
     ZH[0]=0x02;
     ha=(unsigned char *)malloc(sizeof(char)*(hlen+1));
     if(ha==NULL) return SM9_ASK_MEMORY_ERR;
     SM3_KDF(ZH,ZHlen,hlen,ha);

//    printf("\nha\n");
//     for (i=0; i<hlen; i++)
//    {
//        printf("0x%02x,", ha[i]);
//    }

	for(i=hlen-1;i>=0;i--)//key[从大到小]
	{
		premult(i256,ha[i],tmp);
        add(hh,tmp,hh);
        premult(i256,256,i256);
        divide(i256,n1,tmp);
        divide(hh,n1,tmp);
	}
    incr(hh,1,h2);
    free(ZH);free(ha);
    return 0;
}


#define TEST_MEM 0

int main()
{
	int ret = 0;

unsigned char rand[32]={
    0x15,0x86,0xE7,0x6D,0x4F,0x8D,0x91,0x87,0x83,0xA1,0xE5,0x05,0x6A,0x4C,0xC0,0xFA,
    0xBC,0x59,0xA3,0x31,0xCC,0x33,0xFF,0x1F,0x2E,0xE8,0x63,0x7D,0x29,0xC3,0x9A,0x02
    };
unsigned char IDB1[4]={
    0x6B,0x6C,0x1A,0x63};
unsigned char Ppub[64]={
    0x2A,0x6C,0xD7,0x68,0x41,0xB3,0xC2,0xAB,0x4D,0xF1,0x2A,0x00,0xEF,0x47,0x1D,0x24,
    0x03,0x20,0xA3,0x5F,0xF3,0x65,0x43,0x75,0x7E,0x17,0xED,0xDD,0xB1,0x25,0x67,0x67,
    0x06,0x96,0x83,0xA0,0xE8,0x81,0x43,0x82,0xD4,0xCC,0x9B,0x74,0x34,0xB5,0x1B,0xCF,
    0xCA,0xED,0xB2,0x57,0xFA,0x0C,0xD8,0x96,0xE0,0x2D,0x20,0xC9,0x6D,0x24,0xCF,0x7E
    };
int EncID=1;
unsigned char std_message1[32]={
    0x10,0x24,0x42,0x37,0xC2,0xB3,0xCB,0xCE,0x4C,0x17,0xBC,0xC1,0xC1,0x60,0x55,0x29,
    0x50,0x5F,0xC6,0xA6,0xC9,0x6F,0x63,0xAA,0x30,0x74,0x45,0x3C,0x75,0xEE,0xD9,0x7A
    };

/**
	unsigned char rand[32]=
	{0x00,0x00,0xAA,0xC0,0x54,0x17,0x79,0xC8,0xFC,0x45,0xE3,0xE2,0xCB,0x25,0xC1,0x2B,
	0x5D,0x25,0x76,0xB2,0x12,0x9A,0xE8,0xBB,0x5E,0xE2,0xCB,0xE5,0xEC,0x9E,0x78,0x5C};
	unsigned char Ppub[64]=
    {0x78,0x7E,0xD7,0xB8,0xA5,0x1F,0x3A,0xB8,0x4E,0x0A,0x66,0x00,0x3F,0x32,0xDA,0x5C,
    0x72,0x0B,0x17,0xEC,0xA7,0x13,0x7D,0x39,0xAB,0xC6,0x6E,0x3C,0x80,0xA8,0x92,0xFF,
    0x76,0x9D,0xE6,0x17,0x91,0xE5,0xAD,0xC4,0xB9,0xFF,0x85,0xA3,0x13,0x54,0x90,0x0B,
    0x20,0x28,0x71,0x27,0x9A,0x8C,0x49,0xDC,0x3F,0x22,0x0F,0x64,0x4C,0x57,0xA7,0xB1};
	unsigned char IDB1[3]={0x42,0x6f,0x62};
	unsigned char std_message1[20]={0x43,0x68,0x69,0x6e,0x65,0x73,0x65,0x20,0x49,0x42,0x45,0x20,0x73,0x74,0x61,0x6e,0x64,0x61,0x72,0x64};
	int EncID=1;//0,stream	//1 block
**/
    unsigned char KE[32] =
	{0x00,0x01,0xED,0xEE,0x37,0x78,0xF4,0x41,0xF8,0xDE,0xA3,0xD9,0xFA,0x0A,0xCC,0x4E,
	0x07,0xEE,0x36,0xC9,0x3F,0x9A,0x08,0x61,0x8A,0xF4,0xAD,0x85,0xCE,0xDE,0x1C,0x22};

    unsigned char std_deB[128]=
    {0x94,0x73,0x6A,0xCD,0x2C,0x8C,0x87,0x96,0xCC,0x47,0x85,0xE9,0x38,0x30,0x1A,0x13,
    0x9A,0x05,0x9D,0x35,0x37,0xB6,0x41,0x41,0x40,0xB2,0xD3,0x1E,0xEC,0xF4,0x16,0x83,
    0x11,0x5B,0xAE,0x85,0xF5,0xD8,0xBC,0x6C,0x3D,0xBD,0x9E,0x53,0x42,0x97,0x9A,0xCC,
    0xCF,0x3C,0x2F,0x4F,0x28,0x42,0x0B,0x1C,0xB4,0xF8,0xC0,0xB5,0x9A,0x19,0xB1,0x58,
    0x7A,0xA5,0xE4,0x75,0x70,0xDA,0x76,0x00,0xCD,0x76,0x0A,0x0C,0xF7,0xBE,0xAF,0x71,
    0xC4,0x47,0xF3,0x84,0x47,0x53,0xFE,0x74,0xFA,0x7B,0xA9,0x2C,0xA7,0xD3,0xB5,0x5F,
    0x27,0x53,0x8A,0x62,0xE7,0xF7,0xBF,0xB5,0x1D,0xCE,0x08,0x70,0x47,0x96,0xD9,0x4C,
    0x9D,0x56,0x73,0x4F,0x11,0x9E,0xA4,0x47,0x32,0xB5,0x0E,0x31,0xCD,0xEB,0x75,0xC1,};
	unsigned char hid[1]={0x03};
	unsigned char deB[128];
	unsigned char Ppub_out[64];
	unsigned char data_out[2048] = {0};
	unsigned char data_in[2048] = {0};
	int i,data_out_len,data_in_len;

	int k2_len = 32;

	ret=SM9_Init();
	if(ret != 0)
	{
		return ret;
	}
	//m1
	ret=SM9_GenerateEncryptKey(IDB1,4,KE,Ppub_out,deB);
	if(ret != 0)
		return ret;
    printf("\n******************************clear:************************************\n");
    //m2
    for(i=0;i<32;i++)
          printf("%02x",std_message1[i]);
printf("\n******************************Ppub_out:************************************\n");
	for(i=0;i<64;i++)
          printf("%02x",Ppub_out[i]);

printf("\n******************************deB:************************************\n");
	for(i=0;i<128;i++)
          printf("%02x",deB[i]);
    //m3
	ret = SM9_Encrypt(IDB1,4,std_message1,32,data_out,&data_out_len,rand,Ppub_out,EncID,k2_len);
		if(ret != 0)
		{
			printf("SM9_Encrypt error!\n");
			return ret;
		}

        printf("\n******************************Cipher:************************************\n");
        for(i=0;i<data_out_len;i++)
          printf("%02x",data_out[i]);
    //m4
        ret = SM9_Decrypt(data_out,data_out_len,deB,IDB1,4,EncID,k2_len,data_in,&data_in_len);
                if(ret != 0)
                {
                    printf("\n SM9_Decrypt error!\n");
                    return ret;
                }

        printf("\n******************************Clear:************************************\n");
        for(i=0;i<data_in_len;i++)
          printf("%02x",data_in[i]);

	return ret;
}

