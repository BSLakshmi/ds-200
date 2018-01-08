#include <bits/stdc++.h>
using namespace std;
#include <string>
#include <iostream>
#include "BigIntegerLibrary.hh"
#include "BigIntegerUtils.hh"

#define MAX_RANDOM_INT 2147483648
BigInteger powerAndModulo(BigInteger i1, BigInteger i2, BigInteger n1)
{
	BigInteger result = 1;     
	i1 = i1 % n1;  
	//took modulo           
	while (i2 > 0){
		if (i2 %2 == 1) //odd
			result = (result*i1) % n1;
		i2 = i2/2; //halving
		i1 = (i1*i1) % n1;
	}
	return result;
}
bool TestingByMiller(BigInteger val_m , BigInteger n1)
{
	// generate a random number by rand function
	srand(time(NULL));
	int g = 2 + rand();
	BigInteger val1 = (BigInteger)g % (n1 - 4);
	//val1=23;
	BigInteger powmod = powerAndModulo(val1, val_m, n1);
	if (powmod == 1  || powmod == n1-1)
		return true;
	while (val_m != n1-1){
		powmod = (powmod * powmod);
		powmod=powmod % n1;
		val_m *= 2;
		if (powmod == 1)      return false;
		if (powmod == n1-1)    return true;
	}
	//cout >> val1;

	return false;
}
bool PrimeCheck(BigInteger numval, int k)
{

	if (numval <= 1 || numval == 4)  return false;
	if (numval <= 3) return true;


	BigInteger numval1 = numval - 1;
	while (numval1 % 2 == 0){
		numval1 /= 2;
	}
	//cout << numval1;
	for (int i = 0; i < k; i++){
		if (TestingByMiller(numval1, numval) == false)
			return false;
	}

	return true;
}

bool primary_check(BigInteger b1){
	int ar[168]={2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,151,157,163,167,173,179,181,191,193,197,199,211,223,227,229,233,239,241,251,257,263,269,271,277,281,283,293,307,311,313,317,331,337,347,349,353,359,367,373,379,383,389,397,401,409,419,421,431,433,439,443,449,457,461,463,467,479,487,491,499,503,509,521,523,541,547,557,563,569,571,577,587,593,599,601,607,613,617,619,631,641,643,647,653,659,661,673,677,683,691,701,709,719,727,733,739,743,751,757,761,769,773,787,797,809,811,821,823,827,829,839,853,857,859,863,877,881,883,887,907,911,919,929,937,941,947,953,967,971,977,983,991,997
	};
	int i;
	for(i=0;i<168;i++){
		if(b1%ar[i]==0){
			return false;
		}
	}
	return true;
}
bool checkprime(BigInteger num, int k){
	if(primary_check(num)==false){
		return false;
	}	
	return PrimeCheck(num,k);
}
string  rev(string &str1){
	int n = str1.length();
	string s="";
	int i;
	for(i=n;i>=0;i--){
		ostringstream oss;
		oss << s << str1[i] ;
		s = oss.str ();
	}
	return s;
}



BigInteger findgenerator(BigInteger m1){
	BigInteger m2=m1-1;
	while(m2%2==0){
		m2=m2/2;
	}
	//	cout << "_";
	if(checkprime(m2,4)==true){
		return m2;
	}
	return 0;

}


void generatePG() {


	int k = 4;  // Number of iterations
	BigInteger a,b,x,y,m2,res;
	BigInteger num=1; 
	int repeat=1; 
	int i;

	string pStr,gStr;

	FILE *fd;

	fd = fopen("shared.txt","w");

	if(fd == NULL)                     	
	{
		printf("could not open file\n");
		return;
	}

	for(i=1;i<=215;i++){
		num*=2;
	}
	num--;
	bool val=true;
	while(val==true){
		while(!checkprime(num,k)){
			// cout << ".";
			num-=2;
		}
		m2=num-1;
		res=findgenerator(m2);
		if(res==0){
			val=true;
			num-=2;
		}
		else {val=false;
		}
		//cout<<"$";
	}

	srand(time(NULL));
	BigInteger g =(BigInteger)rand() % m2+2;
	BigInteger temp1=m2/res;
	g=powerAndModulo(g,temp1,num);
	
	pStr = bigIntegerToString(num);
	gStr = bigIntegerToString(g);
	fprintf(fd,pStr.c_str());
	fprintf(fd,"\n");
	fprintf(fd,gStr.c_str());

	fclose(fd);

}

int main()
{
	generatePG();
}


