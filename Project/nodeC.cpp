#include <bits/stdc++.h>
#include <string>
#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "BigIntegerLibrary.hh"
#include "BigIntegerUtils.hh"
#include "aes.h"

using namespace std;

#define MAX_RANDOM_INT 2147483648

string name="NodeC", mobile="1234567890", email="nodec@x.com",aadharC="1564896345879965";	
string myPubKey;
BigInteger pub_a;		//public key of A
BigInteger a_n;			// n of A = (p-1)(q-1)
BigInteger d;			//private key of C
BigInteger n1;

/*Prints input num in binary*/
void print_binary(BigInteger num)
{
	static int ctr = 0;
	if (num == 0)	return;
	
	print_binary(num/2);

	if (ctr < 128)
	{
		cout << (num%2);
		ctr++;
	}
}


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



BigInteger gcd(BigInteger a, BigInteger h)
{
	BigInteger temp;
	while (1)
	{
		temp = a%h;
		if (temp == 0)
			return h;
		a = h;
		h = temp;
	}
}
int prime(BigInteger pr) {

	BigInteger i,j;

	j=pr/2;

	for (i=2;i<=j;i++) {

		if(pr%i==0)

			return 0;

	}

	return 1;

}

// C function for extended Euclidean Algorithm
BigInteger gcdExtended(BigInteger a, BigInteger b, BigInteger *x, BigInteger *y)
{
	// Base Case
	if (a == 0)
	{
		*x = 0, *y = 1;
		return b;
	}

	BigInteger x1, y1; // To store results of recursive call
	BigInteger gcd = gcdExtended(b%a, a, &x1, &y1);

	// Update x and y using results of recursive
	// call
	*x = y1 - (b/a) * x1;
	*y = x1;

	return gcd;
}

// Function to find modulo inverse of a
BigInteger modInverse(BigInteger a, BigInteger m)
{
	BigInteger x, y,res;
	BigInteger g = gcdExtended(a, m, &x, &y);
	if (g != 1)
		cout << "Inverse doesn't exist";
	else
	{
		// m is added to handle negative x
		res = (x%m + m) % m;
	}
	return res;
}

string get_e(string pstr, string qstr)
{
	string stri="14272476924470594951"; //for c
	BigInteger e=stringToBigInteger(stri);
	BigInteger p=stringToBigInteger(pstr);
	BigInteger q=stringToBigInteger(qstr);
	BigInteger phi=(p-1)*(q-1);
	while (e < phi)
	{
		// e must be co-prime to phi and
		// smaller than phi.
		if (gcd(e, phi)==1)
			break;
		else
			e++;
	}


	return bigIntegerToString(e);
}

BigInteger encryptrsa(BigInteger plaintext, BigInteger e, BigInteger n){
	return powerAndModulo(plaintext,e,n);
}

BigInteger decryptrsa(BigInteger ciphertext, BigInteger d, BigInteger n){
	return powerAndModulo(ciphertext,d,n);
}

string getEncryptedString(string plaintextstr, BigInteger e, BigInteger n1){
	string strin;
	BigInteger plaintext=stringToBigInteger(plaintextstr);
	while(plaintext>0){
		BigInteger a1=plaintext%10;
		plaintext=plaintext/10;
		ostringstream ostreamstr1;
		string pubkey1;
		if(a1==0)
			pubkey1="0";
		else
			pubkey1 = bigIntegerToString(encryptrsa(a1,e,n1));
		ostreamstr1 <<strin<<pubkey1<<"|";
		strin = ostreamstr1.str ();
	}

	return strin;
}

string getDecryptedString(string ciphertext, BigInteger d, BigInteger n1){

	string nstr;
	int spacepos=ciphertext.find('|');
	BigInteger publicKey_recv=0,n_rec;
	string stt;
	while(spacepos>0 ){
		nstr=ciphertext.substr(0,spacepos);

		ostringstream ostreamstr2;
		string pubkey2;
		if(nstr=="0")
			pubkey2="0";
		else
			pubkey2 = bigIntegerToString(decryptrsa(stringToBigInteger(nstr),d,n1));
		ostreamstr2 <<stt<<pubkey2;
		stt = ostreamstr2.str ();
		ciphertext=ciphertext.substr(spacepos+1,ciphertext.length());
		spacepos=ciphertext.find('|');

	}
	reverse(stt.begin(),stt.end());
	return stt;
}

void generateCMAC(string str,BYTE out[])
{
	int i=0;

	WORD key_schedule[60];
	BYTE plaintext[1][128];
	BYTE iv[1][16] = {
		{0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f}
	};
	BYTE key[1][32] = {
		{0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4}
	};
	int pass = 1;

	aes_key_setup(key[0], key_schedule, 256);

	str.c_str();

	for (i=0;str[i]!='\0';i++)
		plaintext[0][i] = str[i];

	aes_encrypt_cbc_mac(plaintext[0], 32, out, key_schedule, 256, iv[0]);

	out[AES_BLOCK_SIZE] = '\0';

}


string getPublicKeyCertified()
{
	string temp1str="13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084823";
	string temp2str="13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006085201";

	BigInteger temp1 =stringToBigInteger(temp1str);//p
	BigInteger temp2 =stringToBigInteger(temp2str);//q

	BigInteger e;
	BigInteger p,g;
	
	string n;

	string pubstr = "5969449495136382746787";
	pub_a=stringToBigInteger(pubstr);


	string astr ="179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639498687481895548262751904890098932711351636317636408216752995333403048954045557619535414144255069004242878649048783940685111323051791202420977222774603371004423";
	a_n=stringToBigInteger(astr);

	string estr =get_e(temp1str,temp2str);		//calculate e
	e=stringToBigInteger(estr);

	n1=temp1*temp2;

	BigInteger phi=(temp1-1)*(temp2-1);

	d=modInverse(e,phi);

	int clientSocket, portNum, nBytes=1024;

	struct sockaddr_in serverAddr;
	socklen_t addr_size;

	n=bigIntegerToString(n1);
	string str="";

	myPubKey = bigIntegerToString(e);	//public key of C

	ostringstream ostreamstr;
	ostreamstr <<str<< name<<"|"<<mobile<<"|"<<email<<"|"<<aadharC<<"|"<<myPubKey<<"|"<<n;
	str = ostreamstr.str ();
	char sendBuffer[1000000],recvBuffer[1000000];
	strcpy(sendBuffer,str.c_str());

/**********************Start of socket part**********************/

	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(7891);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

/*Initialize size variable to be used later on*/
	addr_size = sizeof serverAddr;
	sendto(clientSocket,sendBuffer,10000,0,(struct sockaddr *)&serverAddr,addr_size);		//sending Bs details to A
	
/*Part2: get nonce*/
	nBytes = recvfrom(clientSocket,recvBuffer,10000,0,NULL, NULL);		//nonce received from A in encrypted form

	recvBuffer[nBytes]='\0';
	str=recvBuffer;
	str=getDecryptedString(str,d,n1);		//decrypt the received nonce

/*part3: send nonce back*/
	str=getEncryptedString(str,pub_a,a_n);
	strcpy(sendBuffer,str.c_str());
	sendto(clientSocket,sendBuffer,nBytes,0,(struct sockaddr *)&serverAddr,addr_size);
	
/*receiving cert*/
	nBytes = recvfrom(clientSocket,recvBuffer,10000,0,NULL, NULL);
	recvBuffer[nBytes]='\0';
	string certificate=recvBuffer;

	shutdown(clientSocket,2);	
	return certificate;	
}

int sharePublicKey(string myCert)
{
	FILE *fd;
	char buffP[128],buffG[128];
	BigInteger p,g;

	//socket related variables

	int udpSocket, nBytes;


	char sendBufferKey[20000],recvBufferKey[20000];
	BYTE recvBufferMac[AES_BLOCK_SIZE+1];
	BYTE sendBufferMac[AES_BLOCK_SIZE+1];



	struct sockaddr_in serverAddr, clientAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size, client_addr_size;


	//Socket part starts here

	/*Create UDP socket*/
	udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

	/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(8000);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	/*Bind socket with address struct*/
	bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

	/*Initialize size variable to be used later on*/
	addr_size = sizeof serverStorage;

	char aadharB_buf[20],puKeyB_buf[25], certB_buf[10000];	//receiving buffers
	char aadharC_buf[20],puKeyC_buf[25], certC_buf[10000];	//sending buffers


	//receiving ID_B
	nBytes = recvfrom(udpSocket,aadharB_buf,1024,0,(struct sockaddr *)&serverStorage, &addr_size);	
	aadharB_buf[nBytes] = '\0';	
	string aadharBStr = aadharB_buf;

	//receiving public key of B
	nBytes = recvfrom(udpSocket,puKeyB_buf,10000,0,(struct sockaddr *)&serverStorage, &addr_size);		
	puKeyB_buf[nBytes] = '\0';
	string puKeyBStr = puKeyB_buf;

	//receiving certificateB
	nBytes = recvfrom(udpSocket,certB_buf,10000,0,(struct sockaddr *)&serverStorage, &addr_size);		
	certB_buf[nBytes] = '\0';

	//sending ID_C
	strcpy(aadharC_buf,aadharC.c_str());
	sendto(udpSocket,aadharC_buf,1024,0,(struct sockaddr *)&serverStorage,addr_size);

	//sending public key of C
	strcpy(puKeyC_buf,myPubKey.c_str());
	sendto(udpSocket,puKeyC_buf,1024,0,(struct sockaddr *)&serverStorage,addr_size);	

	//sending certificateC
	strcpy(certC_buf,myCert.c_str());
	sendto(udpSocket,certC_buf,10000,0,(struct sockaddr *)&serverStorage,addr_size);
	string certBStr;

	certBStr = certB_buf;
	string decryptedCertBStr = getDecryptedString(certBStr,pub_a,n1);


	char aadharB[20],nb[400],puKeyB[1024];
	string strA,     strN,   strK;


	int it,j=0;

	for(it=0;it<16;it++)
	{
		aadharB[it]=decryptedCertBStr[it];	
	}
	aadharB[16]='\0';	
	strA = aadharB;

	for(j=0,it=16;decryptedCertBStr[it]!='\0';it++,j++)
	{
		puKeyB[j]=decryptedCertBStr[it];	
	}
	puKeyB[j]='\0';	
	strK = puKeyB;

	if ((strA.compare(aadharBStr) != 0) && (strK.compare(puKeyBStr) != 0))
	{
		cout <<"\nCertificate and details do not match"<<endl; 	
		return -1;	
	}


	string str;	

	//Exchange 1nd random num
	char recv_encryptedRand1Buf[1024],recv_rand1Buf[1024]; 


	nBytes = recvfrom(udpSocket,recv_encryptedRand1Buf,10000,0,(struct sockaddr *)&serverStorage, &addr_size);                                   	//receive from B rand1 encrypted with public key of C
	recv_encryptedRand1Buf[nBytes] = '\0';	
	str = recv_encryptedRand1Buf; 
	string random1Str = getDecryptedString(str,d,n1);	//decrypt encrypted rand1 with private key of C

	str = puKeyB_buf;

	string encryptedRand1 = getEncryptedString(random1Str,stringToBigInteger(str),n1);	//encrypt rand1 with public key of B

	char encryptedRand1_buf[100000];

	strcpy(encryptedRand1_buf,encryptedRand1.c_str());	
	sendto(udpSocket, encryptedRand1_buf,10000,0,(struct sockaddr *)&serverStorage,addr_size);	//send rand1 encrypted with public key of B to B

	//Exchange second random num
	BigInteger random2;

	srand(time(NULL));	      	
	random2 = (BigInteger) rand() % 10000000;	//generate random num 2

	string encryptedRand2Str = getEncryptedString(bigIntegerToString(random2),stringToBigInteger(str),n1);	//encrypting random2 using the public key of B

	char encryptedRand2_buf[100000],recvRand2_buf[10000];
	strcpy(encryptedRand2_buf,encryptedRand2Str.c_str());
	sendto(udpSocket, encryptedRand2_buf,10000,0,(struct sockaddr *)&serverStorage,addr_size);		//send the rand2 to B

	nBytes = recvfrom(udpSocket,recvRand2_buf,10000,0,(struct sockaddr *)&serverStorage, &addr_size);                             	//receive rand2 encryted with public key of C
	recvRand2_buf[nBytes] = '\0';

	string decryptedRecvRand2 = getDecryptedString(recvRand2_buf,d,n1);			//decrypt the received encrypted rand2 using private key of C

	string random2Str = bigIntegerToString (random2);	//string form of generated rand2
		if ( random2Str.compare(decryptedRecvRand2) != 0)		//compare generated rand2 and decrypted received rand2
		{
		cout << "Random2 does not match\n";
		return -1;
		}
	 

	/*******************************end of key sharing**********************/

	/***************************diffie hellman part**************************/

	fd = fopen("shared.txt","r");

	fgets(buffP,128,fd);
	fgets(buffG,128,fd);	

	p = stringToBigInteger (buffP);

	g = stringToBigInteger (buffG);

	srand(time(NULL));
	BigInteger beta = (BigInteger)rand() % MAX_RANDOM_INT +2;
	BigInteger publicKeyC = powerAndModulo(g,beta,p);

	
	string publicKeyCString = bigIntegerToString(publicKeyC);
	string encPubKeyCStr = getEncryptedString(publicKeyCString,stringToBigInteger(puKeyBStr),n1);

	strcpy(sendBufferKey,encPubKeyCStr.c_str());

	generateCMAC(publicKeyCString,sendBufferMac);

	nBytes = recvfrom(udpSocket,recvBufferKey,20000,0,(struct sockaddr *)&serverStorage, &addr_size);
	recvBufferKey[nBytes] = '\0';

	string tempStr;
	tempStr = recvBufferKey;

	char nonBC[10000],nonCB[10000];

	char sendNonBC[10000],recvNonBC[10000],sendNonCB[10000],recvNonCB[10000];

	nBytes = recvfrom(udpSocket,recvNonBC,10000,0,(struct sockaddr *)&serverStorage, &addr_size);
	recvNonBC[nBytes] = '\0';

	string enc_nonBCStr;
	enc_nonBCStr = recvNonBC;

	string dec_nonBCStr = getDecryptedString(enc_nonBCStr,d,n1);

	string reEnc_nonBCStr= getEncryptedString(dec_nonBCStr,stringToBigInteger(puKeyBStr),n1);
	strcpy(sendNonBC,reEnc_nonBCStr.c_str());

	sendto(udpSocket,sendBufferKey,20000,0,(struct sockaddr *)&serverStorage,addr_size);


	sendto(udpSocket,sendNonBC,10000,0,(struct sockaddr *)&serverStorage,addr_size); 
	
	srand(time(NULL));                                        		
	BigInteger nonceCB=(BigInteger)rand() % MAX_RANDOM_INT +2;

	string encNonceCBStr = getEncryptedString(bigIntegerToString(nonceCB),stringToBigInteger(puKeyBStr),n1);
	


	strcpy(sendNonCB,encNonceCBStr.c_str());	

	sendto(udpSocket,sendNonCB,10000,0,(struct sockaddr *)&serverStorage,addr_size); 

	nBytes = recvfrom(udpSocket,recvNonCB,10000,0,(struct sockaddr *)&serverStorage, &addr_size);
	recvNonCB[nBytes] = '\0';

	string recv_nonCBStr = recvNonCB;
	string dec_nonCBStr = getDecryptedString(recv_nonCBStr,d,n1);

	if (dec_nonCBStr.compare(bigIntegerToString(nonceCB)) != 0)
	{
		cout<<"\nMismatch in nonce. Exiting session"<<endl;
		return -1;
	}


	nBytes = recvfrom(udpSocket,recvBufferMac,AES_BLOCK_SIZE+1,0,(struct sockaddr *)&serverStorage, &addr_size);
	recvBufferMac[nBytes] = '\0';

	sendto(udpSocket,sendBufferMac,AES_BLOCK_SIZE+1,0,(struct sockaddr *)&serverStorage,addr_size);

/*-------------End of socket part---------------*/

	string temp1;
	temp1 = recvBufferKey;
	string decPubKeyBStr = getDecryptedString(temp1,d,n1);


	BYTE calculatedMac[AES_BLOCK_SIZE+1];
	generateCMAC(decPubKeyBStr.c_str(),calculatedMac);


	int isEqual =1;		//isEqual=1 means the received mac and calculate mac are equal

	BYTE *ptr = &calculatedMac[0];
	
	for (int i=0;i<AES_BLOCK_SIZE;i++)
	{
		if (recvBufferMac[i] != calculatedMac[i])
		{
			isEqual = 0;
			break;
		}
		(*ptr)++;
	}

	if(isEqual == 0)
	{
		cout << "\n\nMAC values do not match. Message received is not authentic.\n";
		return 0;
	}

	string recvBufKeyStr = recvBufferKey;


	recvBufKeyStr.erase(std::remove(recvBufKeyStr.begin(), recvBufKeyStr.end(), '|'), recvBufKeyStr.end());


	BigInteger publicKeyB = stringToBigInteger(decPubKeyBStr);	
	BigInteger sharedKey = powerAndModulo (publicKeyB, beta,p);
	cout << "\nShared key = "<<sharedKey<<endl;

	print_binary(sharedKey);


	shutdown(udpSocket,2);
}



int main()
{
	string myCert;
	cout<<"Getting public key certified...\n";
	myCert = getPublicKeyCertified();
	cout<<"Got public key certified\n";
	sharePublicKey(myCert);
	cout <<" Shared public key\n";
	
}	
	
