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

string name="NodeB", mobile="9874563210", email="nodeb@x.com",aadharB="7896541234578589";
string myPubKey;
BigInteger pub_a;		//public key of A
BigInteger a_n;			// n of A = (p-1)(q-1)
BigInteger d;			//private key of B
BigInteger n1;


/*Prints input num in binary*/
void print_binary(BigInteger num)
{
	static int ctr = 0;
	if (num == 0)	return;
	
	print_binary(num/2);

	if(ctr < 128)
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
	string stri="1427247692705959881";//for b
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
	//int k=1;
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

	myPubKey = bigIntegerToString(e);	//public key of B

	ostringstream ostreamstr;
	ostreamstr <<str<< name<<"|"<<mobile<<"|"<<email<<"|"<<aadharB<<"|"<<myPubKey<<"|"<<n;
	str = ostreamstr.str ();
	char sendBuffer[1000000],recvBuffer[1000000];
	strcpy(sendBuffer,str.c_str());
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

	//open a new client socket for communication with C

	int clientSocket, portNum, nBytes;
	char sendBufferKey[20000],recvBufferKey[20000];
	BYTE recvBufferMac[AES_BLOCK_SIZE+1];
	BYTE sendBufferMac[AES_BLOCK_SIZE+1];
	struct sockaddr_in serverAddr;                
	socklen_t addr_size;

	/*Create UDP socket*/
	clientSocket = socket(PF_INET, SOCK_DGRAM, 0);

	/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(8000);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

	/*Initialize size variable to be used later on*/
	addr_size = sizeof serverAddr;

	char aadharB_buf[20],puKeyB_buf[25], certB_buf[10000];	//sending buffers
	char aadharC_buf[20],puKeyC_buf[25], certC_buf[10000];	//receiving buffers

	//sending ID_B
	strcpy(aadharB_buf,aadharB.c_str());
	sendto(clientSocket,aadharB_buf,20,0,(struct sockaddr *)&serverAddr,addr_size);


	//sending public key of B 
	strcpy(puKeyB_buf,myPubKey.c_str());
	sendto(clientSocket,puKeyB_buf,25,0,(struct sockaddr *)&serverAddr,addr_size);	

	//sending certificateB
	strcpy(certB_buf,myCert.c_str());
	sendto(clientSocket,certB_buf,10000,0,(struct sockaddr *)&serverAddr,addr_size);

	//receiving ID_C
	nBytes = recvfrom(clientSocket,aadharC_buf,1024,0,NULL, NULL);	
	aadharC_buf[nBytes] = '\0';
	string aadharCStr = aadharC_buf;

	//receiving public key of C 
	nBytes = recvfrom(clientSocket,puKeyC_buf,1024,0,NULL, NULL);		
	puKeyC_buf[nBytes] = '\0';
	string puKeyCStr = puKeyC_buf;

	//receiving certificateC
	nBytes = recvfrom(clientSocket,certC_buf,10000,0,NULL, NULL);	
	certC_buf[nBytes] = '\0';

	string certCStr = certC_buf;

	
	string decryptedCertCStr = getDecryptedString(certCStr,pub_a,n1);


	char aadharC[20],nc[400],puKeyC[1024];
	string strA,     strN,   strK;
	int it,j=0;
		
	for(it=0;it<16;it++)
	{
		aadharC[it]=decryptedCertCStr[it];	
	}
	aadharC[16]='\0';	
	strA = aadharC;

	for(it=16,j=0;decryptedCertCStr[it]!='\0';it++,j++)
	{
		puKeyC[j]=decryptedCertCStr[it];	
	}
	puKeyC[j]='\0';	
	strK = puKeyC;

	if ((strA.compare(aadharCStr) != 0) && (strK.compare(puKeyCStr) != 0))
	{
		cout <<"\nCertificate and details do not match"<<endl;
		return -1;	
	}


	string str;


	//Exchange first random num
	BigInteger random1;
	char send_encryptedRand1Buf[1024],recv_rand1Buf[1024]; 

	srand(time(NULL));	      	
	random1 = (BigInteger) rand() % 10000000;	//generate random num 1

	string encryptedRand1Str = getEncryptedString(bigIntegerToString(random1),stringToBigInteger(puKeyC_buf),n1);	//encrypting random1 using the public key of C
	strcpy(send_encryptedRand1Buf,encryptedRand1Str.c_str());
	sendto(clientSocket, send_encryptedRand1Buf,10000,0,(struct sockaddr *)&serverAddr,addr_size);		//send the rand1 to C


	nBytes = recvfrom(clientSocket,recv_rand1Buf,10000,0,NULL, NULL);			//receive rand1 encryted with public key of B
	recv_rand1Buf[nBytes] = '\0';

	str = recv_rand1Buf; 
	string decryptedRecvRand1 = getDecryptedString(str,d,n1);			//decrypt the received encrypted rand1 using private key of B

	string random1Str = bigIntegerToString (random1);	//string form of generated rand1		

	if ( random1Str.compare(decryptedRecvRand1) != 0)		//compare generated rand1 and decrypted received rand1
	{
		cout << "Random1 does not match\n";
		return -1;
	}

	//Exchange 2nd random num
	string random2Str;
	char send_encryptedRand2Buf[1024],recv_encryptedRand2Buf[1024]; 

	nBytes = recvfrom(clientSocket,recv_encryptedRand2Buf,10000,0,NULL, NULL);	//receive from C rand2 encrypted with public key of B
	recv_encryptedRand2Buf[nBytes] ='\0';

	str = recv_encryptedRand2Buf;

	random2Str = getDecryptedString(str,d,n1);	//decrypt encrypted rand2 with private key of B

	str = puKeyC_buf;
	string encryptedRand2 = getEncryptedString(random2Str,stringToBigInteger(str),n1);	//encrypt rand2 with public key of C
	strcpy(send_encryptedRand2Buf, encryptedRand2.c_str());
	sendto(clientSocket, send_encryptedRand2Buf,10000,0,(struct sockaddr *)&serverAddr,addr_size);	//send rand2 encrypted with public key of C to C

/***************************End of public key sharing*********************/




/****************Start of Diffie Hellman key sharing**********************/

	fd = fopen("shared.txt","r");

	fgets(buffP,128,fd);
	fgets(buffG,128,fd);	

	p = stringToBigInteger (buffP);

	g = stringToBigInteger (buffG);

	srand(time(NULL));
	BigInteger alpha=(BigInteger)rand() % MAX_RANDOM_INT +2;
	BigInteger publicKeyB=powerAndModulo(g,alpha,p);

	string publicKeyBString = bigIntegerToString(publicKeyB);

	string encPubKeyBStr = getEncryptedString(publicKeyBString,stringToBigInteger(puKeyCStr),n1);

		
	strcpy(sendBufferKey,encPubKeyBStr.c_str());

	generateCMAC(publicKeyBString,sendBufferMac);

	char sendNonBC[10000],recvNonBC[10000],sendNonCB[10000],recvNonCB[10000];


/*1st part*/
	sendto(clientSocket,sendBufferKey,20000,0,(struct sockaddr *)&serverAddr,addr_size);		//DH-pubkey of B (encrypted in RSA pubKey of C) sent to C

	srand(time(NULL));
	BigInteger nonceBC=(BigInteger)rand() % MAX_RANDOM_INT +2;			//create nonceBC ( B to C)

	string encNonceBCStr = getEncryptedString(bigIntegerToString(nonceBC),stringToBigInteger(puKeyCStr),n1);	//encrypt nonceBC with pub key of C	
	strcpy(sendNonBC,encNonceBCStr.c_str());	

	sendto(clientSocket,sendNonBC,10000,0,(struct sockaddr *)&serverAddr,addr_size);	//sending nonceBC to C

/*part 2*/
	nBytes = recvfrom(clientSocket,recvBufferKey,20000,0,NULL, NULL);	//receive DH-pubkey of C encrypted in RSA public key of B
	recvBufferKey[nBytes] = '\0';

	nBytes = recvfrom(clientSocket,recvNonBC,10000,0,NULL, NULL);			//nonceBC encrypted in RSA pubKey of B received back from C
	recvNonBC[nBytes] = '\0';
	string recv_nonBCStr = recvNonBC;


	nBytes = recvfrom(clientSocket,recvNonCB,10000,0,NULL, NULL);			//receive nonceCB encrypted in RSA pubkey of B
	recvNonCB[nBytes] = '\0';

	string dec_recvNonBCStr = getDecryptedString(recv_nonBCStr,d,n1);		//decrypt received nonceBC
	
	if(dec_recvNonBCStr.compare(bigIntegerToString(nonceBC)) != 0)			//compare original nonce with the received decrypted nonce
	{
		cout<<"\nMismatch in nonce. Exiting session"<<endl;
		return -1;
	}

/*part 3*/
	string enc_nonCBStr = recvNonCB;	

	string dec_nonCBStr = getDecryptedString(enc_nonCBStr,d,n1);			//decrypt received nonceCB

	string reEnc_nonCBStr= getEncryptedString(dec_nonCBStr,stringToBigInteger(puKeyCStr),n1);
	strcpy(sendNonCB,reEnc_nonCBStr.c_str());


	sendto(clientSocket,sendNonCB,10000,0,(struct sockaddr *)&serverAddr,addr_size);


	sendto(clientSocket,sendBufferMac,AES_BLOCK_SIZE+1,0,(struct sockaddr *)&serverAddr,addr_size);

	nBytes = recvfrom(clientSocket,recvBufferMac,AES_BLOCK_SIZE+1,0,NULL, NULL);
	recvBufferMac[nBytes] = '\0';

/*-------------End of socket part---------------*/

	string temp;
	temp = recvBufferKey;
	string decPubKeyCStr = getDecryptedString(temp,d,n1);

	BYTE calculatedMac[AES_BLOCK_SIZE+1];
	generateCMAC(decPubKeyCStr.c_str(),calculatedMac);

	int isEqual =1;		//isEqual=1 means the received mac and calculate mac are equal

	BYTE *ptr = &calculatedMac[0];
	
	for (int i=0;i<AES_BLOCK_SIZE;i++)
	{
		if (recvBufferMac[i] != ptr[i])
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

	BigInteger publicKeyC = stringToBigInteger(decPubKeyCStr);	
	BigInteger sharedKey = powerAndModulo (publicKeyC, alpha,p);
	cout << "\nShared key = "<<sharedKey<<endl;

	print_binary(sharedKey);

	shutdown(clientSocket,2);

}



int main()
{
	string myCert;
	cout <<"Getting public key certified\n";
	myCert = getPublicKeyCertified();

	cout <<"\nGot public key certified\n\n";

	cout<<"Sharing key with C\n";
	sharePublicKey(myCert);

	cout <<"\nShared key\n";

	return 0;
}
