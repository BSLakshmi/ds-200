#include <bits/stdc++.h>
#include <string>
#include <stdlib.h>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "BigIntegerLibrary.hh"
#include "BigIntegerUtils.hh"

using namespace std;

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

BigInteger encryptrsa(BigInteger plaintext, BigInteger e, BigInteger n)
{
	return powerAndModulo(plaintext,e,n);
}

BigInteger decryptrsa(BigInteger ciphertext, BigInteger d, BigInteger n)
{
	return powerAndModulo(ciphertext,d,n);
}

string getEncryptedString(string plaintextstr, BigInteger e, BigInteger n1)
{
	string strin;
	BigInteger plaintext=stringToBigInteger(plaintextstr);

	while(plaintext>0)
	{
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

string getDecryptedString(string ciphertext, BigInteger d, BigInteger n1)
{
	string nstr;
	int spacepos=ciphertext.find('|');
	BigInteger publicKey_recv=0,n_rec;
	string stt;
	
	while(spacepos>0 )
	{
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

int main()
{
	FILE *fd;
	char buffP[128],buffG[128];
	BigInteger enc_a;
	string pubstr = "5969449495136382746787";
	enc_a=stringToBigInteger(pubstr);
	BigInteger a_n;
	string astr ="179769313486231590772930519078902473361797697894230657273430081157732675805500963132708477322407536021120113879871393357658789768814416622492847430639498687481895548262751904890098932711351636317636408216752995333403048954045557619535414144255069004242878649048783940685111323051791202420977222774603371004423";
	a_n=stringToBigInteger(astr);

	BigInteger dec_a;
	string decstr = "83276924117726459141846778284509212530259751638291021066028097358207363766668930206858431253690634396420004421896983881609086565634136753468614437331932398463272717414195662911441212925601893249541220504397499747365273506540474781745509500489498838708768247531791869690936877717976216731706075485227487057323"
		;	//pr A
	dec_a=stringToBigInteger(decstr);

	BigInteger ch=20;
	//socket related variables

	int udpSocket, nBytes;
	char sendBuffer[1000000],recvBuffer[1000000];
	struct sockaddr_in serverAddr, clientAddr;
	struct sockaddr_storage serverStorage;
	socklen_t addr_size, client_addr_size;


	//Socket part starts here

	/*Create UDP socket*/
	udpSocket = socket(PF_INET, SOCK_DGRAM, 0);

	/*Configure settings in address struct*/
	serverAddr.sin_family = AF_INET;
	serverAddr.sin_port = htons(7891);
	serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);

	/*Bind socket with address struct*/
	bind(udpSocket, (struct sockaddr *) &serverAddr, sizeof(serverAddr));

	/*Initialize size variable to be used later on*/
	addr_size = sizeof serverStorage;
	/*first received message*/
	nBytes = recvfrom(udpSocket,recvBuffer,10000,0,(struct sockaddr *)&serverStorage, &addr_size);
	recvBuffer[nBytes]='\0';
	string str=recvBuffer;
	string nstr;
	int spacepos=str.find('|');
	int k=1;
	BigInteger publicKey_recv=0,n_rec,aadhar=0;
	while(spacepos>0 )
	{
		nstr=str.substr(0,spacepos);
		if(k==5)
			publicKey_recv=stringToBigInteger(nstr);
		if(k==4)
			aadhar=stringToBigInteger(nstr);
		str=str.substr(spacepos+1,str.length());
		spacepos=str.find('|');
		k++;
	}
	n_rec=stringToBigInteger(str);
	cout<<"\nPublic key received. Verifying..."<<"\n";
	srand(time(NULL));
	BigInteger nonce = (BigInteger)rand() % MAX_RANDOM_INT +2;
	string enc_msgstr=getEncryptedString(bigIntegerToString(nonce),publicKey_recv,n_rec);
	strcpy(sendBuffer,enc_msgstr.c_str());
	sendto(udpSocket,sendBuffer,10000,0,(struct sockaddr *)&serverStorage,addr_size);


	/*receive nonce back*/
	nBytes = recvfrom(udpSocket,recvBuffer,10000,0,(struct sockaddr *)&serverStorage, &addr_size);
	recvBuffer[nBytes]='\0';
	str=recvBuffer;
	string plaintext=getDecryptedString(str,dec_a,a_n);
	if(nonce==stringToBigInteger(plaintext)){
		cout <<"Verified\n";
	}

	/*part 4:: sending certificate*/
	string cert="";
	ostringstream ostreamstr;
	ostreamstr <<cert<< aadhar<<publicKey_recv;
	cert = ostreamstr.str ();
	enc_msgstr=getEncryptedString(cert,dec_a,a_n);

	strcpy(sendBuffer,enc_msgstr.c_str());
	sendto(udpSocket,sendBuffer,10000,0,(struct sockaddr *)&serverStorage,addr_size);
	cout <<"Certificate sent\t"<<endl;

	return 0;
}
