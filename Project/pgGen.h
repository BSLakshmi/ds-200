#include <bits/stdc++.h>
#include <string>
#include <stdlib.h>
#include <iostream>
#include "BigIntegerLibrary.hh"
#include "BigIntegerUtils.hh"

using namespace std;

BigInteger powerAndModulo(BigInteger i1, BigInteger i2, BigInteger n1);
bool TestingByMiller(BigInteger val_m , BigInteger n1);
bool PrimeCheck(BigInteger bigintval, int k);
bool primary_check(BigInteger b1);
bool checkprime(BigInteger bigint, int k);
string rev(string &str1);
BigInteger findgenerator(BigInteger m1);
void generatePG(FILE *fd); 
