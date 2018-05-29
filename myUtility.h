#ifndef _MYUTILITY
#define _MYUTILITY

#include <fstream>
#include <iostream>
//#include <cstdio>

using namespace std;

const int SALT_SIZE = 4;
const int SIZE_16   = 16;
const int SIZE_32   = 32;
const int SIZE      = 128;//Buffer size


//This file contains simple utility functions for handling unsigned strings.

//Converts an unsigned string to a signed string.  Used for accessing 
//c-string concatentation function. 
void unsignedToSigned( unsigned char * data, char* sBuff, const int length ){
	for (int c = 0; c < length; c++){
		sBuff[c] = data[c];
	}
	return;
}

void signedToUnsigned( unsigned char* data, char* sBuff, const int length){
	for (int c = 0; c < length; c++){
		data[c] = sBuff[c];
	}
	return;
}
//Overloaded 'signedToUnsigned' function
void signedToUnsigned( unsigned char* data, const char* sBuff, const int length){
	for (int c = 0; c < length; c++){
		data[c] = sBuff[c];
	}
	return;
}

//Converts an unsigned raw data to hex c-string and writes to a file. 
void writeHexString( unsigned char* data, FILE * file, const int length){
	for (int c = 0; c < length; c++){
		fprintf(file, "%02x", data[c]);
	}
	return;
} 

//Puts raw data into hex c-string.
void signedHexString ( unsigned char* data, char* sBuff, const int length){
	for (int c = 0; c < length; c++){
		sprintf(sBuff + (c*2), "%02x", data[c]);
	}
	return;
}

//Displays an unsigned c-string in hex.  
void displayHexString( unsigned char* data, const int length ) {
	for (int c = 0; c < length; c++){
		printf("%02x", data[c]); 
	}	
	cout << endl;
	return;
}

//Converts unsigned c-string to signed c-string in hex(for salts)
/*
void unsignedToHexStr( unsigned char* data, char * cBuff, const int length){
	for (int c = 0; c < length; c++){
		sprintf(cBuff + (c*2), 
	}
}*/

#endif
