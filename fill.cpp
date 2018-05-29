//Christian Nuckols
//CS-3780

//Program Contents:
//0. Initialization and command line validation
//1. Generate usernames and passwords
//2. Store MD5 values
//3. Store SHA256 values
//4. Store SHA256+salt values

#include <iostream>
#include <stdio.h>
#include <stdlib.h>//For string to unsigned long long
#include <math.h>
#include <string.h>
#include <string>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <vector>
#include "myUtility.h"//Contains functions for readiblity

//#include <chrono>//For generating complex seeds for long long unsigned ints

using namespace std;

void displayVector( vector<string> );//For testing
bool isRepeat( vector<string>, int );//checks for repeat passwords
string randInt(int);		     //Generates random integer with digits parameter 
				     //(If password can be size 7, 0000000 - 9999999 is a valid password).

int main(int argc, char** argv){

	//0. INITIALIZATION AND COMMAND LINE VALIDATION
	if (argc != 3) { 
		cout << "Error. Needs three arguments fill [password Length] [quantity]" << endl;
		exit(0);
	}

	unsigned int c;			       	  
	const unsigned int passLength = atoi(argv[1]); 
	const unsigned int userQuantity = atoi(argv[2]);	
	srand( (unsigned)time(NULL) );
	unsigned char inputBuffer[SIZE]; //unsigned char buffer to send to hashing functions 
	unsigned char outputBuffer[SIZE];//Unsigned char buffer to receive from hash and salt functions
	FILE * file; //For opening files to store usernames and hashed passwords

	if (passLength < 3 || passLength > 9){//argv[1] is password length
		printf("Error.  Password argument must be between 3 and 9.\n");
		//At ten digits or more, the crack runs the risk of timing out 
		//on the server.  
		return 0;
	}
	else if (userQuantity > 102 || userQuantity < 1){ 
		printf("Error. Number of usernames generated should be between 1 and 101.\n");
		return 0;
	}

	
	//Allocate vector array of strings for usernames.
	//The strings will be of length 4 ("user" has 4 letters) + the number of digits (if ten users are
	//created will result in user0 - user9; if 101 users are created, they will be user000 - user100
	vector<string> usernames;
	vector<string> passwords;
	//NOTE** After the unsalted hashes, the salts will be appended to the passwords in the vectors
	char cBuffer[SIZE];
	string buffer[SIZE];
	
	//1. USERNAME AND PASSWORD GENERATION 
	for (c = 0; c < userQuantity; c++) {
		if (userQuantity < 11){                //If 10 or fewer, create userX
			sprintf(cBuffer, "user%1d", c);//Make the username with formatted c string
		}
		else if (userQuantity < 101){          //If 11-100, create userXX
			sprintf(cBuffer, "user%02d", c);
		}
		else {				       //If 101, create userXXX
			sprintf(cBuffer, "user%03d", c);
		}
		buffer[c].assign(cBuffer);
		usernames.push_back(buffer[c]);
		passwords.push_back(randInt(passLength)) ;
		while(isRepeat(passwords, c)){
			passwords[c] = randInt(passLength);
		}
		
	}
	if(!userQuantity){  cout << "Error! no userQuantity!\nExiting\n" << endl;	}
	
	//2. STORE MD5 VALUES
	//First, open the file.  If doesn't exist it will be generated.
	file = fopen("passwdmd5", "a");
	for (c = 0; c < userQuantity; c++){
		fprintf(file, "%s\t", usernames[c].c_str() );//Put username in file
		//Convert the current password to an unsigned c-string for hashing
		signedToUnsigned( inputBuffer, passwords[c].c_str(), passwords[c].length() );
		MD5(inputBuffer, passwords[c].length() , outputBuffer);//MD5 hash
		writeHexString(outputBuffer, file, SIZE_16);//Write to file
		fprintf(file, "\n");//Delimit with newline
	}
	fclose(file);

	//3. STORE SHA256 VALUES
	file = fopen("passwdSHA256", "a");
	for (c = 0; c < userQuantity; c++){
		fprintf(file, "%s\t", usernames[c].c_str() );
		signedToUnsigned(inputBuffer, passwords[c].c_str(), passwords[c].length() );
		SHA256(inputBuffer, passwords[c].length(), outputBuffer);//SHA256 hash
		writeHexString(outputBuffer, file, SIZE_32);
		fprintf(file, "\n");
	}
	fclose(file);
	
	//
	//
	//displayVector(passwords);
	
	//4.  STORE SHA256 + SALT VALUES
	const int digitsPlusSalt = passLength + 8;
	file = fopen("passwdSHA256salt", "a");
	for (c = 0; c < userQuantity; c++){
		fprintf(file, "%s\t", usernames[c].c_str() );
		RAND_bytes(outputBuffer, 4);	    	     //Generate 4-byte salt 
		writeHexString(outputBuffer, file, SALT_SIZE); //Place salt in the file
		fprintf(file, "\t");			     //Add tab after salt to file	
		signedHexString(outputBuffer, cBuffer, SALT_SIZE);//Store the salt in the c-string buffer
		passwords[c].append(cBuffer);			//Append the salt to the password
		signedToUnsigned(inputBuffer, passwords[c].c_str() , passwords[c].length() );
		SHA256(inputBuffer, digitsPlusSalt, outputBuffer);//SHA256 
		writeHexString( outputBuffer, file, SIZE_32);	   
		fprintf(file, "\n");
		
	}
	fclose(file);
	return 0;

}

//Returns a pseudorandom password string consisting of digits
string randInt( int digits){
	char cBuffer[digits];
	for( int c = 0; c < digits; c++){
		cBuffer[c] = '9';
	}
	for (int c = 0; c < digits; c++){
		sprintf(cBuffer + c, "%1d", rand()%static_cast<int>(9) );
	}
	return cBuffer;
}

//Returns T/F if the digit-string is a match with one already generated
bool isRepeat( vector<string> list, int position){
	for (int c = 0; c < list.size(); c++) {
		if (position != c){
			if( strcmp( list[position].c_str(), list[c].c_str() ) == 0) {
				return false;
			}
		}
	}
	return false;
}

//Simple function for displaying a complete vector. For testing.
//The count starts at '0', so the 
void displayVector ( vector<string> list ){
	for (int c = 0; c < list.size(); c++) {
		printf("%d :", c);
		cout <<  list[c] << endl;
	}
	return;
}
