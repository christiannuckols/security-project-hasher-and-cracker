
//This is the file that queries the user to create an account or authenticate
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <string.h>
#include <cmath>
#include "myUtility.h"

using namespace std;

int main() {

	unsigned int c;		 //Counter for loops
	char inputChar;          //For menu selection
	char inputBuff[SIZE];    //Buffer for reading password inputs
	char readBuffer[SIZE];   //Buffer for reading c-strings from files.
	char usernameInput[SIZE];//so use these for inputs
	char sBuffer[SIZE];      //(signed) c-string buffer for retrieved salt and hashed password guesses
	unsigned char hashInput[SIZE];//The data placed into the hashing functions
	unsigned char shaOutput[SIZE];//The result of any SHA256 hash (whether testing or authenticating).
	unsigned char md5Output[SIZE];//The result of any md5 hash
	unsigned char saltedOutput[SIZE];//The result of any 
	unsigned char saltBuff[SIZE];//Buffer for receiving salt from 'rand.h'
	
	fstream currentFile;
	FILE * file;

	//OPEN MENU.  Present three options: create account, authenticate, or quit. 
	while (true) {
	
	cout << "\nPress 1 to create an account\nPress 2 to authenicate\nPress 3 to exit\n";
	cin >> inputChar;
	while(inputChar != '1' && inputChar != '2' && inputChar != '3'){
		cout << "Invalid selection. Press 1, 2, or 3: ";
		cin >> inputChar;
	}
	cin.ignore();
	//OPTION 1: CREATE ACCOUNT
	if (inputChar == '1') {
		cout << "Please enter a username (alphanumerics only):";
		cin.getline(usernameInput, SIZE);
		cout << "Please enter a password (digits only): ";
		cin.getline(inputBuff, SIZE);
		signedToUnsigned(hashInput, inputBuff, strlen(inputBuff));//Convert password to unsigned

		//1.A  MD5 INSERTION
		//printf("Hashing %d characters.\n", strlen(inputBuff));
		MD5(hashInput, strlen(inputBuff), md5Output);
		file = fopen("passwdmd5", "a");
		fprintf(file, "%s\t", usernameInput);
		writeHexString(md5Output, file, SIZE_16);
		fprintf(file, "\n");
		fclose (file);
		//1.B  SHA256 INSERTION
		SHA256(hashInput, strlen(inputBuff), shaOutput);
		file = fopen("passwdSHA256", "a");//File operations
		fprintf(file, "%s\t", usernameInput);
		writeHexString(shaOutput, file, SIZE_32);
		fprintf(file, "\n");
		fclose (file);//Close file
		//1.C  SHA256+SALT INSERTION
		RAND_bytes(saltBuff, SALT_SIZE);//Generate cryptographically random salt
		signedHexString( saltBuff, sBuffer, SALT_SIZE);//Move the salt to a c-string.
		strcat(inputBuff, sBuffer);//Add salt to password buffer
		signedToUnsigned(hashInput, inputBuff, strlen(inputBuff));
		SHA256(hashInput, strlen(inputBuff), saltedOutput);
		file = fopen("passwdSHA256salt", "a");//SHA256+salt File operations begin 
		fprintf(file, "%s\t", usernameInput);
		writeHexString( saltBuff, file, SALT_SIZE);//Write the salt to the file
		fprintf(file, "\t");
		writeHexString( saltedOutput, file, SIZE_32);
		fprintf(file, "\n");
		fclose (file);
	 	cout << endl;	
	}

	//OPTION 2: AUTHENTICATE PASSWORD
	else if (inputChar == '2') { 
		bool foundMatch = false;
		cout << "Enter Username: ";
		cin.getline(usernameInput, SIZE);
		//Verify that the username exists in the database.
		//Check "passwdmd5" and get MD5 string.
		currentFile.open("passwdmd5", fstream::in);
		while (!foundMatch) {
			currentFile.getline(readBuffer, SIZE, '\t');
			if ( strncmp(readBuffer, usernameInput, SIZE) == 0 ){ foundMatch = true; }
			if (currentFile	&& !foundMatch){ currentFile.getline(readBuffer, SIZE);}
			if (!currentFile && !foundMatch) {//If you've reached the end of the file without finding a match
				cout << "No username matches your entry. Enter username: ";
				cin.getline(usernameInput, SIZE);
				currentFile.clear();
				currentFile.seekg(0, ios::beg);
			}
		}
		currentFile.getline(readBuffer, SIZE);//Get the hashed password. The stream will be in 
		currentFile.close();		      //correct position after a username is matched.
						
		cout << "Enter password: ";
		cin.getline(inputBuff, SIZE);
		signedToUnsigned(hashInput, inputBuff, strlen(inputBuff)); 

		//2.A  MD5 AUTHENTICATION
		MD5(hashInput, strlen(inputBuff), md5Output);
		printf("\nMD5 hash produced by the password you entered:\n\t");
		displayHexString( md5Output, SIZE_16);//Displays MD5 hash of password attempt
		signedHexString( md5Output, sBuffer, SIZE_16);//Move the hashed attempt password
		//to a c-string
		printf("MD5 hash retrieved from file:\n\t");
		cout << readBuffer << endl;//Displays the MD5 hash in the database
		bool validPassword;
		if ( strncmp(sBuffer, readBuffer, SIZE_32) == 0 ) { validPassword = true; }
		else { validPassword = false; }
		if (validPassword) { cout << "\t*PASSED MD5 hash\n"; }
		else               { cout << "\t*FAILED MD5 hash\n"; }
		
		//2.B  SHA256 AUTHENTICATION
		currentFile.open("passwdSHA256", fstream::in);
		foundMatch = false;
		while (!foundMatch){        //Locate the SHA256 hash in the file by matching the username
			currentFile.getline(readBuffer, SIZE, '\t');
			if (strncmp(readBuffer, usernameInput, SIZE) == 0){
				foundMatch = true;
			}
			if (!foundMatch){
				currentFile.getline(readBuffer, SIZE);//Keep reading. 
			}
		}
		currentFile.getline(readBuffer, SIZE);//Now in position, retrieve the rest of the line		
		currentFile.close();

		SHA256(hashInput, strlen(inputBuff), shaOutput);
		printf("\nSHA256 hash produced by the password you entered:\n\t");
		displayHexString(shaOutput, SIZE_32);
		signedHexString(shaOutput, sBuffer, SIZE_32);//Convert to c-string
		printf("SHA256 hash retrieved from file:\n\t");
		cout << readBuffer << endl;
		if (strncmp(sBuffer, readBuffer,(SIZE_32 * 2) ) == 0 ) { validPassword = true; }
		else {validPassword = false; } 
		if (validPassword) { cout << "\t*PASSED SHA256 hash\n"; }
		else 		   { cout << "\t*FAILED SHA256 hash\n"; }

		//2.C  SHA256+SALT AUTHENTICATION
		currentFile.open("passwdSHA256salt", fstream::in);
		foundMatch = false;
		while (!foundMatch){
			currentFile.getline(readBuffer, SIZE, '\t');
			if ( strncmp(readBuffer, usernameInput, SIZE) == 0){
				foundMatch = true;;
				currentFile.getline(sBuffer, 9, '\t');//get the salt
			}
			if (!foundMatch){
				currentFile.getline(readBuffer, SIZE);
			}

		}
		currentFile.getline(readBuffer, SIZE);//get the hashed password
		currentFile.close();
		//Commented-out output displays the salt. For debugging.
		//printf("\n\nGot the salt:\t");
		//cout << sBuffer << endl;
		strcat(inputBuff, sBuffer);//Add the salt to the password
		signedToUnsigned(hashInput, inputBuff, strlen(inputBuff) );
		//printf("Hashing this: %s", inputBuff);
		//Now, we need to update the unsigned c-string hashInput (to account for the salt).
		unsignedToSigned( hashInput, inputBuff, strlen(inputBuff) );
		SHA256(hashInput, strlen(inputBuff), saltedOutput);
		printf("\nSHA256 SALTED hash produced by the password you entered.\n\t");
		signedHexString( saltedOutput, sBuffer, SIZE_32);
		cout << sBuffer;
		printf("\nSHA256 SALTED hash retrieved from file:\n\t");
		cout << readBuffer << endl;
		if (strncmp(sBuffer, readBuffer, (SIZE_32*2) ) == 0 ){ validPassword = true; }
		else { validPassword = false; }
		if ( validPassword ) { cout << "\t*PASSED salted SHA256 hash.\n"; }
		else                 { cout << "\t*FAILED salted SHA256 hash.\n"; }
	}
	else//OPTION 3: EXIT
		break;
	}

	return 0;
}

