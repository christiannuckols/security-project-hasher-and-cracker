#include <iostream>
#include <cstdio>
#include <cstdlib>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <string>
#include <vector>
#include <ctime>
#include <cmath>
#include <string.h> 
#include "myUtility.h"

using namespace std;

void displayVector( vector<string> );//Display function for testing
void showTime(clock_t, bool, FILE*);              //Displays running time

void extractData(FILE*, vector<string>&, vector<string>&);
void extractData(FILE*, vector<string>&, vector<string>&, vector<string>&);
void optimize(unsigned int, unsigned int, unsigned int);
void buildNextPassword( unsigned int, string&);//Changes the password guess to the next password. 
void addToRainbow(vector<string>&, unsigned int, string);
void match(vector<string>, vector<string>&, unsigned int, unsigned int, unsigned int&);
void matchSalted(vector<string>, vector<string>&, vector<string>&, unsigned int, unsigned int, unsigned int&);


//MATCHING UNSALTED HASHES (modes 0 and 1)
//1. Determine the ratio of possible passwords to accounts.
//	 If there are 100,000 possible passwords and 100 accounts, the ratio is 1000.
//2. Construct a rainbow table that matches the size of the ratio.  This will be indexed with global variable 'position.'  
//3. Compare every hashed password in the file to the rainbow table.
//4. If no matches are found, delete the current portion of the rainbow table.
//5. Construct the next portion of the rainbow table, starting at the next possible password.
//6. Repeat steps 3-5 till every value has been tested.

//MATCHING SALTED PASSWORDS 
//1. Determine the number of possible values. If there are fewer than 15 accounts,
//   all the hashes will be constructed for each user.  Otherwise, take the floor of 1/3 of all possible passwords. 
//2. Hash up to 1/3 of the possible passwords with the 1st salt and add to the list of guesses (if account quantity 
//	is greater than 15).
//3. If no passwords are found, move one to the next user.





static unsigned long long ratio;//This ratio of possible accounts to total accounts possible.
//It is used to optimize the crack so that unneccesarily large rainbowtables are not generated. 
//This is not used for salted cracking. 

static unsigned long long position;//This is the current position of the rainbow table. 
//For instance, if the first 10 values are created in the rainbow table at initially and 
//no matches are found then the position will be ten.  If no matches are found in values
//10-20, then the position will be 20, and so on. 

static unsigned long long saltedAttempts;//Number of attempts each account will be allocated.
//This is one third of the total possible passwords unless there are fewer than 15 account,
//in which case each account is matched with *every* possible password and its salt.   



int main(int argc, char** argv){

	//Arg 1 is 0 1 2 - crack mode. 0 is MD5, 1 is SHA256, 2 is SHA256 + salt
	//Arg 2 is the password length to attempt to crack
	//Argv 3 is the file name
	
	if (argc != 4){
		printf("Error. Needs four arguments. [crack 0 5 passwdmd5]\n");
		return 0;
	}

	unsigned int c;			        		//Counter variable
	unsigned int crackMode = atoi(argv[1]); //Sets the crack mode 
	unsigned int passLength = atoi(argv[2]);//Number of digits to test in password
	FILE * file;
	file = fopen (argv[3], "r");		//Open the file for read-only mode
	
	//Validate the command line arguments.
	if (crackMode != 0 && crackMode != 1 && crackMode != 2){
		cout << "Error. Please choose 0, 1, or 2 to set crack mode.\n";
		cout << "0. MD5\n1.SHA256\n2.SHA256 + salt\n";
		return 0;
	}
	else if (passLength < 3 || passLength > 9){
		cout << "Error. Password length should be between 3 and 9.\n";
		return 0;
	}
	else if (crackMode == 2 && passLength == 9){
		cout << "In salted SHA256 hash mode, only up to 8 digits can be cracked.\n";
		return 0;
	}
	else if (file == NULL){
		perror("Error: ");
		return 0;
	}

	clock_t start;
	start = clock();//Start the clock to determine the time taken to crack a password. 
	
	//EXTRACT DATA
	vector<string> usernames;//Stores the usernames
	vector<string> hashes;   //Stores the hashed passwords retrieved from the file
	vector<string> salts;	 //Stores the salts
	
	//The following extracts data from the file based on the mode selected by the 
	//user.   Validation confirming that the file is not empty and is the 
	//correct file for the mode is in the extractData functions.
	if(crackMode == 0 || crackMode == 1){
		extractData(file, usernames, hashes );
	}
	else if (crackMode == 2) { 
		extractData(file, usernames, hashes, salts);
	}
	
	//Data from files are placed in the three preceding vectors. 
	//The are stored in the same order as the database.
	unsigned int userIndex = 0;//This is the index of the account being cracked.
	vector<string> rainbow;    //Stores some number of hashes to be attempted
	
	int quantityToCrack = 1;
	bool recordData = false;
	int crackCount = 0;
	unsigned int accountQuantity = usernames.size();
	
	//'optimize' determines how many hashes to attempt per file. 
	optimize( crackMode, passLength, accountQuantity);
	position = 0;//This is the position index of guesses made.  For instance, if 
	//3000 hashes have been attempted, position will be 3000. This is used to 
	//determine the next value to add to the guess-hashes (rainbow).  
	
	//********
	//THE FOLLOWING TWO COMMENTED-OUT LINES ARE FOR WRITING RESULTS TO THE README FILE
	//USED TO GENERATE MULTIPLE MATCHES (RATHER THAN ONE) AND WRITE INFORMATION
	//ABOUT THE TIME TO THE README FILE 
        //quantityToCrack = 1;
	//recordData = true;
	//********
	
	if (recordData){
		fclose(file);
		file = fopen("README", "a+");
		fprintf(file, "\n");
	}

	//'quantityToCrack' is set to 1 by default. 
	while(quantityToCrack){
	    //The following function matches the guesses to the file
		if (crackMode == 0 || crackMode == 1){
			match( hashes, rainbow, crackMode, passLength, userIndex);
		}
		else if (crackMode == 2){
			matchSalted(hashes, rainbow, salts, crackMode, passLength, userIndex);
			salts.erase(salts.begin() + userIndex);
			//remove the salt that corresponds with the the account that matched.
		}
		 	
		cout << "  found for Username: " << usernames[userIndex];
		cout << endl;
		//Remove the cracked account by erasing it from 
		//the username, hashes, and possible password list. 
		usernames.erase( usernames.begin() + userIndex);
		hashes.erase(hashes.begin() + userIndex);

		if(recordData){//For generating information for README
			crackCount++;
			//If cracking more than one password
			//cout << "Next cracking account # " << userIndex << endl;
			fprintf(file, "#%d\t%d-digit\t\t%s\t\t", crackCount, passLength, argv[3]);
			//Prints "Crack #1	5-digit		passwdmd5	X.XX seconds"
		}
		showTime(start, recordData, file);
		quantityToCrack--;
		if (usernames.size() == 0 && quantityToCrack != 0){
			cout << "Error. No more accounts to crack.  Exiting\n\n";
			exit(0);
		}		
	}

	fclose(file);
	
	return 0;
}
//Displays the contents of a vector. For debugging. 
void displayVector(vector<string> list){
	for(int c = 0; c < list.size(); c++){
		printf("%d :", c + 1);
		cout << list[c] << endl;
	}
	cout << "end of list\n";
	return;
}

//'showTime' prints the time taken to find a match, and if the 'record' parameter set to true, records the 
//results to a file. 
void showTime(clock_t start, bool record, FILE* README){
	clock_t end;
	end = clock();//The clocks macro on delmar appears to use hundredths of seconds, so only display only 2 point past the decimal.  
	int errorCheck;
	errorCheck = printf("Cracked in %4.2f seconds.\n", (float)(end - start)/CLOCKS_PER_SEC );
	if (errorCheck == -1){
		cout << "printf error in showTime function. Exiting.\n\n";
		exit(0);
	}
	//The following is for storing results in the README.  The value passed to record is false unless a
	//commented out portion is reinstated. 
	if (record){
		if (README == NULL){
			perror("Error: ");
			exit(0);
		}
		fprintf(README, "Time: %4.2f seconds\n", (long)(end - start) );
	}
	return;  
}

//Extraction functions that fill the vectors.  
void extractData(FILE* file, vector<string>& usernames, vector<string>& hashes) {
	char buffer[SIZE];
	unsigned int argIndex = 0;
	//Iterate through the file to the end.  
	while (fscanf(file, "%s", buffer) != EOF){
		argIndex++;
		if (argIndex % 2 == 0){//Every 2nd string is a hashed password	
				hashes.push_back(buffer);
		}
		else {	usernames.push_back(buffer); }
	}
	//The following if statements confirm that the hashes are of the 
	//same length.  This is prevent errors if the user accidently 
	//selects the passwdSHA256salt file but chooses mode 0 or 1.
	if(usernames.size() != hashes.size() ){//One account total and wrong file
		cout << "Error extracting data from file. Did you select the ";
		cout << "correct mode and file? Exiting.\n\n";
		exit(0);
	}
	else if( usernames.size() == 0){//File exists but is empty.
		cout << "Error. Empty file. Exiting.\n\n";
		exit(0);
	}
	else if (hashes[1].length() != 0){//If there is more than one account
		if (hashes[1].length() != hashes[0].length()){
			cout << "Error extracting data from file. Did you select ";
			cout << "the correct mode and file? Exiting.\n\n";
			exit(0);
		}
	}	
		
	return;
}

//Overloaded extraction function to accept salts.
void extractData(FILE* file, vector<string>& usernames, vector<string>& hashes, vector<string>& salts){
	char buffer[SIZE];
	unsigned int argIndex = 0;
	while (fscanf(file, "%s", buffer) != EOF){
		argIndex++;
		if (argIndex % 3 == 0){//Every 3rd string is a hashed password	
				hashes.push_back(buffer);
		}
		else if ( (argIndex + 1) % 3 == 0) { salts.push_back(buffer); }
		else {	usernames.push_back(buffer); }
	}
	//File extraction validation.
	if (usernames.size() == 0 ){//File exists but is empty.
		cout << "Error. Empty file. Exiting.\n\n";
		exit(0);
	}
	else if (usernames.size() != hashes.size() || usernames.size() != salts.size() ){
		//The wrong file was selected for salted crack mode. 
		cout << "Error extracting data from file. Did you select the ";
		cout << "correct mode and file? Exiting.\n\n";
		exit(0);
	}
	return;
} 

//'optimize' determines how large the vectors that store guess hashes should be.  
void optimize(unsigned int mode, unsigned int digits, unsigned int accountQuantity){
		
	//	cout << "Optimizing for " << accountQuantity << " accounts." << endl;
		unsigned long long possiblePasswords = pow(10, digits);
	//	cout << "Cracking " << digits << "-digit passwords.  There are " << possiblePasswords << " possible passwords.\n";
			
		if (mode == 0 || mode == 1){
			ratio = possiblePasswords/accountQuantity;
			//cout << "The ratio of possible passwords to accounts is " << ratio << endl;
			//cout << "The odds of NOT finding a match in first set is: ";
			double odds;
			//'odds' represents the chances of an account match NOT being found if the number of guesses per set of 
			//hashes generated is the same as the ratio of users to passwords.  For instance, if there are 10 accounts
			//and three digits, there are 1000 possible passwords; 100 possible for every account. The odds of 
			//any account being a match in 100 hashes is 1/10, or 90%. So 90%^accountQuantity represents the odds of 
			//a hash table equal to the size of the ratio not finding a match.  
			odds = (double)pow( ((double)(possiblePasswords - ratio)/(double) possiblePasswords), (accountQuantity) ) ;
	//		cout << odds << endl;
		}
		else if (mode == 2){
			saltedAttempts = floor( possiblePasswords/3);
			//cout << "One third of the possible passwords is " << saltedAttempts << endl;
			if (accountQuantity < 15){
				//cout << "However, there are too few accounts for efficient cracking. ";
				//cout << "Brute-forcing the first account. " << endl;
				saltedAttempts = possiblePasswords; 
			}
			
		}
		return;
		
}

//Format password takes a string, adds leading zeros, and adds one.  This is used to format the 
//*next* password in the match functions and to format the *cracked* password for output. 
void formatPassword( unsigned int digits, string& guess){

	int leadZeros = 0; //Will be used to determine if lead zeros are necessary
	char buffer [SIZE];//Buffer to use format string function
	
	string finalGuess; //Find the last password to build. If four digits, lastGuess is "9999"
	for (int c = 0; c < digits; c++){
		finalGuess.append("9");//Build finalGuess
	}
	
	if (guess.compare("S") == 0 ){
		//cout << "in build next pwd should get all zeros.string b4: ";
		// S (for start) denotes that no guessses have been made and the password should be all zeros.
		//Will still need to add lead zeros after. 
		guess = "0";
		//cout << guess << endl;
	}
	else if ( guess.compare(finalGuess) == 0){
		guess = "E";//E (for end) denotes at all values have been tested.
		return;
	}	
	else{
		unsigned long int next = atol( guess.c_str() );
		next++;//Get the value from the string and increment it. 
		sprintf(buffer, "%d", next);//put that in the buffer
		guess = buffer;//assign it to the string.
	}
	
	leadZeros = digits - guess.length();//Count the number of lead zeros needed. 
	if (leadZeros){
		for (int c2 = 0; c2 < leadZeros; c2++){
			guess = "0" + guess;
		}
		return; 
	}
	else { return; }
}

//addToRainbow adds builds a rainbow table as passwords are being matched.  If the crack is in salted 
//mode (2), then the rainbow vector will just contain 1 value.  
void addToRainbow(  vector<string>& rainbow, unsigned int mode, string password){
	
	unsigned char oBuffer [SIZE];//Unsigned buffer to retrieve results of hash.
	unsigned char iBuffer [SIZE];//Unsigned buffer to send to hash
	char sBuffer [SIZE];         //Signed c-string buffer to format hash results
	signedToUnsigned(iBuffer, password.c_str() , password.length() );
	unsigned long val = atol( password.c_str() );	

	if (mode != 0 && mode != 1 && mode != 2) {
		cout << "Invalid mode input into addToRainbow" << endl;
		exit(0);
	}
	
	if( mode == 0) {
		MD5(iBuffer, password.length(), oBuffer);//Call MD5 hash
		signedHexString( oBuffer, sBuffer, SIZE_16);//Format to hex
		rainbow.push_back(sBuffer);//add to rainbow table
		return;
	}
	else if( mode == 1) {
		SHA256(iBuffer, password.length(), oBuffer);//Call SHA256 hash
		signedHexString( oBuffer, sBuffer, SIZE_32);
		rainbow.push_back(sBuffer);//add to rainbow table
		return;
	}
	else { //This is salted SHA256 mode.  No values will be useful more than once so clear the 
	//whole rainbow vector and just add the one value to be tested. 
		rainbow.erase( rainbow.begin(), rainbow.end());
		SHA256(iBuffer, password.length(), oBuffer);//Call SHA256 hash
		signedHexString( oBuffer, sBuffer, SIZE_32);
		rainbow.push_back(sBuffer);//add to rainbow table
		return;
	}
}

//Returns the position of the match found and keeps track of which username from the 
//file is the correct username. 
void match(vector<string> file, vector<string>& rainbow, unsigned int mode, unsigned int digits, unsigned int& userIndex){

	if (mode != 0 && mode != 1){
		cout << "Invalid function call." << endl;
		return;
	}	

	//'tableSize' represents the quantity of possible passwords.  In this function,
	//which matches UNSALTED passwords, if the position of the rainbow table exceeds
	//tableSize, it means that every possible password hash has been tested against 
	//every account, meaning the match failed.  
	unsigned long int tableSize = pow(10, digits);	
	userIndex = 0;//Sets the userIndex to zero, since every user account will be tested. 
	
	//The following sets the string 'guess' which respresents the next guess to 
	//build.  Guess doesn't represent the hash-string being matched, but the *next* guess
	//being sent to the rainbow table. 
	
	string guess = "S";//set the string to 'S.' this will indicate to that the 
	//first password needs to be built in the 'buildNextPassword' function. 
	
	char buffer [SIZE];
	//The following if statement will, by default, always fail as position will be zero.
	//Only if multiple passwords are requested in the main function-- which is commented out by default--
	//will the guess string need to be updated. 
	
	if (position != 0){
		sprintf(buffer, "%lu", position);
		guess = buffer;
		cout << "next value added to table(if necessary) will be " << guess << endl;
	}
	else{//Send "S" to formatPassword to generate the first possible password string.
		formatPassword(digits, guess);
	}
	
	//The following if-statement will add a number of values to the rainbow table equal to the ratio of 
	//accounts to possible passwords.  For instance, if there are 10,000 possible passwords and 50 accounts 
	//then the first portion of the rainbow table will be 200 hash guesses. 
	
	if (position == 0){
		//cout << "\nBuilding first portion of table..." << endl;
		//The following if-statement checks for mix-ups of modes 0 and 1
		//to the corresponding password file.  That is, if mode 1 was 
		//selected with passwdmd5 or mode 0 was selected with passwdSHA256,
		//the program will terminate.  All other file-mode validation
		//is performed in the extractData functions. 
		addToRainbow(rainbow, mode, guess);//Test after the first value to 
		formatPassword(digits, guess); //avoid wasting time if cracking large passwords.
		if (file[0].length() != rainbow[0].length() ){
			cout << "Error: wrong mode selected for the file.";
			cout << "\nMode 0 should correspond to passwdmd5 and";
			cout << "mode 1 should correspond to passwdSHA256.\n\n";
			exit(0);
		}
		//Build the first portion of table, now that the correct mode
		//has been confirmed. 
		for (int c = 1; c < ratio; c++){
			addToRainbow(rainbow, mode, guess);
			formatPassword(digits, guess);
		}
		position = ratio;
	}
	
	userIndex = 0;

	while (position <= (unsigned long int)(tableSize)  && mode != 2){
	
		//The following for loop goes though the current rainbow table (which is some proportion of 
		//all possible hashes, rather than a complete rainbow table) and checks against every user. 
		for(unsigned long int c = 0; c < rainbow.size(); c++){   //Go through the rainbow table
			for(userIndex; userIndex < file.size(); userIndex++){//Check every user to every value in the table
				if(rainbow[c].compare(file[userIndex]) == 0){
					cout << "Matched in  " << position << " hashes." << endl;
		
					sprintf(buffer, "%d", (position - ratio) + (c - 1)) ;//The password will have value c
					guess = buffer;
					
					//Send c-1 to buffer and format it with formatPassword. (the next password being built isn't
					//being added to the hash-guesses here, rather c - 1 is being sent to the function for formatting.)
					formatPassword(digits, guess);
					cout << "\t***Password: " << guess;
					return;
				}
			}
			userIndex = 0;
		}

		//cout << "\nFound all the matches for in last portion of table for values:  ";
		//cout << (position - ratio) << " through " << position << endl;
	
		//If no match has been found by this point, the next portion of the rainbow table needs 
		//to be built.  The value 'guess' represents the next guess that has not been placed in
		//the table. Increment 'position' by ratio.
		position += ratio;
		
		//Clean the rainbow table, since there were no matches in the previous set. 
		rainbow.erase(rainbow.begin(), rainbow.end() );
		
		//And build the next portion of the table, which will be of the same size. 
		for (unsigned long long int c = 0; c < ratio; c++){
			addToRainbow(rainbow, mode, guess);
			formatPassword(digits, guess);
		}
		
	}//End of while-loop			
	
	cout << "Failed to match. Did you select the correct number of digits?\n" << endl;
	return;
}

//The following function attempts to crack SALTED passwords.  
void matchSalted(vector<string> file, vector<string>& rainbow, vector<string>& salts, unsigned int mode, unsigned int digits, unsigned int& userIndex){

	if (mode != 2){
		cout << "Invalid function call." << endl;
		return;
	}	

	unsigned long int tableSize = pow(10, digits);	
	string guess = "S";

	char buffer [SIZE];
	
	formatPassword(digits, guess);//Build the first password. 
	
	//Iterate users
	for (userIndex; userIndex < file.size() ; userIndex++){
		
		//The for-loop below makes a guess hash and tries to find a match.  If there are fewer than 
		//15 accounts, every possible password is attempted starting with the first salt. Otherwise
		//a third of all the possible hashes are attemped before proceeding to the next account.
		for (unsigned long long int c = 0; c < saltedAttempts; c++){
		//	cout << "\n\nhashing this : " << guess << salts[userIndex] << endl;
			addToRainbow(rainbow, mode, guess + salts[userIndex]);//The previous hash guess is deleted in this function;
		//	cout << "got this :" << rainbow[0] << endl;
			formatPassword(digits, guess);
			position++;//Counts all the total hashes performed

			if (rainbow[0].compare(file[userIndex]) == 0){
				cout << "Matched in " << position << " hashes." <<  endl;
				sprintf(buffer, "%lu", c - 1);
				guess = buffer;
				formatPassword(digits, guess);
				cout << "\t***Password: " << guess;
				return;
			}
		}
		guess = "S";//Reset the guess to S, so all-zero digit string is built
		formatPassword(digits, guess);
		
	}//End of while-loop			
	
	cout << "Failed to match. Did you select the correct number of digits? Exiting\n" << endl;
	exit(0);
}



