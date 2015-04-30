//////////////////////////////////////////////////////////////////////
/*
This program implements the Advanced Encryption Standard (AES), also
known as the Rijndael Algorithm.

For detailed documentation, visit the following webpage:
csrc.nist.gov/publications/fips/fips197/fips-197.pdf


Extra Specifications to this program:

If a file's size does not divide into 16 bytes, 0's are padded at
the end.

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

const unsigned char Sbox[16][16] = {"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b\xfe\xd7\xab\x76",
"\xca\x82\xc9\x7d\xfa\x59\x47\xf0\xad\xd4\xa2\xaf\x9c\xa4\x72\xc0",
"\xb7\xfd\x93\x26\x36\x3f\xf7\xcc\x34\xa5\xe5\xf1\x71\xd8\x31\x15",
"\x04\xc7\x23\xc3\x18\x96\x05\x9a\x07\x12\x80\xe2\xeb\x27\xb2\x75",
"\x09\x83\x2c\x1a\x1b\x6e\x5a\xa0\x52\x3b\xd6\xb3\x29\xe3\x2f\x84",
"\x53\xd1\x00\xed\x20\xfc\xb1\x5b\x6a\xcb\xbe\x39\x4a\x4c\x58\xcf",
"\xd0\xef\xaa\xfb\x43\x4d\x33\x85\x45\xf9\x02\x7f\x50\x3c\x9f\xa8",
"\x51\xa3\x40\x8f\x92\x9d\x38\xf5\xbc\xb6\xda\x21\x10\xff\xf3\xd2",
"\xcd\x0c\x13\xec\x5f\x97\x44\x17\xc4\xa7\x7e\x3d\x64\x5d\x19\x73",
"\x60\x81\x4f\xdc\x22\x2a\x90\x88\x46\xee\xb8\x14\xde\x5e\x0b\xdb",
"\xe0\x32\x3a\x0a\x49\x06\x24\x5c\xc2\xd3\xac\x62\x91\x95\xe4\x79",
"\xe7\xc8\x37\x6d\x8d\xd5\x4e\xa9\x6c\x56\xf4\xea\x65\x7a\xae\x08",
"\xba\x78\x25\x2e\x1c\xa6\xb4\xc6\xe8\xdd\x74\x1f\x4b\xbd\x8b\x8a",
"\x70\x3e\xb5\x66\x48\x03\xf6\x0e\x61\x35\x57\xb9\x86\xc1\x1d\x9e",
"\xe1\xf8\x98\x11\x69\xd9\x8e\x94\x9b\x1e\x87\xe9\xce\x55\x28\xdf",
"\x8c\xa1\x89\x0d\xbf\xe6\x42\x68\x41\x99\x2d\x0f\xb0\x54\xbb\x16"};

const unsigned char InvSBox[16][16] = {"\x52\x09\x6a\xd5\x30\x36\xa5\x38\xbf\x40\xa3\x9e\x81\xf3\xd7\xfb",
"\x7c\xe3\x39\x82\x9b\x2f\xff\x87\x34\x8e\x43\x44\xc4\xde\xe9\xcb",
"\x54\x7b\x94\x32\xa6\xc2\x23\x3d\xee\x4c\x95\x0b\x42\xfa\xc3\x4e",
"\x08\x2e\xa1\x66\x28\xd9\x24\xb2\x76\x5b\xa2\x49\x6d\x8b\xd1\x25",
"\x72\xf8\xf6\x64\x86\x68\x98\x16\xd4\xa4\x5c\xcc\x5d\x65\xb6\x92",
"\x6c\x70\x48\x50\xfd\xed\xb9\xda\x5e\x15\x46\x57\xa7\x8d\x9d\x84",
"\x90\xd8\xab\x00\x8c\xbc\xd3\x0a\xf7\xe4\x58\x05\xb8\xb3\x45\x06",
"\xd0\x2c\x1e\x8f\xca\x3f\x0f\x02\xc1\xaf\xbd\x03\x01\x13\x8a\x6b",
"\x3a\x91\x11\x41\x4f\x67\xdc\xea\x97\xf2\xcf\xce\xf0\xb4\xe6\x73",
"\x96\xac\x74\x22\xe7\xad\x35\x85\xe2\xf9\x37\xe8\x1c\x75\xdf\x6e",
"\x47\xf1\x1a\x71\x1d\x29\xc5\x89\x6f\xb7\x62\x0e\xaa\x18\xbe\x1b",
"\xfc\x56\x3e\x4b\xc6\xd2\x79\x20\x9a\xdb\xc0\xfe\x78\xcd\x5a\xf4",
"\x1f\xdd\xa8\x33\x88\x07\xc7\x31\xb1\x12\x10\x59\x27\x80\xec\x5f",
"\x60\x51\x7f\xa9\x19\xb5\x4a\x0d\x2d\xe5\x7a\x9f\x93\xc9\x9c\xef",
"\xa0\xe0\x3b\x4d\xae\x2a\xf5\xb0\xc8\xeb\xbb\x3c\x83\x53\x99\x61",
"\x17\x2b\x04\x7e\xba\x77\xd6\x26\xe1\x69\x14\x63\x55\x21\x0c\x7d"};

const unsigned char Nb = 4;


// Encryption and sub steps
void Cipher(unsigned char state[4][4], unsigned char*** keySchedule, unsigned char Nk, unsigned char Nr);
void ShiftRows(unsigned char state[4][4]);
void SubBytes(unsigned char state[4][4]);
void MixColumns(unsigned char state[4][4]);
void AddRoundKey(unsigned char state[4][4], unsigned char** keySchedule);

// Decryption and sub steps
void InvCipher(unsigned char state[4][4], unsigned char***keySchedule, unsigned char Nk, unsigned char Nr);
void InvShiftRows(unsigned char state[4][4]);
void InvSubBytes(unsigned char state[4][4]);
void InvMixColumns(unsigned char state[4][4]);

// Key Expansion and sub steps
void KeyExpansion(unsigned char* cipherKey, unsigned char*** keySchedule, unsigned char Nk, unsigned char Nr);
void RotWord(unsigned char word[4]);
void SubWord(unsigned char word[4]);
void RoundCon(unsigned char in, unsigned char word[4]);


// Mathematical operations in the Galois field
// Taken from www.samiam.org/galois.html
unsigned char GaloisAdd(unsigned char a, unsigned char b);
unsigned char GaloisSubtract(unsigned char a, unsigned char b);
unsigned char GaloisMultiply(unsigned char a, unsigned char b);

// Other tools
unsigned char SubByte(unsigned char byte);
unsigned char InvSubByte(unsigned char byte);
void WordXor(unsigned char* a, unsigned char* b, unsigned char* result);


int main(int argc, char * argv[])
{
	//////////////////////////////////////////////////////////////////////
	//                        ERROR CHECKING                            //
	//////////////////////////////////////////////////////////////////////

	// There should be 5 arguments
	// The first argument should be the target file
	// The second argument should be the encryption key
	// The third argument should be the output file's name
	// The fourth argument should be either '128' '192' or '256'
	// The fifth argument should be either 'encrypt' or 'decrypt'

	// Error checking
	// Check for exactly correct number of arguments
	if (argc != 6)
	{
		printf("Usage: ./aes target_file key_file output_file (128 or 192 or 256) (encrypt or decrypt)\n");
		return 1;
	}
	// Check for whether target_file exists
	if (fopen(argv[1], "rb") == NULL)
	{
		printf("Error! target_file specified does not exist. Exiting now...\n");
		return 1;
	}
	// Check for whether key_file exists
	if (fopen(argv[2], "rb") == NULL)
	{
		printf("Error! key_file specified does not exist. Exiting now...\n");
		return 1;
	}
	// Check for permitted block length (only 128. 192, or 256)
	if (strcmp(argv[4], "128") != 0 && strcmp(argv[4], "192") != 0 && strcmp(argv[4], "256") != 0)
	{
		printf("Error! Please only enter 128, 196, or 256. Exiting now...\n");
		return 1;
	}

	// Check for permitted operation (only encrypt or decrypt)
	if (strcmp(argv[5], "encrypt") != 0 && strcmp(argv[5], "decrypt") != 0)
	{
		printf("Errot! Please specify encrypt or decrypt. Exiting now...\n");
		return 1;
	}

	//////////////////////////////////////////////////////////////////////
	//                        ALL VARIABLES                             //
	//////////////////////////////////////////////////////////////////////

	unsigned char* input;
	unsigned char* output;
	unsigned char* cipher_key;
	unsigned char*** key_schedule;
	unsigned char state[4][4];
	unsigned char Nk = 0;
	unsigned char Nr = 0;

	unsigned long inputLength;

	int i, j, k;

	//////////////////////////////////////////////////////////////////////
	//                        PARSE FILES                               //
	//////////////////////////////////////////////////////////////////////

	// File IO
	// Parse target_file
	FILE* fp;
	char c;
	unsigned long index = 0;
	unsigned long length;
	fp = fopen(argv[1], "rb");
	printf("Parsing ");
	printf(argv[1]);
	printf("... ");

	fseek(fp, 0, SEEK_END); // Find file size (efficiently allocate exact amount of memory)
	length = ftell(fp);
	inputLength = length;
	input = (unsigned char*) malloc(length*sizeof(unsigned char));

	// for decryption, check if file size is divisible by 16
	// if not, then the file is invalid
	if ((strcmp(argv[5], "decrypt") == 0) && (inputLength % 16 != 0))
	{
		printf("\nTarget file for decrypting must have a size divisible by 16 bytes. Exiting now...\n");
		return 1;
	}

	fseek(fp, 0, 0);
	while (fscanf(fp, "%c", &c) != EOF)
	{
		input[index] = c;
		++index;
	}
	fclose(fp);

	printf("Done.\n");

	// Parse key_file
	index = 0;
	fp = fopen(argv[2], "rb");
	printf("Parsing ");
	printf(argv[2]);
	printf("... ");

	fseek(fp, 0, SEEK_END); // Find file size (efficiently allocate exact amount of memory)
	length = ftell(fp);
	cipher_key = (unsigned char*) malloc(length*sizeof(unsigned char));

	fseek(fp, 0, 0);
	while (fscanf(fp, "%c", &c) != EOF)
	{
		cipher_key[index] = c;
		++index;
	}
	fclose(fp);
	printf("Done.\n");

	//////////////////////////////////////////////////////////////////////
	//                        INITIALIZATION                            //
	//////////////////////////////////////////////////////////////////////

	// Assign constants based on n-bit encryption/decryption
	if (strcmp(argv[4], "128") == 0)
	{
		Nk = 4;
		Nr = 10;
	}
	else if (strcmp(argv[4], "192") == 0)
	{
		Nk = 6;
		Nr = 12;
	}
	else
	{
		Nk = 8;
		Nr = 14;
	}

	// Dynamically allocate memory for key_schedule based on encryption bit size
	key_schedule = (unsigned char***) malloc((Nr+1)*sizeof(unsigned char**));
	for (i = 0; i < (Nr+1); ++i)
	{
		key_schedule[i] = (unsigned char**) malloc(4*sizeof(unsigned char*));
		for (j = 0; j < 4; ++j)
		{
			key_schedule[i][j] = (unsigned char*) malloc(4*sizeof(unsigned char));
		}
	}

	// Initialize key_schedule
	for (i = 0; i < (Nr+1); ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			for (k = 0; k < 4; ++k)
			{
				key_schedule[i][j][k] = 0;
			}
		}
	}

	//////////////////////////////////////////////////////////////////////
	//                        COMPUTATIONS                              //
	//////////////////////////////////////////////////////////////////////

	// Calculate key_schedule
	KeyExpansion(cipher_key, key_schedule, Nk, Nr);

	// calculate the number of states needed to encrypt the whole file
	// first 
	int stateLoops = inputLength / 16;
	int stateRounds = stateLoops;
	if (inputLength % 16 != 0)
	{
		++stateRounds;
	}
	output = (unsigned char*) malloc(stateRounds*16*sizeof(unsigned char));

	for (i = 0; i < stateLoops; ++i)
	{
		// load state
		for (j = 0; j < 4; ++j)
		{
			for (k = 0; k < 4; ++k)
			{
				state[j][k] = input[16*i+4*k+j];
			}
		}
		
		// encrypt/decrypt
		if (strcmp(argv[5], "encrypt") == 0)
		{
			Cipher(state, key_schedule, Nk, Nr);
		}
		else
		{
			InvCipher(state, key_schedule, Nk, Nr);
		}

		// dump state
		for (j = 0; j < 4; ++j)
		{
			for (k = 0; k < 4; ++k)
			{
				output[16*i+4*k+j] = state[j][k];
			}
		}
	}

	// do another round
	// does not evenly divide into 16
	// the algorithm is described at the very beginning
	if (inputLength % 16 != 0)
	{
		// retrieve input values
		for (i = 0; i < (inputLength % 16); ++i)
		{
			state[i%4][i/4] = input[16*stateLoops+i];
		}

		// pad the rest with 0's
		for (i = (inputLength % 16); i < 16; ++i)
		{
			state[i%4][i/4] = 0;
		}

		// encrypt
		Cipher(state, key_schedule, Nk, Nr);
		
		// add to output
		for (j = 0; j < 4; ++j)
		{
			for (k = 0; k < 4; ++k)
			{
				output[16*stateLoops+4*k+j] = state[j][k];
			}
		}
	}

	//////////////////////////////////////////////////////////////////////
	//                        OUTPUT RESULTS                            //
	//////////////////////////////////////////////////////////////////////

	int paddedZeros = 0;
	i = 16*stateLoops - 1;
	while (output[i] == 0)
	{
		++paddedZeros;
		--i;
	}

	// Dump file into output file
	fp = fopen(argv[3], "wb");
	for (i = 0; i < (16*stateRounds - paddedZeros); ++i)
	{
		fprintf(fp, "%c", output[i]);
	}
	fclose(fp);


	//////////////////////////////////////////////////////////////////////
	//                        END PROGRAM                               //
	//////////////////////////////////////////////////////////////////////

	return 0;
}

//void Cipher(unsigned char state[4][4], unsigned char keySchedule[][4][4], unsigned char Nk, unsigned char Nr)
void Cipher(unsigned char state[4][4], unsigned char*** keySchedule, unsigned char Nk, unsigned char Nr)
{
	// Initial Round
	AddRoundKey(state, keySchedule[0]);

	// Rounds
	unsigned char i;
	for (i = 1; i < Nr; ++i)
	{
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, keySchedule[i]);
	}

	// Final Round (without MixColumns)
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, keySchedule[Nr]);
}

void ShiftRows(unsigned char state[4][4])
{
	unsigned char temp[4];
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		// store each row's original position
		for (j = 0; j < 4; ++j)
		{
			temp[j] = state[i][j];
		}
		// shift each row
		for (j = 0; j < 4; ++j)
		{
			state[i][j] = temp[(j+i)%4];
		}
	}
}

void SubBytes(unsigned char state[4][4])
{
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			state[i][j] = SubByte(state[i][j]);
		}
	}
}

void MixColumns(unsigned char state[4][4])
{
	unsigned char temp[4];
	unsigned char i, j;
	for (j = 0; j < 4; ++j)
	{
		for (i = 0; i < 4; ++i)
		{
			temp[i] = state[i][j];
		}
		// multiply the following matrix by each column:
		// 2 3 1 1
		// 1 2 3 1
		// 1 1 2 3
		// 3 1 1 2
		state[0][j] = GaloisMultiply(temp[0],2) ^ GaloisMultiply(temp[1],3) ^ GaloisMultiply(temp[2],1) ^ GaloisMultiply(temp[3],1);
		state[1][j] = GaloisMultiply(temp[0],1) ^ GaloisMultiply(temp[1],2) ^ GaloisMultiply(temp[2],3) ^ GaloisMultiply(temp[3],1);
		state[2][j] = GaloisMultiply(temp[0],1) ^ GaloisMultiply(temp[1],1) ^ GaloisMultiply(temp[2],2) ^ GaloisMultiply(temp[3],3);
		state[3][j] = GaloisMultiply(temp[0],3) ^ GaloisMultiply(temp[1],1) ^ GaloisMultiply(temp[2],1) ^ GaloisMultiply(temp[3],2);
	}
}

void AddRoundKey(unsigned char state[4][4], unsigned char** keySchedule)
{
	// state goes by column, keyschedule goes by row
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			state[i][j] ^= keySchedule[j][i];
		}
	}
}

void InvCipher(unsigned char state[4][4], unsigned char***keySchedule, unsigned char Nk, unsigned char Nr)
{
	// Initial Round
	AddRoundKey(state, keySchedule[Nr]);

	// Rounds
	unsigned char i;
	for (i = (Nr-1); i > 0; --i)
	{
		InvShiftRows(state);
		InvSubBytes(state);
		AddRoundKey(state, keySchedule[i]);
		InvMixColumns(state);
	}

	// Final Round (without MixColumns)
	InvShiftRows(state);
	InvSubBytes(state);
	AddRoundKey(state, keySchedule[0]);
}

void InvShiftRows(unsigned char state[4][4])
{
	unsigned char temp[4];
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		// store each row's original position
		for (j = 0; j < 4; ++j)
		{
			temp[j] = state[i][j];
		}
		// shift each row
		for (j = 0; j < 4; ++j)
		{
			state[i][j] = temp[(j+4-i)%4];
		}
	}
}

void InvSubBytes(unsigned char state[4][4])
{
	unsigned char i, j;
	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			state[i][j] = InvSubByte(state[i][j]);
		}
	}
}

void InvMixColumns(unsigned char state[4][4])
{
	unsigned char temp[4];
	unsigned char i, j;
	for (j = 0; j < 4; ++j)
	{
		for (i = 0; i < 4; ++i)
		{
			temp[i] = state[i][j];
		}
		// multiply the following matrix by each column:
		// 0e 0b 0d 09
		// 09 0e 0b 0d
		// 0d 09 0e 0b
		// 0b 0d 09 0e
		state[0][j] = GaloisMultiply(temp[0],14) ^ GaloisMultiply(temp[1],11) ^ GaloisMultiply(temp[2],13) ^ GaloisMultiply(temp[3],9);
		state[1][j] = GaloisMultiply(temp[0],9) ^ GaloisMultiply(temp[1],14) ^ GaloisMultiply(temp[2],11) ^ GaloisMultiply(temp[3],13);
		state[2][j] = GaloisMultiply(temp[0],13) ^ GaloisMultiply(temp[1],9) ^ GaloisMultiply(temp[2],14) ^ GaloisMultiply(temp[3],11);
		state[3][j] = GaloisMultiply(temp[0],11) ^ GaloisMultiply(temp[1],13) ^ GaloisMultiply(temp[2],9) ^ GaloisMultiply(temp[3],14);
	}
}

// KeyExpansion algorithm works for 128 bit cipher key
// still must test for 192 and 256 bit cipher key
//void KeyExpansion(unsigned char* cipherKey, unsigned char keySchedule[][4][4], unsigned char Nk, unsigned char Nr)
void KeyExpansion(unsigned char* cipherKey, unsigned char*** keySchedule, unsigned char Nk, unsigned char Nr)
{
	unsigned char temp[4], temp2[4];

	// first four/six/eight rounds are the cipher key itself
	unsigned char i, j;
	unsigned char grid; // grid tells which round #'s grid
	unsigned char word; // word tells the current word # within each grid
	for (i = 0; i < Nk; ++i)
	{
		grid = i / 4;
		word = i % 4;
		for (j = 0; j < 4; ++j)
		{
			keySchedule[grid][word][j] = cipherKey[4*i+j];
		}
	}

	// the rest of the rounds are calculated
	// there are a total of 11/13/15 rounds * 4
	for (i = Nk; i < Nb*(Nr+1); ++i)
	{
		grid = i / 4;
		word = i % 4;
		// store previous word
		for (j = 0; j < 4; ++j)
		{
			if (word == 0)
			{
				temp[j] = keySchedule[grid-1][3][j];
			}
			else
			{
				temp[j] = keySchedule[grid][word-1][j];
			}
		}
		// for 128 or 196 bit
		if ((i % Nk) == 0)
		{
			RotWord(temp);
			SubWord(temp);
			RoundCon((i/Nk), temp2);
			WordXor(temp, temp2, temp);
		}
		// for 256 bit
		else if (Nk > 6 && (i % Nk == 4))
		{
			SubWord(temp);
		}
		WordXor(temp, keySchedule[(i-Nk)/4][(i-Nk)%4], keySchedule[grid][word]);
	}
}

void RotWord(unsigned char word[4])
{
	unsigned char a = word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = a;
}

void SubWord(unsigned char word[4])
{
	unsigned char i;
	for (i=0; i < 4; ++i)
	{
		word[i] = SubByte(word[i]);
	}
}

void RoundCon(unsigned char in, unsigned char word[4])
{
	unsigned char i;
	for (i = 1; i < 4; ++i)
	{
		word[i] = 0;
	}
	if (in == 0)
	{
		word[0] = 0;
		return;
	}
	unsigned char c = 1;
	while (in != 1)
	{
		c = GaloisMultiply(2, c);
		--in;
	}
	word[0] = c;
}

unsigned char SubByte(unsigned char byte)
{
	return Sbox[byte/16][byte%16];
}

unsigned char InvSubByte(unsigned char byte)
{
	return InvSBox[byte/16][byte%16];
}

void WordXor(unsigned char* a, unsigned char* b, unsigned char* result)
{
	unsigned char i;
	for (i = 0; i < 4; ++i)
	{
		result[i] = a[i] ^ b[i];
	}
}

unsigned char GaloisAdd(unsigned char a, unsigned char b)
{
	return a ^ b;
}

unsigned char GaloisSubtract(unsigned char a, unsigned char b)
{
	return a ^ b;
}

unsigned char GaloisMultiply(unsigned char a, unsigned char b)
{
	unsigned char p = 0;
	unsigned char counter;
	unsigned char hi_bit_set;
	for (counter = 0; counter < 8; ++counter)
	{
		if ((b & 1) == 1)
		{
			p ^= a;
		}
		hi_bit_set = (a & 0x80);
		a <<= 1;
		if (hi_bit_set == 0x80)
		{
			a ^= 0x1b;
		}
		b >>= 1;
	}
	return p;
}
