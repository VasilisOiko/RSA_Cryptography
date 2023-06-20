#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <openssl/bn.h>

#define NBITS 256

char* str2hex(char *string)
{
	char *hex_string;
	int i, j;

	/* Initialize output variable */
	int length = (strlen(string)*2)+1;
	hex_string = malloc(sizeof(char)*length);

	if(hex_string == NULL)
	{
		printf("Error on convertion");
		return NULL;
	}

	/* encode char to hex as a char* type */
	for(j=0, i=0; string[i]!='\0'; i++, j+=2)
	{
		sprintf((char *)hex_string+j, "%02X", *(string+i));
	}

	hex_string[j] = '\0';

	return hex_string;
}

char* hex2str(char *string)
{
    for(int i=0;i<strlen(string);i+=2)
	{
        char ch[2];
        ch[0]=string[i];
		string[i]=' ';

        ch[1]=string[i+1];
		string[i+1]=' ';

        char c=(char)strtol(ch,NULL,16);
        string[i/2]=c;
    }
    return string;
}

void DispBN2str(BIGNUM * a)
{
	/* Use BN_bn2hex(a) for hex string
	* Use BN_bn2dec(a) for decimal string */
	char * number_str = BN_bn2hex(a);
	
	printf("Message: %s\n", hex2str(number_str));
	OPENSSL_free(number_str);
}

void printBN(char *msg, BIGNUM * a)
{
	/* Use BN_bn2hex(a) for hex string
	* Use BN_bn2dec(a) for decimal string */
	char * number_str = BN_bn2hex(a);
	printf("%s %s\n", msg, number_str);
	OPENSSL_free(number_str);
}


int main(int argc, char **argv)
{
	char *hex_string;

	BN_CTX *ctx = BN_CTX_new();

	BIGNUM *p1 = BN_new();	//prime number 1
	BIGNUM *p2 = BN_new();	//prime number 2
	BIGNUM *e = BN_new();	//encryption key (public key)
	BIGNUM *d = BN_new();	//decryption key (private key)
	BIGNUM *n = BN_new();
	BIGNUM *message = BN_new(); //hexadecimal string message
	BIGNUM *encrypt_message = BN_new(); //encrypted message
	BIGNUM *decrypt_message = BN_new(); //encrypted message

	BIGNUM *phi_p1 = BN_new(); //hexadecimal string message
	BIGNUM *phi_p2 = BN_new(); //hexadecimal string message
	BIGNUM *phi_n = BN_new(); //hexadecimal string message


	hex_string = str2hex(argv[1]);
	if(hex_string == NULL)
		return 0;

	printf("message: \"%s\" convert to:\"%s\"\nLength:%d\n\n", argv[1], hex_string, strlen(hex_string));

	/* Encode the message to hex */
	BN_hex2bn(&message, hex_string); //4f696b6f6e6f6d6f7520566173696c65696f73

	printBN("Encoding message: ", message);

	printf("\n--------------------------------------------------\n");
	BN_hex2bn(&p1, "953AAB9B3F23ED593FBDC690CA10E703");
	printBN("p1: ", p1);	//

	BN_hex2bn(&p2, "C34EFC7C4C2369164E953553CDF94945");
	printBN("p2: ", p2);	//

	BN_hex2bn(&e, "0D88C3");
	printBN("e: ", e);	//
	
	BN_mul(n, p1, p2, ctx);
	
	BN_sub(phi_p1, p1, BN_value_one());
	BN_sub(phi_p2, p2, BN_value_one());
	BN_mul(phi_n, phi_p1, phi_p2, ctx);
	printBN("n: ", n);	//
	printf("\n");

/* ______________________________________________________________________________________ */

	/* _______Activity 1_______ */
	printf("\n\nACTIVITY 1\n");

	BN_mod_inverse(d, e, phi_n, ctx);
	printBN("private key: ", d);	//
	printf("--------------------------------------------------\n\n");

	/* ________OPTIONAL________ */
	/* Encryption */
	BN_mod_exp(encrypt_message, message, e, n, ctx);
	printBN("Encrypted message: ", encrypt_message);

	/* Decryption */
	BN_mod_exp(decrypt_message, encrypt_message, d, n, ctx);
	printBN("Decrypted message: ", decrypt_message);

	/* Display message */
	DispBN2str(decrypt_message);
	printf("\n");
	/* ________OPTIONAL________ */

/* ______________________________________________________________________________________ */

	/* _______Activity 3_______ */
	printf("\n\nACTIVITY 3\n");

	BIGNUM *c = BN_new();

	/* Initialize d(private key), e(public key), n */
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");


	/* Encrypted message */
	BN_hex2bn(&c, "CAF7D72776AFEFBAC8269E1A8B76CE44A3B28015CA9A54E22C239EF38FCFAFFA");
	printBN("C Encrypted message: ", c);

	/* Decryption */
	BN_mod_exp(decrypt_message, c, d, n, ctx);

	/* Display message in hex and ascii */
	printBN("Decrypted message: ", decrypt_message);
	DispBN2str(decrypt_message);

/* ______________________________________________________________________________________ */

	/* _______Activity 4_______ */
	printf("\n\nACTIVITY 4\n");

	BIGNUM *alter_message = BN_new();			//Second message
	BIGNUM *signature_1 = BN_new();		//sign of variable: message
	BIGNUM *signature_2 = BN_new();		// sign of variable: alter_message
		 

	/* Original Message */
	printf("First");
	DispBN2str(message);

	/* Encryption with private key(variable: d) */
	BN_mod_exp(signature_1, message, d, n, ctx);
	printBN("signed message: ", signature_1);



	/* Change message */
	hex_string = str2hex("Oikonomou Vasileios");
	if(hex_string == NULL)
		return 0;

	/* Encode the message to hex */
	BN_hex2bn(&alter_message, hex_string);

	printf("\nSecond ");
	DispBN2str(alter_message);

	/* Encryption with private key(variable: d) */
	BN_mod_exp(signature_2, alter_message, d, n, ctx);
	printBN("signed message: ", signature_2);

	/* Compare the two signs */
	printf("\nsign_1 EQUAL sign_2 -> %s\n", BN_cmp(signature_1, signature_2)? "FALSE" : "TRUE");
	
/* ______________________________________________________________________________________ */

	/* _______Activity 5_______ */
	printf("\n\nACTIVITY 5\n");

	BIGNUM *verification = BN_new();

	/* ---------------Case A--------------- */
	printf("\tCase A\n");
	
	/* Initialize: , e(public key), n,  message_sign */
	BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&e, "010001");
	BN_hex2bn(&signature_1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

	/* Change message */
	hex_string = str2hex("Launch a missile.");
	if(hex_string == NULL)
		return 0;

	/* Encode the message to hex */
	BN_hex2bn(&message, hex_string);	//Original message to variable: message

	/* Display message */
	DispBN2str(message);
	printBN("Message(hex):", message);

	/* Display signature */
	printBN("Message sign:", signature_1);


	/* Verification */
	BN_mod_exp(verification, signature_1, e, n, ctx);
	printBN("Message verification:", verification);
	printf("\n");

	/* Check if produced the Message */
	printf("Message EQUAL verification -> %s\n\n", BN_cmp(message, verification)? "FALSE" : "TRUE");

	/* Modify sign  */
	BN_hex2bn(&signature_2, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	printBN("modified sign: ", signature_2);


	/* Verification on modified sign */
	BN_mod_exp(verification, signature_2, e, n, ctx);
	printBN("Message verification:", verification);
	/* ------------------------------------ */



	/* ---------------Case B--------------- */
	printf("\n\tCase B\n");

	
	/* Initialize: n, message_sign */
	BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	BN_hex2bn(&signature_1, "DB3F7CDB93483FC1E70E4EACA650E3C6505A3E5F49EA6EDF3E95E9A7C6C7A320");

	/* Change message */
	hex_string = str2hex("Please transfer me $2000.Alice.");
	if(hex_string == NULL)
		return 0;

	/* Encode the message to hex */
	BN_hex2bn(&message, hex_string);	//Original message to variable: message

	/* Display message */
	DispBN2str(message);
	printBN("Message(hex):", message);

	/* Display signature */
	printBN("Message sign:", signature_1);

	/* Verification */
	BN_mod_exp(verification, signature_1, e, n, ctx);
	printBN("Message verification:", verification);
	printf("\n");

	/* Check if produced the Message */
	printf("Message EQUAL verification -> %s\n", BN_cmp(message, verification)? "FALSE" : "TRUE");
	/* ------------------------------------ */

/* ______________________________________________________________________________________ */

	/* _______Activity 6_______ */
	printf("\n\nACTIVITY 6\n");

	BIGNUM *hash = BN_new();

	/* Initialize: , e(public key), n(modulo),  message_sign */
	BN_hex2bn(&e, argv[2]);
	BN_hex2bn(&n, argv[3]);
	BN_hex2bn(&signature_1, argv[4]);
	BN_hex2bn(&hash, argv[5]);

	printBN("public key:", e);
	printf("\n");
	printBN("modulo:", n);
	printf("\n");
	printBN("signature:", signature_1);
	printf("\n");
	printBN("hash:", hash);

	/* Verification */
	BN_mod_exp(verification, signature_1, e, n, ctx);
	printBN("\nMessage verification:", verification);
	printf("\n");


	/* Free memory */
	free(hex_string);
	OPENSSL_free(p1);
	OPENSSL_free(p2);
	OPENSSL_free(e);
	OPENSSL_free(d);
	OPENSSL_free(n);
	OPENSSL_free(message);
	OPENSSL_free(encrypt_message);
	OPENSSL_free(decrypt_message);
	OPENSSL_free(phi_p1);
	OPENSSL_free(phi_p2);
	OPENSSL_free(phi_n);
	OPENSSL_free(c);
	OPENSSL_free(alter_message);
	OPENSSL_free(signature_1);
	OPENSSL_free(signature_2);

	return 0;
}