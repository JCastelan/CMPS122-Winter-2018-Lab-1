#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <crypt.h>
#include <pthread.h>
#include <string.h>

//I used man pthread_create's example as a base for almost all pthread stuff in this code
struct threadInfo{ 
    pthread_t thread_id;
    int thread_num; 
    char *username; 
    char *cryptPasswd;
    char* salt;
    int pwlen; 
    char *passwd; 
    int startIncl;
    int endIncl;
    int maxCpu;
};
char validChars[62] = { '0','1','2','3','4','5', //0-5 [0]
                        '6','7','8','9','A','B', //6-11[1]
                        'C','D','E','F','G', //12-16 [2]
                        'H','I','J','K','L', //17-21 [3]
                        'M','N','O','P','Q', //22-26 [4]
                        'R','S','T','U','V', //27-31 [5]
                        'W','X','Y','Z','a', //32-36 [6]
                        'b','c','d','e','f', //37-41 [7]
                        'g','h','i','j','k', //42-46 [8]
                        'l','m','n','o','p', //47-51 [9]
                        'q','r','s','t','u', //52-56 [10]
                        'v','w','x','y','z'};//57-61 [11]

int isCracked;
int isSaved;
/*gets salt from the first 2 chars of encrypted result*/
char* getSalt( char *cryptPasswd){
    char* extractedSalt = calloc(1,  sizeof(char)*2); 
    extractedSalt[0] = cryptPasswd[0];
    extractedSalt[1] = cryptPasswd[1];
    return extractedSalt;
    free( extractedSalt);
}

/*Each thread starts in this function. The threads should already have all the necessary info to use this*/
void* threadBegins( void* threadArgs){
    struct threadInfo *tinfo = threadArgs;
    struct crypt_data data; //needed for cyrpt_r
    data.initialized=0;
    char* passAttempt= calloc( 4 , sizeof(char)); //what will be encrypted
    char* passAttemptResult;// = malloc( 4 * sizeof(char)); //result of encrypting passAttempt
    /*Each thread will look within a certain range of possibile passwords*/
    int startRange = tinfo->startIncl;
    int endRange = tinfo->endIncl;
    char* salt = tinfo->salt;
    //printf( "Some thread started looking between [%d] and [%d] (salt: %s)\n", startRange, endRange, salt);
    for( int index1 = startRange; index1 <= endRange; index1++){
        passAttempt[0] = validChars[index1];
        if( isCracked) {pthread_exit(NULL);}
        for( int index2=0; index2<62; index2++){
            passAttempt[1] = validChars[index2];
            for( int index3=0; index3<62; index3++){
                passAttempt[2] = validChars[index3];
                for( int index4=0; index4<62; index4++){
                    passAttempt[3] = validChars[index4];
                    passAttemptResult= crypt_r( passAttempt, salt, &data);
                    if( strcmp( passAttemptResult, tinfo->cryptPasswd) == 0){
                        //printf( "<<<<<<<<<<<<<<<<<<<<<<<Found [%s]\n", passAttemptResult);
                        isCracked++;
                        return passAttempt;
                    }
                }
            }
        }
    }
    return NULL;
}

/*This was my original attempt at a solution. It only works for a single thread*/
char* getCrackin( char* cryptPasswd, char* salt, int depth){
    struct crypt_data data;
    data.initialized=0;
    char* passAttempt= calloc( 4 , sizeof(char)); //what will be encrypted
    char* passAttemptResult = calloc( 4 , sizeof(char)); //result of encrypting passAttempt
    //printf( "depth was %d\t", depth);
    for( int index1=0; index1 < 62; index1++){
        passAttempt[0] = validChars[index1];
        for( int index2=0; index2<62; index2++){
            passAttempt[1] = validChars[index2];
            for( int index3=0; index3<62; index3++){
                passAttempt[2] = validChars[index3];
                //printf("[[%s]]\n", crypt( ", salt ));
                for( int index4=0; /*depth>3 &&*/index4<62; index4++){
                    passAttempt[3] = validChars[index4];
                    passAttemptResult= crypt_r( passAttempt, salt, &data);
                    if( strcmp( passAttemptResult, cryptPasswd) == 0){
                        printf( "Found [%s]\n", passAttemptResult);
                        return passAttempt;
                    }
                }
            }
        }
    }
    return "none";
}

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD.
 */
void crackSingle(char *username, char *cryptPasswd, int pwlen, char *passwd) { 
    //printf("\n[%s]  [%s]  [%d]  [%s]\n", username, cryptPasswd, pwlen, passwd);
    isCracked=0;
    isSaved=0;
    struct threadInfo* threads = calloc( 12, sizeof( struct threadInfo) );
    int startIncl=0;
    int endIncl=5;
    int addThis=6;
    char* salt = getSalt(cryptPasswd);
    for(int index = 0; index < 12; index++){
        threads[index].cryptPasswd = cryptPasswd;
        threads[index].salt = salt;
        threads[index].startIncl = startIncl;
        threads[index].endIncl = endIncl;
        threads[index].passwd = passwd;
        if(index == 1){ addThis = 5;startIncl++;} //I divided the range so that the first two threads get slightly more work than the rest
        startIncl+=addThis;
        endIncl+=addThis;
        pthread_create( &threads[index].thread_id, NULL, threadBegins, &threads[index]);
    }
    
    void * crackRes; 
    for( int index = 0; index < 12; index++){
        pthread_join( threads[index].thread_id, &crackRes );
        if( crackRes != NULL ){strcpy( passwd, (char*) crackRes);isSaved++;}
        if( isSaved){break;}
    }
    free(crackRes);
}

char* findEncrypted( char* bufContents){
    char* encryptedPassword= calloc( 13, sizeof(char));;
    int counter=0;
    while( bufContents[counter] != ':'){
        counter++;
    }
    counter++;
    for( int index = 0; index<13;index++){
        encryptedPassword[index]=bufContents[counter];
        counter++;
    }
    //printf( "Extracted this encrypted Pass:[%s] \n",encryptedPassword);
    return encryptedPassword;
}
/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackMultiple(char *fname, int pwlen, char **passwds) { 
    int passwdsIndex=0;
    FILE* fp = fopen( fname, "r");
    int bufSize=512;
    char buffer[bufSize];
    char *cryptPasswd;
    
    while( fgets( buffer, bufSize, fp)){
        //printf( "buffer contents:%s", buffer);
        cryptPasswd = findEncrypted(buffer);
        crackSingle( "dc", cryptPasswd, pwlen, passwds[passwdsIndex]);
        passwdsIndex++;
    }
    fclose(fp);
    
} 

/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackSpeedy(char *fname, int pwlen, char **passwds) { 
    crackMultiple(fname,pwlen,&*passwds);
}

/*
 * Find the plain-text password PASSWD of length PWLEN for the user USERNAME 
 * given the encrypted password CRYPTPASSWD withoiut using more than MAXCPU
 * percent of any processor.
 */
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu) { 
    crackSingle( "don't care", cryptPasswd, pwlen, passwd);
    //need to use a thread with limited resource
    //I could probably store all crypt results in some hash table when I do crack multiple
    //and then use that table here in crack stealthy
}
