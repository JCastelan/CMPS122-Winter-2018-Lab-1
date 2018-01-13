#include <stdio.h>
#include <stdlib.h>
#include <crypt.h>
#include <pthread.h>
#include <string.h>

struct threadInfo{ //TODO:add more relevant info to this
    int startIncl;
    
};
char validChars[62] = { '0','1','2','3','4','5',
                        '6','7','8','9','A','B',
                        'C','D','E','F','G',
                        'H','I','J','K','L',
                        'M','N','O','P','Q',
                        'R','S','T','U','V',
                        'W','X','Y','Z','a',
                        'b','c','d','e','f',
                        'g','h','i','j','k',
                        'l','m','n','o','p',
                        'q','r','s','t','u',
                        'v','w','x','y','z'};

char* crackedPassword=NULL;
    
char* getSalt( char *cryptPasswd){
    char* extractedSalt = malloc( sizeof(char)*2); //possible memory leaks...
    extractedSalt[0] = cryptPasswd[0];
    extractedSalt[1] = cryptPasswd[1];
    return extractedSalt;
}

void crackRange( int startIncl, int endExcl, char* salt ){ //TODO: use these variables
    for( int index1=0; index1 < 62; index1++){
        for( int index2=0; index2<62; index2++){
            for( int index3=0; index3<62; index3++){
                printf("[[%s]]\n", crypt( "joseph", "jc" ));
                for( int index4=0; index4<62; index4++){}
            }
        }
    }
}

void* threadBegins( void* identity){//TODO: think about merging it with crackRange (given we have the info packet)
    //int* threadIdent = (int*)identity;
    //crackRange(0,62,salt);
    return NULL;
}

char* getCrackin( char* cryptPasswd, char* salt, int depth){
    char* passAttempt= malloc( depth * sizeof(char));
    char* passAttemptResult = malloc( 4 * sizeof(char));
    printf( "depth was %d", depth);
    for( int index1=0; index1 < 62; index1++){
        passAttempt[0] = validChars[index1];
        for( int index2=0; /*depth>1 &&*/ index2<62; index2++){
            passAttempt[1] = validChars[index2];
            for( int index3=0; /*depth>2 && */index3<62; index3++){
                passAttempt[2] = validChars[index3];
                //printf("[[%s]]\n", crypt( ", salt ));
                for( int index4=0; /*depth>3 &&*/index4<62; index4++){
                    passAttempt[3] = validChars[index4];
                    passAttemptResult= crypt( passAttempt, salt);
                    if( strcmp( passAttemptResult, cryptPasswd) == 0){
                        printf( "Found [%s]\n", passAttemptResult);
                        return passAttempt;
                    }
                }
                /*if( depth ==3){
                    passAttemptResult= crypt( passAttempt, salt);
                    if( strcmp( passAttemptResult, cryptPasswd) == 0){
                        printf( "Found [%s]\n", passAttemptResult);
                        return passAttempt;
                    }
                }*/
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
    printf("\n[%s]  [%s]  [%d]  [%s]\n", username, cryptPasswd, pwlen, passwd);
    char* salt = getSalt(cryptPasswd);
    printf("SALT=[%s]\n", salt);
    
    //char* testCrypt;
    //testCrypt = crypt( "joseph", salt );
    //printf("TEST CRYPT= [%s]\n (testing array...[%c])\n", testCrypt, validChars[61]);
    
    //TODO: Create more threads with a thread packet for each one(AFTER SEMAPHORES FINISHED)
    //pthread_t thread0;
    //int tIdent = 1;
    //pthread_create( &thread0, NULL, threadBegins, &tIdent);
    //printf( "one path\n"); 
    char* crackRes= getCrackin( cryptPasswd, salt, pwlen);
    strcpy( passwd, crackRes);
    //passwd = crackRes;
    printf( "The password is %s\n", passwd);
    free(salt);
    free(crackRes);
}

char* findEncrypted( char* bufContents){
    char* encryptedPassword= malloc( sizeof(char)*13);;
    int counter=0;
    while( bufContents[counter] != ':'){
        counter++;
    }
    counter++;
    for( int index = 0; index<13;index++){
        encryptedPassword[index]=bufContents[counter];
        counter++;
    }
    printf( "Extracted this encrypted Pass:[%s] ",encryptedPassword);
    return encryptedPassword;
}
/*
 * Find the plain-text passwords PASSWDS of length PWLEN for the users found
 * in the old-style /etc/passwd format file at pathe FNAME.
 */
void crackMultiple(char *fname, int pwlen, char **passwds) { 
    printf("\n[%s] [%d]\n", fname, pwlen);
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
void crackStealthy(char *username, char *cryptPasswd, int pwlen, char *passwd, int maxCpu) { }
