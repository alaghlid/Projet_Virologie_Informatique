// Program.cpp : définit le point d'entrée pour l'application console.


/*	
 *  Projet de Virologie Informatique 
 *    LAGHLID Ayoub - ZKIM Youssef
 *			   5ASL - 2022/2023
*/

#include "stdafx.h"
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DETECTION_VALUE 0xDEADBEEF

DWORD protectionValue;

int key=8765432;

void	antiDebug() {
	// Sauvegarder la valeur de protection actuelle
    VirtualProtect((LPVOID)antiDebug, 1, PAGE_EXECUTE_READWRITE, &protectionValue);

    // Modifier le premier octet de la fonction antiDebug pour contenir la valeur de détection
    *(unsigned char *)antiDebug = (unsigned char)DETECTION_VALUE;

    // Rétablir la valeur de protection sauvegardée
    VirtualProtect((LPVOID)antiDebug, 1, protectionValue, &protectionValue);

	if (IsDebuggerPresent()) {
		ExitProcess(0);
	}
}

int	numLen(int num){
	int digits = 0;
	while (num != 0) {
        num /= 10;
        digits++;
    }
	return digits;
}

int	main(int argc, char* argv[])
{
	antiDebug();
	// Vérifier si la valeur de détection a été modifiée
    if (*(unsigned char *)antiDebug != (unsigned char)DETECTION_VALUE)
    {
        ExitProcess(0);
    }
	if (argc < 2){
		printf("Usage: Program.exe <key>\n");
		return 0;
	}
	int number = atoi(argv[1]);
	if (numLen(number) < 8) {
		printf("%d\n", number);
		if (number == key){	printf("Nice ! You have found the key\n");}
	} else {
		printf("The Key must be a number of less than 8 digits long.\n");
	}
	return 0;
}
