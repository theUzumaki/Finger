#include "myFinger.h"

int stringCompare(char *string1, char *string2){
	// help function for sorting, alphabetic order
	int i= 0;
	while (i< 32){
		if (string1[i]<string2[i]){ return -1; }
		else if (string1[i]>string2[i]){ return 1; }
		i++;
	}
	return 0;
}

int compare(const void *string1, const void *string2){
	// help function for sorting
	return (stringCompare((char*)string1, (char*)string2));
}

int strToLower(char *newString, char *oldString){
	// convert a string to all lowercase
	int i= 0;
	while (oldString[i]!= 0){
		newString[i]= tolower(oldString[i]);
		i+= 1;
	}
	return 0;
}

int filePrinter(FILE *file){
	// formats the output of a file to avoid double \n
	int newLine= 0;
	fseek(file, -1, SEEK_END);
	if (fgetc(file)== 10){ newLine= 1; }
	fseek(file, 0, SEEK_SET);

	char c= fgetc(file);

	while ((int)c!= 255){
		printf("%c", c);
		c= fgetc(file);
	}
	if (!newLine) { printf("\n"); };
	fclose(file);
	return 0;
}

FILE *fileRetrieve(char *path, char *userString, int pathSize, char *fileName, struct stat data, FILE *file){
	// checks if a file can be opened and if so loads it
	strncat(path, userString, pathSize-strlen(path));
	strncat(path, fileName, pathSize-strlen(path));
	stat(path, &data);
	const mode_t mode= S_IRUSR;
	if (open(path, O_RDONLY, mode) != 1){
		file= fopen(path, "r");
		return file;
	}
	else {
		return file;
	}
}

struct utmp *utEntryRetrieve(char *user){
	// looks through entry table to find specified one
	struct utmp *entry;
	setutent();
	entry= getutent();
	while (entry!= NULL){
		if (entry->ut_type== USER_PROCESS){
			char toCompare[32]= "";
			strncpy(toCompare, entry->ut_user, 32);
			if (!strcmp(toCompare, user)){
				return entry;
			}
		}
		entry= getutent();
	}
	return NULL;
}

int entryAnalyzer(char *userName, int logged){
	// receives user to analyze and prints data
	char idleTime[32];
	char userString[UT_NAMESIZE];
	struct passwd *pwd_entry, pwdent;
	struct utmp *ut_entry, entry;
	struct tm lastAccessStruct, lastModifiedStruct;
	struct stat machineFile;
	int idle, h, min, sec, days;

	// if user to display is logged retrieves its utmp entry
	if (logged){
		ut_entry= utEntryRetrieve(userName);
		entry= *ut_entry;
	}
	// pwd entry retrieve
	pwd_entry= getpwnam(userName);
	pwdent= *pwd_entry;
	strncpy(userString, pwdent.pw_name, sizeof(userString));

	if (firstArg && argL){ printf("\n"); }
	else { firstArg= 1; }

	//storing of already seen users
	strncat(visionatedUsers, userString, sizeof(visionatedUsers)-strlen(visionatedUsers));

	//breakdown of gecos
	char gecosInfo[64];
	strcpy(gecosInfo, pwdent.pw_gecos);
	gecosInfo[sizeof(gecosInfo)-1]= 0;
	char *pgecos= gecosInfo;
	char *office, *officeNum, *realName;

	realName= strtok_r(pgecos, ",", &pgecos);
	office= strtok_r(pgecos, ",", &pgecos);
	officeNum= strtok_r(pgecos, ",", &pgecos);

	//retrieve of idle time and date of login
	char finalS[32]= "", date[32]= "";
	if (logged){
		long int epoch= entry.ut_tv.tv_sec;
		stat("/dev/tty", &machineFile);

		// different time formats for argL and argS for login date
		if (argL){ strftime(date, sizeof(date), "%a %b %e %H:%M", localtime(&epoch)); }
		else { strftime(date, sizeof(date), "%b %e %H:%M", localtime(&epoch)); }
		if (!access("/dev/tty", F_OK)){ idle= (int)(difftime(time(NULL), machineFile.st_ctime)); }
		else { idle= 0; }
	}

	// formatting of idle time
	if (logged && idle>86399){
		// idle greater of one day
		days= idle/86400;
		sprintf(finalS, "%dd", days);
	}
	else if (logged && idle>3599){
		// idle greater of one hour
		min= idle%3600/60;
		h= idle/3600;
		int j= 0;
		j= sprintf(finalS, "%d:", h);
		if (min>= 10){
			j= sprintf(finalS, "%d:", h);
			sprintf(finalS+j, "%d", min);
		}
		else {
			j= sprintf(finalS, "%d:", h);
			sprintf(finalS+j, "0%d", min);
		}
	}
	else if (logged){
		// idle smaller than one hour
		sec= idle%60;
		min= idle/60;
		sprintf(finalS, "%d", idle/60);
	}
	else {
		// no idle because user is not logged
		strcat(finalS, "*");
	}

	// retrieve of m-time and a-time of mail
	char mailPath[64]= "/var/spool/mail/";
	char mail[32], mailDate1[32], mailDate2[32], lastOpenMail[32];
	FILE *mailFile;
	struct stat mailData;

	strcat(mailPath, userString);
	stat(mailPath, &mailData);
	if (logged && &mailData!= NULL){
		localtime_r(&(mailData.st_atime), &lastAccessStruct);
		localtime_r(&(mailData.st_mtime), &lastModifiedStruct);
		strftime(mailDate1, sizeof(mailDate1), "%a %b %e %H:%M %Y", &lastAccessStruct);
		strftime(mailDate2, sizeof(mailDate2), "%a %b %e %H:%M %Y", &lastModifiedStruct);

		// sets variable of read or unread mail for print formatting
		if (mailData.st_atim.tv_sec<mailData.st_mtim.tv_sec){
			unreadMail= 1;
		}
		else{
			unreadMail= 0;
		}
	}

	// retrieve of plan, project and pgpkey
	char planPath[64]= "/home/", projectPath[64]= "/home/", pgpPath[64]= "/home/";
	int plan= 0, project= 0, pgp= 0;
	FILE *planFile, *projectFile, *pgpFile;
	struct stat planData, projectData, pgpData;

	planFile= fileRetrieve(planPath, userString, sizeof(planPath), "/.plan", planData, planFile);
	if (planFile!= NULL){ plan= 1; }
	projectFile= fileRetrieve(projectPath, userString, sizeof(projectPath), "/.project", projectData, projectFile);
	if (projectFile!= NULL){ project= 1; }
	pgpFile= fileRetrieve(pgpPath, userString, sizeof(pgpPath), "/.pgpkey", pgpData, pgpFile);
	if (pgpFile!= NULL){ pgp= 1; }

	// print of line on screen
	if (argS){
		int spacing1, spacing2, spacing3;

		// aligning the columns
		if (maxLoginName< 8){ spacing1= 11-strlen(userString); }
		else { spacing1= maxLoginName-strlen(userString)+3; }

		if (maxRealName< 8){ spacing2= 12-strlen(realName); }
		else { spacing2= maxRealName-strlen(realName)+4; }

		spacing3= 10-strlen(finalS);

		// print on screen
		if (!logged){
			if (office== NULL){ office== ""; }
			if (officeNum== NULL){ officeNum= ""; }
			printf("%s%*c%s%*c *%*c*%*cNo logins    %s        %s\n", userString, spacing1,0, realName, spacing2,0, 6,0, 3,0, office, officeNum);
		}
		else {
			printf("%s%*c%s%*c%s%*c%s%*c%s (%s)\n", userString, spacing1,0, realName, spacing2,0, entry.ut_line, spacing3,0, finalS, 3,0, date, entry.ut_host);
		}

	}

	if (argL){
		// aligning the columns
		int spacing1= 16-strlen(userString);
		int spacing2= 23-strlen(pwdent.pw_dir);
		printf("Login: %s%*c\t\t\tName: %s\n", userString, spacing1,0, realName);
		printf("Directory: %s%*c\tShell: %s\n", pwdent.pw_dir, spacing2,0, pwdent.pw_shell);
		// office print
		if (office!= NULL){
			printf("Office: %s", office);
			if (officeNum!= NULL){ printf(", %s\n", officeNum); }
			else { printf("\n"); }
		}
		// idle and date of login
		if (logged){
			printf("On since %s (%s) on %s from %s\n", date, tzname[1], entry.ut_line, entry.ut_host);
			if (idle>86399){ printf("   %d days idle\n", days); }
			else if (idle>3599){ printf("   %d hours %d minutes idle\n", h, min); }
			else { printf("   %d minutes %d seconds idle\n", min, sec); }
		}
		else {
			printf("Never logged in.\n");
		}
		// if accessible, last mail read or unread
		if (!access(mailPath, F_OK)){
			stat(mailPath, &mailData);
			if (mailData.st_size> 0){
				if (unreadMail){
					printf("New mail received %s (%s)\n", mailDate2, tzname[1]);
					printf("     Unread since %s (%s)\n", mailDate1, tzname[1]);
				}
				else {
					printf("Mail last read %s (%s)\n", mailDate1, tzname[1]);
				}
			}
			else {
				printf("No mail.\n");
			}
		}
		else {
			printf("No mail.\n");
		}
		//argP prevents print of plan, project and pgpkey
		if (!argP){
			if (pgp){
				printf("PGP key:\n");
				filePrinter(pgpFile);
			}
			if (project){
				printf("Project:\n");
				filePrinter(projectFile);
			}
			if (plan){
				printf("Plan:\n");
				filePrinter(planFile);
			}
			else {
				printf ("No plan.\n");
			}
		}//end of argP
	}//end of argL print
	return 0;
}//end of function


int main(int argc, char* argv[]){
	char userString[UT_NAMESIZE]= "";
	char userArray[128]= "", userToDisplay[128]= "";
	struct utmp *ut_entry, entry;
	struct passwd *pwd_entry, pwdent;
	int i= 0;
	// reading of args
	while (i<argc){
		if (!strcmp(argv[i],"-l") || !strcmp(argv[i],"-L")){
			argL= 1;
			argS= 0;
		}
		else if (!strcmp(argv[i],"-s") || !strcmp(argv[i],"-S")){
			topArgS= 1;
		}
		else if (!strcmp(argv[i],"-m") || !strcmp(argv[i],"-M")){
			argM= 1;
		}
		else if (!strcmp(argv[i],"-p") || !strcmp(argv[i],"-P")){
			argP= 1;
		}
		else if (i>0){
			char userFormat[32]= "/";
			search= 1;
			argL= 1;
			argS= 0;
			strcat(userFormat, argv[i]);
			strcat(userArray, userFormat);
		}
		i+= 1;
	}
	// hierarchy of arg
	if (topArgS){
		argL= 0;
		argS= 1;
	}

	//alphabetic sorting of users to search
	if (search){
		char stringArray[8][32], *user;
		user= strtok(userArray, "/");

		int i= 0;
		while (i< 8){
			memset(stringArray[i], 0, 32);
			i++;
		}
		i= 0;
		// load of user in the array
		while (user!= NULL){
			strcpy(stringArray[i], user);
			i++;
			user= strtok(NULL, "/");
		}
		memset(userArray, 0, sizeof(userArray));;
		qsort(stringArray, 8, 32, compare);
		i= 0;
		while (i< 8){
			// rewriting users from array to string
			if (stringArray[i]!= NULL){
				strcat(userArray, stringArray[i]);
				strcat(userArray, "/");
			}
			i++;
		}
	}

	//retrieve of users to display
	if (!search){
		ut_entry= getutent();
		while (ut_entry!= NULL){
			entry= *ut_entry;
			if (entry.ut_type==USER_PROCESS){
				// copy onto the userToDisplay string
				strncpy(userString, entry.ut_user, sizeof(userString));
				strcat(userToDisplay, userString);
				strcat(userToDisplay, "Y/");

				// retrieve of names to calculate columns formatting
				char *completeName, *gecos;
				gecos= getpwnam(entry.ut_user)->pw_gecos;
				completeName= strtok_r(gecos, ",", &gecos);

				if (strlen(userString)> maxLoginName){
					maxLoginName= strlen(userString);
				}
				if (strlen(completeName)> maxRealName){
					maxRealName= strlen(completeName);
				}
			}
			ut_entry= getutent();
		}
	}
	else {
		ut_entry= getutent();
		while(ut_entry!= NULL){
			entry= *ut_entry;
			if (entry.ut_type==USER_PROCESS){
				// entry.ut_user doesn't have the null terminator, this is to add it
				strncpy(userString, entry.ut_user, sizeof(userString));
				char copyToIterateOn[128]= "", gecos[64]= "";
				char *pointerGecos;
				pointerGecos= gecos;

				strcpy(copyToIterateOn, userArray);
				// string to check already seen users in case of double input of same user
				char *userName= strtok(copyToIterateOn, "/");
				char formattedUser[64]= "";
				strcat(formattedUser, userName);
				strcat(formattedUser, "/");
				// iterates the input string of names for each utmp entry
				while (userName!= NULL && !(strstr(visionatedUsers, formattedUser))){
					char *name, *surname, *pointerToFullName, completeName[64];
					char lowerLoginName[32]= "", lowerUserName[64]= "";
					int booleanUserFound= 0;
					// strings are passed to lowercase to confront them
					strToLower(lowerLoginName, userString);
					strToLower(lowerUserName, userName);
					// gets the real name of the utmp entry and it duplicate it
					// cause is going to be tokenized
					strcpy(pointerGecos, getpwnam(entry.ut_user)->pw_gecos);
					pointerToFullName= strtok_r(pointerGecos, ",", &pointerGecos);
					strcpy(completeName, pointerToFullName);
					// loginName corresponds to an entry in utmp, userName to the names in input
					// checks if the name in input is a login name
					if (!strcmp(lowerUserName, lowerLoginName) && !booleanUserFound){
						booleanUserFound= 1;
						// adding the found user to userToDisplay and visionatedUsers
						strcat(visionatedUsers, userString);
						strcat(visionatedUsers, "/");
						// userToDisplay carries also the info about user logged (Y) or not (N)
						strcat(userToDisplay, userString);
						strcat(userToDisplay, "Y/");
						if (strlen(userString)> maxLoginName){ maxLoginName= strlen(userString); }
						if (strlen(userString)> maxRealName){ maxRealName= strlen(completeName); }
						break;
					}
					// checks if the name in input is a real name
					else if (!argM){
						// iterates on the complete name tokenizing it
						char *pointer;
						name= strtok_r(pointerToFullName, ",", &pointer);
						while (name!= NULL){
							strToLower(name, name);
							// token of real name corresponds to input
							if (!strcmp(name, lowerUserName) && !booleanUserFound){
								booleanUserFound= 1;
								if (strstr(visionatedUsers, userString)){ break; }
								// adding the user to userToDisplay and visionatedUsers
								strcat(visionatedUsers, userString);
								strcat(visionatedUsers, "/");
								strcat(userToDisplay, userString);
								strcat(userToDisplay, "Y/");
								if (strlen(userString)> maxLoginName){ maxLoginName= strlen(userString); }
								if (strlen(completeName)> maxRealName){ maxRealName= strlen(completeName); }
							}
							name= strtok_r(pointerToFullName, " ", &pointerToFullName);
						}
					}

					// last check in case the user to display is not logged but exist using pwd
					pwd_entry= getpwnam(userName);
					if (pwd_entry!= NULL && !booleanUserFound){
						strcpy(pointerGecos, pwd_entry->pw_gecos);
						pointerToFullName= strtok_r(pointerGecos, ",", &pointerGecos);
						strcpy(completeName, pointerToFullName);
						booleanUserFound= 1;
						// adding the found user to userToDisplay and visionatedUsers
						strcat(visionatedUsers, userString);
						strcat(visionatedUsers, "/");
						strcat(userToDisplay, userName);
						strcat(userToDisplay, "N/");
						if (strlen(userName)> maxLoginName){ maxLoginName= strlen(userName); }
						if (strlen(completeName)> maxRealName){ maxRealName= strlen(completeName); }
					}
					// if the user has never been found then the user doesn't exist on disk
					if (!booleanUserFound){ printf("HW_1: %s: no such user.\n", userName); }
					// next user
					userName= strtok(NULL, "/");
					memset(formattedUser, 0, sizeof(formattedUser));
					if (userName!= NULL){ strcat(formattedUser, userName); }
					strcat(formattedUser, "/");
				}
			}
			ut_entry= getutent();
		}
	}

	// print of header
	if (argS){
		int spacing1, spacing2;
		// column alignment
		if (maxLoginName< 8){ spacing1= 6; }
		else { spacing1= maxLoginName-2; }
		if (maxRealName< 8){ spacing2= 8; }
		else { spacing2= maxRealName; }
		printf("Login%*cName%*cTty%*cIdle%*cLogin Time%*cOffice%*cOffice Phone\n", spacing1,0, spacing2,0, 7,0, 3,0, 4,0, 6,0);
	}

	char *user;
	char *pUsers2= userToDisplay;
	user= strtok_r(pUsers2, "/", &pUsers2);
	// looping through the users to display
	while (user!= NULL) {
		char userToBePassed[32]= "";
		// not logged
		if (user[strlen(user)-1]== 78){
			strncpy(userToBePassed, user, strlen(user)-1);
			entryAnalyzer(userToBePassed, 0);
		}
		// logged
		else {
			strncpy(userToBePassed, user, strlen(user)-1);
			entryAnalyzer(userToBePassed, 1);
		}
		user= strtok_r(pUsers2, "/", &pUsers2);
	}

	return 0;
}
