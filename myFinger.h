#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <utmp.h>
#include <pwd.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

char visionatedUsers[128];
int argL= 0, argM= 0, argP= 0, argS= 1, topArgS= 0, unreadMail= 0, search= 0, firstArg= 0;
int maxLoginName=0, maxRealName= 0;
