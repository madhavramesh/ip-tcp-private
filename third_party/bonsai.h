#ifndef _BONSAI_H_
#define _BONSAI_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <curses.h>
#include <panel.h>

enum branchType {trunk, shootLeft, shootRight, dying, dead};
struct config {
	int live;
	int infinite;
	int screensaver;
	int printTree;
	int verbosity;
	int lifeStart;
	int multiplier;
	int baseType;
	int seed;
	int leavesSize;
	int save;
	int load;
	int targetBranchCount;
	double timeWait;
	double timeStep;
	char* message;
	char* leaves[64];
	char* saveFile;
	char* loadFile;
};
struct ncursesObjects {
	WINDOW* baseWin;
	WINDOW* treeWin;
	WINDOW* messageBorderWin;
	WINDOW* messageWin;
	PANEL* basePanel;
	PANEL* treePanel;
	PANEL* messageBorderPanel;
	PANEL* messagePanel;
};
struct counters {
	int branches;
	int shoots;
	int shootCounter;
};

void quit(struct config *conf, struct ncursesObjects *objects, int returnCode);

int saveToFile(char* fname, int seed, int branchCount);
int loadFromFile(struct config *conf);

void finish(const struct config *conf, struct counters *myCounters);
void printHelp(void);

void drawBase(WINDOW* baseWin, int baseType);
void drawWins(int baseType, struct ncursesObjects *objects);

void roll(int *dice, int mod);

int checkKeyPress(const struct config *conf, struct counters *myCounters);
void updateScreen(float timeStep);

void chooseColor(enum branchType type, WINDOW* treeWin);
void setDeltas(enum branchType type, int life, int age, int multiplier, int *returnDx, int *returnDy);
char* chooseString(const struct config *conf, enum branchType type, int life, int dx, int dy);
void branch(struct config *conf, struct ncursesObjects *objects, struct counters *myCounters, int y, int x, enum branchType type, int life);
void addSpaces(WINDOW* messageWin, int count, int *linePosition, int maxWidth);

void createMessageWindows(struct ncursesObjects *objects, char* message);
int drawMessage(const struct config *conf, struct ncursesObjects *objects, char* message);

void init(const struct config *conf, struct ncursesObjects *objects);
void growTree(struct config *conf, struct ncursesObjects *objects, struct counters *myCounters);
void printstdscr(void);
char* createDefaultCachePath(void);

int runBonsai(int argc, char* argv[]);

#ifdef __cplusplus
}
#endif

#endif
