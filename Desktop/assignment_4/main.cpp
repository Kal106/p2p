#include "common.h"

using namespace std;

int main(int argc , char* argv[]) {
    string input;
    Command command;
    commandLineParser(input, argc, argv);
    inputParser(input, command);
    cout<<command.command<<"\n";
    for (auto it : command.params) {
        cout<<"Parms: "<<it<<"\n";
    }
    handleCommand(command);
}