#include <iostream>
#include <vector>
#include <time.h>
#include <cstdlib>
#include <unistd.h>
#include "compatibilidad.h"
#include "menus.cpp"
using namespace std;

int main(){
   startCompat();
   menus();
   endCompat();
   return 0;
}