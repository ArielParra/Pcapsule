#pragma once //para que no de problemas de compilacion por inclusion multiple
#ifndef compatibilidad_h
#define compatibilidad_h

#include <iostream>


#include <stdlib.h> //scanf(),printf()
#include <unistd.h> //usleep()

#ifdef delay
#undef delay
#endif
#define delay(ms) usleep(ms * 1000)

/*Teclas compartidas de getch()*/
#define KEY_SPACE 32
#define KEY_TAB 9
#define KEY_ESC 27

/*Modificadores de texto*/
#define RESET_TEXT          "\x1b[0m"
#define BOLD_ON             "\x1b[1m"
#define BOLD_OFF            "\x1b[22m"
#define UNDERLINE_ON        "\x1b[4m"
#define UNDERLINE_ON        "\x1b[4m"
#define UNDERLINE_OFF       "\x1b[24m"
#define REVERSE_ON          "\x1b[7m"
#define REVERSE_OFF         "\x1b[27m"
#define INVISIBLE_ON        "\x1b[8m"
#define INVISIBLE_OFF       "\x1b[28m"
#define DIM_ON              "\x1b[2m"
#define DIM_OFF             "\x1b[22m"
#define CROSS_ON            "\x1b[9m"
#define CROSS_OFF           "\x1b[29m"
#define BLINK_ON            "\x1b[5m"
#define BLINK_OFF           "\x1b[25m"
#define ITALIC_ON           "\x1b[3m"
#define ITALIC_OFF          "\x1b[23m"

/*Modificadores de terminal*/
#define RESET_COLOR         "\x1b[0m"
#define CURSOR_ON          "\033[?25h"
#define CURSOR_OFF           "\033[?25l"
#define CLEAR_SCREEN        "\e[1;1H\e[2J"

/*Colores ANSI */
/*Foreground*/
#define FG_BLACK            "\x1b[30m"
#define FG_RED              "\x1b[31m"       
#define FG_GREEN            "\x1b[32m"      
#define FG_YELLOW           "\x1b[33m"   
#define FG_BLUE             "\x1b[34m"       
#define FG_MAGENTA          "\x1b[35m"    
#define FG_CYAN             "\x1b[36m"
#define FG_WHITE            "\x1b[37m"
#define FG_DEFAULT          "\x1b[39m" 
/*Background*/
#define BG_BLACK            "\x1b[40m"
#define BG_RED              "\x1b[41m"
#define BG_GREEN            "\x1b[42m"
#define BG_YELLOW           "\x1b[43m"
#define BG_BLUE             "\x1b[44m"
#define BG_MAGENTA          "\x1b[45m"
#define BG_CYAN             "\x1b[46m"
#define BG_WHITE            "\x1b[47m"
#define BG_DEFAULT          "\x1b[49m" 

#if defined(_WIN32) || defined(_CYGWIN_) 
inline void clrscr() {system("cls");}

    /*Teclas para getch()*/
    #define KEY_LEFT 75     //ascii 75 es K
    #define KEY_RIGHT 77    //ascii 77 es M
    #define KEY_UP 72       //ascii 72 es H
    #define KEY_DOWN 80     //ascii 80 es P
    #define KEY_ENTER 13    //'\n' on ncurses    
    #define KEY_BACKSPACE 8 
    #define KEY_HOME 71     //ascii 71 es G
    #define KEY_END 79      //ascii 79 es O
    #define KEY_IC 82       //ascii 82 es R
    #define KEY_DC 83       //ascii 83 es S
    #define KEY_PPAGE 73    //ascii 73 es I
    #define KEY_NPAGE 81    //ascii 81 es Q
    #define KEY_F(n) KEY_F_##n
    #define KEY_F_1  59     //ascii 59 es ;
    #define KEY_F_2  60     //ascii 60 es <
    #define KEY_F_3  61     //ascii 61 es =
    #define KEY_F_4  62     //ascii 62 es >
    #define KEY_F_5  63     //ascii 63 es ?
    #define KEY_F_6  64     //ascii 64 es @
    #define KEY_F_7  65     //ascii 65 es A
    #define KEY_F_8  66     //ascii 66 es B
    #define KEY_F_9  67     //ascii 67 es C
    #define KEY_F_10 68     //ascii 68 es D
    #define KEY_F_11 133     
    #define KEY_F_12 134 
    #include <conio.h>   //kbhit(),getch();
    #include <windows.h> //GetConsoleScreenBufferInfo(),GetStdHandle(),SetConsoleCursorPosition(),COORD, etc.

    /*Compatibilidad con Colores (Consola virtual de cmd)*/
    //Definiciones para algunos Compiladores MinGW/CYGWIN antiguos
    #ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING 
        #define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
    #endif
    #ifndef CP_UTF8 
        #define CP_UTF8 65001 
    #endif
    void setANSI(){//Inicia la consola virtual
        DWORD console_mode;
        GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &console_mode);
        console_mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), console_mode);
    }
    void setUTF8(){SetConsoleOutputCP(CP_UTF8);}//compatibilidad con Unicodes


    /*Compatibilidad con conio.h*/
    void gotoxy(int x, int y) {
    COORD coordinate;
    coordinate.X = x;
    coordinate.Y = y;
    SetConsoleCursorPosition(GetStdHandle(STD_OUTPUT_HANDLE), coordinate);
    }
    #include <stdlib.h>
    /*Compatibilidad con ncurses.h*/
    inline void reset_shell_mode(void){}
    inline void reset_prog_mode(void){}
    int getmaxX(){
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
        return(csbi.srWindow.Right-csbi.srWindow.Left);
    }
    int getmaxY(){
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE),&csbi);
        return(csbi.srWindow.Bottom-csbi.srWindow.Top);
    }
    #define LINES getmaxY() 
    #define COLS getmaxX()

      inline void endCompat() { 
        clrscr();
        printf(CURSOR_ON);
    }
    inline void startCompat() {
        setANSI();
        clrscr();
        setUTF8();
        printf(CURSOR_OFF);
    }

#else  //*NIX
void clrscr() { printf(CLEAR_SCREEN);fflush(stdout); }
    /*Compatibilidad con Colores (Consola virtual de cmd)*/
    //En sistemas basados en Unix el sistema suele ya soportar esto asi que es implicito
    void setUTF8(void){};
    void setANSI(void){};
    #include <ncurses.h> //getch()
    #warning "ncurses.h necesita -lncurses como argumento de compilación"

    //Compatibilidad con conio.h

    void gotoxy(int x, int y) {
    printf("%c[%d;%df", 0x1B, y, x);
    fflush(stdout);
    }
/*
    int kbhit() {
        int ch = 0, r = 0;
        nodelay(stdscr, TRUE);
        ch = getch();
        if (ch == ERR) { // no input
            r = FALSE;
        } else { // input
            r = TRUE;
            ungetch(ch);
        }
        nodelay(stdscr, FALSE);
        return (r);
    }
*/
    #include <sys/ioctl.h>
    #include <termios.h>

    bool kbhit()
    {
        termios term;
        tcgetattr(0, &term);

        termios term2 = term;
        term2.c_lflag &= ~ICANON;
        tcsetattr(0, TCSANOW, &term2);

        int byteswaiting;
        ioctl(0, FIONREAD, &byteswaiting);

        tcsetattr(0, TCSANOW, &term);
        return byteswaiting > 0;
    }

    #define _kbhit() kbhit()

    #include <string.h> //strcat()
    int nocbreak_getch() {
    raw(); // nocbreak para getch
    int ch = getch();
    cbreak();
    return ch;
    }
    #undef getch
    #define getch() nocbreak_getch()

    int getche() {
    echo();
    int ch = getch();
    noecho();
    return ch;
    }
    #define _getche getche

    //Compatibilidad con ncurses.h
    #undef  KEY_ENTER      // en ncurses es ctrl + m 
    #define KEY_ENTER '\n' // funciona como en Windows
    inline int getmaxX() { return getmaxx(stdscr); }
    inline int getmaxY() { return getmaxy(stdscr); } 

    inline void endCompat() {
            refresh();
            echo();
            fflush(stdout);
            std::cout<<CURSOR_ON;
            endwin();
            clrscr();
        }
    inline void startCompat() {   
        clrscr();
        initscr();            // Iniciar el modo curses
        std::cout<<CURSOR_OFF; 
        keypad(stdscr, TRUE); // Habilita el uso de teclas como las flechas, etc.
        noecho();             // sin echo() de  getch() como en conio.h
        cbreak();             // Se para con ctrl +C como en Windows
        refresh();            // actualiza la pantalla
    }

#endif 

#endif //compatibilidad_h