inline void PresioneTecla(){
    gotoxy(getmaxX()/2-18,getmaxY()-2);
    cout<<"Presione la tecla espacio para volver";
    fflush(stdout);
    getch();
}

void recuadro(){
#if defined(_WIN32)
gotoxy(0,0);cout<<"█";
#endif
unsigned int x=getmaxX(),j=0;
unsigned int y=getmaxY(),i=0;

//lineas verticales
  while(i<=getmaxY()){
    gotoxy(x,y);cout<<"█";
    gotoxy(0,y--);cout<<"█";
    fflush(stdout);
    i++;
  }
//lineas horizontales
  y=getmaxY();
  while(j<=getmaxX()){
    gotoxy(x,y);cout<<"█";
    gotoxy(x--,0);cout<<"█";
    fflush(stdout);
    j++;
  }
fflush(stdout);
cout<<RESET_COLOR;
}

void mensajeCentrado(const string mensaje){
  clrscr();
  gotoxy(getmaxX()/2 - mensaje.size()/2, getmaxY()/2 + 1);
  cout<<mensaje;fflush(stdout);
  recuadro();
  PresioneTecla();
  clrscr();
}


inline void logouaa()
{
  static const int altura_grafico = 16, ancho_grafico = 43;
  int x = (getmaxX() / 4) - (ancho_grafico / 2), y = (getmaxY() / 2) - (altura_grafico / 2);
  gotoxy(x, y);
  cout << FG_BLUE << "█▒  " << FG_CYAN << "██████       " << FG_CYAN << "██████ " << FG_BLUE << "▒▒█████▒▒▒        ";
  gotoxy(x, y++);
  cout << FG_BLUE << "███  " << FG_CYAN << "███████   " << FG_CYAN << "███████ " << FG_BLUE << "▒█████████████     ";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████                      " << FG_BLUE << "█████   ";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████               " << FG_CYAN << "███████  " << FG_BLUE << "▒███▒ ";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████        " << FG_YELLOW << "██      " << FG_CYAN << "████████ " << FG_BLUE << "▒███▒";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████       " << FG_YELLOW << "████ " << FG_RED << "█    " << FG_CYAN << "████████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████      " << FG_YELLOW << "████ " << FG_RED << "███    " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████     " << FG_YELLOW << "████ " << FG_RED << "█████   " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████    " << FG_YELLOW << "████ " << FG_RED << "██████   " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████    " << FG_YELLOW << "███ " << FG_RED << "██████    " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "███▒ " << FG_CYAN << "███████    " << FG_YELLOW << "██ " << FG_RED << "█████      " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "████ " << FG_CYAN << "████████      " << FG_RED << "████       " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << " ███▒ " << FG_CYAN << "████████      " << FG_RED << "██        " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << " ▒████  " << FG_CYAN << "███████               ███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "   █████                      " << FG_CYAN << "███████ " << FG_BLUE << "▒███";
  gotoxy(x, y++);
  cout << FG_BLUE << "     ▒████████████▒ " << FG_CYAN << "████████   ███████ " << FG_BLUE << "███" << RESET_COLOR;
  fflush(stdout);
}

inline void flecha_derecha()
{
  static const int altura_grafico = 9, ancho_grafico = 14;
  int x = getmaxX() - ancho_grafico, y = getmaxY() - altura_grafico;
  cout << FG_BLUE;
  gotoxy(x, y++);
  cout << "   ▒▒▒▒▒▒▒▒    ";
  gotoxy(x, y++);
  cout << "  ▒        ▒   ";
  gotoxy(x, y++);
  cout << " ▒      ▒   ▒  ";
  gotoxy(x, y++);
  cout << "▒        ▒   ▒ ";
  gotoxy(x, y++);
  cout << "▒  ▒▒▒▒▒▒▒▒  ▒ ";
  gotoxy(x, y++);
  cout << "▒        ▒   ▒ ";
  gotoxy(x, y++);
  cout << " ▒      ▒   ▒  ";
  gotoxy(x, y++);
  cout << "  ▒        ▒   ";
  gotoxy(x, y++);
  cout << "   ▒▒▒▒▒▒▒▒    " << RESET_COLOR;
  fflush(stdout);
}

inline void flecha_izquierda()
{
  static const int altura_grafico = 9;
  int x = 1, y = getmaxY() - altura_grafico;
  cout << FG_BLUE;
  gotoxy(x, y++);
  cout << "   ▒▒▒▒▒▒▒▒    ";
  gotoxy(x, y++);
  cout << "  ▒        ▒   ";
  gotoxy(x, y++);
  cout << " ▒   ▒      ▒  ";
  gotoxy(x, y++);
  cout << "▒   ▒        ▒ ";
  gotoxy(x, y++);
  cout << "▒  ▒▒▒▒▒▒▒▒  ▒ ";
  gotoxy(x, y++);
  cout << "▒   ▒        ▒ ";
  gotoxy(x, y++);
  cout << " ▒   ▒      ▒  ";
  gotoxy(x, y++);
  cout << "  ▒        ▒   ";
  gotoxy(x, y++);
  cout << "   ▒▒▒▒▒▒▒▒    " << RESET_COLOR;
  fflush(stdout);
}

void primer_pantalla()
{
  /*Primer Pantalla*/

  clrscr();
  flecha_derecha();
  static const unsigned int altura_grafico = 16, ancho_grafico = 43;
  unsigned int x = (getmaxX() / 3) + (ancho_grafico / 3);
  unsigned int y = (getmaxY() / 2) - (altura_grafico / 3);
  logouaa();
  x = (getmaxX() / 3) + 18;
  y = (getmaxY() / 2) - (altura_grafico / 3);

  /*Nombres removidos en la version púbica para la proteccion de privacidad*/
  gotoxy(x, y++);
  cout << FG_BLUE << "Nombre del Profesor   ";
  cout << FG_MAGENTA << " Materia: Sistemas Operativos" << RESET_COLOR;

  gotoxy(x, y++);
  cout << FG_CYAN << "Nombres de los integrantes" << RESET_COLOR;
  gotoxy(x, y++);
  fflush(stdout);
}
void segunda_pantalla()
{
  /*segunda Pantalla*/
  clrscr();
  flecha_izquierda();
  flecha_derecha();
  static const int ancho_grafico = 93, altura_grafico = 12;

  int x = (getmaxX() / 2) - (ancho_grafico / 2), y = (getmaxY() / 2) - (altura_grafico / 2);

  cout << FG_BLUE;
  gotoxy(x, y++);
  cout << "██████╗ ██╗   ██╗██████╗ ██████╗ ██╗   ██╗   ██████╗██╗   ██╗ ██████╗████████╗███████╗███╗   ███╗";
  gotoxy(x, y++);
  cout << "██╔══██╗██║   ██║██╔══██╗██╔══██╗╚██╗ ██╔╝  ██╔════╝╚██╗ ██╔╝██╔════╝╚══██╔══╝██╔════╝████╗ ████║";
  gotoxy(x, y++);
  cout << "██████╦╝██║   ██║██║  ██║██║  ██║ ╚████╔╝   ╚█████╗  ╚████╔╝ ╚█████╗    ██║   █████╗  ██╔████╔██║";
  gotoxy(x, y++);
  cout << "██╔══██╗██║   ██║██║  ██║██║  ██║  ╚██╔╝     ╚═══██╗  ╚██╔╝   ╚═══██╗   ██║   ██╔══╝  ██║╚██╔╝██║";
  gotoxy(x, y++);
  cout << "██████╦╝╚██████╔╝██████╔╝██████╔╝   ██║     ██████╔╝   ██║   ██████╔╝   ██║   ███████╗██║ ╚═╝ ██║";
  gotoxy(x, y++);
  cout << "╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝     ╚═════╝    ╚═╝   ╚═════╝    ╚═╝   ╚══════╝╚═╝     ╚═╝" << RESET_COLOR;

  cout << FG_CYAN;
  gotoxy(x, y++);
  cout << "   ██████╗  █████╗ ██╗   ██╗███╗  ██╗██████╗   ██████╗  █████╗ ██████╗ ██████╗ ██╗███╗  ██╗";
  gotoxy(x, y++);
  cout << "   ██╔══██╗██╔══██╗██║   ██║████╗ ██║██╔══██╗  ██╔══██╗██╔══██╗██╔══██╗██╔══██╗██║████╗ ██║";
  gotoxy(x, y++);
  cout << "   ██████╔╝██║  ██║██║   ██║██╔██╗██║██║  ██║  ██████╔╝██║  ██║██████╦╝██████╦╝██║██╔██╗██║";
  gotoxy(x, y++);
  cout << "   ██╔══██╗██║  ██║██║   ██║██║╚████║██║  ██║  ██╔══██╗██║  ██║██╔══██╗██╔══██╗██║██║╚████║";
  gotoxy(x, y++);
  cout << "   ██║  ██║╚█████╔╝╚██████╔╝██║ ╚███║██████╔╝  ██║  ██║╚█████╔╝██████╦╝██████╦╝██║██║ ╚███║";
  gotoxy(x, y++);
  cout << "   ╚═╝  ╚═╝ ╚════╝  ╚═════╝ ╚═╝  ╚══╝╚═════╝   ╚═╝  ╚═╝ ╚════╝ ╚═════╝ ╚═════╝ ╚═╝╚═╝  ╚══╝" << RESET_COLOR;
  fflush(stdout);
}

void tercer_pantalla(int seleccion)
{
  /*tercer Pantalla*/
  clrscr();
  flecha_izquierda();
  fflush(stdout);
  static const char *colores[] = {FG_CYAN, FG_MAGENTA, FG_BLUE, FG_GREEN, FG_YELLOW, FG_BLUE, FG_RED};
  static const char *opciones1[] = {"█▀█ █ █ ▄▀█ █▄ █ ▀█▀ █ █ █▀▄▀█   █▀ █ █▀ ▀█▀ █▀▀ █▀▄▀█ ▄▀█", "█▀█ █ █ ▄▀█ █▄ █ ▀█▀ █ █ █▀▄▀█  █▀█ █▀█ █▀█ █▀▀ █▀▀ █▀ █▀█", "▀█▀ ▄▀█ █▀▄▀█ ▄▀█ █▄ █ █▀█  █▀█ █▀█ █▀█ █▀▀ █▀▀ █▀ █▀█", "▀█▀ ▄▀█ █▀▄▀█ ▄▀█ █▄ █ █▀█  █▀▄▀█ █▀▀ █▀▄▀█ █▀█ █▀█ █ ▄▀█", "█ █▄ █ ▀█▀ █▀▀ █▀█ █ █ ▄▀█ █   █▀█", "█▀ █ █▀▄▀█ █ █ █   ▄▀█ █▀▀ █ █▀█ █▄ █", "█▀ ▄▀█ █   █ █▀█"};
  static const char *opciones2[] = {"▀▀█ █▄█ █▀█ █ ▀█  █  █▄█ █ ▀ █   ▄█ █ ▄█  █  ██▄ █ ▀ █ █▀█", "▀▀█ █▄█ █▀█ █ ▀█  █  █▄█ █ ▀ █  █▀▀ █▀▄ █▄█ █▄▄ ██▄ ▄█ █▄█", " █  █▀█ █ ▀ █ █▀█ █ ▀█ █▄█  █▀▀ █▀▄ █▄█ █▄▄ ██▄ ▄█ █▄█", " █  █▀█ █ ▀ █ █▀█ █ ▀█ █▄█  █ ▀ █ ██▄ █ ▀ █ █▄█ █▀▄ █ █▀█", "█ █ ▀█  █  ██▄ █▀▄ ▀▄▀ █▀█ █▄▄ █▄█", "▄█ █ █ ▀ █ █▄█ █▄▄ █▀█ █▄▄ █ █▄█ █ ▀█", "▄█ █▀█ █▄▄ █ █▀▄"};
  static const int cantidad_opciones = sizeof(opciones2) / sizeof(opciones2[0]);
  static const int altura_grafico = 20, ancho_grafico = 66;
  int x = (getmaxX() / 2) - (ancho_grafico / 2), y = (getmaxY() / 2) - (altura_grafico / 2);

  for (int i = 0; i < cantidad_opciones; i++)
  {
    cout << colores[i];
    if (i == seleccion)
    {
      gotoxy(x, y++);
      cout << "    ▀▄  " << opciones1[i];
      gotoxy(x, y++);
      cout << "▀▀▀▀▀█▀ " << opciones2[i];
      gotoxy(x, y++);
      cout << "    ▀   " << RESET_COLOR;
      gotoxy(x, y++);
    }
    else
    {
      gotoxy(x, y++);
      cout << "        " << opciones1[i];
      gotoxy(x, y++);
      cout << "        " << opciones2[i];
      gotoxy(x, y++);
      cout << "        " << RESET_COLOR;
      gotoxy(x, y++);
    }
  }
  fflush(stdout);
}

void menus()
{
  int pantalla = 1, seleccion = 0;
  const int limite_seleccion = 6;
  bool salir = false;
  while (!salir)
  {

    switch (pantalla)
    {
    case 1:
      primer_pantalla();
      break;
    case 2:
      segunda_pantalla();
      break;
    case 3:
      tercer_pantalla(seleccion);
      break;
    }

    switch (getch())
    {
    case KEY_LEFT:
      if (pantalla > 1)
      {
        pantalla--;
      }
      break;
    case KEY_RIGHT:
      if (pantalla < 3)
      {
        pantalla++;
      }
      break;
    case KEY_UP:
      if (pantalla == 3 && seleccion > 0)
      {
        seleccion--;
      }

      break;
    case KEY_DOWN:
      if (pantalla == 3 && seleccion < limite_seleccion)
      {
        seleccion++;
      }
      break;
    case KEY_ENTER:
      if (pantalla == 3)
      {
        switch (seleccion)
        {
        case 0: // niveles
          break;
        case 1:
          break;
        case 2:
          break;
        case 3:
          break;
        case 4:
          break;
        case 5:
          break;
        case 6: // salir
          endCompat();
          exit(0);
          break;
        }
        break;
      } // if
    } // getch
  } // while
}
