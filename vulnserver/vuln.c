#include <stdio.h>

int main ()
{
  char name [80];
  char note [1024];
  int i;

  printf ("Enter your family name: ");
  fflush(stdout);
  scanf ("%s",name);  
  printf("your name is:");
  printf(name);
  fflush(stdout);
  printf ("\nEnter your note: ");
  fflush(stdout);
  scanf ("%s",&note);
  printf ("your note saved, bye!");
  
  return 0;
}
