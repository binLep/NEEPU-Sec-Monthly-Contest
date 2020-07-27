// powerpc64-linux-gnu-gcc powerpc64-ret2text.c -fno-stack-protector -o pwn
#include <stdio.h>
#include <stdlib.h>

void wuwu(){
    system("/bin/sh");
}

int main(){
    setbuf(stdin, 0);
    setbuf(stdout, 0);
    setbuf(stderr, 0);
    char buf[0x220];
    puts("binLep is really slacking off..");
    read(0, buf, 0x300);
    puts("wuwuwu");
    return 0;
}
