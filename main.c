#include <stddef.h>
#include "toolkit.h"

int main(int argc, char **argv)
{
    unsigned char *key = NULL;

    toolkit_init(argc, argv);

    toolkit_keygen(&key);

    toolkit_run(key);
	
    toolkit_exit(key);

    return 0;
}
