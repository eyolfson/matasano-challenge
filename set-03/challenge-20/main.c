#include "matasano/aes.h"
#include "matasano/utils.h"

#include <unistd.h>

int main()
{
    int ret = 0;

    struct mmaped_bytes file_bytes;
    ret = file_content(&file_bytes, "20.txt");
    if (ret != 0) {
        return ret;
    }

    if (file_bytes.size != write(STDOUT_FILENO,
                                 file_bytes.data, file_bytes.size)) {
        ret = 1;
    }

    fini_mmaped_bytes(&file_bytes);
    return ret;
}
