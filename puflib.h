// PUFlib Main Header File
//
// (C) Copyright 2016 Assured Information Security, Inc.
//
//

#ifndef _PUFLIB_H_
#define _PUFLIB_H_

#include <stdint.h>

enum provisioning_status {
  NOT_SUPPORTED,
  INCOMPLETE,
  COMPLETED
};

struct module_info_s {
  char * name;
  char * author;
  char * desc;
  int8_t (*is_hw_supported)();
  provisioning_status (*provision)();
  int8_t * (*chal_resp)()
};
typedef struct module_info_s module_info;

#include <modules/modules.h>




#endif // _PUFLIB_H_
