/*-
 * chromium-taint.cpp
 * 
 * Source code for our taint analysis engine, tracking taint to combat browser
 * fingerprinting attacks.
 */

#include "branch_pred.h"
#include "libdft_api.h"
#include "pin.H"
#include "syscall_desc.h"
#include "syscall_hook.h"

#include <stdio.h>
#include <stdlib.h>

VOID EntryPoint(VOID *v)
{
  for (IMG img = APP_ImgHead(); IMG_Valid(img); img = IMG_Next(img))
  {
    RTN test_get_rtn = RTN_FindByName(img, "__libdft_get_taint");
    if (RTN_Valid(test_get_rtn))
    {
      // RTN_Open(test_get_rtn);
      // RTN_InsertCall(test_get_rtn, IPOINT_BEFORE, (AFUNPTR)TestGetHandler,
      //                IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);
      // RTN_Close(test_get_rtn);
    }
  }
}

int main(int argc, char **argv)
{
  /* initialize symbol processing */
  PIN_InitSymbols();

  /* initialize Pin; optimized branch */
  if (unlikely(PIN_Init(argc, argv)))
    /* Pin initialization failed */
    goto err;

  /* initialize the core tagging engine */
  if (unlikely(libdft_init() != 0))
    /* failed */
    goto err;

  PIN_AddApplicationStartFunction(EntryPoint, nullptr);

  hook_file_syscall();
  /* start Pin */
  PIN_StartProgram();

  /* typically not reached; make the compiler happy */
  return EXIT_SUCCESS;

err: /* error handling */

  /* return */
  return EXIT_FAILURE;
}
