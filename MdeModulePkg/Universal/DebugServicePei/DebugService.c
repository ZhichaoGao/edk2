/** @file
  Debug services instances for PEI phase.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Ppi/Debug.h>
#include <Library/DebugLib.h>

/**
  Print a debug message to debug output device if the specified error level
  is enabled.

  @param[in] PeiServices              The pointer to the PEI Services Table.
  @param[in] This                     The pointer to this instance of EDKII_DEBUG_PPI
  @param[in] ErrorLevel               The error level of the debug message.
  @param[in] Format                   Format string for the debug message to print.
  @param[in] VaListMarker             VA_LIST marker for the variable argument list.

**/
VOID
EFIAPI
PeiDebugVPrint(
  IN CONST EFI_PEI_SERVICES         **PeiServices,
  IN EDKII_DEBUG_PPI                *This,
  IN UINTN                          ErrorLevel,
  IN CONST CHAR8                    *Format,
  IN VA_LIST                        Marker
  )
{
  DebugVPrint(ErrorLevel, Format, Marker);
}

/**
  Print an assert message containing a filename, line number, and description.
  This may be followed by a breakpoint or a dead loop.

  @param[in] PeiServices              The pointer to the PEI Services Table.
  @param[in] This                     The pointer to this instance of EDKII_DEBUG_PPI
  @param[in] FileName                 The pointer to the name of the source file that
                                      generated the assert condition.
  @param[in] LineNumber               The line number in the source file that generated
                                      the assert condition
  @param[in] Description              The pointer to the description of the assert condition.

**/
VOID
EFIAPI
PeiDebugAssert(
  IN CONST EFI_PEI_SERVICES         **PeiServices,
  IN EDKII_DEBUG_PPI                *This,
  IN CONST CHAR8                    *FileName,
  IN UINTN                          LineNumber,
  IN CONST CHAR8                    *Description
  )
{
  DebugAssert(FileName, LineNumber, Description);
}

