/** @file
  This driver installs gEdkiiPeiDebugLibDebugGuid PPI to provide
  debug services for PEIMs.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi/UefiBaseType.h>
#include <Library/PeimEntryPoint.h>
#include <Library/PeiServicesLib.h>
#include "DebugService.h"

EDKII_DEBUG_PPI mDebugPpi = {
  PeiDebugVPrint,
  PeiDebugAssert
};

EFI_PEI_PPI_DESCRIPTOR mDebugServicePpi = {
  (EFI_PEI_PPI_DESCRIPTOR_PPI | EFI_PEI_PPI_DESCRIPTOR_TERMINATE_LIST),
  &gEdkiiDebugPpiGuid,
  (VOID *)&mDebugPpi
};

/**
  Entry point of Debug Service PEIM

  This funciton installs EDKII DEBUG PPI

  @param  FileHandle  Handle of the file being invoked.
  @param  PeiServices Describes the list of possible PEI Services.

  @retval EFI_SUCESS  The entry point of Debug Service PEIM executes successfully.
  @retval Others      Some error occurs during the execution of this function.

**/
EFI_STATUS
EFIAPI
DebugSerivceInitialize (
  IN EFI_PEI_FILE_HANDLE        FileHandle,
  IN CONST EFI_PEI_SERVICES     **PeiServices
  )
{
  return PeiServicesInstallPpi (&mDebugServicePpi);
}

