/** @file
  GUID is the name of events used with CreateEventEx in order to be notified
  when closely before ReadyToBoot.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#ifndef __EVENT_PRE_READY_TO_BOOT_H__
#define __EVENT_PRE_READY_TO_BOOT_H__

#define EVENT_PRE_READY_TO_BOOT_GUID \
   { 0x7b94c75c, 0x36a4, 0x4aa4, { 0xa1, 0xdf, 0x14, 0xbc, 0x9a, 0x04, 0x9a, 0xe4 } }

extern EFI_GUID gEfiEventPreReadyToBootGuid;

#endif

