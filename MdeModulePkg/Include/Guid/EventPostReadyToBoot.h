/** @file
  GUID is the name of events used with CreateEventEx in order to be notified
  when closely after ReadyToBoot.

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/
#ifndef __EVENT_POST_READY_TO_BOOT_H__
#define __EVENT_POST_READY_TO_BOOT_H__

#define EVENT_POST_READY_TO_BOOT_GUID \
   { 0xa5b489b4, 0x18fd, 0x4425, { 0x91, 0xa4, 0x61, 0x3a, 0xdd, 0xd2, 0x74, 0x5 } }

extern EFI_GUID gEfiEventPostReadyToBootGuid;

#endif

