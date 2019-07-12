
#include <Uefi.h>
#include <Library/PcdLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>

EFI_STATUS
TestBase64 (
  VOID
  )
{
  UINT8         *OrgData;
  UINTN         OrgDataSize;
  UINT8         *DestData;
  UINTN         DestDataSize;
  UINT8         *DecodeData;
  UINTN         DecodeDataSize;
  UINT8         *DecodeDataBackup;
  UINTN         DecodeDataBackupSize;
  INTN          Result;
  EFI_STATUS    Status;

  // one byte binary data zero for base64 encode and decode test
  OrgDataSize = 1;
  OrgData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DestDataSize = 5;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);

  Status = Base64Encode (OrgData, OrgDataSize, DestData, &DestDataSize);
  Print (L"Org: %a, DestData: %a, DestDataSize: %x\n", OrgData, DestData, DestDataSize);

  ASSERT (Status == EFI_SUCCESS);

  DecodeData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DecodeDataSize = OrgDataSize;
  Status = Base64Decode (DestData, DestDataSize - 1, DecodeData, &DecodeDataSize);

  if (!EFI_ERROR (Status)) {
    Result = CompareMem (DecodeData, OrgData, DecodeDataSize);
  } else {
    Print (L"Error decode one byte zero binary data!\n");
    return Status;
  }
  if (Result == 0) {
    Print (L"Pass one byte binary data zero for base64 encode and decode test!\n");
  }
  if (OrgData != NULL) {
    FreePool (OrgData);
    OrgData = NULL;
  }
  if (DestData != NULL) {
    FreePool (DestData);
    DestData = NULL;
  }
  if (DecodeData != NULL) {
    FreePool (DecodeData);
    DecodeData = NULL;
  }

  // one byte binary data 'A' for base64 encode and decode test
  OrgDataSize = 2;
  OrgData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DestDataSize = 5;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  *OrgData = 'A';

  Status = Base64Encode (OrgData, OrgDataSize, DestData, &DestDataSize);

  ASSERT (Status == EFI_SUCCESS);

  DecodeData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DecodeDataSize = OrgDataSize;
  Status = Base64Decode (DestData, DestDataSize - 1, DecodeData, &DecodeDataSize);

  if (!EFI_ERROR (Status)) {
    Result = CompareMem (DecodeData, OrgData, DecodeDataSize);
  } else {
    Print (L"Error decode one byte zero binary data!\n");
    return Status;
  }
  if (Result == 0) {
    Print (L"Pass one byte binary data 'A' for base64 encode and decode test!\n");
  }
  if (OrgData != NULL) {
    FreePool (OrgData);
    OrgData = NULL;
  }
  if (DestData != NULL) {
    FreePool (DestData);
    DestData = NULL;
  }
  if (DecodeData != NULL) {
    FreePool (DecodeData);
    DecodeData = NULL;
  }

  // 2 bytes binary data 'A' for base64 encode and decode test
  OrgDataSize = 3;
  OrgData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DestDataSize = 5;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  *OrgData = 'A';

  Status = Base64Encode (OrgData, OrgDataSize, DestData, &DestDataSize);

  ASSERT (Status == EFI_SUCCESS);

  DecodeData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DecodeDataSize = OrgDataSize;
  Status = Base64Decode (DestData, DestDataSize  - 1, DecodeData, &DecodeDataSize);

  if (!EFI_ERROR (Status)) {
    Result = CompareMem (DecodeData, OrgData, DecodeDataSize);
  } else {
    Print (L"Error decode one byte zero binary data!\n");
    return Status;
  }
  if (Result == 0) {
    Print (L"Pass 2 bytes binary data 'A' for base64 encode and decode test!\n");
  }
  if (OrgData != NULL) {
    FreePool (OrgData);
    OrgData = NULL;
  }
  if (DestData != NULL) {
    FreePool (DestData);
    DestData = NULL;
  }
  if (DecodeData != NULL) {
    FreePool (DecodeData);
    DecodeData = NULL;
  }

  // 3 bytes binary data 'A' for base64 encode and decode test
  OrgDataSize = 4;
  OrgData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DestDataSize = 9;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  *OrgData = 'A';

  Status = Base64Encode (OrgData, OrgDataSize, DestData, &DestDataSize);

  ASSERT (Status == EFI_SUCCESS);

  DecodeData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DecodeDataSize = OrgDataSize;
  Status = Base64Decode (DestData, DestDataSize - 1, DecodeData, &DecodeDataSize);

  if (!EFI_ERROR (Status)) {
    Result = CompareMem (DecodeData, OrgData, DecodeDataSize);
  } else {
    Print (L"Error decode one byte zero binary data!\n");
    return Status;
  }
  if (Result == 0) {
    Print (L"Pass 3 bytes binary data 'A' for base64 encode and decode test!\n");
  }
  if (OrgData != NULL) {
    FreePool (OrgData);
    OrgData = NULL;
  }
  if (DestData != NULL) {
    FreePool (DestData);
    DestData = NULL;
  }
  if (DecodeData != NULL) {
    FreePool (DecodeData);
    DecodeData = NULL;
  }

  // 4 bytes binary data 'A' for base64 encode and decode test
  OrgDataSize = 4;
  OrgData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DestDataSize = 9;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  *OrgData = 'A';

  Status = Base64Encode (OrgData, OrgDataSize, DestData, &DestDataSize);

  ASSERT (Status == EFI_SUCCESS);

  DecodeData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DecodeDataSize = OrgDataSize;
  Status = Base64Decode (DestData, DestDataSize - 1, DecodeData, &DecodeDataSize);

  if (!EFI_ERROR (Status)) {
    Result = CompareMem (DecodeData, OrgData, DecodeDataSize);
  } else {
    Print (L"Error decode one byte zero binary data!\n");
    return Status;
  }
  if (Result == 0) {
    Print (L"Pass 4 bytes binary data 'A' for base64 encode and decode test!\n");
  }
  if (OrgData != NULL) {
    FreePool (OrgData);
    OrgData = NULL;
  }
  if (DestData != NULL) {
    FreePool (DestData);
    DestData = NULL;
  }
  if (DecodeData != NULL) {
    FreePool (DecodeData);
    DecodeData = NULL;
  }

  // 5 bytes binary data 'A' for base64 encode and decode test
  OrgDataSize = 5;
  OrgData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DestDataSize = 9;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  *OrgData = 'A';

  Status = Base64Encode (OrgData, OrgDataSize, DestData, &DestDataSize);

  ASSERT (Status == EFI_SUCCESS);

  DecodeData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DecodeDataSize = OrgDataSize;
  Status = Base64Decode (DestData, DestDataSize - 1, DecodeData, &DecodeDataSize);

  if (!EFI_ERROR (Status)) {
    Result = CompareMem (DecodeData, OrgData, DecodeDataSize);
  } else {
    Print (L"Error decode one byte zero binary data!\n");
    return Status;
  }
  if (Result == 0) {
    Print (L"Pass 5 bytes binary data 'A' for base64 encode and decode test!\n");
  }
  if (OrgData != NULL) {
    FreePool (OrgData);
    OrgData = NULL;
  }
  if (DestData != NULL) {
    FreePool (DestData);
    DestData = NULL;
  }
  if (DecodeData != NULL) {
    FreePool (DecodeData);
    DecodeData = NULL;
  }

  // Catch
  OrgDataSize = 5;
  OrgData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DestDataSize = 9;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  *OrgData = 'A';

  Status = Base64Encode (OrgData, OrgDataSize, DestData, &DestDataSize);

  ASSERT (Status == EFI_SUCCESS);

  DecodeData = (UINT8 *)AllocateZeroPool (OrgDataSize);
  DecodeDataSize = 0;
  Status = Base64Decode (DestData, DestDataSize - 1, DecodeData, &DecodeDataSize);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    if (5 == DecodeDataSize) {
      Print (L"Catch RETURN_BUFFER_TOO_SMALL!\n");
    } else {
      // only indicate the failure test, meaningless
      return EFI_INVALID_PARAMETER;
    }
  } else {
    // only indicate the failure test, meaningless
    return EFI_INVALID_PARAMETER;
  }

  // miss line 2000, 2017 (address wraps around), 2040 (Source and Destination overlap)
  // Invalidate data test
  // Catch line 1983
  DestData = NULL;
  DestDataSize = 0;
  DecodeData = NULL;
  DecodeDataSize = 0;
  Status = Base64Decode (DestData, DestDataSize, DecodeData, NULL);
  if (Status == EFI_SUCCESS) {
    Print (L"Source == NULL, SourceDataSize == 0, Destination == NULL, DestinationSize == NULL, return EFI_INVALID_PARAMETER, expect!\n");
  } else {
    Print (L"Status: %r\n", Status);
  }

  // Catch line 2220
  DestData = NULL;
  DestDataSize = 0;
  DecodeData = NULL;
  DecodeDataSize = 0;
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_SUCCESS) {
    Print (L"Source == NULL, SourceDataSize == 0, Destination == NULL, *DestinationSize == 0, return EFI_SUCCESS, expect!\n");
  } else {
    Print (L"Status: %r\n", Status);
  }

  // Catch line 1994
  DestData = NULL;
  DestDataSize = 1;
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"Source == NULL, SourceDataSize == 0, Destination == NULL, *DestinationSize == 1, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // Catch line 2011
  DestData = NULL;
  DestDataSize = 0;
  DecodeDataSize = 1;
  DecodeData = NULL;
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"Source == NULL, SourceDataSize == 0, Destination == NULL, *DestinationSize == 1, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // '=' at 3 (start from 1) the second should be 0x10, 0x20, 0x30 i.e. 'Q', 'g', 'w'

  // Catch line 2139
  DestDataSize = 4;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = 'B';
  DestData[2] = '=';
  DestData[3] = 'C';
  DecodeDataSize = 4;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"DestData == \'AB=C\', SourceDataSize == 4, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // Catch line 2085 SourceChar == '='
  DestDataSize = 4;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = 'Q';
  DestData[2] = '=';
  DestData[3] = 'C';
  DecodeDataSize = 4;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"DestData == \'AB=C\', SourceDataSize == 4, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // '=' Should be at the end
  // Catch line 2085 SixBitGroupsConsumed == 3
  DestDataSize = 5;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = 'Q';
  DestData[2] = '=';
  DestData[3] = '=';
  DestData[4] = '=';
  DecodeDataSize = 6;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"DestData == \'AB===\', SourceDataSize == 4, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // max number of '=' is two
  // catch line 2129
  DestDataSize = 4;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = '=';
  DestData[2] = '=';
  DestData[3] = '=';
  DecodeDataSize = 4;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"DestData == \'A===\', SourceDataSize == 4, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // Other condition
  // catch line 2129
  DestDataSize = 4;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = '=';
  DestData[2] = '=';
  DestData[3] = 'C';
  DecodeDataSize = 4;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"DestData == \'A==C\', SourceDataSize == 4, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // Catch line 2150
  DestDataSize = 4;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = 'B';
  DestData[2] = 'C';
  DestData[3] = 0xff;
  DecodeDataSize = 4;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"DestData == \'A==C\', SourceDataSize == 4, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // Source should be multipul integrator of 4 bytes
  // Catch line 2213
  DestDataSize = 3;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = 'g';
  DestData[2] = '=';
  DecodeDataSize = 4;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (Status == EFI_INVALID_PARAMETER) {
    Print (L"DestData == \'AB=\', SourceDataSize == 3, return EFI_INVALID_PARAMETER, expect!\n");
  }

  // ignore whitespace
  DestDataSize = 10;
  DestData = (UINT8 *)AllocateZeroPool (DestDataSize);
  DestData[0] = 'A';
  DestData[1] = ' ';
  DestData[2] = '\n';
  DestData[3] = 'B';
  DestData[4] = '\t';
  DestData[5] = '\r';
  DestData[6] = '\f';
  DestData[7] = 'C';
  DestData[8] = '\v';
  DestData[9] = 'D';
  DecodeDataSize = 4;
  DecodeData = (UINT8 *)AllocateZeroPool (DestDataSize);
  Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);
  if (!EFI_ERROR (Status)) {
    DecodeDataBackup = (UINT8 *)AllocateZeroPool (DestDataSize);
    CopyMem (DecodeDataBackup, DecodeData, DecodeDataSize);
    DecodeDataBackupSize = DecodeDataSize;
    DestDataSize = 4;
    DestData[0] = 'A';
    DestData[1] = 'B';
    DestData[2] = 'C';
    DestData[3] = 'D';
    Status = Base64Decode (DestData, DestDataSize, DecodeData, &DecodeDataSize);

    if (!EFI_ERROR (Status)) {
      if (DecodeDataSize == DecodeDataBackupSize) {
        Result = CompareMem (DecodeData, DecodeDataBackup, DecodeDataSize);

        if (Result == 0) {
          Print (L"Pass whitespace skip test!\n");
        } else {
          // just indicate the failure, not invalid parameter
          return EFI_INVALID_PARAMETER;
        }
      } else {
        return EFI_INVALID_PARAMETER;
      }
    } else {
      return Status;
    }
  } else {
    return Status;
  }

  return EFI_SUCCESS;
}

/**
  The user Entry Point for Application. The user code starts with this function
  as the real entry point for the application.

  @param[in] ImageHandle    The firmware allocated handle for the EFI image.
  @param[in] SystemTable    A pointer to the EFI System Table.

  @retval EFI_SUCCESS       The entry point is executed successfully.
  @retval other             Some error occurs when executing this entry point.

**/
EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS          Status;

  Status = TestBase64();

  return Status;
}
