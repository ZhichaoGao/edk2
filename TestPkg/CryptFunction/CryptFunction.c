/** @file simple test for new apis in BaseCryptLib

  Copyright (c) 2019, Intel Corporation. All rights reserved.<BR>

  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>

#include <Protocol/ShellParameters.h>

#include "Pkcs7Signature.h"

CONST CHAR8 FIRMWARE_SIGNER_EKU[] = "1.3.6.1.4.1.311.76.9.21.1";

/**
  TestVerifyEKUsInSignature()

  Verify that "1.3.6.1.4.1.311.76.9.21.1" (Firmware signature) is in the
  leaf signer certificate.

**/
static
VOID
EFIAPI
TestVerifyEKUsInSignature (
  VOID
  )
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  CONST CHAR8* RequiredEKUs[] = { FIRMWARE_SIGNER_EKU };

  Status = VerifyEKUsInPkcs7Signature (
            ProductionECCSignature,
            ARRAY_SIZE(ProductionECCSignature),
            (CONST CHAR8**)RequiredEKUs,
            ARRAY_SIZE(RequiredEKUs),
            TRUE);

  Print (L"TestVerifyEKUsInSignature: %r\n", Status);
}// TestVerifyEKUsInSignature()


/**
  TestVerifyEKUsWith3CertsInSignature()
  
  This PKCS7 signature has 3 certificates in it. (Policy CA, Issuing CA
  and leaf signer). It has one firmware signing EKU in it.
  "1.3.6.1.4.1.311.76.9.21.1"

**/
static
VOID
EFIAPI
TestVerifyEKUsWith3CertsInSignature (
  VOID
  )
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  CONST CHAR8* RequiredEKUs[] = { FIRMWARE_SIGNER_EKU };

  Status = VerifyEKUsInPkcs7Signature (
            TestSignEKUsWith3CertsInSignature,
            ARRAY_SIZE(TestSignEKUsWith3CertsInSignature),
            (CONST CHAR8**)RequiredEKUs,
            ARRAY_SIZE(RequiredEKUs),
            TRUE);

  Print (L"TestVerifyEKUsWith3CertsInSignature: %r\n", Status);
}// TestVerifyEKUsWith3CertsInSignature()

/**
  TestVerifyEKUsWith2CertsInSignature()
  
  This PKCS7 signature has 2 certificates in it. (Issuing CA and leaf signer).
  It has one firmware signing EKU in it. "1.3.6.1.4.1.311.76.9.21.1"
 
  @param[in]  Framework - Unit-test framework handle.
  @param[in]  Context   - Optional context pointer for this test.
 
  @retval UNIT_TEST_PASSED            - The required EKUs were found in the signature.
  @retval UNIT_TEST_ERROR_TEST_FAILED - Something failed, check the debug output.
**/
static
VOID
EFIAPI
TestVerifyEKUsWith2CertsInSignature (
  VOID
  )
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  CONST CHAR8* RequiredEKUs[] = { FIRMWARE_SIGNER_EKU };

  Status = VerifyEKUsInPkcs7Signature (
            TestSignEKUsWith2CertsInSignature,
            ARRAY_SIZE(TestSignEKUsWith2CertsInSignature),
            (CONST CHAR8**)RequiredEKUs,
            ARRAY_SIZE(RequiredEKUs),
            TRUE);

  Print (L"TestVerifyEKUsWith2CertsInSignature: %r\n", Status);
}// TestVerifyEKUsWith2CertsInSignature()


/**
  TestVerifyEKUsWith1CertInSignature()
  
  This PKCS7 signature only has the leaf signer in it.
  It has one firmware signing EKU in it. "1.3.6.1.4.1.311.76.9.21.1"

**/
static
VOID
EFIAPI
TestVerifyEKUsWith1CertInSignature (
  VOID
  )
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  CONST CHAR8* RequiredEKUs[] = { FIRMWARE_SIGNER_EKU };

  Status = VerifyEKUsInPkcs7Signature(
            TestSignEKUsWith1CertInSignature,
            ARRAY_SIZE(TestSignEKUsWith1CertInSignature),
            (CONST CHAR8**)RequiredEKUs,
            ARRAY_SIZE(RequiredEKUs),
            TRUE);

  Print (L"TestVerifyEKUsWith1CertInSignature: %r\n", Status);
}// TestVerifyEKUsWith1CertInSignature()


/**
  TestVerifyEKUsWithMultipleEKUsInCert()
  
  
  This signature has two EKU's in it:
  "1.3.6.1.4.1.311.76.9.21.1"
  "1.3.6.1.4.1.311.76.9.21.2"
  We verify that both EKU's were present in the leaf signer.

  @param[in]  Framework - Unit-test framework handle.
  @param[in]  Context   - Optional context pointer for this test.
 
  @retval UNIT_TEST_PASSED            - The required EKUs were found in the signature.
  @retval UNIT_TEST_ERROR_TEST_FAILED - Something failed, check the debug output.
**/
static
VOID
EFIAPI
TestVerifyEKUsWithMultipleEKUsInCert (
  VOID
  )
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  CONST CHAR8* RequiredEKUs[] = { "1.3.6.1.4.1.311.76.9.21.1",
                                  "1.3.6.1.4.1.311.76.9.21.2" };

  Status = VerifyEKUsInPkcs7Signature(TestSignedWithMultipleEKUsInCert,
                                      ARRAY_SIZE(TestSignedWithMultipleEKUsInCert),
                                      (CONST CHAR8**)RequiredEKUs,
                                      ARRAY_SIZE(RequiredEKUs),
                                      TRUE);

  Print (L"TestVerifyEKUsWithMultipleEKUsInCert: %r\n", Status);
}// TestVerifyEKUsWithMultipleEKUsInCert()


/**
  TestEkusNotPresentInSignature()
  
  This test verifies that if we send an EKU that is not in the signature, 
  that we get back an error.

**/
static
VOID
EFIAPI
TestEkusNotPresentInSignature (
  VOID
  )
{
  EFI_STATUS       Status = EFI_SUCCESS;

  //
  // This EKU is not in the signature.
  //
  CONST CHAR8* RequiredEKUs[] = { "1.3.6.1.4.1.311.76.9.21.3" };

  Status = VerifyEKUsInPkcs7Signature(TestSignedWithMultipleEKUsInCert,
                                      ARRAY_SIZE(TestSignedWithMultipleEKUsInCert),
                                      (CONST CHAR8**)RequiredEKUs,
                                      ARRAY_SIZE(RequiredEKUs),
                                      TRUE);

  Print (L"TestEkusNotPresentInSignature: %r\n", Status);
}// TestEkusNotPresentInSignature()

/**
  TestEkusNotPresentInSignature()
  
  This test signature has two EKU's in it:  (Product ID is 10001)
  "1.3.6.1.4.1.311.76.9.21.1"
  "1.3.6.1.4.1.311.76.9.21.1.10001"

**/

static
VOID
EFIAPI
TestProductId10001PresentInSignature(
  VOID
)
{
  EFI_STATUS       Status = EFI_SUCCESS;

  //
  // These EKU's are present in the leaf signer certificate.
  //
  CONST CHAR8* RequiredEKUs[] = { "1.3.6.1.4.1.311.76.9.21.1",
                                  "1.3.6.1.4.1.311.76.9.21.1.10001" };

  Status = VerifyEKUsInPkcs7Signature(TestSignedWithProductId10001,
                                      ARRAY_SIZE(TestSignedWithProductId10001),
                                      (CONST CHAR8**)RequiredEKUs,
                                      ARRAY_SIZE(RequiredEKUs),
                                      TRUE);

  Print (L"TestProductId10001PresentInSignature: %r\n", Status);
}// TestProductId10001PresentInSignature()


/**
  TestOnlyOneEkuInListRequired()
  
  This test will check the BOOLEAN RequireAllPresent parameter in the
  call to VerifyEKUsInPkcs7Signature() behaves properly.  The signature
  has two EKU's in it:

  "1.3.6.1.4.1.311.76.9.21.1"
  "1.3.6.1.4.1.311.76.9.21.1.10001"

  but we only pass in one of them, and set RequireAllPresent to FALSE.

**/

static
VOID
EFIAPI
TestOnlyOneEkuInListRequired(
  VOID
)
{
  EFI_STATUS       Status = EFI_SUCCESS;

  //
  // This will test the flag that specifies it is OK to succeed if 
  // any one of the EKU's passed in is found.
  //
  CONST CHAR8* RequiredEKUs[] = { "1.3.6.1.4.1.311.76.9.21.1.10001" };

  Status = VerifyEKUsInPkcs7Signature(TestSignedWithProductId10001,
                                      ARRAY_SIZE(TestSignedWithProductId10001),
                                      (CONST CHAR8**)RequiredEKUs,
                                      ARRAY_SIZE(RequiredEKUs),
                                      FALSE);

  Print (L"TestOnlyOneEkuInListRequired: %r\n", Status);
}// TestOnlyOneEkuInListRequired()

/**
  TestNoEKUsInSignature()
  
  This test uses a signature that was signed with a certificate that does
  not contain any EKUs.

**/

static
VOID
EFIAPI
TestNoEKUsInSignature(
  VOID
)
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  //
  // This EKU is not in the certificate, so it should fail. 
  //
  CONST CHAR8* RequiredEKUs[] = { "1.3.6.1.4.1.311.76.9.21.1" };

  Status = VerifyEKUsInPkcs7Signature(TestSignatureWithNoEKUsPresent,
                                      ARRAY_SIZE(TestSignatureWithNoEKUsPresent),
                                      (CONST CHAR8**)RequiredEKUs,
                                      ARRAY_SIZE(RequiredEKUs),
                                      TRUE);

  Print (L"TestNoEKUsInSignature: %r\n", Status);
}// TestNoEKUsInSignature()


/**
  TestInvalidParameters()

  Passes the API invalid parameters, and ensures that it does not succeed.

**/
static
VOID
EFIAPI
TestInvalidParameters(
  VOID
)
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  CONST CHAR8* RequiredEKUs[] = { "1.3.6.1.4.1.311.76.9.21.1" };

  //
  // Check bad signature.
  //
  Status = VerifyEKUsInPkcs7Signature(NULL, 
                                      0, 
                                      (CONST CHAR8**)RequiredEKUs,
                                      ARRAY_SIZE(RequiredEKUs),
                                      TRUE);

  //
  // Ensure that the call failed.
  //
  Print (L"TestInvalidParameters: %r\n", Status);


  //
  // Check invalid EKU's
  //
  Status = VerifyEKUsInPkcs7Signature(TestSignatureWithNoEKUsPresent,
                                      ARRAY_SIZE(TestSignatureWithNoEKUsPresent),
                                      (CONST CHAR8**)NULL,
                                      0,
                                      TRUE);
  //
  // Ensure that the call failed.
  //
  Print (L"TestInvalidParameters 2: %r\n", Status);
}// TestInvalidParameters()


/**
  TestEKUSubStringFails()
  
  Pass the API a sub set and super set of an EKU and ensure that they 
  don't pass.

**/
static
VOID
EFIAPI
TestEKUSubsetSupersetFails(
  VOID
)
{
  EFI_STATUS       Status     = EFI_SUCCESS;

  //
  // This signature has an EKU of: 
  // "1.3.6.1.4.1.311.76.9.21.1.10001"
  // so ensure that 
  // "1.3.6.1.4.1.311.76.9.21"
  // does not pass.
  //
  CONST CHAR8* RequiredEKUs1[] = { "1.3.6.1.4.1.311.76.9.21" };

  Status = VerifyEKUsInPkcs7Signature(TestSignedWithProductId10001,
                                      ARRAY_SIZE(TestSignedWithProductId10001),
                                      (CONST CHAR8**)RequiredEKUs1,
                                      ARRAY_SIZE(RequiredEKUs1),
                                      TRUE);


  //
  // Ensure that the call failed.
  //
  Print (L"TestEKUSubsetSupersetFails: %r\n", Status);

  //
  // This signature has an EKU of: 
  // "1.3.6.1.4.1.311.76.9.21.1.10001"
  // so ensure that a super set
  // "1.3.6.1.4.1.311.76.9.21.1.10001.1"
  // does not pass.
  //
  CONST CHAR8* RequiredEKUs2[] = { "1.3.6.1.4.1.311.76.9.21.1.10001.1" };

  Status = VerifyEKUsInPkcs7Signature(TestSignedWithProductId10001,
                                      ARRAY_SIZE(TestSignedWithProductId10001),
                                      (CONST CHAR8**)RequiredEKUs2,
                                      ARRAY_SIZE(RequiredEKUs2),
                                      TRUE);
  Print (L"TestEKUSubsetSupersetFails 2: %r\n", Status);
}// TestEKUSubsetSupersetFails()


VOID
CryptMainFunc (
  UINTN       Argc,
  CHAR16      **Argv
  )
{
  BOOLEAN                   GetName;
  BOOLEAN                   EncryptFile;
  CHAR16                    *FileName;
  UINT8                     *FileBuffer;
  UINT64                    FileSize;
  CHAR16                    *OutFileName;
  UINT8                     *OutFileBuffer;
  UINT64                    OutFileSize;
  CHAR16                    *PubKeyFileName;
  UINT8                     *PubKeyFileBuffer;
  UINT64                    PubKeyFileSize;
  CHAR16                    *PrngSeedName;
  UINT8                     *PrngSeed;
  UINT64                    PrngSeedSize;
  BOOLEAN                   Result;
  SHELL_FILE_HANDLE         FileHandle;
  CHAR8                     OrgName[100];
  UINTN                     OrgNameSize;
  EFI_STATUS                Status;

  if (Argc < 2) {

    TestVerifyEKUsInSignature ();
    TestVerifyEKUsWith3CertsInSignature ();
    TestVerifyEKUsWith2CertsInSignature ();
    TestVerifyEKUsWith1CertInSignature ();
    TestVerifyEKUsWithMultipleEKUsInCert ();
    TestEkusNotPresentInSignature ();
    TestProductId10001PresentInSignature ();
    TestOnlyOneEkuInListRequired ();
    TestNoEKUsInSignature ();
    TestInvalidParameters ();
    TestEKUSubsetSupersetFails ();
    return;
  }

  GetName = !StrCmp (Argv[1], L"getname");
  EncryptFile = !StrCmp (Argv[1], L"encrypt");

  if (GetName) {
    FileName = Argv[2];

    Print (L"FileName: %s\n", FileName);
    Status = ShellOpenFileByName (FileName, &FileHandle, EFI_FILE_MODE_READ, 0);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);
    Status = ShellGetFileSize (FileHandle, &FileSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    FileBuffer = AllocatePool ((UINTN)FileSize);
    if (FileBuffer == NULL) {
      return;
    }

    Status = ShellReadFile (FileHandle, (UINTN *)&FileSize, FileBuffer);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    OrgNameSize = 100;
    Status = X509GetOrganizationName (FileBuffer, (UINTN)FileSize, OrgName, &OrgNameSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    if (!EFI_ERROR (Status)) {
      Print (L"OrgName: %a\n", OrgName);
    }

    Status = X509GetOrganizationName (FileBuffer, (UINTN)0, OrgName, &OrgNameSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    OrgNameSize = 0;
    Status = X509GetOrganizationName (FileBuffer, (UINTN)FileSize, OrgName, &OrgNameSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    OrgNameSize = 100;
    Status = X509GetOrganizationName (FileBuffer, (UINTN)FileSize, NULL, &OrgNameSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);
  }

  if (EncryptFile) {
    FileName = Argv[2];
    Print (L"FileName: %s\n", FileName);
    OutFileName = Argv[3];
    Print (L"OutFileName: %s\n", OutFileName);
    PubKeyFileName = Argv[4];
    Print (L"PubKeyFileName: %s\n", PubKeyFileName);
    PrngSeedName = Argv[5];
    Print (L"PrngSeed: %s\n", PrngSeedName);

    Status = ShellOpenFileByName (FileName, &FileHandle, EFI_FILE_MODE_READ, 0);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);
    Status = ShellGetFileSize (FileHandle, &FileSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    FileBuffer = AllocatePool ((UINTN)FileSize);
    if (FileBuffer == NULL) {
      return;
    }

    Status = ShellReadFile (FileHandle, (UINTN *)&FileSize, FileBuffer);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    Status = ShellOpenFileByName (PubKeyFileName, &FileHandle, EFI_FILE_MODE_READ, 0);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);
    Status = ShellGetFileSize (FileHandle, &PubKeyFileSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    PubKeyFileBuffer = AllocatePool ((UINTN)PubKeyFileSize);
    if (PubKeyFileBuffer == NULL) {
      return;
    }

    Status = ShellReadFile (FileHandle, (UINTN *)&PubKeyFileSize, PubKeyFileBuffer);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    Status = ShellOpenFileByName (PrngSeedName, &FileHandle, EFI_FILE_MODE_READ, 0);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);
    Status = ShellGetFileSize (FileHandle, &PrngSeedSize);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    PrngSeed = AllocatePool ((UINTN)PrngSeedSize);
    if (PrngSeed == NULL) {
      return;
    }

    Status = ShellReadFile (FileHandle, (UINTN *)&PrngSeedSize, PrngSeed);
    Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

    Result = Pkcs1v2Encrypt (
              PubKeyFileBuffer,
              (UINTN)PubKeyFileSize,
              FileBuffer,
              (UINTN)FileSize,
              NULL,
              0,
              &OutFileBuffer,
              (UINTN *)&OutFileSize
              );

    if (Result) {
      // Wirte output file to OutFileName
      Status = ShellOpenFileByName (OutFileName, &FileHandle, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
      Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

      Status = ShellWriteFile (FileHandle, (UINTN *)&OutFileSize, OutFileBuffer);
      Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);
    }

    Result = Pkcs1v2Encrypt (
              PubKeyFileBuffer,
              (UINTN)PubKeyFileSize,
              FileBuffer,
              (UINTN)FileSize,
              PrngSeed,
              (UINTN)PrngSeedSize,
              &OutFileBuffer,
              (UINTN *)&OutFileSize
              );

    if (Result) {
      // Wirte output file to OutFileName
      OutFileName[0] += 1;
      Status = ShellOpenFileByName (OutFileName, &FileHandle, EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE | EFI_FILE_MODE_CREATE, 0);
      Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

      Status = ShellWriteFile (FileHandle, (UINTN *)&OutFileSize, OutFileBuffer);
      Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);
    }

    Result = Pkcs1v2Encrypt (
              PubKeyFileBuffer,
              (UINTN)0,
              FileBuffer,
              (UINTN)FileSize,
              NULL,
              0,
              &OutFileBuffer,
              (UINTN *)&OutFileSize
              );
    Print (L"%a %d: Status: %d\n", __FUNCTION__, __LINE__, Result);

    Result = Pkcs1v2Encrypt (
              NULL,
              (UINTN)PubKeyFileSize,
              FileBuffer,
              (UINTN)FileSize,
              NULL,
              0,
              &OutFileBuffer,
              (UINTN *)&OutFileSize
              );
    Print (L"%a %d: Status: %d\n", __FUNCTION__, __LINE__, Result);

    OutFileSize = 0;
    Result = Pkcs1v2Encrypt (
              PubKeyFileBuffer,
              (UINTN)PubKeyFileSize,
              FileBuffer,
              (UINTN)FileSize,
              NULL,
              0,
              &OutFileBuffer,
              (UINTN *)&OutFileSize
              );
    Print (L"%a %d: Status: %d\n", __FUNCTION__, __LINE__, Result);

    Result = Pkcs1v2Encrypt (
              PubKeyFileBuffer,
              (UINTN)PubKeyFileSize,
              FileBuffer,
              (UINTN)FileSize,
              NULL,
              0,
              (UINT8 **)NULL,
              (UINTN *)&OutFileSize
              );
    Print (L"%a %d: Status: %d\n", __FUNCTION__, __LINE__, Result);

    Result = Pkcs1v2Encrypt (
              PubKeyFileBuffer,
              (UINTN)PubKeyFileSize,
              FileBuffer,
              (UINTN)FileSize,
              NULL,
              0,
              (UINT8 **)&OutFileBuffer,
              (UINTN *)NULL
              );
    Print (L"%a %d: Status: %d\n", __FUNCTION__, __LINE__, Result);
  }

}


EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                    Status;
  EFI_SHELL_PARAMETERS_PROTOCOL *ShellParameters;

  Status = gBS->HandleProtocol (
                  gImageHandle,
                  &gEfiShellParametersProtocolGuid,
                  (VOID**)&ShellParameters
                  );
  Print (L"%a %d: Status: %r\n", __FUNCTION__, __LINE__, Status);

  if (EFI_ERROR (Status)) {
    return Status;
  }

  CryptMainFunc (ShellParameters->Argc, ShellParameters->Argv);

  return EFI_SUCCESS;
}

