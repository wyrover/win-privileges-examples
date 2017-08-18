#include "SecurityUtils.h"

#include <Sddl.h>
//#include "FileUtils.h"
#include <Aclapi.h>
#include <ShlObj.h>
#include <ShellAPI.h>
#include <string>

namespace
{

CString GetAbsolutePath(const CString& path)
{
    TCHAR buffer[MAX_PATH + 1] = {0};
    _wfullpath(buffer, (LPCTSTR)path, MAX_PATH);
    return CString(buffer);
}
}


// (b.cardillo 2009-03-26 14:40) - This whole utility source file was created originally for use
// by plid 14887, but I created it separately since it could be useful in general.

// (b.cardillo 2011-01-06 20:34) - A few new utility functions necessary for PLID 33748.

// Returns the unfriendly string associated with the specified SID (e.g. "S-1-5-21-2263713762-513851276-1464104247-1008")
CString SecurityUtils::GetSidRawString(PSID pSID)
{
    CString strRawSIDString;
    {
        LPTSTR pstrName = NULL;

        if (ConvertSidToStringSid(pSID, &pstrName)) {
            strRawSIDString = pstrName;
        }

        LocalFree(pstrName);
    }
    return strRawSIDString;
}

// Takes a relative or absolute path and returns the remote machine name the path references, automatically
// expanding network drive if necessary.  If the path is local, empty string is returned.
// TODO: This is implemented in a way that could be used more generally than just this local source file, so
// ultimately it should be moved somewhere more generic, like FileUtils.  But right now FileUtils doesn't
// have a dependency on mpr.lib, and this function does.  Someday we'll need to move it.
CString GuessSystemNameFromPath(const CString &strFilePath)
{
    CString strAbsolutePath = GetAbsolutePath(strFilePath);

    if (strAbsolutePath.GetLength() > 2) {
        // Detect whether it's a drive letter or unc based path
        if (strAbsolutePath.GetAt(1) == _T(':')) {
            // The only valid drive letters are a-z && A-Z.
            TCHAR c = strAbsolutePath.GetAt(0);

            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
                CString strDrive = strAbsolutePath.Left(2);
                DWORD dwLength = 0;

                if (WNetGetConnection(strDrive, NULL, &dwLength) == ERROR_MORE_DATA) {
                    // Good, allocate the string of the correct size and call it again
                    LPTSTR pstrBase = new TCHAR[dwLength];

                    if (WNetGetConnection(strDrive, pstrBase, &dwLength) == NO_ERROR) {
                        CString strBase = pstrBase;
                        delete []pstrBase;

                        // Ok, now we just need to extract the machine name from the unc base
                        if (strBase.GetLength() > 2 && strBase.GetAt(0) == _T('\\') && strBase.GetAt(1) == _T('\\')) {
                            long nEnd = strBase.Find(_T('\\'), 2);

                            if (nEnd == -1) {
                                nEnd = strBase.GetLength();
                            }

                            return strBase.Mid(2, nEnd - 2);
                        } else {
                            // We got some crazy kind of string back as the mapped path
                            return _T("");
                        }
                    } else {
                        // Weird, we got the size, but then failed after allocating that size
                        delete []pstrBase;
                        return _T("");
                    }
                } else {
                    // Couldn't get info about the drive letter, so it's probably local
                    return _T("");
                }
            } else {
                // Not a valid drive letter
                return _T("");
            }
        } else if (strAbsolutePath.GetAt(0) == _T('\\') && strAbsolutePath.GetAt(1) == _T('\\')) {
            // Unc already
            long nEnd = strAbsolutePath.Find(_T('\\'), 2);

            if (nEnd == -1) {
                nEnd = strAbsolutePath.GetLength();
            }

            return strAbsolutePath.Mid(2, nEnd - 2);
        } else {
            // Unrecognizable path, doesn't start with "X:" or "\\"
            return _T("");
        }
    } else {
        // Invalid path given
        return _T("");
    }
}

// Returns the friendly name of the account that owns the specified file; if the friendly name cannot be
// determined, returns the raw SID string.
CString SecurityUtils::GetFileOwner(const CString &strFilePath)
{
    DWORD dwSizeNeeded = 0;

    if (GetFileSecurity(strFilePath, OWNER_SECURITY_INFORMATION, 0, 0, &dwSizeNeeded) == FALSE &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
        dwSizeNeeded != 0) {
        // Call it again with a buffer of appropriate size
        LPBYTE lpSecurityBuffer = new BYTE[dwSizeNeeded];

        if (GetFileSecurity(strFilePath, OWNER_SECURITY_INFORMATION, lpSecurityBuffer, dwSizeNeeded, &dwSizeNeeded)) {
            // Get the the owner SID from the descriptor
            PSID pSID = NULL;
            BOOL bOwnerDefaulted = FALSE;

            if (GetSecurityDescriptorOwner(lpSecurityBuffer, &pSID, &bOwnerDefaulted)) {
                CString strAns = GetSidAccountName(pSID, _T(""));

                if (!strAns.IsEmpty()) {
                    // Good, we got it.  Fall through
                } else {
                    // Try again this time guessing the system name from the path
                    CString strSystemName = GuessSystemNameFromPath(strFilePath);

                    if (!strSystemName.IsEmpty()) {
                        strAns = GetSidAccountName(pSID, strSystemName);

                        if (!strAns.IsEmpty()) {
                            // Good, we got it this time! Fall through.
                        } else {
                            // Still failed, so just use the raw SID string
                            strAns = GetSidRawString(pSID);
                        }
                    } else {
                        // Couldn't guess the system name, so don't bother trying again (we'd just get the
                        // same failure).  So use the raw SID string.
                        strAns = GetSidRawString(pSID);
                    }
                }

                // We have our answer
                delete []lpSecurityBuffer;
                return strAns;
            } else {
                delete []lpSecurityBuffer;
                return _T("");
            }
        } else {
            delete []lpSecurityBuffer;
            return _T("");
        }
    } else {
        return _T("");
    }
}

// Returns the friendly name of the account that owns the specified NT object; if the friendly name cannot be
// determined, returns the raw SID string.
CString SecurityUtils::GetObjectOwnerName(const CString &strObjectName)
{
    // Pretty simple, just ask Windows for the SID of the object's owner, then return the friendly name
    PSID psidOwner;
    PSECURITY_DESCRIPTOR psd;

    // Ask windows for the SID of the object's owner
    if (GetNamedSecurityInfo(CString(strObjectName).GetBuffer(0), SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION, &psidOwner, NULL, NULL, NULL, &psd) == ERROR_SUCCESS) {
        // Try to get the actual friendly username; we don't bother considering a remote machine name because we're talking
        // about an NT object, which is inherently local to this machine.  It seems conceivable to me that the user doesn't
        // actually exist on this machine (and is operating under more general group permission at the moment); I'm not sure
        // that's possible but even if it is I don't expect it to come up very much at all.  If it becomes an issue we'll
        // have to find a way to guess the machine name, find another way, or more likely just give a slightly different
        // message to the user.
        CString strAns = GetSidAccountName(psidOwner, _T(""));

        if (strAns.IsEmpty()) {
            strAns = GetSidRawString(psidOwner);
        }

        // Free the psd (which is home to the psidOwner, so we don't need to free that)
        LocalFree(psd);
        return strAns;
    } else {
        return _T("");
    }
}

// Handy utility for creating a copy of a SID.  Call LocalFree() to free the SID when you're finished.
PSID SecurityUtils::CopySid(PSID pSid)
{
    DWORD dwLength = GetLengthSid(pSid);
    PSID pSidAns = (PSID)LocalAlloc(LPTR, dwLength);

    if (::CopySid(dwLength, pSidAns, pSid)) {
        return pSidAns;
    } else {
        LocalFree(pSidAns);
        return NULL;
    }
}

// Returns a user account SID associated with the specified token.  Call LocalFree() to free the SID when you're finished.
BOOL SecurityUtils::GetTokenUserSid(HANDLE token, PSID *ppSID)
{
    *ppSID = NULL;
    DWORD cb = 0;

    if (GetTokenInformation(token, TokenUser, NULL, 0, &cb) == FALSE && GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
        PTOKEN_USER ptokUser = (PTOKEN_USER)LocalAlloc(LPTR, cb);

        if (GetTokenInformation(token, TokenUser, ptokUser, cb, &cb)) {
            *ppSID = CopySid(ptokUser->User.Sid);
            LocalFree(ptokUser);
            return TRUE;
        } else {
            LocalFree(ptokUser);
            return FALSE;
        }
    } else {
        return FALSE;
    }
}

// Returns a user account SID associated with the specified process.  Call LocalFree() to free the SID when you're finished.
BOOL SecurityUtils::GetProcessUserSid(HANDLE hProcess, PSID *ppSID)
{
    *ppSID = NULL;
    HANDLE procToken = NULL;

    if (OpenProcessToken(hProcess, TOKEN_QUERY, &procToken)) {
        BOOL ret = GetTokenUserSid(procToken, ppSID);
        CloseHandle(procToken);
        return ret;
    } else {
        return FALSE;
    }
}

// Returns a pointer to a new SECURITY_DESCRIPTOR object with the specified parameters.  Call LocalFree() to destroy it.
PSECURITY_DESCRIPTOR SecurityUtils::CreateSecurityDescriptor(BOOL bCurUserIsOwner, DWORD grfEveryoneAccessPermissions)
{
    // Create a well-known SID for the Everyone group.
    PSID pEveryoneSID;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;

    if (AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSID)) {
        // Initialize an EXPLICIT_ACCESS structure for an ACE.
        // The ACE will allow Everyone read access to the key.
        EXPLICIT_ACCESS eaEveryoneReadWrite;
        ZeroMemory(&eaEveryoneReadWrite, sizeof(EXPLICIT_ACCESS));
        eaEveryoneReadWrite.grfAccessPermissions = grfEveryoneAccessPermissions;
        eaEveryoneReadWrite.grfAccessMode = SET_ACCESS;
        eaEveryoneReadWrite.grfInheritance = NO_INHERITANCE;
        eaEveryoneReadWrite.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        eaEveryoneReadWrite.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
        eaEveryoneReadWrite.Trustee.ptstrName  = (LPTSTR)pEveryoneSID;
        // Create a new ACL that contains the new ACE.
        PACL pACL = NULL;
        DWORD dwRes = SetEntriesInAcl(1, &eaEveryoneReadWrite, NULL, &pACL);

        if (ERROR_SUCCESS == dwRes) {
            // Create a security descriptor.
            PSECURITY_DESCRIPTOR pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH);

            if (pSD != NULL) {
                // Initialize the security descriptor
                if (InitializeSecurityDescriptor(pSD, SECURITY_DESCRIPTOR_REVISION)) {
                    // Optionally set the owner
                    PSID pUserSid;

                    if (bCurUserIsOwner) {
                        if (GetProcessUserSid(GetCurrentProcess(), &pUserSid)) {
                            if (SetSecurityDescriptorOwner(pSD, pUserSid, FALSE)) {
                                // Fall through to the rest of the function
                            } else {
                                // SetSecurityDescriptorDacl() failed
                                LocalFree(pUserSid);
                                LocalFree(pSD);
                                LocalFree(pACL);
                                FreeSid(pEveryoneSID);
                                return NULL;
                            }
                        } else {
                            // SetSecurityDescriptorDacl() failed
                            LocalFree(pSD);
                            LocalFree(pACL);
                            FreeSid(pEveryoneSID);
                            return NULL;
                        }
                    } else {
                        pUserSid = NULL;
                    }

                    // Add the ACL to the security descriptor.
                    {
                        if (SetSecurityDescriptorDacl(pSD, TRUE, pACL, FALSE)) {
                            // Success!
                            FreeSid(pEveryoneSID);
                            return pSD;
                        } else {
                            // SetSecurityDescriptorDacl() failed
                            if (pUserSid != NULL) {
                                LocalFree(pUserSid);
                            }

                            LocalFree(pSD);
                            LocalFree(pACL);
                            FreeSid(pEveryoneSID);
                            return NULL;
                        }
                    }
                } else {
                    // InitializeSecurityDescriptor() failed
                    LocalFree(pSD);
                    LocalFree(pACL);
                    FreeSid(pEveryoneSID);
                    return NULL;
                }
            } else {
                // LocalAlloc() failed
                LocalFree(pACL);
                FreeSid(pEveryoneSID);
                return NULL;
            }
        } else {
            // SetEntriesInAcl() failed
            FreeSid(pEveryoneSID);
            return NULL;
        }
    } else {
        // AllocateAndInitializeSid() failed
        return NULL;
    }
}

// Creates a security attributes object with the specified parameters.  Call DestroySecurityAttributes() to destroy it.
LPSECURITY_ATTRIBUTES SecurityUtils::CreateSecurityAttributes(BOOL bCurUserIsOwner, DWORD grfEveryoneAccessPermissions)
{
    // Instantiate and initialize the sa
    LPSECURITY_ATTRIBUTES psa = (LPSECURITY_ATTRIBUTES)LocalAlloc(LPTR, sizeof(SECURITY_ATTRIBUTES));
    psa->nLength = sizeof(SECURITY_ATTRIBUTES);
    psa->bInheritHandle = FALSE;
    // Create the descriptor and set our psa to point to it
    psa->lpSecurityDescriptor = CreateSecurityDescriptor(bCurUserIsOwner, grfEveryoneAccessPermissions);

    // Return success or failure
    if (psa->lpSecurityDescriptor != NULL) {
        return psa;
    } else {
        DWORD dwLastError = GetLastError();
        LocalFree(psa);
        SetLastError(dwLastError);
        return NULL;
    }
}

// Destroys a security attributes object created by CreateSecurityAttributes()
BOOL SecurityUtils::DestroySecurityAttributes(LPSECURITY_ATTRIBUTES psa)
{
    // Destroy the descriptor
    if (psa != NULL) {
        // See if there's a descriptor to destroy
        if (psa->lpSecurityDescriptor != NULL) {
            // Determine the pSidOwner to destroy
            PSID pSidOwner = NULL;
            {
                BOOL bOwnerDefaulted = TRUE;

                if (GetSecurityDescriptorOwner(psa->lpSecurityDescriptor, &pSidOwner, &bOwnerDefaulted)) {
                    if (pSidOwner != NULL && bOwnerDefaulted == FALSE) {
                        // Got it, we know what to destroy
                    } else {
                        // None to destroy
                        pSidOwner = FALSE;
                    }
                } else {
                    // Bad security descriptor?
                    return FALSE;
                }
            }
            // Determine the pACL to destroy
            PACL pACL = NULL;
            {
                BOOL bDaclPresent, bDaclDefaulted;

                if (GetSecurityDescriptorDacl(psa->lpSecurityDescriptor, &bDaclPresent, &pACL, &bDaclDefaulted)) {
                    if (bDaclPresent && !bDaclDefaulted) {
                        if (pACL != NULL) {
                            // Got it, we know what to destroy
                        } else {
                            // None to destroy
                            pACL = NULL;
                        }
                    } else {
                        // None to destroy
                        pACL = NULL;
                    }
                } else {
                    // Bad security descriptor?
                    return FALSE;
                }
            }

            // Ok, now we know what to destroy, so destroy it
            if (pSidOwner != NULL) {
                LocalFree(pSidOwner);
            }

            if (pACL != NULL) {
                LocalFree(pACL);
            }

            // And destroy the descriptor
            LocalFree(psa->lpSecurityDescriptor);
            psa->lpSecurityDescriptor = NULL;
        }

        // And finally destroy the security attributes object itself
        LocalFree(psa);
        return TRUE;
    } else {
        // Bad pointer passed
        return FALSE;
    }
}

// Returns a friendly username corresponding to the user account of the given SID.  This can be slow, especially for
// remote accounts, so consider displaying GetSidRawString() first and then calling this function asynchronously.
CString SecurityUtils::GetSidAccountName(PSID pSid, OPTIONAL const CString &strSystemName)
{
    DWORD dwNameLen = 0;
    DWORD dwDomainNameLen = 0;
    SID_NAME_USE sidNameUse = SidTypeUser;

    if (LookupAccountSid(strSystemName, pSid, NULL, &dwNameLen, NULL, &dwDomainNameLen, &sidNameUse) == FALSE &&
        GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
        dwNameLen != 0 &&
        dwDomainNameLen != 0 &&
        sidNameUse == SidTypeUser) {
        LPTSTR pstrName = new TCHAR[dwNameLen];
        LPTSTR pstrDomainName = new TCHAR[dwDomainNameLen];

        if (LookupAccountSid(strSystemName, pSid, pstrName, &dwNameLen, pstrDomainName, &dwDomainNameLen, &sidNameUse)) {
            CString strAns = pstrDomainName + CString(_T("\\")) + pstrName;
            delete []pstrName;
            delete []pstrDomainName;
            return strAns;
        } else {
            delete []pstrName;
            delete []pstrDomainName;
            return _T("");
        }
    } else {
        return _T("");
    }
}

// Creates a file at the specified path the same way CreateFile() does, applying a
// security descriptor according to the "Sec" parameters.
HANDLE SecurityUtils::CreateSecureFile(LPCTSTR strFilePathName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile, BOOL bSec_CurUserIsObjectOwner, DWORD grfSec_EveryoneAccessPermissions)
{
    // Create the self-owned public security attributes object
    LPSECURITY_ATTRIBUTES psa = CreateSecurityAttributes(bSec_CurUserIsObjectOwner, grfSec_EveryoneAccessPermissions);

    if (psa != NULL) {
        // Good, now create the mutex with the self-owned public security attributes
        HANDLE hAns = CreateFile(strFilePathName, dwDesiredAccess, dwShareMode, psa, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
        DWORD dwLastError = GetLastError();
        // Destroy our security attributes object, now that it's been copied into the mutex
        DestroySecurityAttributes(psa);
        SetLastError(dwLastError);
        // Return the result
        return hAns;
    } else {
        // Couldn't create self-owned security attributes
        return INVALID_HANDLE_VALUE;
    }
}

// Creates a mutex of the specified name the same way CreateMutex() does, applying a
// security descriptor according to the "Sec" parameters.
HANDLE SecurityUtils::CreateSecureMutex(LPCTSTR strMutexName, BOOL bEnterMutexOnCreate, BOOL bSec_CurUserIsObjectOwner, DWORD grfSec_EveryoneAccessPermissions)
{
    // Create the self-owned public security attributes object
    LPSECURITY_ATTRIBUTES psa = CreateSecurityAttributes(bSec_CurUserIsObjectOwner, grfSec_EveryoneAccessPermissions);

    if (psa != NULL) {
        // Good, now create the mutex with the self-owned public security attributes
        HANDLE hMut = CreateMutex(psa, bEnterMutexOnCreate, strMutexName);
        DWORD dwLastError = GetLastError();
        // Destroy our security attributes object, now that it's been copied into the mutex
        DestroySecurityAttributes(psa);
        SetLastError(dwLastError);
        // Return the result
        return hMut;
    } else {
        // Couldn't create self-owned security attributes
        return NULL;
    }
}

////////////////////////////////////////////////////////////


DWORD
GetCurrentUserSID(
    PSID *Sid
)
{
    TOKEN_USER  *tokenUser = NULL;
    HANDLE      tokenHandle;
    DWORD       tokenSize;
    DWORD       sidLength;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        GetTokenInformation(tokenHandle,
                            TokenUser,
                            tokenUser,
                            0,
                            &tokenSize);
        tokenUser = (TOKEN_USER *) malloc(tokenSize);

        if (GetTokenInformation(tokenHandle,
                                TokenUser,
                                tokenUser,
                                tokenSize,
                                &tokenSize)) {
            sidLength = GetLengthSid(tokenUser->User.Sid);          

            *Sid = (PSID) malloc(sidLength);
            memcpy(*Sid, tokenUser->User.Sid, sidLength);
            CloseHandle(tokenHandle);
        } else {
            free(tokenUser);
            return GetLastError();
        }
    } else {
        free(tokenUser);
        return GetLastError();
    }

    free(tokenUser);
    return ERROR_SUCCESS;
}


DWORD
CreateNewSD(
    SECURITY_DESCRIPTOR **SD
)
{
    PACL    dacl;
    DWORD   sidLength;
    PSID    sid;
    PSID    groupSID;
    PSID    ownerSID;
    DWORD   returnValue;
    *SD = NULL;
    returnValue = GetCurrentUserSID(&sid);

    if (returnValue != ERROR_SUCCESS)
        return returnValue;

    sidLength = GetLengthSid(sid);
    *SD = (SECURITY_DESCRIPTOR *) malloc(
              (sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sidLength) +
              (2 * sidLength) +
              sizeof(SECURITY_DESCRIPTOR));
    groupSID = (SID *)(*SD + 1);
    ownerSID = (SID *)(((BYTE *) groupSID) + sidLength);
    dacl = (ACL *)(((BYTE *) ownerSID) + sidLength);

    if (!InitializeSecurityDescriptor(*SD, SECURITY_DESCRIPTOR_REVISION)) {
        free(*SD);
        free(sid);
        return GetLastError();
    }

    if (!InitializeAcl(dacl,
                       sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + sidLength,
                       ACL_REVISION2)) {
        free(*SD);
        free(sid);
        return GetLastError();
    }

    if (!AddAccessAllowedAce(dacl,
                             ACL_REVISION2,
                             COM_RIGHTS_EXECUTE,
                             sid)) {
        free(*SD);
        free(sid);
        return GetLastError();
    }

    if (!SetSecurityDescriptorDacl(*SD, TRUE, dacl, FALSE)) {
        free(*SD);
        free(sid);
        return GetLastError();
    }

    memcpy(groupSID, sid, sidLength);

    if (!SetSecurityDescriptorGroup(*SD, groupSID, FALSE)) {
        free(*SD);
        free(sid);
        return GetLastError();
    }

    memcpy(ownerSID, sid, sidLength);

    if (!SetSecurityDescriptorOwner(*SD, ownerSID, FALSE)) {
        free(*SD);
        free(sid);
        return GetLastError();
    }

    return ERROR_SUCCESS;
}


DWORD
MakeSDAbsolute(
    PSECURITY_DESCRIPTOR OldSD,
    PSECURITY_DESCRIPTOR *NewSD
)
{
    PSECURITY_DESCRIPTOR  sd = NULL;
    DWORD                 descriptorSize;
    DWORD                 daclSize;
    DWORD                 saclSize;
    DWORD                 ownerSIDSize;
    DWORD                 groupSIDSize;
    PACL                  dacl;
    PACL                  sacl;
    PSID                  ownerSID;
    PSID                  groupSID;
    BOOL                  present;
    BOOL                  systemDefault;

    //
    // Get SACL
    //

    if (!GetSecurityDescriptorSacl(OldSD, &present, &sacl, &systemDefault))
        return GetLastError();

    if (sacl && present) {
        saclSize = sacl->AclSize;
    } else saclSize = 0;

    //
    // Get DACL
    //

    if (!GetSecurityDescriptorDacl(OldSD, &present, &dacl, &systemDefault))
        return GetLastError();

    if (dacl && present) {
        daclSize = dacl->AclSize;
    } else daclSize = 0;

    //
    // Get Owner
    //

    if (!GetSecurityDescriptorOwner(OldSD, &ownerSID, &systemDefault))
        return GetLastError();

    ownerSIDSize = GetLengthSid(ownerSID);

    //
    // Get Group
    //

    if (!GetSecurityDescriptorGroup(OldSD, &groupSID, &systemDefault))
        return GetLastError();

    groupSIDSize = GetLengthSid(groupSID);
    //
    // Do the conversion
    //
    descriptorSize = 0;
    MakeAbsoluteSD(OldSD, sd, &descriptorSize, dacl, &daclSize, sacl,
                   &saclSize, ownerSID, &ownerSIDSize, groupSID,
                   &groupSIDSize);
    sd = (PSECURITY_DESCRIPTOR) new BYTE [SECURITY_DESCRIPTOR_MIN_LENGTH];

    if (!InitializeSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION))
        return GetLastError();

    if (!MakeAbsoluteSD(OldSD, sd, &descriptorSize, dacl, &daclSize, sacl,
                        &saclSize, ownerSID, &ownerSIDSize, groupSID,
                        &groupSIDSize))
        return GetLastError();

    *NewSD = sd;
    return ERROR_SUCCESS;
}

DWORD
SetNamedValueSD(
    HKEY RootKey,
    LPTSTR KeyName,
    LPTSTR ValueName,
    SECURITY_DESCRIPTOR *SD
)
{
    DWORD   returnValue;
    DWORD   disposition;
    HKEY    registryKey;
    //
    // Create new key or open existing key
    //
    returnValue = RegCreateKeyEx(RootKey, KeyName, 0, TEXT(""), 0, KEY_ALL_ACCESS, NULL, &registryKey, &disposition);

    if (returnValue != ERROR_SUCCESS)
        return returnValue;

    //
    // Write the security descriptor
    //
    returnValue = RegSetValueEx(registryKey, ValueName, 0, REG_BINARY, (LPBYTE) SD, GetSecurityDescriptorLength(SD));

    if (returnValue != ERROR_SUCCESS)
        return returnValue;

    RegCloseKey(registryKey);
    return ERROR_SUCCESS;
}

DWORD
GetNamedValueSD(
    HKEY RootKey,
    LPTSTR KeyName,
    LPTSTR ValueName,
    SECURITY_DESCRIPTOR **SD,
    BOOL *NewSD
)
{
    DWORD               returnValue;
    HKEY                registryKey;
    DWORD               valueType;
    DWORD               valueSize;
    *NewSD = FALSE;
    //
    // Get the security descriptor from the named value. If it doesn't
    // exist, create a fresh one.
    //
    returnValue = RegOpenKeyEx(RootKey, KeyName, 0, KEY_ALL_ACCESS, &registryKey);

    if (returnValue != ERROR_SUCCESS) {
        if (returnValue == ERROR_FILE_NOT_FOUND) {
            *SD = NULL;
            returnValue = CreateNewSD(SD);

            if (returnValue != ERROR_SUCCESS)
                return returnValue;

            *NewSD = TRUE;
            return ERROR_SUCCESS;
        } else
            return returnValue;
    }

    returnValue = RegQueryValueEx(registryKey, ValueName, NULL, &valueType, NULL, &valueSize);

    if (returnValue && returnValue != ERROR_INSUFFICIENT_BUFFER) {
        *SD = NULL;
        returnValue = CreateNewSD(SD);

        if (returnValue != ERROR_SUCCESS)
            return returnValue;

        *NewSD = TRUE;
    } else {
        *SD = (SECURITY_DESCRIPTOR *) malloc(valueSize);
        returnValue = RegQueryValueEx(registryKey, ValueName, NULL, &valueType, (LPBYTE) * SD, &valueSize);

        if (returnValue) {
            free(*SD);
            *SD = NULL;
            returnValue = CreateNewSD(SD);

            if (returnValue != ERROR_SUCCESS)
                return returnValue;

            *NewSD = TRUE;
        }
    }

    RegCloseKey(registryKey);
    return ERROR_SUCCESS;
}

DWORD
ListNamedValueSD(
    HKEY RootKey,
    LPTSTR KeyName,
    LPTSTR ValueName
)
{
    DWORD               returnValue;
    SECURITY_DESCRIPTOR *sd;
    BOOL                present;
    BOOL                defaultDACL;
    PACL                dacl;
    BOOL                newSD = FALSE;
    returnValue = GetNamedValueSD(RootKey, KeyName, ValueName, &sd, &newSD);

    if ((returnValue != ERROR_SUCCESS) || (newSD == TRUE)) {
        free(sd);
        return returnValue;
    }

    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaultDACL)) {
        free(sd);
        return GetLastError();
    }

    if (!present) {
        free(sd);
        return ERROR_SUCCESS;
    }

    ListACL(dacl);
    free(sd);
    return ERROR_SUCCESS;
}

DWORD
AddPrincipalToNamedValueSD(
    HKEY RootKey,
    LPTSTR KeyName,
    LPTSTR ValueName,
    LPTSTR Principal,
    BOOL Permit
)
{
    DWORD               returnValue;
    SECURITY_DESCRIPTOR *sd = NULL;
    SECURITY_DESCRIPTOR *sdSelfRelative = NULL;
    SECURITY_DESCRIPTOR *sdAbsolute = NULL;
    DWORD               secDescSize;
    BOOL                present;
    BOOL                defaultDACL;
    PACL                dacl;
    BOOL                newSD = FALSE;
    returnValue = GetNamedValueSD(RootKey, KeyName, ValueName, &sd, &newSD);

    //
    // Get security descriptor from registry or create a new one
    //

    if (returnValue != ERROR_SUCCESS)
        return returnValue;

    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaultDACL))
        return GetLastError();

    if (newSD) {
        AddAccessAllowedACEToACL(&dacl, COM_RIGHTS_EXECUTE, TEXT("SYSTEM"));
        AddAccessAllowedACEToACL(&dacl, COM_RIGHTS_EXECUTE, TEXT("INTERACTIVE"));
    }

    //
    // Add the Principal that the caller wants added
    //

    if (Permit)
        returnValue = AddAccessAllowedACEToACL(&dacl, COM_RIGHTS_EXECUTE, Principal);
    else
        returnValue = AddAccessDeniedACEToACL(&dacl, GENERIC_ALL, Principal);

    if (returnValue != ERROR_SUCCESS) {
        free(sd);
        return returnValue;
    }

    //
    // Make the security descriptor absolute if it isn't new
    //

    if (!newSD)
        MakeSDAbsolute((PSECURITY_DESCRIPTOR) sd, (PSECURITY_DESCRIPTOR *) &sdAbsolute);
    else
        sdAbsolute = sd;

    //
    // Set the discretionary ACL on the security descriptor
    //

    if (!SetSecurityDescriptorDacl(sdAbsolute, TRUE, dacl, FALSE))
        return GetLastError();

    //
    // Make the security descriptor self-relative so that we can
    // store it in the registry
    //
    secDescSize = 0;
    MakeSelfRelativeSD(sdAbsolute, sdSelfRelative, &secDescSize);
    sdSelfRelative = (SECURITY_DESCRIPTOR *) malloc(secDescSize);

    if (!MakeSelfRelativeSD(sdAbsolute, sdSelfRelative, &secDescSize))
        return GetLastError();

    //
    // Store the security descriptor in the registry
    //
    SetNamedValueSD(RootKey, KeyName, ValueName, sdSelfRelative);
    free(sd);
    free(sdSelfRelative);
    free(sdAbsolute);
    return ERROR_SUCCESS;
}

DWORD
RemovePrincipalFromNamedValueSD(
    HKEY RootKey,
    LPTSTR KeyName,
    LPTSTR ValueName,
    LPTSTR Principal
)
{
    DWORD               returnValue;
    SECURITY_DESCRIPTOR *sd = NULL;
    SECURITY_DESCRIPTOR *sdSelfRelative = NULL;
    SECURITY_DESCRIPTOR *sdAbsolute = NULL;
    DWORD               secDescSize;
    BOOL                present;
    BOOL                defaultDACL;
    PACL                dacl;
    BOOL                newSD = FALSE;
    returnValue = GetNamedValueSD(RootKey, KeyName, ValueName, &sd, &newSD);

    //
    // Get security descriptor from registry or create a new one
    //

    if (returnValue != ERROR_SUCCESS)
        return returnValue;

    if (!GetSecurityDescriptorDacl(sd, &present, &dacl, &defaultDACL))
        return GetLastError();

    //
    // If the security descriptor is new, add the required Principals to it
    //

    if (newSD) {
        AddAccessAllowedACEToACL(&dacl, COM_RIGHTS_EXECUTE, TEXT("SYSTEM"));
        AddAccessAllowedACEToACL(&dacl, COM_RIGHTS_EXECUTE, TEXT("INTERACTIVE"));
    }

    //
    // Remove the Principal that the caller wants removed
    //
    returnValue = RemovePrincipalFromACL(dacl, Principal);

    if (returnValue != ERROR_SUCCESS) {
        free(sd);
        return returnValue;
    }

    //
    // Make the security descriptor absolute if it isn't new
    //

    if (!newSD)
        MakeSDAbsolute((PSECURITY_DESCRIPTOR) sd, (PSECURITY_DESCRIPTOR *) &sdAbsolute);
    else
        sdAbsolute = sd;

    //
    // Set the discretionary ACL on the security descriptor
    //

    if (!SetSecurityDescriptorDacl(sdAbsolute, TRUE, dacl, FALSE))
        return GetLastError();

    //
    // Make the security descriptor self-relative so that we can
    // store it in the registry
    //
    secDescSize = 0;
    MakeSelfRelativeSD(sdAbsolute, sdSelfRelative, &secDescSize);
    sdSelfRelative = (SECURITY_DESCRIPTOR *) malloc(secDescSize);

    if (!MakeSelfRelativeSD(sdAbsolute, sdSelfRelative, &secDescSize))
        return GetLastError();

    //
    // Store the security descriptor in the registry
    //
    SetNamedValueSD(RootKey, KeyName, ValueName, sdSelfRelative);
    free(sd);
    free(sdSelfRelative);

    if (!newSD)
        free(sdAbsolute);

    return ERROR_SUCCESS;
}

void
ListACL(
    PACL Acl
)
{
    ACL_SIZE_INFORMATION     aclSizeInfo;
    ACL_REVISION_INFORMATION aclRevInfo;
    ULONG                    i = 0;
    LPVOID                   ace = NULL;
    ACE_HEADER               *aceHeader = NULL;
    ACCESS_ALLOWED_ACE       *paaace = NULL;
    ACCESS_DENIED_ACE        *padace = NULL;
    TCHAR                    domainName [256];
    TCHAR                    userName [256];
    DWORD                    nameLength = 0;
    SID_NAME_USE             snu;

    if (!GetAclInformation(Acl,
                           &aclSizeInfo,
                           sizeof(ACL_SIZE_INFORMATION),
                           AclSizeInformation)) {
        _tprintf(TEXT("Could not get AclSizeInformation"));
        return;
    }

    if (!GetAclInformation(Acl,
                           &aclRevInfo,
                           sizeof(ACL_REVISION_INFORMATION),
                           AclRevisionInformation)) {
        _tprintf(TEXT("Could not get AclRevisionInformation"));
        return;
    }

    for (i = 0; i < aclSizeInfo.AceCount; i++) {
        if (!GetAce(Acl, i, &ace))
            return;

        aceHeader = (ACE_HEADER *) ace;

        if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE) {
            paaace = (ACCESS_ALLOWED_ACE *) ace;
            nameLength = 255;
            LookupAccountSid(NULL,
                             &paaace->SidStart,
                             userName,
                             &nameLength,
                             domainName,
                             &nameLength,
                             &snu);
            _tprintf(TEXT("Access permitted to %s\\%s.\n"), domainName, userName);
        } else if (aceHeader->AceType == ACCESS_DENIED_ACE_TYPE) {
            padace = (ACCESS_DENIED_ACE *) ace;
            nameLength = 255;
            LookupAccountSid(NULL,
                             &padace->SidStart,
                             userName,
                             &nameLength,
                             domainName,
                             &nameLength,
                             &snu);
            _tprintf(TEXT("Access denied to %s\\%s.\n"), domainName, userName);
        }
    }
}

DWORD
ListDefaultAccessACL()
{
    return ListNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultAccessPermission"));
}

DWORD
ListDefaultLaunchACL()
{
    return ListNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultLaunchPermission"));
}

DWORD
ListAppIDAccessACL(
    LPTSTR AppID
)
{
    TCHAR   keyName [256];

    if (AppID [0] == '{')
        wsprintf(keyName, TEXT("APPID\\%s"), AppID);
    else
        wsprintf(keyName, TEXT("APPID\\{%s}"), AppID);

    return ListNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("AccessPermission"));
}

DWORD
ListAppIDLaunchACL(
    LPTSTR AppID
)
{
    TCHAR   keyName [256];

    if (AppID [0] == '{')
        wsprintf(keyName, TEXT("APPID\\%s"), AppID);
    else
        wsprintf(keyName, TEXT("APPID\\{%s}"), AppID);

    return ListNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("LaunchPermission"));
}

DWORD
ChangeDefaultAccessACL(
    LPTSTR Principal,
    BOOL SetPrincipal,
    BOOL Permit
)
{
    if (SetPrincipal) {
        RemovePrincipalFromNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultAccessPermission"), Principal);
        return AddPrincipalToNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultAccessPermission"), Principal, Permit);
    } else
        return RemovePrincipalFromNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultAccessPermission"), Principal);
}

DWORD
ChangeDefaultLaunchACL(
    LPTSTR Principal,
    BOOL SetPrincipal,
    BOOL Permit
)
{
    if (SetPrincipal) {
        RemovePrincipalFromNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultLaunchPermission"), Principal);
        return AddPrincipalToNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultLaunchPermission"), Principal, Permit);
    } else
        return RemovePrincipalFromNamedValueSD(HKEY_LOCAL_MACHINE, TEXT("Software\\Microsoft\\Ole"), TEXT("DefaultLaunchPermission"), Principal);
}

DWORD
ChangeAppIDAccessACL(
    LPTSTR AppID,
    LPTSTR Principal,
    BOOL SetPrincipal,
    BOOL Permit
)
{
    TCHAR   keyName [256];

    if (AppID [0] == '{')
        wsprintf(keyName, TEXT("APPID\\%s"), AppID);
    else
        wsprintf(keyName, TEXT("APPID\\{%s}"), AppID);

    if (SetPrincipal) {
        RemovePrincipalFromNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("AccessPermission"), Principal);
        return AddPrincipalToNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("AccessPermission"), Principal, Permit);
    } else
        return RemovePrincipalFromNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("AccessPermission"), Principal);
}

DWORD
ChangeAppIDLaunchACL(
    LPTSTR AppID,
    LPTSTR Principal,
    BOOL SetPrincipal,
    BOOL Permit
)
{
    TCHAR   keyName [256];

    if (AppID [0] == '{')
        wsprintf(keyName, TEXT("APPID\\%s"), AppID);
    else
        wsprintf(keyName, TEXT("APPID\\{%s}"), AppID);

    if (SetPrincipal) {
        RemovePrincipalFromNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("LaunchPermission"), Principal);
        return AddPrincipalToNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("LaunchPermission"), Principal, Permit);
    } else
        return RemovePrincipalFromNamedValueSD(HKEY_CLASSES_ROOT, keyName, TEXT("LaunchPermission"), Principal);
}


DWORD
CopyACL (
         PACL OldACL,
         PACL NewACL
         )
{
    ACL_SIZE_INFORMATION  aclSizeInfo;
    LPVOID                ace = NULL;
    ACE_HEADER            *aceHeader = NULL;
    ULONG                 i = 0;

    GetAclInformation (OldACL, (LPVOID) &aclSizeInfo, (DWORD) sizeof (aclSizeInfo), AclSizeInformation);

    //
    // Copy all of the ACEs to the new ACL
    //

    for (i = 0; i < aclSizeInfo.AceCount; i++)
    {
        //
        // Get the ACE and header info
        //

        if (!GetAce (OldACL, i, &ace))
            return GetLastError();

        aceHeader = (ACE_HEADER *) ace;

        //
        // Add the ACE to the new list
        //

        if (!AddAce (NewACL, ACL_REVISION, 0xffffffff, ace, aceHeader->AceSize))
            return GetLastError();
    }

    return ERROR_SUCCESS;
}

DWORD
AddAccessDeniedACEToACL (
                         PACL *Acl,
                         DWORD PermissionMask,
                         LPTSTR Principal
                         )
{
    ACL_SIZE_INFORMATION  aclSizeInfo;
    int                   aclSize = 0;
    DWORD                 returnValue = 0;
    PSID                  principalSID = 0;
    PACL                  oldACL = NULL, newACL = NULL;

    oldACL = *Acl;

    if (!GetAccountSid(NULL, Principal, &principalSID))
    {
        return GetLastError();
    }

    GetAclInformation (oldACL, (LPVOID) &aclSizeInfo, (DWORD) sizeof (ACL_SIZE_INFORMATION), AclSizeInformation);

    aclSize = aclSizeInfo.AclBytesInUse +
        sizeof (ACL) + sizeof (ACCESS_DENIED_ACE) +
        GetLengthSid (principalSID) - sizeof (DWORD);

    newACL = (PACL) new BYTE [aclSize];

    if (!InitializeAcl (newACL, aclSize, ACL_REVISION))
    {
        HeapFree(GetProcessHeap(), 0, principalSID);
        return GetLastError();
    }

    if (!AddAccessDeniedAce (newACL, ACL_REVISION2, PermissionMask, principalSID))
    {
        HeapFree(GetProcessHeap(), 0, principalSID);
        return GetLastError();
    }

    returnValue = CopyACL (oldACL, newACL);
    if (returnValue != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, principalSID);
        return returnValue;
    }

    *Acl = newACL;

    if(principalSID != NULL) HeapFree(GetProcessHeap(), 0, principalSID);
    return ERROR_SUCCESS;
}

DWORD
AddAccessAllowedACEToACL (
                          PACL *Acl,
                          DWORD PermissionMask,
                          LPTSTR Principal
                          )
{
    ACL_SIZE_INFORMATION  aclSizeInfo;
    int                   aclSize = 0;
    DWORD                 returnValue = 0;
    PSID                  principalSID = NULL;
    PACL                  oldACL = NULL, newACL = NULL;

    oldACL = *Acl;

    if (!GetAccountSid(NULL, Principal, &principalSID))
    {
        return GetLastError();
    }

    GetAclInformation (oldACL, (LPVOID) &aclSizeInfo, (DWORD) sizeof (ACL_SIZE_INFORMATION), AclSizeInformation);

    aclSize = aclSizeInfo.AclBytesInUse +
        sizeof (ACL) + sizeof (ACCESS_ALLOWED_ACE) +
        GetLengthSid (principalSID) - sizeof (DWORD);

    newACL = (PACL) new BYTE [aclSize];

    if (!InitializeAcl (newACL, aclSize, ACL_REVISION))
    {
        HeapFree(GetProcessHeap(), 0, principalSID);
        return GetLastError();
    }

    returnValue = CopyACL (oldACL, newACL);
    if (returnValue != ERROR_SUCCESS)
    {
        HeapFree(GetProcessHeap(), 0, principalSID);
        return returnValue;
    }

    if (!AddAccessAllowedAce (newACL, ACL_REVISION2, PermissionMask, principalSID))
    {
        HeapFree(GetProcessHeap(), 0, principalSID);
        return GetLastError();
    }

    *Acl = newACL;

    if(principalSID != NULL) HeapFree(GetProcessHeap(), 0, principalSID);
    return ERROR_SUCCESS;
}

DWORD
RemovePrincipalFromACL (
                        PACL Acl,
                        LPTSTR Principal
                        )
{
    ACL_SIZE_INFORMATION    aclSizeInfo;
    ULONG                   i = 0;
    LPVOID                  ace = NULL;
    ACCESS_ALLOWED_ACE      *accessAllowedAce = NULL;
    ACCESS_DENIED_ACE       *accessDeniedAce = NULL;
    SYSTEM_AUDIT_ACE        *systemAuditAce = NULL;
    PSID                    principalSID = NULL;
    DWORD                   returnValue = 0;
    ACE_HEADER              *aceHeader = NULL;

    if (!GetAccountSid(NULL, Principal, &principalSID))
    {
        return GetLastError();
    }

    GetAclInformation (Acl, (LPVOID) &aclSizeInfo, (DWORD) sizeof (ACL_SIZE_INFORMATION), AclSizeInformation);

    for (i = 0; i < aclSizeInfo.AceCount; i++)
    {
        if (!GetAce (Acl, i, &ace))
        {
            HeapFree(GetProcessHeap(), 0, principalSID);
            return GetLastError();
        }

        aceHeader = (ACE_HEADER *) ace;

        if (aceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE)
        {
            accessAllowedAce = (ACCESS_ALLOWED_ACE *) ace;

            if (EqualSid (principalSID, (PSID) &accessAllowedAce->SidStart))
            {
                DeleteAce (Acl, i);
                HeapFree(GetProcessHeap(), 0, principalSID);
                return ERROR_SUCCESS;
            }
        } else

            if (aceHeader->AceType == ACCESS_DENIED_ACE_TYPE)
            {
                accessDeniedAce = (ACCESS_DENIED_ACE *) ace;

                if (EqualSid (principalSID, (PSID) &accessDeniedAce->SidStart))
                {
                    DeleteAce (Acl, i);
                    HeapFree(GetProcessHeap(), 0, principalSID);
                    return ERROR_SUCCESS;
                }
            } else

                if (aceHeader->AceType == SYSTEM_AUDIT_ACE_TYPE)
                {
                    systemAuditAce = (SYSTEM_AUDIT_ACE *) ace;

                    if (EqualSid (principalSID, (PSID) &systemAuditAce->SidStart))
                    {
                        DeleteAce (Acl, i);
                        HeapFree(GetProcessHeap(), 0, principalSID);
                        return ERROR_SUCCESS;
                    }
                }
    }

    if(principalSID != NULL) HeapFree(GetProcessHeap(), 0, principalSID);
    return ERROR_SUCCESS;
}


BOOL
GetAccountSid(
              LPCTSTR SystemName,
              LPCTSTR AccountName,
              PSID *Sid
              )
{
    LPTSTR ReferencedDomain=NULL;
    DWORD cbSid=128;    // initial allocation attempt
    DWORD cchReferencedDomain=16; // initial allocation size
    SID_NAME_USE peUse;
    BOOL bSuccess=FALSE; // assume this function will fail

    __try {

        //
        // initial memory allocations
        //
        *Sid = (PSID)HeapAlloc(GetProcessHeap(), 0, cbSid);

        if(*Sid == NULL) __leave;

        ReferencedDomain = (LPTSTR)HeapAlloc(
            GetProcessHeap(),
            0,
            cchReferencedDomain * sizeof(TCHAR)
            );

        if(ReferencedDomain == NULL) __leave;

        //
        // Obtain the SID of the specified account on the specified system.
        //
        while(!LookupAccountName(
            SystemName,         // machine to lookup account on
            AccountName,        // account to lookup
            *Sid,               // SID of interest
            &cbSid,             // size of SID
            ReferencedDomain,   // domain account was found on
            &cchReferencedDomain,
            &peUse
            )) {
                if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                    //
                    // reallocate memory
                    //
                    *Sid = (PSID)HeapReAlloc(
                        GetProcessHeap(),
                        0,
                        *Sid,
                        cbSid
                        );
                    if(*Sid == NULL) __leave;

                    ReferencedDomain = (LPTSTR)HeapReAlloc(
                        GetProcessHeap(),
                        0,
                        ReferencedDomain,
                        cchReferencedDomain * sizeof(TCHAR)
                        );
                    if(ReferencedDomain == NULL) __leave;
                }
                else __leave;
        }

        //
        // Indicate success.
        //
        bSuccess = TRUE;

    } // try
    __finally {

        //
        // Cleanup and indicate failure, if appropriate.
        //

        HeapFree(GetProcessHeap(), 0, ReferencedDomain);

        if(!bSuccess) {
            if(*Sid != NULL) {
                HeapFree(GetProcessHeap(), 0, *Sid);
                *Sid = NULL;
            }
        }

    } // finally

    return bSuccess;
}

//////////////////////////////////////////////////////////////////
CZElevation::CZElevation()
{
}
CZElevation::~CZElevation()
{
}

BOOL CZElevation::GetProcessElevation(TOKEN_ELEVATION_TYPE* pElevationType, BOOL* pIsAdmin)
{
    HANDLE hToken = NULL;
    DWORD dwSize; 

    // Get current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
        return(FALSE);

    BOOL bResult = FALSE;

    // Retrieve elevation type information 
    if (GetTokenInformation(hToken, TokenElevationType, 
        pElevationType, sizeof(TOKEN_ELEVATION_TYPE), &dwSize)) {
            // Create the SID corresponding to the Administrators group
            byte adminSID[SECURITY_MAX_SID_SIZE];
            dwSize = sizeof(adminSID);
            CreateWellKnownSid(WinBuiltinAdministratorsSid, NULL, &adminSID, 
                &dwSize);

            if (*pElevationType == TokenElevationTypeLimited) {
                // Get handle to linked token (will have one if we are lua)
                HANDLE hUnfilteredToken = NULL;
                GetTokenInformation(hToken, TokenLinkedToken, (VOID*) 
                    &hUnfilteredToken, sizeof(HANDLE), &dwSize);

                // Check if this original token contains admin SID
                if (CheckTokenMembership(hUnfilteredToken, &adminSID, pIsAdmin)) {
                    bResult = TRUE;
                }

                // Don't forget to close the unfiltered token
                CloseHandle(hUnfilteredToken);
            } else {
                *pIsAdmin = IsUserAnAdmin();
                bResult = TRUE;
            }
    }

    // Don't forget to close the process token
    CloseHandle(hToken);

    return(bResult);
}

DWORD CZElevation::StartElevatedProcess(LPCTSTR szExecutable, LPCTSTR szCmdLine)
{
    // Initialize the structure.
    SHELLEXECUTEINFO sei = { sizeof(SHELLEXECUTEINFO) };

    // Ask for privileges elevation.
    sei.lpVerb = TEXT("runas");

    // Pass the application to start with high privileges.
    sei.lpFile = szExecutable;

    // Pass the command line.
    sei.lpParameters = szCmdLine;

    // Don't forget this parameter otherwise the window will be hidden.
    //sei.nShow = SW_SHOWNORMAL;

    ShellExecuteEx(&sei);
    return(GetLastError());
}


BOOL IsElevated( ) {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if( OpenProcessToken( GetCurrentProcess(),TOKEN_QUERY,&hToken) ) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if( GetTokenInformation( hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize ) ) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if(hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}

#ifndef SUCCESS
#define SUCCESS 0
#endif
#ifndef FAILURE
#define FAILURE 1
#endif

// DebugMode (BOOL)
// activates the debug mode for the current process 
// requires the privilege to be 'ENABLED'
// returns FAILURE on failure, and SUCCESS on success

int DebugMode(BOOL bToggle) {
    HANDLE hToken;
    DWORD cbTokPriv = sizeof (TOKEN_PRIVILEGES);
    static TOKEN_PRIVILEGES tpGodModeActivated, tpOriginalMode;

    if (bToggle) {
        tpGodModeActivated.PrivilegeCount = 1;
        tpGodModeActivated.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tpGodModeActivated.Privileges[0].Luid);

        if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
                return FAILURE;
        }

        if (!AdjustTokenPrivileges(hToken, FALSE, &tpGodModeActivated, sizeof (tpGodModeActivated),
            &tpOriginalMode, &cbTokPriv) != ERROR_SUCCESS) {
                CloseHandle(hToken);
                return FAILURE;
        }
        CloseHandle(hToken);
    }
    else {

        if (!OpenProcessToken(GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
                return FAILURE;
        }
        if (AdjustTokenPrivileges(hToken, FALSE, &tpOriginalMode, sizeof (tpOriginalMode), NULL, NULL)
            != ERROR_SUCCESS) {
                CloseHandle(hToken);
                return FAILURE;
        }

    }

    return SUCCESS;
}



std::wstring GetSIDForCurrentUser() 
{
    ATL::CHandle processHandle(GetCurrentProcess());
    HANDLE tokenHandle;
    if(OpenProcessToken(processHandle,TOKEN_READ,&tokenHandle) == FALSE) {
        
        return L"";
    }

    PTOKEN_USER userToken;
    DWORD userTokenSize;
    GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS::TokenUser, NULL, 0, &userTokenSize);
    userToken = (PTOKEN_USER) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, userTokenSize);
    GetTokenInformation(tokenHandle, TOKEN_INFORMATION_CLASS::TokenUser, userToken, userTokenSize, &userTokenSize);

    LPTSTR simpleSidString;
    ConvertSidToStringSid(userToken->User.Sid, &simpleSidString);
    std::wstring sidString = std::wstring(simpleSidString);

    LocalFree(simpleSidString); // as per documentation of ConvertSidToStringSid
    HeapFree(GetProcessHeap(), 0, userToken);
    CloseHandle(tokenHandle);

    return sidString;
}