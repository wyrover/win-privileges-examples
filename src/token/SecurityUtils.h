#ifndef __CACTUS_SECURITYUTILS_H__
#define __CACTUS_SECURITYUTILS_H__

#include <Windows.h>
#include <atlstr.h>

namespace SecurityUtils
{
    // (b.cardillo 2011-01-06 20:34) - A few new utility functions necessary for PLID 33748.

    ///////////////////////////////////////////////
    // Most useful security utility functions
    //////////

    // Creates a file at the specified path the same way CreateFile() does, applying a 
    // security descriptor according to the "Sec" parameters.
    HANDLE CreateSecureFile(LPCTSTR strFilePathName, DWORD dwDesiredAccess, DWORD dwShareMode, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile, BOOL bSec_CurUserIsObjectOwner, DWORD grfSec_EveryoneAccessPermissions);

    // Creates a mutex of the specified name the same way CreateMutex() does, applying a 
    // security descriptor according to the "Sec" parameters.
    HANDLE CreateSecureMutex(LPCTSTR strMutexName, BOOL bEnterMutexOnCreate, BOOL bSec_CurUserIsObjectOwner, DWORD grfSec_EveryoneAccessPermissions);

    // Returns the friendly name of the account that owns the specified file; if the friendly name cannot be 
    // determined, returns the raw SID string.
    CString GetFileOwner(const CString &strFilePath);

    // Returns the friendly name of the account that owns the specified NT object; if the friendly name cannot be 
    // determined, returns the raw SID string.
    CString GetObjectOwnerName(const CString &strObjectName);

    ///////////////////////////////////////////////




    ///////////////////////////////////////////////
    // Somewhat useful helper functions
    //////////

    // Returns a friendly username corresponding to the user account of the given SID.  This can be slow, especially for 
    // remote accounts, so consider displaying GetSidRawString() first and then calling this function asynchronously.
    CString GetSidAccountName(PSID pSid, OPTIONAL const CString &strSystemName);

    // Returns the unfriendly string associated with the specified SID (e.g. "S-1-5-21-2263713762-513851276-1464104247-1008")
    CString GetSidRawString(PSID pSID);

    // Returns a user account SID associated with the specified process.  Call LocalFree() to free the SID when you're finished.
    BOOL GetProcessUserSid(HANDLE hProcess, PSID *ppSID);

    // Handy utility for creating a copy of a SID.  Call LocalFree() to free the SID when you're finished.
    PSID CopySid(PSID pSid);

    // Creates a security attributes object with the specified parameters.  Call DestroySecurityAttributes() to destroy it.
    LPSECURITY_ATTRIBUTES CreateSecurityAttributes(BOOL bCurUserIsOwner, DWORD grfEveryoneAccessPermissions);

    // Destroys a security attributes object created by CreateSecurityAttributes()
    BOOL DestroySecurityAttributes(LPSECURITY_ATTRIBUTES psa);

    ///////////////////////////////////////////////





    ///////////////////////////////////////////////
    // Lower level helper functions
    //////////

    // Returns a user account SID associated with the specified token.  Call LocalFree() to free the SID when you're finished.
    BOOL GetTokenUserSid(HANDLE token, PSID *ppSID);

    // Returns a pointer to a new SECURITY_DESCRIPTOR object with the specified parameters.  Call LocalFree() to destroy it.
    PSECURITY_DESCRIPTOR CreateSecurityDescriptor(BOOL bCurUserIsOwner, DWORD grfEveryoneAccessPermissions);

    ///////////////////////////////////////////////
}

#define GUIDSTR_MAX 38

#ifndef STR2UNI

#define STR2UNI(unistr, regstr) \
    mbstowcs (unistr, regstr, strlen (regstr)+1);

#define UNI2STR(regstr, unistr) \
    wcstombs (regstr, unistr, wcslen (unistr)+1);

#endif


//
// Wrappers
//

DWORD
ListDefaultAccessACL();

DWORD
ListDefaultLaunchACL();

DWORD
ListAppIDAccessACL (
                    LPTSTR AppID
                    );

DWORD
ListAppIDLaunchACL (
                    LPTSTR AppID
                    );

DWORD
ChangeDefaultAccessACL (
                        LPTSTR Principal,
                        BOOL SetPrincipal,
                        BOOL Permit
                        );

DWORD
ChangeDefaultLaunchACL (
                        LPTSTR Principal,
                        BOOL SetPrincipal,
                        BOOL Permit
                        );

DWORD
ChangeAppIDAccessACL (
                      LPTSTR AppID,
                      LPTSTR Principal,
                      BOOL SetPrincipal,
                      BOOL Permit
                      );

DWORD
ChangeAppIDLaunchACL (
                      LPTSTR AppID,
                      LPTSTR Principal,
                      BOOL SetPrincipal,
                      BOOL Permit
                      );

DWORD GetRunAsPassword (
                        LPTSTR AppID,
                        LPTSTR Password
                        );

DWORD SetRunAsPassword (
                        LPTSTR AppID,
                        LPTSTR Principal,
                        LPTSTR Password
                        );

DWORD GetRunAsPassword (
                        LPTSTR AppID,
                        LPTSTR Password
                        );

DWORD SetRunAsPassword (
                        LPTSTR AppID,
                        LPTSTR Password
                        );

//
// Internal functions
//

DWORD
CreateNewSD (
             SECURITY_DESCRIPTOR **SD
             );

DWORD
MakeSDAbsolute (
                PSECURITY_DESCRIPTOR OldSD,
                PSECURITY_DESCRIPTOR *NewSD
                );

DWORD
SetNamedValueSD (
                 HKEY RootKey,
                 LPTSTR KeyName,
                 LPTSTR ValueName,
                 SECURITY_DESCRIPTOR *SD
                 );

DWORD
GetNamedValueSD (
                 HKEY RootKey,
                 LPTSTR KeyName,
                 LPTSTR ValueName,
                 SECURITY_DESCRIPTOR **SD,
                 BOOL *NewSD
                 );

DWORD
ListNamedValueSD (
                  HKEY RootKey,
                  LPTSTR KeyName,
                  LPTSTR ValueName
                  );

DWORD
AddPrincipalToNamedValueSD (
                            HKEY RootKey,
                            LPTSTR KeyName,
                            LPTSTR ValueName,
                            LPTSTR Principal,
                            BOOL Permit
                            );

DWORD
RemovePrincipalFromNamedValueSD (
                                 HKEY RootKey,
                                 LPTSTR KeyName,
                                 LPTSTR ValueName,
                                 LPTSTR Principal
                                 );

DWORD
GetCurrentUserSID (
                   PSID *Sid
                   );

DWORD
CopyACL (
         PACL OldACL,
         PACL NewACL
         );

DWORD
AddAccessDeniedACEToACL (
                         PACL *Acl,
                         DWORD PermissionMask,
                         LPTSTR Principal
                         );

DWORD
AddAccessAllowedACEToACL (
                          PACL *Acl,
                          DWORD PermissionMask,
                          LPTSTR Principal
                          );

DWORD
RemovePrincipalFromACL (
                        PACL Acl,
                        LPTSTR Principal
                        );

void
ListACL (
         PACL Acl
         );

BOOL
GetAccountSid(
              LPCTSTR SystemName,
              LPCTSTR AccountName,
              PSID *Sid
              );


////////////////////////////////////////////////////////
class CZElevation
{
public:
    CZElevation();
    virtual ~CZElevation();
    BOOL GetProcessElevation(TOKEN_ELEVATION_TYPE* pElevationType, BOOL* pIsAdmin);
    DWORD StartElevatedProcess(LPCTSTR szExecutable, LPCTSTR szCmdLine);
};

#endif // __CACTUS_SECURITYUTILS_H__
