#define _WIN32_DCOM
#define UNICODE
#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "credui.lib")
#pragma comment(lib, "comsuppw.lib")
#include <wincred.h>
#include <strsafe.h>
#include <String>
#include <iomanip>


int RemoteTaskKill(wchar_t domain, wchar_t* user, wchar_t* password, wchar_t* argument, const char* mode)
{
    HRESULT hres;

    // Step 1: --------------------------------------------------
    // Initialize COM. ------------------------------------------

    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Failed to initialize COM library. Error code = 0x"
            << hex << hres << endl;
        return 1;                  // Program has failed.
    }

    // Step 2: --------------------------------------------------
    // Set general COM security levels --------------------------

    hres = CoInitializeSecurity(
        NULL,
        -1,                          // COM authentication
        NULL,                        // Authentication services
        NULL,                        // Reserved
        RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
        RPC_C_IMP_LEVEL_IDENTIFY,    // Default Impersonation  
        NULL,                        // Authentication info
        EOAC_NONE,                   // Additional capabilities 
        NULL                         // Reserved
    );


    if (FAILED(hres))
    {
        cout << "Failed to initialize security. Error code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;                    // Program has failed.
    }

    // Step 3: ---------------------------------------------------
    // Obtain the initial locator to WMI -------------------------

    IWbemLocator* pLoc = NULL;

    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator, (LPVOID*)&pLoc);

    if (FAILED(hres))
    {
        cout << "Failed to create IWbemLocator object."
            << " Err code = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1;                 // Program has failed.
    }

    // Step 4: -----------------------------------------------------
    // Connect to WMI through the IWbemLocator::ConnectServer method

    IWbemServices* pSvc = NULL;

    // Get the user name and password for the remote computer
    bool useToken = false;
    bool useNTLM = true;
    wchar_t pszName[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
    wcscpy_s(pszName, user);
    wchar_t pszPwd[CREDUI_MAX_PASSWORD_LENGTH + 1] = { 0 };
    wcscpy_s(pszPwd, password);
    wchar_t pszDomain[CREDUI_MAX_USERNAME_LENGTH + 1];
    wchar_t pszUserName[CREDUI_MAX_USERNAME_LENGTH + 1];
    wchar_t pszAuthority[CREDUI_MAX_USERNAME_LENGTH + 1];
    BOOL fSave;
    DWORD dwErr;


    // change the computerName strings below to the full computer name
    // of the remote computer
    if (!useNTLM)
    {
        StringCchPrintf(pszAuthority, CREDUI_MAX_USERNAME_LENGTH + 1, L"kERBEROS:%s", L"COMPUTERNAME");
    }

    // Connect to the remote root\cimv2 namespace
    // and obtain pointer pSvc to make IWbemServices calls.
    //---------------------------------------------------------

    hres = pLoc->ConnectServer(
        _bstr_t(L"\\\\TASKEXAMPLE\\root\\cimv2"),
        _bstr_t(useToken ? NULL : pszName),    // User name
        _bstr_t(useToken ? NULL : pszPwd),     // User password
        NULL,                              // Locale             
        NULL,                              // Security flags
        _bstr_t(useNTLM ? NULL : pszAuthority),// Authority        
        NULL,                              // Context object 
        &pSvc                              // IWbemServices proxy
    );

    if (FAILED(hres))
    {
        cout << "Could not connect. Error code = 0x"
            << hex << hres << endl;
        pLoc->Release();
        CoUninitialize();
        return 1;                // Program has failed.
    }

    cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


    // step 5: --------------------------------------------------
    // Create COAUTHIDENTITY that can be used for setting security on proxy

    COAUTHIDENTITY* userAcct = NULL;
    COAUTHIDENTITY authIdent;

    if (!useToken)
    {
        memset(&authIdent, 0, sizeof(COAUTHIDENTITY));
        authIdent.PasswordLength = wcslen(pszPwd);
        authIdent.Password = (USHORT*)pszPwd;

        // Conversion to include \\ operator
        std::wstring auxName = L"\\";
        auxName.append(pszName);
        wchar_t* pszNameAux = const_cast<wchar_t*>(auxName.c_str());
        wchar_t pszName2[CREDUI_MAX_USERNAME_LENGTH + 1] = { 0 };
        wcscpy_s(pszName2, pszNameAux);

        LPWSTR slash = wcschr(pszName2, L'\\');

        if (slash == NULL)
        {
            cout << "Could not create Auth identity. No domain specified\n";
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return 1;               // Program has failed.
        }

        StringCchCopy(pszUserName, CREDUI_MAX_USERNAME_LENGTH + 1, slash + 1);
        authIdent.User = (USHORT*)pszUserName;
        authIdent.UserLength = wcslen(pszUserName);

        StringCchCopyN(pszDomain, CREDUI_MAX_USERNAME_LENGTH + 1, pszName2, slash - pszName2);
        authIdent.Domain = (USHORT*)pszDomain;
        authIdent.DomainLength = slash - pszName2;
        authIdent.Flags = SEC_WINNT_AUTH_IDENTITY_UNICODE;

        userAcct = &authIdent;

    }

    // Step 6: --------------------------------------------------
    // Set security levels on a WMI connection ------------------

    hres = CoSetProxyBlanket(
        pSvc,                           // Indicates the proxy to set
        RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
        COLE_DEFAULT_PRINCIPAL,         // Server principal name 
        RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
        RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
        userAcct,                       // client identity
        EOAC_NONE                       // proxy capabilities 
    );

    if (FAILED(hres))
    {
        cout << "Could not set proxy blanket. Error code = 0x"
            << hex << hres << endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return 1;               // Program has failed.
    }

    // Step 6: --------------------------------------------------
    // Use the IWbemServices pointer to make requests of WMI ----


    if (mode == "/PID") {
        // Set up to call the Win32_Process::Create method

        BSTR ClassName = SysAllocString(L"Win32_Process");


        _bstr_t MethodName = (L"Terminate");

        IWbemClassObject* pClass = NULL;

        hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

        if (FAILED(hres))
        {
            cout << "Could not get the object. Error code = 0x"
                << hex << hres << endl;
        }

        IWbemClassObject* pInParamsDefinition = NULL;
        IWbemClassObject* pOutMethod = NULL;

        hres = pClass->GetMethod(MethodName, 0,
            &pInParamsDefinition, &pOutMethod);


        if (FAILED(hres))
        {
            cout << "Could not get the method. Error code = 0x"
                << hex << hres << endl;
        }

        IWbemClassObject* pClassInstance = NULL;
        hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

        // Create the values for the in parameters
        VARIANT pcVal;
        VariantInit(&pcVal);
        V_VT(&pcVal) = VT_I4;

        // Store the value for the in parameters
        hres = pClassInstance->Put(L"Reason", 0, &pcVal, 0);

        // Execute Method

        std::wstring classNameInstance = L"\\\\TASKEXAMPLE\\root\\cimv2:";
        classNameInstance.append(L"Win32_Process.Handle=");
        std::wstring argumentString(argument);
        classNameInstance.append(L"\"").append(argumentString).append(L"\"");

        BSTR ClassNameInstance = SysAllocString(
            classNameInstance.c_str());


        hres = pSvc->ExecMethod(ClassNameInstance, MethodName, 0,
            NULL, pClassInstance, NULL, NULL);

        if (FAILED(hres))
        {
            cout << "Could not execute method. Error code = 0x"
                << hex << hres << endl;
            VariantClear(&pcVal);
            SysFreeString(ClassName);
            SysFreeString(MethodName);
            pClass->Release();
            //pInParamsDefinition->Release();
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return 1;           // Program has failed.
        }


        // Clean up
        //--------------------------
        VariantClear(&pcVal);
        SysFreeString(ClassName);
        SysFreeString(MethodName);
        pClass->Release();
        pInParamsDefinition->Release();
        pLoc->Release();
        pSvc->Release();
        //CoUninitialize();
    }

    else if (mode == "/IM") {
        IEnumWbemClassObject* pEnumerator = NULL;
        hres = pSvc->ExecQuery(
            bstr_t("WQL"),
            bstr_t("SELECT * FROM Win32_Process"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator);

        if (FAILED(hres))
        {
            cout << "Query for processes failed. "
                << "Error code = 0x"
                << hex << hres << endl;
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return 1;               // Program has failed.
        }

        hres = CoSetProxyBlanket(
            pEnumerator,                    // Indicates the proxy to set
            RPC_C_AUTHN_DEFAULT,            // RPC_C_AUTHN_xxx
            RPC_C_AUTHZ_DEFAULT,            // RPC_C_AUTHZ_xxx
            COLE_DEFAULT_PRINCIPAL,         // Server principal name 
            RPC_C_AUTHN_LEVEL_PKT_PRIVACY,  // RPC_C_AUTHN_LEVEL_xxx 
            RPC_C_IMP_LEVEL_IMPERSONATE,    // RPC_C_IMP_LEVEL_xxx
            userAcct,                       // client identity
            EOAC_NONE                       // proxy capabilities 
        );

        if (FAILED(hres))
        {
            cout << "Could not set proxy blanket on enumerator. Error code = 0x"
                << hex << hres << endl;
            pEnumerator->Release();
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return 1;               // Program has failed.
        }

        IWbemClassObject* pclsObj;
        ULONG uReturn = 0;

        wchar_t* pid;

        while (pEnumerator)
        {
            hres = pEnumerator->Next(WBEM_INFINITE, 1,
                &pclsObj, &uReturn);

            if (0 == uReturn)
            {
                break;
            }

            VARIANT vtProp;
            VARIANT vtProp2;

            // Get the value of the Name property
            hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            hres = pclsObj->Get(L"ProcessID", 0, &vtProp2, 0, 0);
            if (wcscmp(vtProp.bstrVal, argument) == 0) {
                std::wstring processId = std::to_wstring(vtProp2.uintVal);

                BSTR ClassName = SysAllocString(L"Win32_Process");

                std::wstring classNameInstance = L"\\\\TASKEXAMPLE\\root\\cimv2:";
                classNameInstance.append(L"Win32_Process.Handle=");
                std::wstring argumentString(const_cast<wchar_t*>(processId.c_str()));
                classNameInstance.append(L"\"").append(argumentString).append(L"\"");
                BSTR ClassNameInstance = SysAllocString(
                    classNameInstance.c_str());

                _bstr_t MethodName = (L"Terminate");
                BSTR ParameterName = SysAllocString(L"Reason");

                IWbemClassObject* pClass = NULL;
                hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

                IWbemClassObject* pInParamsDefinition = NULL;
                IWbemClassObject* pOutMethod = NULL;
                hres = pClass->GetMethod(MethodName, 0,
                    &pInParamsDefinition, &pOutMethod);

                if (FAILED(hres))
                {
                    cout << "Could not get the method. Error code = 0x"
                        << hex << hres << endl;
                }

                IWbemClassObject* pClassInstance = NULL;
                hres = pInParamsDefinition->SpawnInstance(0, &pClassInstance);

                // Create the values for the in parameters
                VARIANT pcVal;
                VariantInit(&pcVal);
                V_VT(&pcVal) = VT_I4;

                // Store the value for the in parameters
                hres = pClassInstance->Put(L"Reason", 0,
                    &pcVal, 0);

                // Execute Method
                hres = pSvc->ExecMethod(ClassNameInstance, MethodName, 0,
                    NULL, pClassInstance, NULL, NULL);
                std::wcout << "Process Id Terminated: " << ClassNameInstance << std::endl;


                // Clean up
                //--------------------------
                VariantClear(&pcVal);
                SysFreeString(ClassName);
                SysFreeString(MethodName);
                pClass->Release();
                pInParamsDefinition->Release();
                //pLoc->Release();
            }
        }
    }

    else {
        std::wcout << "OK" << std::endl;
    }


}