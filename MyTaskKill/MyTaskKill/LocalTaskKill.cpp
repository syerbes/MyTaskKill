#define _WIN32_DCOM

#include <iostream>
using namespace std;
#include <comdef.h>
#include <Wbemidl.h>
#include <String>

#pragma comment(lib, "wbemuuid.lib")


int LocalTaskKill(wchar_t* argument, const char* mode, const char* child)
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
		-1,                          // COM negotiates service
		NULL,                        // Authentication services
		NULL,                        // Reserved
		RPC_C_AUTHN_LEVEL_DEFAULT,   // Default authentication 
		RPC_C_IMP_LEVEL_IMPERSONATE, // Default Impersonation  
		NULL,                        // Authentication info
		EOAC_NONE,                   // Additional capabilities 
		NULL                         // Reserved
	);


	if (FAILED(hres))
	{
		cout << "Failed to initialize security. Error code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;                      // Program has failed.
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
		cout << "Failed to create IWbemLocator object. "
			<< "Err code = 0x"
			<< hex << hres << endl;
		CoUninitialize();
		return 1;                 // Program has failed.
	}

	// Step 4: ---------------------------------------------------
	// Connect to WMI through the IWbemLocator::ConnectServer method

	IWbemServices* pSvc = NULL;

	// Connect to the local root\cimv2 namespace
	// and obtain pointer pSvc to make IWbemServices calls.
	hres = pLoc->ConnectServer(
		_bstr_t(L"ROOT\\CIMV2"), // WMI Namespace
		NULL,                    // User name
		NULL,                    // User password
		0,                       // Locale
		NULL,                    // Security flags                 
		0,                       // Authority    
		0,                       // Context object
		&pSvc                    // IWbemServices proxy
	);

	if (FAILED(hres))
	{
		cout << "Could not connect. Error code = 0x"
			<< hex << hres << endl;
		pLoc->Release();
		pSvc->Release();
		CoUninitialize();
		return 1;                // Program has failed.
	}

	//cout << "Connected to ROOT\\CIMV2 WMI namespace" << endl;


	// Step 5: --------------------------------------------------
	// Set security levels for the proxy ------------------------

	hres = CoSetProxyBlanket(
		pSvc,                        // Indicates the proxy to set
		RPC_C_AUTHN_WINNT,           // RPC_C_AUTHN_xxx 
		RPC_C_AUTHZ_NONE,            // RPC_C_AUTHZ_xxx 
		NULL,                        // Server principal name 
		RPC_C_AUTHN_LEVEL_CALL,      // RPC_C_AUTHN_LEVEL_xxx 
		RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
		NULL,                        // client identity
		EOAC_NONE                    // proxy capabilities 
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

	// Code to Handle PID type requests
	if (mode == "/PID") {
		// Code to handle PID based requests without /T flag
		if (child == "NoChild") {
			// Set up to call the Win32_Process::Terminate method
			BSTR ClassName = SysAllocString(L"Win32_Process");

			// Setting handler to locate the Process to Terminate specified as parameter
			std::wstring classNameInstance = L"Win32_Process.Handle=";
			std::wstring argumentString(argument);
			classNameInstance.append(L"\"").append(argumentString).append(L"\"");
			BSTR ClassNameInstance = SysAllocString(
				classNameInstance.c_str());

			// Preparing context for Method call
			_bstr_t MethodName = (L"Terminate");
			BSTR ParameterName = SysAllocString(L"Reason");

			IWbemClassObject* pClass = NULL;
			hres = pSvc->GetObject(ClassName, 0, NULL, &pClass, NULL);

			IWbemClassObject* pInParamsDefinition = NULL;
			IWbemClassObject* pOutMethod = NULL;

			// Getting Terminate method for later execution
			hres = pClass->GetMethod(MethodName, 0,
				&pInParamsDefinition, &pOutMethod);

			if (FAILED(hres))
			{
				cout << "Could not get Terminate Method. Error code = 0x"
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

			if (FAILED(hres))
			{	
				if (hres == WBEM_E_NOT_FOUND) {
					cout << "The Process Does Not Exist" << std::endl;
				}
				else{
					cout << "Could not Terminate process. Error code = 0x"
						<< hex << hres << endl;
				}
				VariantClear(&pcVal);
				SysFreeString(ClassName);
				SysFreeString(MethodName);
				pClass->Release();
				pInParamsDefinition->Release();
				pSvc->Release();
				pLoc->Release();
				CoUninitialize();
				return 1;           // Program has failed.
			}
			std::wcout << "Process PID: " << argument << " Terminated" << std::endl;

			// Clean up
			//--------------------------
			VariantClear(&pcVal);
			SysFreeString(ClassName);
			SysFreeString(MethodName);
			//pClass->Release();
			pInParamsDefinition->Release();
			//pLoc->Release();
			//pSvc->Release();
			//CoUninitialize();
			//return 0;
		}
		// Child Mode
		else {
			// Executing query to obtain all Process Objects
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
			IWbemClassObject* pclsObj;
			ULONG uReturn = 0;

			wchar_t* pid;

			// Iterate all processes
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

				// Get the value of the PID and Parent PID properties
				hres = pclsObj->Get(L"ProcessID", 0, &vtProp, 0, 0);
				hres = pclsObj->Get(L"ParentProcessID", 0, &vtProp2, 0, 0);

				std::wstring parentProcessId = std::to_wstring(vtProp2.uintVal);
				std::wstring processId = std::to_wstring(vtProp.uintVal);

				// Comparison between the Parent PID and the input PID. If equals, the child process is Terminated.
				if (wcscmp(parentProcessId.c_str(), argument) == 0) {

					BSTR ClassName = SysAllocString(L"Win32_Process");

					// Handler for the function
					std::wstring classNameInstance = L"Win32_Process.Handle=";
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

					if (FAILED(hres))
					{
						cout << "Could not Terminate Child Process" << std::endl;
					}

					std::wcout << "Child Process With ID: " << processId << std::endl;

					// Clean up
					//--------------------------
					VariantClear(&pcVal);
					SysFreeString(ClassName);
					SysFreeString(MethodName);
					pClass->Release();
					pInParamsDefinition->Release();
				}
			}

			// Terminate Parent Process after Childs have been Terminated

			BSTR ClassName = SysAllocString(L"Win32_Process");

			std::wstring classNameInstance = L"Win32_Process.Handle=";
			std::wstring argumentString(argument);
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
				cout << "Could not get Terminate Method. Error code = 0x"
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

			if (FAILED(hres))
			{
				if (hres == WBEM_E_NOT_FOUND) {
					cout << "The Process Does Not Exist" << std::endl;
				}
				else {
					cout << "Could not Terminate process. Error code = 0x"
						<< hex << hres << endl;
				}
				VariantClear(&pcVal);
				SysFreeString(ClassName);
				SysFreeString(MethodName);
				pClass->Release();
				pInParamsDefinition->Release();
				pSvc->Release();
				pLoc->Release();
				CoUninitialize();
				return 1;           // Program has failed.
			}
			std::wcout << "Process PID: " << argument << " Terminated" << std::endl;
		}
	}
	// Image Name Mode
	else if (mode == "ImageName") {
		// No Child Mode
		if (child == "NoChild") {
			// Execute query to obtain all processes
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
			IWbemClassObject* pclsObj;
			ULONG uReturn = 0;

			wchar_t* pid;

			bool success = false;

			// Iterate all processes
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

				// Get the value of the Name and PID properties
				hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
				hres = pclsObj->Get(L"ProcessID", 0, &vtProp2, 0, 0);
				// Comparison between our input Image Name and the Process Name. If matches, the PID is Terminated.
				if (wcscmp(vtProp.bstrVal, argument) == 0) {
					std::wstring processId = std::to_wstring(vtProp2.uintVal);

					BSTR ClassName = SysAllocString(L"Win32_Process");

					std::wstring classNameInstance = L"Win32_Process.Handle=";
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

					if (FAILED(hres))
					{
						if (hres == WBEM_E_NOT_FOUND) {
							cout << "The Process Does Not Exist" << std::endl;
						}
						else {
							cout << "Could not Terminate process. Error code = 0x"
								<< hex << hres << endl;
						}
						VariantClear(&pcVal);
						SysFreeString(ClassName);
						SysFreeString(MethodName);
						pClass->Release();
						pInParamsDefinition->Release();
						pSvc->Release();
						pLoc->Release();
						CoUninitialize();
						return 1;           // Program has failed.
					}

					std::wcout << "Process " << processId << " Terminated, as part of " << argument << std::endl;
					success = true;

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
			// No results found given that Image
			if (!success) {
				std::wcout << "No Process Found for Image Name " << argument << std::endl;
			}
		}
		//Child Mode. There is a first iteration to find out ProcessId coressponding to the Image Name. For each ProcessID found, there is another
		//iteration to search for childs of that process.
		else {
			// Query to obtain all processes
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
			IWbemClassObject* pclsObj;
			ULONG uReturn = 0;

			wchar_t* pid;

			// Variable to indicate success in process finding
			bool success = false;

			// Iterate all processes
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

				// Get the value of the Name and ProcessID properties
				hres = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
				hres = pclsObj->Get(L"ProcessID", 0, &vtProp2, 0, 0);
				// Match between Image Name and Process Object. As we are in child mode, we should iterate again to find child for this processID.
				if (wcscmp(vtProp.bstrVal, argument) == 0) {
					IEnumWbemClassObject* pEnumerator2 = NULL;
					hres = pSvc->ExecQuery(
						bstr_t("WQL"),
						bstr_t("SELECT * FROM Win32_Process"),
						WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
						NULL,
						&pEnumerator2);

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
					IWbemClassObject* pclsObj2;
					ULONG uReturn2 = 0;

					wchar_t* pid;
					// Second iteration to find new childs for the matching PID.
					while (pEnumerator2)
					{
						hres = pEnumerator2->Next(WBEM_INFINITE, 1,
							&pclsObj2, &uReturn2);

						if (0 == uReturn2)
						{
							break;
						}

						VARIANT vtProp3;
						VARIANT vtProp4;

						// Get the value of the Name property
						hres = pclsObj2->Get(L"ProcessID", 0, &vtProp3, 0, 0);
						hres = pclsObj2->Get(L"ParentProcessID", 0, &vtProp4, 0, 0);

						// Converting to String the Process ID which we are searching childs for.
						std::wstring iteratedProcessId = std::to_wstring(vtProp2.uintVal);
						std::wstring parentProcessId = std::to_wstring(vtProp4.uintVal);
						std::wstring processId = std::to_wstring(vtProp3.uintVal);

						// If the child iteration matches the initial Process Id iteration, the child is terminated.
						if (wcscmp(parentProcessId.c_str(), iteratedProcessId.c_str()) == 0) {

							BSTR ClassName = SysAllocString(L"Win32_Process");

							std::wstring classNameInstance = L"Win32_Process.Handle=";
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

							if (FAILED(hres))
							{
								std::wcout << "Could Not Terminate Child Process " << processId << " from Parent Process " << iteratedProcessId << std::endl;
							}

							std::wcout << "Child Process " << processId << " Terminated, from Parent " << iteratedProcessId << " Processs" << std::endl;

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


					// Kill Parent Process ID after terminating Childs. These parents processes correspond to the Image Name

					std::wstring processId = std::to_wstring(vtProp2.uintVal);

					BSTR ClassName = SysAllocString(L"Win32_Process");

					std::wstring classNameInstance = L"Win32_Process.Handle=";
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
						cout << "Could not get the method for Termination. Error code = 0x"
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

					std::wcout << "Process " << processId << " Terminated from " << argument << std::endl;
					success = true;

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
			if (!success) {
				std::wcout << "No Process Found for Image Name " << argument << std::endl;
			}
		}
	}	
	else {
	std::wcout << "Something Went Wrong" << std::endl;
	}

}