// MyTaskKill.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "LocalTaskKill.h"
#include "RemoteTaskKill.h"
#include <iostream>




int wmain(int argc, wchar_t* argv[])
{
    int local = 1;
    int child = 0;
    int i;
    // If not /S   -  No remote
    for (i = 0; i < argc; i++) {
        if (wcscmp(argv[i], L"/S") == 0) {
            local = 0;
        }
        if (wcscmp(argv[i], L"/T") == 0) {
            child = 1;
        }
    }


    // We are in local mode
    if (local == 1) {
        // Child mode inactive
        if (child == 0) {
            // TaskKill Withouth Arguments
            if (argc == 1) {
                std::wcout << "Error. At Least /PID or /IM should be specified" << std::endl;
            }
            else if (argc == 2) {
                std::wcout << "Error. At Least /PID PID or /IM ImageName should be specified" << std::endl;
            }
            // Basic Functioning: 1 Argument.
            else if (argc == 3) {
                // Basic Mode specifying PID
                if ((wcscmp(argv[1], L"/PID") == 0)) {
                    LocalTaskKill(argv[2], "/PID", "NoChild");
                }
                // Basic Mode specifying Image Name
                else if ((wcscmp(argv[1], L"/IM") == 0)) {
                    LocalTaskKill(argv[2], "ImageName", "NoChild");
                }

                // Incorrect First Argument
                else {
                    std::wcout << "Incorrect Argument. At Least /PID PID or /IM ImageName should be specified" << std::endl;
                }
            }
            // Wrong input
            else {
                std::wcout << "Incorrect arguments" << std::endl;
            }
        }
        //Child Mode Active
        else {
            if (argc == 2) {
                std::wcout << "Error. At Least /PID or /IM should be specified along with /T" << std::endl;
                //LocalTaskKill("Standard");
            }
            else if (argc == 3) {
                std::wcout << "Error. At Least /PID PID or /IM ImageName should be specified along with /T" << std::endl;
            }
            // Basic Functioning: 1 Argument with Child Mode.
            else if (argc == 4 && (wcscmp(argv[3], L"/T") == 0)) {
                // Basic Mode specifying PID
                if ((wcscmp(argv[1], L"/PID") == 0)) {
                    LocalTaskKill(argv[2], "/PID", "Child");
                }
                // Basic Mode specifying Image Name
                else if ((wcscmp(argv[1], L"/IM") == 0)) {
                    LocalTaskKill(argv[2], "ImageName", "Child");
                }

                // Incorrect First Argument
                else {
                    std::wcout << "Incorrect Argument. At Least /PID PID or /IM ImageName should be specified along with /T" << std::endl;
                }
            }
            // Wrong input
            else {
                std::wcout << "Incorrect arguments: Use [/PID PID OR /IM ImageName] /T " << std::endl;
            }
        }
    }

    // Remote Mode
    else {
        // Child mode inactive
        if (child == 0) {
            if (argc == 2) {
                std::wcout << "Need to specify Domain Name: /S Domain /U User /P Password [/PID pid OR /IM ImageName]" << std::endl;
            }
            else if (argc >= 3 && argc <= 8) {
                std::wcout << "Need User and Password: /U User /P Password [/PID pid OR /IM ImageName]" << std::endl;
            }
            else if (argc == 9) {
                if (wcscmp(argv[1], L"/S") == 0 && wcscmp(argv[3], L"/U") == 0 && wcscmp(argv[5], L"/P") == 0 && (wcscmp(argv[7], L"/PID") == 0) || wcscmp(argv[7], L"/IM") == 0) {
                    // Every parameter is OK and the code should be executed
                    if ((wcscmp(argv[7], L"/PID") == 0)) {
                        RemoteTaskKill(argv[2], argv[4], argv[6], argv[8], "/PID", "NoChild");
                    }
                    else {
                        RemoteTaskKill(argv[2], argv[4], argv[6], argv[8], "/IM", "NoChild");
                    }
                }
                else {
                    std::wcout << "Need to specify Domain, User and Password: /S Domain /U User /P Password [/PID pid OR /IM ImageName]" << std::endl;
                }
            }
            else {
                std::wcout << "Need to specify Domain, User and Password: /S Domain /U User /P Password [/PID pid OR /IM ImageName]" << std::endl;
            }
        }
        // Child Mode Active
        else {
            if (argc == 3) {
                std::wcout << "Need to specify Domain Name: /S Domain /U User /P Password [/PID pid OR /IM ImageName] /T" << std::endl;
            }
            else if (argc >= 4 && argc <= 9) {
                std::wcout << "Need User and Password: /U User /P Password [/PID pid OR /IM ImageName] /T" << std::endl;
            }
            else if (argc == 10) {
                if (wcscmp(argv[1], L"/S") == 0 && wcscmp(argv[3], L"/U") == 0 && wcscmp(argv[5], L"/P") == 0 && ((wcscmp(argv[7], L"/PID") == 0) || wcscmp(argv[7], L"/IM") == 0) && (wcscmp(argv[9], L"/T") == 0)) {
                    // Every parameter is OK and the code should be executed
                    if ((wcscmp(argv[7], L"/PID") == 0)) {
                        RemoteTaskKill(argv[2], argv[4], argv[6], argv[8], "/PID", "Child");
                    }
                    else {
                        RemoteTaskKill(argv[2], argv[4], argv[6], argv[8], "/IM", "Child");
                    }
                }
                else {
                    std::wcout << "Need to specify Domain, User and Password: /S Domain /U User /P Password [/PID pid OR /IM ImageName] /T" << std::endl;
                }
            }
            else {
                std::wcout << "Need to specify Domain, User and Password: /S Domain /U User /P Password [/PID pid OR /IM ImageName] /T" << std::endl;
            }
        }
        
    }
    return 0;
}

