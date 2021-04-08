# MyTaskKill
@ author - Sergio Yerbes

<br/><br/>

## Usage:

MYTASKKILL [/S system /U username /P password]
         [/PID Pid | /IM ImageName] [/T]
         
<br/><br/>         

## Description: 

Taskkill customized implementation with a similar functionality than the original Windows command. It forcefully terminates processes from the system, locally or remotely.

<br/><br/>

## Parameter List:

/S : Remote system to connect to, corresponding to the system name. It queries DNS server for routing purposes. Optional parameter defined always as the first parameter.

/U : Sets username for remote connections. Forced usage if /S flag is active.

/P : Sets password for remote connections. Also forced usage if /S flag is active.

/PID : Process ID to be terminated.

/IM : Image Name to terminate. It iterates though all processes to terminate PID with such name.

/T : Kills the processes specified in /PID or processes in /IM, along with all the child processes created by them. Always specified at the end. Optional parameter.

<br/><br/>

## Examples:

MyTaskKill /S system /U user /P password /PID 3908

MyTaskKill /IM firefox.exe /T
