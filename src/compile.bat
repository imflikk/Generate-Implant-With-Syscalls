@ECHO OFF

cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tp src\\*.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE
rem Cleaning up...
del *.obj
