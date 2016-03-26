@echo off
del *.sdf
del /s *.aps
del /a:h *.suo
rmdir /s /q .vs
rmdir /s /q ipch
rmdir /s /q x64
rmdir /s /q Debug
rmdir /s /q Release
rmdir /s /q DdiMon\x64
rmdir /s /q DdiMon\Debug
rmdir /s /q DdiMon\Release
cd HyperPlatform
clean.bat
