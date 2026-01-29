@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\Tools\VsDevCmd.bat" -arch=x86
cd /d "C:\Users\123\Desktop\NFS\NFSOR_Custom"
msbuild "build\NFSOR_Custom.vcxproj" /p:Configuration=Release /p:Platform=Win32 /t:Rebuild
if %ERRORLEVEL% EQU 0 (
    echo Build successful!
    copy /Y "build\Release\NFSOR_Custom.asi" "C:\Users\123\Desktop\NFS\NFS Underground 2\scripts\NFSOR_Custom.asi"
    if %ERRORLEVEL% EQU 0 (
        echo Copied to game folder!
    ) else (
        echo Failed to copy!
    )
) else (
    echo Build failed!
)
