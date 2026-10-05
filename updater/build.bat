@echo off
REM ===========================================================================
REM  Compila el actualizador de EVM con MSVC.
REM  Uso:  build.bat
REM  Salida: actualizador.exe
REM
REM  Necesario Visual Studio Build Tools con la carga de trabajo "Desarrollo
REM  para el escritorio con C++". No hacen falta librerias externas: el
REM  ejecutable solo usa DLLs del sistema de Windows.
REM ===========================================================================
setlocal

pushd "%~dp0"

REM --- localizar vcvarsall.bat --------------------------------------------
set "VCV="
for %%D in (
    "%ProgramFiles(x86)%\Microsoft Visual Studio\18\BuildTools"
    "%ProgramFiles%\Microsoft Visual Studio\18\BuildTools"
    "%ProgramFiles(x86)%\Microsoft Visual Studio\2022\BuildTools"
    "%ProgramFiles%\Microsoft Visual Studio\2022\BuildTools"
    "%ProgramFiles(x86)%\Microsoft Visual Studio"
    "%ProgramFiles%\Microsoft Visual Studio"
) do (
    if exist "%%~D\VC\Auxiliary\Build\vcvarsall.bat" (
        if not defined VCV set "VCV=%%~D\VC\Auxiliary\Build\vcvarsall.bat"
    )
)

if not defined VCV (
    echo [ERROR] No se encontro vcvarsall.bat.
    echo         Instala "Desarrollo para el escritorio con C++" en Visual Studio.
    popd
    exit /b 1
)

echo Usando: %VCV%
call "%VCV%" x64 >nul
if errorlevel 1 (
    echo [ERROR] fallo al preparar el entorno de compilacion.
    popd
    exit /b 1
)

echo.
echo Compilando actualizador.exe ...
echo.

REM  /MT   -> CRT estatico: el .exe no depende de nada instalado
REM  /W4   -> avisos habilitados
REM  /GS   -> proteccion de pila
cl /nologo /O2 /MT /W4 /GS /DUNICODE /D_UNICODE ^
   updater.cpp ^
   /Fe:actualizador.exe ^
   /link /SUBSYSTEM:WINDOWS

if errorlevel 1 (
    echo.
    echo [ERROR] la compilacion fallo.
    popd
    exit /b 1
)

REM --- limpiar intermedios -------------------------------------------------
del /q updater.obj 2>nul

echo.
echo [OK]Listo: %CD%\actualizador.exe
echo.

REM --- prueba rapida -------------------------------------------------------
echo Prueba rapida (--help):
actualizador.exe --help

popd
endlocal