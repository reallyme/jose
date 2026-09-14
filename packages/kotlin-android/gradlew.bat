@rem SPDX-FileCopyrightText: 2026 ReallyMe LLC
@rem
@rem SPDX-License-Identifier: MIT OR Apache-2.0
@echo off
setlocal
set "SCRIPT_DIR=%~dp0"
call "%SCRIPT_DIR%..\kotlin\gradlew.bat" %*
set "EXIT_CODE=%ERRORLEVEL%"
exit /b %EXIT_CODE%
