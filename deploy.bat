@setlocal enableextensions
@cd /d "%~dp0"
powershell -ExecutionPolicy ByPass -File .\agent_deploy.ps1 -api_ip 192.168.1.50 -username foo -password bar -ossec_exe ossec-wazuh-winagent-v1.1.1.exe
