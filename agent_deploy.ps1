# WAZUH Windows Add Agent Script

# v2.2 2016/04/06
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is a free software; you can redistribute it and/or modify it under the terms of GPLv2

param (
    #Mandatory
    [switch]$Elevated,
    [string]$api_ip = "",
    [string]$username = "",
    [string]$password = "",
    [string]$ossec_exe = "",

    #Optionals
    [string]$api_port = "55000",
    [string]$api_protocol = "http",
    [string]$server_ip = $api_ip,
    [string]$agent_name = $env:computername,
    [string]$ossec_path = $env:SystemDrive+"\ossec-agent\",
    [Int]$prompt_agent_name = 0,
    [string]$agent_ip = "",
    [switch]$help

    )

if(($help.isPresent)) {
    "Wazuh Deploy OSSEC Agent Windows
Github repository: http://github.com/wazuh/wazuh-tools
API Documentation: http://documentation.wazuh.com/en/latest/ossec_api.html
Site: http://www.wazuh.com"
""
""
    "Usage: agent_deploy.ps1 -api_ip IP -username USERNAME -password PASSWORD"
    "Arguments description:
    Mandatory:
        -api_ip Wazuh API IP
        -username Wazuh API auth https username
        -password Wazuh API auth https password
        -ossec_exe OSSEC Agent installer full path
    Optionals:
        -api_port Wazuh API port [Default 55000]
        -server_ip OSSEC Manager IP [Default -api_ip]
        -agent_name OSSEC Agent Name [Default windows hostname]
        -ossec_path OSSEC Agent installation path [Default Sysdrive:\ossec-agent]
        -agent_ip Agent IP [Default automatic | any | IP Address]
        -prompt_agent_name [0/1] In case agent name already exists on OSSEC Manager, prompt to ask Agent Name [default 0]
        -help Display help
    "
    Exit
}


# Opening powershell as Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
       "This script requires Administrator privileges"
       Write-Host "Press any key to continue ..."
       $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
       Exit
}

# Checking Administrator privilegies
function Test-Admin {
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
if ((Test-Admin) -eq $false)  {
       "This script requires Administrator privileges"
       Write-Host "Press any key to continue ..."
       $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
       Exit
}

## Checking arguments
if($api_ip -eq ""){
    "-api_ip is required. Try help to display arguments list"
    Write-Host "Press any key to continue ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit
}
if($username -eq ""){
    "-username is required. Try -help to display arguments list"
    Write-Host "Press any key to continue ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit
}
if($password -eq ""){
    "-password is required. Try -help to display arguments list"
    Write-Host "Press any key to continue ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit
}
if($ossec_exe -eq ""){
    "-ossec_exe is required. Try -help to display arguments list"
    Write-Host "Press any key to continue ..."
    $x = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit
}

# Create Log file
# ps1
$path = "."

$file_log = "\agent_deploy.log"

# Ossec service name
$ossec_service = 'OssecSvc'

#Agent installer path and name
$exe = $ossec_exe

$base_url = $api_protocol+"://"+$api_ip+":"+$api_port


if(!(Test-Path -Path $path$file_log)){
    New-Item -Path $path$file_log -ItemType File
}else{
    Clear-Content $path$file_log
    Add-Content -Path $path$file_log -Value "Starting"
    "Starting"
}

#################
# Aux functions
#################
function ConvertTo-Json20([object] $item){
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer
    return $ps_js.Serialize($item)
}

function ConvertFrom-Json20([object] $item){
    add-type -assembly system.web.extensions
    $ps_js=new-object system.web.script.serialization.javascriptSerializer

    #The comma operator is the array construction operator in PowerShell
    return ,$ps_js.DeserializeObject($item)
}
function validateIp($item, $path, $file_log){
    if(!($item -match "^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:\/\d{1,2})*$|^any$|^ANY$")){
        Add-Content -Path $path$file_log -Value "Agent IP format invalid. Allowed: IP Address/mask or 'any'"
        Write-Host "Agent IP format invalid. Allowed: IP Address/mask or 'any'"
        Exit 1001
    }

}

function AgentName
{
    $read_agent_name = ""
    while(!($read_agent_name -match "^[A-Za-z0-9\\-_]+$") -Or !($read_agent_name.length -gt 2 -And $read_agent_name.length -lt 33)){
        $read_agent_name = Read-Host 'Enter OSSEC Agent name (Name must contain only alphanumeric characters min=2 max=32)'
    }
    $read_agent_name
}

## Checking IP format
if($agent_ip -ne ""){
    validateIp $agent_ip $path $file_log
}


# If OSSEC service already exits, do not install.
Get-Service -Name $ossec_service -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
if ($? -eq $true) {
    Add-Content -Path $path$file_log -Value "INFO: OSSEC SERVICE already installed. Reinstalling."
    "INFO: OSSEC SERVICE already installed. Reinstalling."
}

# Verifying executable path
if(!(Test-Path -Path $exe)){
    Add-Content -Path $path$file_log -Value "OSSEC Executable does not exists: $exe"
    "OSSEC Executable does not exists: $exe"
    Exit
}

# Certs functions
function Ignore-SelfSignedCerts {
    add-type @"
        using System.Net;
        using System.Security.Cryptography.X509Certificates;

        public class PolicyCert : ICertificatePolicy {
            public PolicyCert() {}
            public bool CheckValidationResult(
                ServicePoint sPoint, X509Certificate cert,
                WebRequest wRequest, int certProb) {
                return true;
            }
        }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = new-object PolicyCert
}
Ignore-SelfSignedCerts
Add-Content -Path $path$file_log -Value "Certify OK"
"Certify OK"
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))

############################
# Aux functions
############################
function Http-Web-Request([string]$method,[string]$encoding,[string]$server,[string]$path,$headers,[string]$postData)
{
    ## Compose the URL and create the request
    $url = "$server/$path"
    [System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($url)
    ## Add the method (GET, POST, etc.)
    $request.Method = $method
    ## Add an headers to the request
    foreach($key in $headers.keys)
    {
        $request.Headers.Add($key, $headers[$key])
    }
    ## We are using $encoding for the request as well as the expected response
    $request.Accept = $encoding
    ## Send a custom user agent if you want
    $request.UserAgent = "PowerShell script"

    ## Create the request body if the verb accepts it (NOTE: utf-8 is assumed here)
    if ($method -eq "POST" -or $method -eq "PUT") {
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($postData)
        $request.ContentType = $encoding
        $request.ContentLength = $bytes.Length

        [System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
        $outputStream.Write($bytes,0,$bytes.Length)
        $outputStream.Close()
    }


    ## This is where we actually make the call.
    try
    {
        [System.Net.HttpWebResponse] $response = [System.Net.HttpWebResponse] $request.GetResponse()
        $sr = New-Object System.IO.StreamReader($response.GetResponseStream())
        $txt = $sr.ReadToEnd()

        ## Return the response body to the caller
        return $txt
    }
    ## This catches errors from the server (404, 500, 501, etc.)
    catch [Net.WebException] {

        [System.Net.HttpWebResponse] $resp = [System.Net.HttpWebResponse] $_.Exception.Response
        ## NOTE: comment out the next line if you don't want this function to print to the terminal
        Write-Host $resp.StatusCode -ForegroundColor Red -BackgroundColor Yellow
        ## NOTE: comment out the next line if you don't want this function to print to the terminal
        Write-Host $resp.StatusDescription -ForegroundColor Red -BackgroundColor Yellow
        ## Return the error to the caller
        return $resp.StatusDescription
    }
}


function req($method, $resource, $data){
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))
    $url = $base_url + $resource;
    $headers = @{
        Authorization=("Basic {0}" -f $base64AuthInfo)
    }
    if ($data){
        # POST or PUT
        return Http-Web-Request $method "application/json" $base_url $resource $headers $data
    }else{
        return Http-Web-Request $method "application/json" $base_url $resource $headers ""
    }
}

####################
# API: Adding Agent
####################
function addAgent($agent_name, $agent_ip, $prompt_agent_name, $path, $file_log){
    $addedOK = 0
    $ID = "-1"
    while($addedOK -eq 0){
        $resource = "agents"
        $data = '{"name":"'+$agent_name+'","ip":"'+$agent_ip+'"}'
        try{
            $response = req -method "POST" -resource $resource $data
            $response = ConvertFrom-Json20 $response
        }catch{
            $exceptionDetails = $_
            Add-Content -Path $path$file_log -Value "Some error adding the agent $($exceptionDetails)"
            Write-Host "Some error adding the agent:" $($exceptionDetails)
            Exit 1001
        }

        if($response.error -eq 0){
            $ID = $response.data
            $addedOK = 1
        }else{
            Add-Content -Path $path$file_log -Value "$($response.message)"
            if($response.error -eq 75){
                if($prompt_agent_name){
                    Write-Host $response.message
                    $agent_name = AgentName
                }else{
                    Add-Content -Path $path$file_log -Value "Agent name already exists or it is invalid. Please use option -prompt_agent_name"
                    Write-Host "Agent name already exists or it is invalid. Please use option -prompt_agent_name"
                    Write-Host $response.message
                    exit 1001
                }
            }else{
                Add-Content -Path $path$file_log -Value $response.message
                Write-Host $response.message
                exit 1001
            }
        }
    }
    return $ID

}
##################
# API: Getting key
##################
function getKey($agent_id, $path, $file_log ){

    $key = "-1"
    $resource = "agents/"+$ID+"/key"
    try{
        $response = req -method "GET" -resource $resource
        $response = ConvertFrom-Json20 $response
    }catch{
        $exceptionDetails = $_
        Add-Content -Path $path$file_log -Value "Some error getting the agent key from API $($exceptionDetails)"
        $error = $exceptionDetails | ConvertFrom-Json20
        Write-Host "Some error getting the agent key from API :"$error
        Exit 1001
    }
    if($response.error -eq 0){
        $key = $response.data
    }else{
        Add-Content -Path $path$file_log -Value "Some error getting the agent key from API $($response.message)"
        Write-Host "Some error getting the agent key from API :"$response.message
        exit 1001
    }
    return $key
}
##################
# Importing key
##################
function importKey($key, $ossec_path, $path, $file_log ){
    $psi = New-Object System.Diagnostics.ProcessStartInfo;
    $psi.FileName = $ossec_path+"manage_agents.exe"; #process file_log
    #Verifying manage_agent path
    if(!(Test-Path -Path $psi.FileName)){
        Add-Content -Path $path$file_log -Value $psi.FileName" does not exists"
        Write-Host $psi.FileName" does not exists"
        Exit
    }
    $psi.UseShellExecute = $false; #start the process from it's own executable file
    $psi.RedirectStandardInput = $true; #enable the process to read from standard input
    $psi.Arguments = "-i " + $key
    $p = [System.Diagnostics.Process]::Start($psi);
    Start-Sleep -s 2 #wait 2 seconds so that the process can be up and running
    $p.StandardInput.WriteLine("y");
    Start-Sleep -s 2 #wait 2 seconds so that the process can be up and running
    $p.StandardInput.WriteLine("ENTER");
    Add-Content -Path $path$file_log -Value "Import Key into OSSEC OK"
    Write-Host "Import Key into OSSEC OK"
    # Start OSSEC Service
    net start OssecSvc
    Add-Content -Path $path$file_log -Value "OSSEC SERVICE OK"
    Write-Host "OSSEC SERVICE OK"
    # Restart Service
    Start-Sleep -s 5 #wait 5s and restart OSSEC Agent (Better way to send a notification to OSSEC Manager)
    Get-Service -Name $ossec_service -ErrorAction SilentlyContinue | Restart-Service -ErrorAction SilentlyContinue
    Write-Host "AGENT INSTALLED SUCCESSFULLY"
}

############################
# MAIN
############################


#Installing Agent Executable

$AllArgs = @('/S /D='+$ossec_path)
try{
        $check = Start-Process $exe $AllArgs -Wait -Verb runAs
}catch{
        "OSSEC Installation failed"
        Add-Content -Path $path$file_log -Value "OSSEC Executable does not exists: $exe"
        "OSSEC Executable does not exists: $exe"
        $exceptionDetails = $_.Exception
        Add-Content -Path $path$file_log -Value "$($exceptionDetails)"
        Write-Host $exceptionDetails.Message
        exit 1001
}

Add-Content -Path $path$file_log -Value "OSSEC Installed OK"
"OSSEC Installed OK"


#Server ip to ossec.conf
if((Test-Path -Path $ossec_path"ossec.conf")){
    if(!(select-string -Quiet -path $ossec_path"ossec.conf" -pattern '<server-ip>.*[^1.2.3.4].*</server-ip>')){
        Add-Content -Path $ossec_path"ossec.conf" -Value "<ossec_config><client><server-ip>$server_ip</server-ip></client></ossec_config>"
        Add-Content -Path $path$file_log -Value "Added server-ip to ossec.conf"
        "Added server-ip to ossec.conf"
    }
}else{
    Add-Content -Path $path$file_log -Value "ERROR: OSSEC conf not found at $ossec_path"+"ossec.conf"
    "ERROR: OSSEC conf not found at "+$ossec_path+"ossec.conf"
}

# Prompt: Agent name
if($prompt_agent_name){
    $agent_name = AgentName
}


# API: Adding Agent
$ID = addAgent $agent_name $agent_ip $prompt_agent_name $path $file_log


# API: Get key
if($ID -ne "-1"){
    Add-Content -Path $path$file_log -Value "Adding Agent OK"
    Write-Host "Adding Agent OK"
    $KEY = getKey $ID $path $file_log
}else{
    Add-Content -Path $path$file_log -Value "Error registering agent, ID not valid, stop."
    Write-Host "Error registering agent, ID not valid, stop."
    exit 1001
}

# API: Import key
if($KEY -ne "-1"){
    Add-Content -Path $path$file_log -Value "Getting KEY OK"
    Write-Host "Getting KEY OK"
    importKey $KEY $ossec_path $path $file_log
}else{
    Add-Content -Path $path$file_log -Value "Error getting key, KEY not valid, stop."
    Write-Host "Error getting key, KEY not valid, stop."
    exit 1001
}
