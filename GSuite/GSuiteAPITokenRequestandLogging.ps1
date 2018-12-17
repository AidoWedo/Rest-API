<#
.SYNOPSIS
Google G-Suite API Authnetication with OATHv2 with refresh of access tokens using refresh-tokens and grabbing of admin logs to file with error logging and interactive google api auth window

.DESCRIPTION
 
.NOTES
August 2017 @richardbevan

.LINK
https://github.com/

.Credits
blog.technet.com and foxdeploy.com
#>

#This script use Invoke-RestMethod which only comes with PowerShell 3.0 of higher.
if ($PSVersionTable.PSVersion -lt [Version]"3.0") {
  write-host "PowerShell version " $PSVersionTable.PSVersion "not supported.  This script requires PowerShell 3.0 or greater." -ForegroundColor Red
  exit
}

# specify location of error logging
$logfile="C:\Users\richard.bevan\Documents\Powershell\MSExample\errorlogs\errorgsuite.log"
$date = [DateTime]::UtcNow.ToString('r')


Function Show-OAuthWindow
{
    param(
        [System.Uri]$Url
    )


    Add-Type -AssemblyName System.Windows.Forms
 
    $form = New-Object -TypeName System.Windows.Forms.Form -Property @{Width=440;Height=640}
    $web  = New-Object -TypeName System.Windows.Forms.WebBrowser -Property @{Width=420;Height=600;Url=($url ) }
    $DocComp  = {
        $Global:uri = $web.Url.AbsoluteUri
        if ($Global:Uri -match "error=[^&]*|code=[^&]*") {$form.Close() }
    }
    $web.ScriptErrorsSuppressed = $true
    $web.Add_DocumentCompleted($DocComp)
    $form.Controls.Add($web)
    $form.Add_Shown({$form.Activate()})
    $form.ShowDialog() | Out-Null

    $queryOutput = [System.Web.HttpUtility]::ParseQueryString($web.Url.Query)
    $output = @{}
    foreach($key in $queryOutput.Keys){
        $output["$key"] = $queryOutput[$key]
    }
    
    $output
}

# Define Variables from 
# Get Google API access - https://developers.google.com/identity/protocols/OAuth2WebServer#offline
# variable queryOutput will have access code

Add-Type -AssemblyName System.Web
$client_id = "replace_with_your_details"
$client_secret = "joOCDNOXtHuxna_ZCRHnMbID" # Copied or Downloaded from Google API Console
$redirectUrl = "http://localhost/oauth2callback" # Defined in Google API Console
$scope = "https://www.googleapis.com/auth/admin.reports.audit.readonly https://www.googleapis.com/auth/admin.reports.usage.readonly" # Fixed Variable for both audit and admin scopes in api but could also have scope for Google Drive etc
$access_type = "offline" # Fixed Variable
$approval_prompt = "consent" # Fixed Variable
$response_type= "code"

$loginUrl = "https://accounts.google.com/o/oauth2/v2/auth?redirect_uri=" + 
            [System.Web.HttpUtility]::UrlEncode($redirectUrl) + 
            "&client_id=$client_id" + 
            "&scope=$scope" +
            "&access_type=$access_type" +
            "&response_type=code"
            "&prompt=login"
            
            
$queryOutput = Show-OAuthWindow -Url $loginUrl

# Access token code after Google Api App authorisation

$AuthorisationPostRequest = 
    "grant_type=authorization_code" + "&" +
    "redirect_uri=" + [System.Web.HttpUtility]::UrlEncode($redirectUrl) + "&" +
    "client_id=$client_id" + "&" +
    "client_secret=" + [System.Web.HttpUtility]::UrlEncode("$client_secret") + "&" +
    "code=" + $queryOutput["code"] + "&" +
    "scope=$scope"

    $Authorisation = 
    Invoke-RestMethod   -Method Post `
                        -ContentType application/x-www-form-urlencoded `
                        -Uri https://www.googleapis.com/oauth2/v4/token `
                        -Body $AuthorisationPostRequest

# Store refreshToken in directory where script is run from and capture as variable, if statement to make sure we are not writing nothing to file

if ($Authorisation.refresht_token -ne $null) {}
else {Set-Content $PSScriptRoot"\tokens\refreshToken.txt" $Authorisation.refresh_token}

$refresh_token=$Authorisation.refresh_token
 
# Store accessToken in directory where script is run from and capture as variable

Set-Content $PSScriptRoot"\tokens\accessToken.txt" $Authorisation.access_token
$access_token=$Authorisation.access_token

# If statement if refresh token is null get from text file written above

if ($refresh_token -like $null) {
    GET-Content "C:\Users\richard.bevan\Documents\Powershell\MSExample\tokens\refreshToken.txt"}
else{}

# Write out to screen $Authorisation variables captured

write-output $Authorisation 

# Capture as variable Expiry

$expiry_token=$Authorisation.expires_in

# Refresh Token when expiry value less than 10 minutes
# Check this is working
if ($expiry_token -lt 600) {
$RefreshTokenRequest = 
    "grant_type=refresh_token" + "&" +
    "redirect_uri=" + [System.Web.HttpUtility]::UrlEncode($redirectUrl) + "&" +
    "client_id=$client_id" + "&" +
    "client_secret=" + [System.Web.HttpUtility]::UrlEncode("$client_secret") + "&" +
    "scope=$scope"

    $RefreshToken = 
    Invoke-RestMethod   -Method Post `
                        -ContentType application/x-www-form-urlencoded `
                        -Uri https://www.googleapis.com/oauth2/v4/token `
                        -Body $RefreshTokenRequest
}
else {}

# Retrieve Login Data from Gsuite AdminSDK
# GET https://www.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=25
# login Data

$Uriloginactivity = "https://www.googleapis.com/admin/reports/v1/activity/users/all/applications/login?maxResults=250"
Try {
 $adminloginresp = Invoke-RestMethod -Headers @{Authorization = "Bearer $access_token"} -ContentType "application/json" -Method Get -Uri $uriloginactivity 
  write-output $adminloginresp.items | convertto-csv | out-file -append "C:\Users\richard.bevan\Documents\Powershell\MSExample\logs\adminloginactivity.log"
}
Catch {
  # If there's an error along the way, log it 
		($date + " Error getting results from Gsuite Api: " + $error[0]) | out-file $logFile -append
		write-host ("Error getting results from Gsuite API: " + $error[0])
}
# If we error out, return null
	return $null

# Retrieve all Admin activity
# GET https://www.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?maxResults=2
#Admin all activity

$Uriadminactivity = "https://www.googleapis.com/admin/reports/v1/activity/users/all/applications/admin?maxResults=250"

Try {
 $adminactivityresp = Invoke-RestMethod -Headers @{Authorization = "Bearer $access_token"} -ContentType "application/json" -Method Get -Uri $uriadminactivity 
 write-output $adminactivityresp.items | convertto-csv | out-file -append "C:\Users\richard.bevan\Documents\Powershell\MSExample\logs\adminactivity.log"
 
}

Catch {
  # If there's an error, log it 
		($date + " Error getting results from Gsuite Api: " + $error[0]) | out-file $logFile -append
		write-host ("Error getting results from Gsuite API: " + $error[0])
}
# If we error out, return null
	return $null


#>
<# Left in for troubleshooting
Try {
 Invoke-RestMethod -Method Post -Uri $uri -Body $json -ContentType $ContentType -Headers @{"Authorization"="Bearer $Authorisation.accessToken"}
}
Catch {
 Write-Host $_.Exception.ToString()
 $error[0] | Format-List -Force
}
#>
<# 	catch {	
		# If there's an error, log it 
		($date + " Error getting results from Gsuite Api: " + $error[0]) | out-file $logFile -append
		write-host ("Error getting results from Gsuite API: " + $error[0])
	}

	# If we error out, return null
	return $null
#>