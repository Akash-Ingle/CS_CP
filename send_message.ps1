# PowerShell script to send a message to the Flask server

# Import the required module for HTTP requests
try {
    Import-Module -Name "Microsoft.PowerShell.Utility" -ErrorAction Stop
    Import-Module -Name "Microsoft.PowerShell.Management" -ErrorAction Stop
    Import-Module -Name "Microsoft.PowerShell.Security" -ErrorAction Stop
    Import-Module -Name "Microsoft.PowerShell.Diagnostics" -ErrorAction Stop
} catch {
    Write-Host "Error: Failed to import required modules."
    exit 1
}

# Specify the Flask server URL
$flaskServerUrl = "http://127.0.0.1:5000"

# Define the message to send
$messageToSend = "Hello from SkyBell!, Akash Ingle just rang the bell and is waiting for you!"

# Define the JSON payload
$jsonPayload = @{
    message = $messageToSend
} | ConvertTo-Json

# Define the endpoint URL to send the message to device A
$endpointUrlDeviceA = "$flaskServerUrl/deviceA/send_message"

# Send the message to device A
$responseDeviceA = Invoke-RestMethod -Uri $endpointUrlDeviceA -Method Post -Body $jsonPayload -ContentType "application/json"

# Display the response from device A
$responseDeviceA.response

# Define the endpoint URL to send the message to device B
$endpointUrlDeviceB = "$flaskServerUrl/deviceB/send_message"

# Send the message to device B
$responseDeviceB = Invoke-RestMethod -Uri $endpointUrlDeviceB -Method Post -Body $jsonPayload -ContentType "application/json"

# Display the response from device B
$responseDeviceB.response
