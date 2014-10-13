#Requires -Version 3
# ------------------------------------------------------------------------
# NAME: Graylog2.psm1
# AUTHOR: Frederic MARTIN (@vmdude_fr), Raphael SCHITZ (@hypervisor_fr)
# DATE: 2014.09.25
#
# COMMENTS: Powershell module for managing Graylog2 instances
# ------------------------------------------------------------------------


<#
	HELPER FUNCTIONS

	These functions will be only used inside this module.
	These functions will not be exported/visible to user thanks to Export-ModuleMember cmdlet.
#>

function _ConvertTo_UnsecureString_ {
	<#
	.SYNOPSIS
	Convert System.Security.SecureString to regular string
	.DESCRIPTION
	Convert System.Security.SecureString to regular string.
	It's used to build header which will be pass to REST API
	.EXAMPLE
	_ConvertTo_UnsecureString_ (Get-Credential).Password
	.PARAMETER SecurePassword
	System.Security.SecureString that will be transformed to string
	#>

	[CmdletBinding()]
	param (
		[System.Security.SecureString][Parameter(Mandatory=$True)]$SecurePassword
	)

	# A read-only field that represents a pointer or handle that has been initialized to zero
    $unmanagedString = [System.IntPtr]::Zero

    try {
    	# Copies the contents of a managed SecureString object into unmanaged memory
        $unmanagedString = [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($SecurePassword)
        # Allocates a managed String and copies all of an unmanaged Unicode string into it
        return [Runtime.InteropServices.Marshal]::PtrToStringUni($unmanagedString)
    } finally {
    	# Frees unmanaged string pointer that was allocated
        [Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($unmanagedString)
    }
}

function _ConvertTo_Base64_ {
	<#
	.SYNOPSIS
	Convert string to base64
	.EXAMPLE
	_ConvertTo_Base64_ "graylog2rocks"
	.PARAMETER string
	String to be converted to base64
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)]$string
	)

   $bytes  = [System.Text.Encoding]::UTF8.GetBytes($string);
   $encoded = [System.Convert]::ToBase64String($bytes);

   return $encoded;
}

function _ConvertFrom_Base64_ {
	<#
	.SYNOPSIS
	Convert base64 to string
	.EXAMPLE
	_ConvertFrom_Base64_ "Z3JheWxvZzJyb2Nrcw=="
	.PARAMETER string
	String to be converted from base64
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)]$string
	)

   $bytes  = [System.Convert]::FromBase64String($string);
   $decoded = [System.Text.Encoding]::UTF8.GetString($bytes);

   return $decoded;
}

function _Get_HttpBasicHeader_ {
	<#
	.SYNOPSIS
	Build HTTP header for REST API call
	.EXAMPLE
	_Get_HttpBasicHeader_
	.PARAMETER Headers
	Headers that will be populated
	#>

	[CmdletBinding()]
	param (
		$Headers = @{}
	)

	$b64 = _ConvertTo_Base64_ "$($credentialRest.UserName):$(_ConvertTo_UnsecureString_ $credentialRest.Password)"
	$Headers["Authorization"] = "Basic $b64"
	return $Headers
}

function _Write_TBC_ {
	# Dummy display for function to be written
	Write-Host -Foregroundcolor Magenta "Function not yet available... but it will be soon thanks to Gorilla's force !"
}

function _Get_ModuleState_ {
	# Dummy display for % function to be written
	$commandModule = Get-Command -Module Graylog2
	$missingCommand = ($commandModule | ?{($_.Definition | select-string "_Write_TBC_" | Measure-Object).Count -gt 0} | Measure-Object).Count
	$totalCommand = ($commandModule | Measure-Object).Count
	Write-Host -ForegroundColor Green "Module State: $missingCommand left to be written on total of $totalCommand [" ([Math]::Round((($totalCommand-$missingCommand)*100/$totalCommand),0)) "% done]"
}

<#
	END HELPER FUNCTIONS
#>


<#
	COMMON FUNCTIONS

	These functions are not only based on REST API and must be usable for user (non-helper functions).
#>

function Connect-Graylog2Rest {
	<#
	.SYNOPSIS
	Connect to Graylog2 REST API
	.DESCRIPTION
	Connect to Graylog2 server through REST API and validate supplied credentials (or prompt for credentials if not specified).
	The result will display information about Graylog2 system
	.EXAMPLE
	Connect-Graylog2Rest -restInstance 69.69.69.69 -restUsername "admin" -restPassword "graylog2rocks"
	.EXAMPLE
	Connect-Graylog2Rest -restInstance 69.69.69.69 -restPort 14900
	.PARAMETER restInstance
	IP address of Graylog2 REST API instance
	.PARAMETER restPort
	Used to specified custom (aka non-12900) REST API port
	.PARAMETER restUsername
	Username used to connect to Graylog2 REST API (if not specified, Get-Credentials will be prompted)
	.PARAMETER restPassword
	Password for username used to connect to Graylog2 REST API (if not specified, Get-Credentials will be prompted)
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$restInstance,
		[string]$restUsername,
		[string]$restPassword,
		[int]$restPort = 12900
	)
	
	if (-Not $restUsername -Or -Not $restPassword) {
		$credentialRest = Get-Credential
	} else {
		$credentialRest = New-Object System.Management.Automation.PSCredential($restUsername, (ConvertTo-SecureString $restPassword -AsPlainText -Force))
	}
	
	# These global variables will be used for further functions
	$Global:credentialRest = $credentialRest
	$Global:restInstance = $restInstance
	$Global:restPort = $restPort

	try {
		$connectionState = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $connectionState
}

function Get-Graylog2StreamRuleType {
	<#
	.SYNOPSIS
	Display static stream rule type
	.DESCRIPTION
	This is used to make easier stream management
	.EXAMPLE
	Get-Graylog2StreamRuleType
	#>

	$streamRuleType = @()
	foreach ($ruletype in (@("match exactly",1),@("match regular expression",2),@("greater than",3),@("smaller than",4))) {
		$tmpDbLine = "" | Select Name, TypeId
		$tmpDbLine.Name = $ruletype[0]
		$tmpDbLine.TypeId = $ruletype[1]
		$streamRuleType += $tmpDbLine
	}

	Return $streamRuleType
}

<#
	END COMMON FUNCTIONS
#>


<#
	ALERTS: Manage stream alerts
#>

function Get-Graylog2StreamAlert {
	<#
	.SYNOPSIS
	Get the 100 most recent alarms of this stream
	.EXAMPLE
	Get-Graylog2StreamAlert -streamId "5357b946e4b02d59485c8ee2"
	.PARAMETER streamId
	Id of the stream you want to display alerts
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)
	
	if ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$streamAlerts = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	if ($streamAlerts.total -eq 0) {
		Write-Host -ForegroundColor Yellow "No alert for stream $streamId"
		Return
	}

	Return $streamAlerts.alerts
}

function Test-Graylog2StreamAlert {
	<#
	.SYNOPSIS
	Check for triggered alert conditions of this streams. Results cached for 30 seconds
	.EXAMPLE
	Test-Graylog2StreamAlert -streamId "5357b946e4b02d59485c8ee2"
	.PARAMETER streamId
	The ID of the stream to check
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)
	
	if ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$streamAlertCheck = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts/check" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	if ($streamAlertCheck.total_triggered -eq 0) {
		Write-Host -ForegroundColor Yellow "No alert triggered for stream $streamId"
		Return
	}

	Return $streamAlertCheck.results
}

function New-Graylog2StreamAlertConditions {
	<#
	.SYNOPSIS
	Create a alert condition
	.EXAMPLE
	New-Graylog2StreamAlertConditions -streamId "5357b946e4b02d59485c8ee2" -conditionType "message_count" -grace 5 -time 5 -threshold 10 -thresholdType "more" -backlog 10
	.EXAMPLE
	New-Graylog2StreamAlertConditions -streamId "5357b946e4b02d59485c8ee2" -conditionType "field_value" -grace 5 -time 5 -field "user_id" -threshold 10 -thresholdType "higher" -conditionParameterType "max"
	.PARAMETER streamId
	The stream id this new alert condition belongs to
	.PARAMETER conditionType
	Definie type of alert condition. Must be one of "message_count", "field_value"
	.PARAMETER thresholdType
	Type of alert threshold. Must be one of "more" or "less" if conditionType = "message_count" or one of "lower" or "higher" if conditionType = "field_value"
	.PARAMETER field
	Field to based alert on
	.PARAMETER conditionParameterType
	Condition parameter type. Must be one of "mean", "min", "max", "sum" or "stddev"
	.PARAMETER grace
	Period until triggering a new alert
	.PARAMETER backlog
	When sending an alert, include the last XX messages of the stream evaluated for this alert condition
	.PARAMETER threshold
	Threshold for the alert
	.PARAMETER time
	Time for the alert
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId,
		[ValidateSet("message_count","field_value")][Parameter(Mandatory=$True)][string]$conditionType,
		[string]$thresholdType,
		[string]$field,
		[string]$conditionParameterType,
		[int]$grace,
		[int]$threshold,
		[int]$backlog,
		[int]$time
	)
	
	if ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}
	
	if ([int]$grace -eq 0 -and [int]$time -eq 0) {
		Write-Host -ForegroundColor Red "grace and time variable must be non-null integer"
		Return
	}

	$hashRequest = @{}
	$hashParametersRequest = @{}
	$hashRequest.Add("type",$conditionType)
	$hashRequest.Add("creator_user_id",$credentialRest.UserName)

	$hashParametersRequest.Add("grace",$grace)
	$hashParametersRequest.Add("time",$time)
	$hashParametersRequest.Add("threshold",$threshold)
	$hashParametersRequest.Add("backlog",$backlog)

	if ($conditionType -eq "message_count") {
		if ($thresholdType -notmatch "^more$|^less$") {
			Write-Host -ForegroundColor Red "thresholdType variable must be one of 'more', 'less'"
			Return
		}
		$hashParametersRequest.Add("threshold_type",$thresholdType)
	} else { # The ValidateSet() ensure that the value will be "field_value", no need to check again
		$hashParametersRequest.Add("field",$field)
		if ($thresholdType -notmatch "^lower$|^higher$") {
			Write-Host -ForegroundColor Red "thresholdType variable must be one of 'lower', 'higher'"
			Return
		}
		$hashParametersRequest.Add("threshold_type",$thresholdType)
		if ($conditionParameterType -notmatch "^mean$|^min$|^max$|^sum$|^stddev$") {
			Write-Host -ForegroundColor Red "conditionParameterType variable must be one of 'mean', 'min', 'max', 'sum', 'stddev'"
			Return
		}
		$hashParametersRequest.Add("type",$conditionParameterType)
	}

	$hashRequest.Add("parameters",$hashParametersRequest)

	try {
		$alertConditionId = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts/conditions" -Headers (_Get_HttpBasicHeader_) -ContentType "application/json" -Body ($hashRequest | ConvertTo-Json -Compress)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Write-Host -ForegroundColor Red "JSON body:"
		Write-Host -ForegroundColor Red ($hashRequest | ConvertTo-Json)
		Return
	}

	Return $alertConditionId
}

function Get-Graylog2StreamAlertConditions {
	<#
	.SYNOPSIS
	Get all alert conditions of this stream
	.EXAMPLE
	Get-Graylog2StreamAlertConditions -streamId "5357b946e4b02d59485c8ee2"
	.PARAMETER streamId
	The stream id this new alert condition belongs to
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)
	
	if ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$streamAlertConditions = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts/conditions" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	if ($streamAlertConditions.total -eq 0) {
		Write-Host -ForegroundColor Yellow "No alert conditions for stream $streamId"
		Return
	}

	return $streamAlertConditions.conditions
}

function Remove-Graylog2StreamAlertConditions {
	<#
	.SYNOPSIS
	Delete an alert condition
	.EXAMPLE
	Remove-Graylog2StreamAlertConditions -streamId "5357b946e4b02d59485c8ee2" -conditionId "a302c06d-8302-4d8c-8c5d-39d574355173"
	.PARAMETER streamId
	The stream id this new alert condition belongs to
	.PARAMETER conditionId
	The condition id to be removed
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId,
		[Parameter(Mandatory=$True)][string]$conditionId
	)
	
	if ( ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) -Or ((Get-Graylog2StreamAlertConditions -streamId $streamId | ?{$_.Id -eq $conditionId} | Measure-Object).Count -ne 1) ) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId and/or condition with conditionId $conditionId, please check before running this command again"
		Return
	}	
	
	try {
		$streamAlertCondition = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts/conditions/$conditionId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Condition $conditionId on stream $streamId deleted successfully"
	Return
}

function New-Graylog2StreamAlertReceivers {
	<#
	.SYNOPSIS
	Add an alert receiver
	.EXAMPLE
	New-Graylog2StreamAlertReceivers -streamId "5357b946e4b02d59485c8ee2" -entity "admin" -type "users"
	.EXAMPLE
	New-Graylog2StreamAlertReceivers -streamId "5357b946e4b02d59485c8ee2" -entity "graylog2@vmdude.fr" -type "emails"
	.PARAMETER streamId
	The stream id this new alert receiver belongs to
	.PARAMETER entity
	Name/ID of user or email address to add as alert receiver
	.PARAMETER type
	Type of receiver. Must be one of "users" or "emails"
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId,
		[Parameter(Mandatory=$True)][string]$entity,
		[ValidateSet("emails","users")][Parameter(Mandatory=$True)][string]$type
	)
	
	if ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}
	
	if ($type -eq "users") {
		if ((Get-Graylog2Users | ?{$_.username -eq $entity} | Measure-Object).Count -ne 1) {
			Write-Host -ForegroundColor Red "Error on user with streamId $streamId, please check before running this command again"
			Return
		}
	}
	
	try {
		$streamAlertReceiver = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts/receivers?entity=$entity&type=$type" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $streamAlertReceiver
}

function Remove-Graylog2StreamAlertReceivers {
	<#
	.SYNOPSIS
	Remove an alert receiver
	.EXAMPLE
	Remove-Graylog2StreamAlertReceivers -streamId "5357b946e4b02d59485c8ee2" -entity "admin" -type "users"
	.EXAMPLE
	Remove-Graylog2StreamAlertReceivers -streamId "5357b946e4b02d59485c8ee2" -entity "graylog2@vmdude.fr" -type "emails"
	.PARAMETER streamId
	The stream id this alert receiver belongs to
	.PARAMETER entity
	Name/ID of user or email address to remove from alert receiver
	.PARAMETER type
	Type of receiver. Must be one of "users" or "emails"
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId,
		[Parameter(Mandatory=$True)][string]$entity,
		[ValidateSet("emails","users")][Parameter(Mandatory=$True)][string]$type
	)
	
	if ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}
	
	if ($type -eq "users") {
		if ((Get-Graylog2Users | ?{$_.username -eq $entity} | Measure-Object).Count -ne 1) {
			Write-Host -ForegroundColor Red "Error on user with streamId $streamId, please check before running this command again"
			Return
		}
	}
	
	try {
		$streamAlertReceiver = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts/receivers?entity=$entity&type=$type" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Alert receiver $entity from stream $streamId deleted successfully"
	Return
}

function Send-Graylog2DummyStreamAlert {
	<#
	.SYNOPSIS
	Send a test mail for a given stream
	.EXAMPLE
	Send-Graylog2DummyStreamAlert -streamId "5357b946e4b02d59485c8ee2"
	.PARAMETER streamId
	The stream id this alert belongs to
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)
	
	if ((Get-Graylog2Streams | ?{$_.Id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}
	
	try {
		$streamDummyAlert = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams/$streamId/alerts/sendDummyAlert" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $streamDummyAlert
}

<#
	END ALERTS
#>


<#
	COUNTS: Message counts
#>

function Get-Graylog2MessageCounts {
	<#
	.SYNOPSIS
	Retrieve total message count handled by Graylog2
	.EXAMPLE
	Get-Graylog2MessageCounts
	#>

	try {
		$messageCount = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/count/total" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return [long]($messageCount.events)
}

<#
	END COUNTS
#>


<#
	DASHBOARDS: Manage dashboards
#>

function Get-Graylog2Dashboards {
	<#
	.SYNOPSIS
	Get a list of all dashboards and all configurations of their widgets
	.EXAMPLE
	Get-Graylog2Dashboards
	#>

	try {
		$dashboards = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/dashboards" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}
	
	Return $dashboards.dashboards
}

function New-Graylog2Dashboard {
	_Write_TBC_
}

function Get-Graylog2Dashboard {
	<#
	.SYNOPSIS
	Get a single dashboard and all configurations of its widgets
	.EXAMPLE
	Get-Graylog2Dashboard -dashboardId "52d6abb4498e2b793a713fc7"
	.PARAMETER dashboardId
	The dashboard id to display configuration
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$dashboardId
	)
	
	if ((Get-Dashboards | ?{$_.Id -eq $dashboardId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on dashboard with dashboardId $dashboardId, please check before running this command again"
		Return
	}

	try {
		$dashboard = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/dashboards/$dashboardId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $dashboard
}

function Remove-Graylog2Dashboard {
	<#
	.SYNOPSIS
	Delete a dashboard and all its widgets
	.EXAMPLE
	Remove-Graylog2Dashboard -dashboardId "52d6abb4498e2b793a713fc7"
	.PARAMETER dashboardId
	The dashboard id to delete
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$dashboardId
	)
	
	if ((Get-Dashboards | ?{$_.Id -eq $dashboardId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on dashboard with dashboardId $dashboardId, please check before running this command again"
		Return
	}

	try {
		$dashboardDeleted = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/dashboards/$dashboardId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Dashboard $dashboardId deleted successfully"
	Return
}

function Update-Graylog2Dashboard {
	_Write_TBC_
}

function Update-Graylog2DashboardPositions {
	_Write_TBC_
}

function Add-Graylog2DashboardWidget {
	_Write_TBC_
}

function Remove-Graylog2DashboardWidget {
	_Write_TBC_
}

function Update-Graylog2DashboardWidgetCachetime {
	_Write_TBC_
}

function Update-Graylog2DashboardWidgetDescription {
	_Write_TBC_
}

function Get-Graylog2DashboardWidget {
	_Write_TBC_
}

<# END DASHBOARDS #>


<#
	EXTRACTORS: Extractors of an input
#>

function Get-Graylog2Extractors {
	<#
	.SYNOPSIS
	List all extractors of an input
	.EXAMPLE
	Get-Graylog2Extractors -inputId "52d6abb4498e2b793a713fc7"
	.PARAMETER inputId
	The input id to list extractors
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$inputId
	)
	
	if ((Get-Graylog2Inputs | ?{$_.Id -eq $inputId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on input with inputId $inputId, please check before running this command again"
		Return
	}

	try {
		$extractors = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/inputs/$inputId/extractors" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	return $extractors.extractors
}

function New-Graylog2Extractor {
	_Write_TBC_
}

function Remove-Graylog2Extractor {
	<#
	.SYNOPSIS
	Delete an extractor
	.EXAMPLE
	Remove-Graylog2Extractor -inputId "52d6abb4498e2b793a713fc7" -extractorId "52d6abb4498e2b793a713fc7"
	.PARAMETER inputId
	The input id to delete extractor from
	.PARAMETER extractorId
	The extractor id to delete
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$inputId,
		[Parameter(Mandatory=$True)][string]$extractorId
	)
	
	if ((Get-Graylog2Extractors -inputId $inputId | ?{$_.extractorId -eq $extractorId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on extractor with extractorId $extractorId, please check before running this command again"
		Return
	}

	try {
		$extractorDeleted = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/system/inputs/$inputId/extractors/$extractorId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Extractor $extractorId from input $inputId deleted successfully"
	Return
}

<#
	END EXTRACTORS
#>


<#
	INDEXER/CLUSTER: Indexer cluster information
#>

function Get-Graylog2ClusterHealth {
	<#
	.SYNOPSIS
	Get cluster and shard health overview
	.EXAMPLE
	Get-Graylog2ClusterHealth
	#>

	try {
		$clusterHealth = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/indexer/cluster/health" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $clusterHealth
}

function Get-Graylog2ClusterName {
	<#
	.SYNOPSIS
	Get the cluster name
	.EXAMPLE
	Get-Graylog2ClusterName
	#>

	try {
		$clusterName = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/indexer/cluster/name" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $clusterName
}

<#
	END INDEXER/CLUSTER
#>


<#
	INDEXER/INDICES: Index informations
#>

function Get-Graylog2ClosedIndices {
	<#
	.SYNOPSIS
	Get a list of closed indices that can be reopened.
	.EXAMPLE
	Get-Graylog2ClosedIndices
	#>

	try {
		$closedIndices = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/indexer/indices/closed" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	if ($closedIndices.total -eq 0) {
		Write-Host -ForegroundColor Yellow "No closed indices."
		Return
	}

	Return $closedIndices.indices
}

function Remove-Graylog2Index {
	<#
	.SYNOPSIS
	Delete an index.
	.DESCRIPTION
	This will also trigger an index ranges rebuild job.
	.EXAMPLE
	Remove-Graylog2Index -index "graylog2_23"
	.PARAMETER index
	Name of the index to remove
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$index
	)

	try {
		$removedIndex = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/system/indexer/indices/$index" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Index $index deleted successfully"
	Return
}

function Get-Graylog2IndexInformation {
	<#
	.SYNOPSIS
	Get information of an index and its shards
	.EXAMPLE
	Get-Graylog2IndexInformation -index "graylog2_23"
	.PARAMETER index
	Name of the index to retrieve information from
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$index
	)

	try {
		$indexInformation = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/indexer/indices/$index" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $indexInformation
}

function Close-Graylog2Index {
	<#
	.SYNOPSIS
	Close an index
	.DESCRIPTION
	This will also trigger an index ranges rebuild job
	.EXAMPLE
	Close-Graylog2Index -index "graylog2_23"
	.PARAMETER index
	Name of the index to close
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$index
	)

	try {
		$closedIndex = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/system/indexer/indices/$index/close" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $closedIndex
}

function Resume-Graylog2Index {
	<#
	.SYNOPSIS
	Reopen a closed index
	.DESCRIPTION
	This will also trigger an index ranges rebuild job
	.EXAMPLE
	Resume-Graylog2Index -index "graylog2_23"
	.PARAMETER index
	Name of the index to reopen
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$index
	)

	try {
		$reopenIndex = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/system/indexer/indices/$index/reopen" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $reopenIndex
}

<#
	END INDEXER/INDICES
#>


<# MESSAGES: Single messages #>

function Get-Graylog2MessageAnalyze {
	_Write_TBC_
}

function Get-Graylog2Message {
	_Write_TBC_
}

<# END MESSAGES #>


<# SEARCH/ABSOLUTE: Message search #>
<# END SEARCH/ABSOLUTE #>


<#
	SEARCH/SAVED: Saved searches
#>

function Get-Graylog2SavedSearches {
	<#
	.SYNOPSIS
	Get a list of all saved searches
	.EXAMPLE
	Get-Graylog2SavedSearches
	#>

	try {
		$savedSearches = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/search/saved" -Headers (_Get_HttpBasicHeader_) -ContentType "application/json"
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	if ($savedSearches.total -eq 0) {
		Write-Host -ForegroundColor Yellow "No saved search."
		Return
	}

	Return $savedSearches.searches
}

function New-Graylog2SavedSearch {
	<#
	.SYNOPSIS
	Create a new saved search
	.EXAMPLE
	New-Graylog2SavedSearch -title "Saved Search 1" -queryTitle "Long VMFS3 rsv time" -rangeType "relative" -query "Long VMFS3 rsv" -relative 28800
	.EXAMPLE
	New-Graylog2SavedSearch -title "Saved Search 2" -queryTitle "Long VMFS3 rsv time" -rangeType "absolute" -query "Long VMFS3 rsv" -from ((Get-Date).AddDays(-3)) -to (Get-Date)
	.EXAMPLE
	New-Graylog2SavedSearch -title "Saved Search 3" -queryTitle "Long VMFS3 rsv time" -rangeType "keyword" -query "Long VMFS3 rsv" -keyword "last day"
	.PARAMETER title
	Title of the saved search
	.PARAMETER queryTitle
	Title of the query
	.PARAMETER rangeType
	Type of the range search, must be one of 'relative','absolute' or 'keyword'
	.PARAMETER query
	Query that will be executed for this search
	.PARAMETER relative
	Set the number is seconds to use for relative search
	.PARAMETER from
	Start of the time range, must be DateTime type
	.PARAMETER to
	End of the time range, must be DateTime type
	.PARAMETER keyword
	Keyword sentence to be used for saved search
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$title,
		[Parameter(Mandatory=$True)][string]$queryTitle,
		[ValidateSet("relative","absolute","keyword")][Parameter(Mandatory=$True)][string]$rangeType,
		[Parameter(Mandatory=$True)][string]$query,
		[string]$relative,
		[DateTime]$from,
		[DateTime]$to,
		[string]$keyword
	)

	$hashRequest = @{}
	$hashRequest.Add("title",$title)
	$hashRequest.Add("creator_user_id",$credentialRest.UserName)
	$hashQueryRequest = @{}
	$hashQueryRequest.Add("query",$query)
	$hashQueryRequest.Add("rangeType",$rangeType)

	if ($rangeType -eq "relative") {
		$hashQueryRequest.Add("relative",$relative)
	} elseif ($rangeType -eq "absolute") {
		$hashQueryRequest.Add("from",(Get-Date -Format s $from)+".000Z")
		$hashQueryRequest.Add("to",(Get-Date -Format s $to)+".000Z")
	} else { # The ValidateSet() ensure that the value will be "keyword", no need to check again
		$hashQueryRequest.Add("keyword",$keyword)
	}

	$hashRequest.Add("query",$hashQueryRequest)

	try {
		$saveSearch = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/search/saved" -Headers (_Get_HttpBasicHeader_) -ContentType "application/json" -Body ($hashRequest | ConvertTo-Json -Compress)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Write-Host -ForegroundColor Red "JSON body:"
		Write-Host -ForegroundColor Red ($hashRequest | ConvertTo-Json)
		Return
	}

	Return $saveSearch
}

function Get-Graylog2SavedSearch {
	<#
	.SYNOPSIS
	Get a single saved search
	.EXAMPLE
	Get-Graylog2SavedSearch -searchId "53590485e4b02d59485deab2"
	.PARAMETER searchId
	Id of the search
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$searchId
	)
	
	if ((Get-Graylog2SavedSearches | ?{$_.id -eq $searchId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on saved search with searchId $searchId, please check before running this command again"
		Return
	}

	try {
		$savedSearch = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/search/saved/$searchId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $savedSearch
}

function Remove-Graylog2SavedSearch {
	<#
	.SYNOPSIS
	Delete a saved search
	.EXAMPLE
	Remove-Graylog2SavedSearch -searchId "53590485e4b02d59485deab2"
	.PARAMETER searchId
	Id of the search
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$searchId
	)
	
	if ((Get-Graylog2SavedSearch -searchId $searchId | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on search with searchId $searchId, please check before running this command again"
		Return
	}

	try {
		$deletedSearch = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/search/saved/$searchId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Search $searchId deleted successfully"
	Return
	
}

<#
	END SEARCH/SAVED
#>


<#
	SOURCES: Listing message sources (e.g. hosts sending logs)
#>

function Get-Graylog2Sources {
	<#
	.SYNOPSIS
	Get a list of all sources (not more than 5000) that have messages in the current indices. The result is cached for 10 seconds
	.EXAMPLE
	Get-Graylog2Sources -msRange 86400
	.PARAMETER msRange
	Relative timeframe to search in. The parameter is in seconds relative to the current time. 86400 means 'in the last day',0 is special and means 'across all indices'
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][int]$msRange
	)

	try {
		$sourcesList = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/sources?range=$msRange" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	# As retrieved sources is based on an unique object with NoteProperty member, we need to decompose it in order to get usable objects
	$reportSources = @()
	foreach ($source in $sourcesList.sources | Get-Member -MemberType NoteProperty) {
		$line = "" | Select Source, Count
		$line.Source = $source.Name
		$line.Count = [int]($source.Definition.ToString().Split("=")[1].Trim())
		$reportSources += $line
	}

	Return $reportSources
}

<#
	END SOURCES
#>


<# STATICFIELDS: Static fields of an input #>

function New-Graylog2InputStaticfields {
	_Write_TBC_
}

function Remove-Graylog2InputStaticfields {
	_Write_TBC_
}

<# END STATICFIELDS #>


<#
	STREAMRULES: Manage stream rules
#>

function Get-Graylog2StreamRules {
	<#
	.SYNOPSIS
	Get a list of all stream rules
	.EXAMPLE
	Get-Graylog2StreamRules -streamid "53590485e4b02d59485deab2"
	.PARAMETER streamid
	The id of the stream whose stream rules we want
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)

	if ((Get-Graylog2Streams | ?{$_.id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$streamRules = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/$streamId/rules" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $streamRules.stream_rules
}

function New-Graylog2StreamRule {
	<#
	.SYNOPSIS
	Create a stream rule
	.EXAMPLE
	New-Graylog2StreamRule -stream_id "53319288498e9ee49c6ffd57" -field "full_message" -value "Could not open device" -type "match regular expression" -inverted
	.EXAMPLE
	New-Graylog2StreamRule -stream_id "53319288498e9ee49c6ffd57" -field "full_message" -value "Could not open device" -type "match exactly"
	.EXAMPLE
	New-Graylog2StreamRule -stream_id "53319288498e9ee49c6ffd57" -field "level" -value "6" -type "greater than"
	.PARAMETER stream_id
	Id of the stream
	.PARAMETER field
	Field to based rule on
	.PARAMETER value
	Value that will be used for rule
	.PARAMETER type
	Type of rule, must be one of "match exactly", "match regular expression", "greater than" or "smaller than"
	.PARAMETER inverted
	Switch that will invert the rule
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$stream_id,
		[Parameter(Mandatory=$True)][string]$field,
		[Parameter(Mandatory=$True)][string]$value,
		[Parameter(Mandatory=$True)][ValidateSet("match exactly","match regular expression","greater than","smaller than")][string]$type,
		[switch]$inverted
	)

	# type values quick reminder
	# 1 = "match exactly"
	# 2 = "match regular expression"
	# 3 = "greater than"
	# 4 = "smaller than"
	
	# $streamRuleType = Get-Graylog2StreamRuleType | ?{$_.Name -eq $type}
	
	if ((Get-Graylog2Stream -streamId $stream_id | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with stream_id $stream_id, please check before running this command again"
		Return
	}
	
	$hashRequest = @{}
	$hashRequest.Add("field",$field)
	$hashRequest.Add("value",$value)
	$hashRequest.Add("type",[int]((Get-Graylog2StreamRuleType | ?{$_.Name -eq $type}).TypeId))
	if ($inverted) {
		$hashRequest.Add("inverted","true")
	} else {
		$hashRequest.Add("inverted","false")
	}

	try {
		$streamRuleId = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams/$stream_id/rules" -Headers (_Get_HttpBasicHeader_) -ContentType "application/json" -Body ($hashRequest | ConvertTo-Json -Compress)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Write-Host -ForegroundColor Red "JSON body:"
		Write-Host -ForegroundColor Red ($hashRequest | ConvertTo-Json)
		Return
	}

	Return $streamRuleId
}

function Get-Graylog2StreamRule {
	<#
	.SYNOPSIS
	Get a list of all stream rules
	.EXAMPLE
	Get-Graylog2StreamRule -streamid "53590485e4b02d59485deab2" -streamRuleId "aa590485e4b02d59485deaaa"
	.PARAMETER streamid
	The id of the stream whose stream rule we want
	.PARAMETER streamid
	The id of the stream rule
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId,
		[Parameter(Mandatory=$True)][string]$streamRuleId
	)

	if ((Get-Graylog2StreamRules -streamId $streamId | ?{$_.id -eq $streamRuleId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream rule with streamRuleId $streamRuleId, please check before running this command again"
		Return
	}

	try {
		$streamRule = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/$streamId/rules/$streamRuleId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $streamRule
}

function Remove-Graylog2StreamRule {
	<#
	.SYNOPSIS
	Delete a stream rule
	.EXAMPLE
	Remove-Graylog2StreamRule -streamid "53590485e4b02d59485deab2" -streamRuleId "aa590485e4b02d59485deaaa"
	.PARAMETER streamid
	The stream id this rule belongs to
	.PARAMETER streamRuleId
	The id of the stream rule
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId,
		[Parameter(Mandatory=$True)][string]$streamRuleId
	)

	if ((Get-Graylog2StreamRules -streamId $streamId | ?{$_.id -eq $streamRuleId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream rule with streamRuleId $streamRuleId, please check before running this command again"
		Return
	}

	try {
		$deletedStreamRule = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/streams/$streamId/rules/$streamRuleId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Successfully remove stream rule $streamRuleId from stream $streamId"
	Return
}

function Update-Graylog2StreamRule {
	_Write_TBC_
}

<# END STREAMRULES #>


<#
	STREAMS: Manage streams
#>

function Get-Graylog2Streams {
	<#
	.SYNOPSIS
	Get a list of all streams
	.EXAMPLE
	Get-Graylog2Streams
	#>

	try {
		$streams = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $streams.streams
}

function New-Graylog2Stream {
	<#
	.SYNOPSIS
	Create a stream
	.EXAMPLE
	New-Graylog2Stream -description "Description Lorem Ipsum" -title "Titre Lorem Ipsum" -enabled
	.EXAMPLE
	New-Graylog2Stream -title "New Awesome Stream"
	.PARAMETER description
	Description of the stream
	.PARAMETER title
	Title of the stream
	.PARAMETER enabled
	By default, newly created stream are disabled
	Use this switch to enabled it by default
	#>

	[CmdletBinding()]
	param (
		[string]$description,
		[Parameter(Mandatory=$True)][string]$title,
		[switch]$enabled
	)

	$hashRequest = @{}
	$hashRequest.Add("description",$description)
	$hashRequest.Add("creator_user_id",$credentialRest.UserName)
	$hashRequest.Add("title",$title)

	# Multiple streams can't have same title, we must check if a stream with the same title already exist
	if ((Get-Graylog2Streams | ?{$_.title -eq $title} | Measure-Object).Count -eq 1) {
		Write-Host -ForegroundColor Red "Stream with title $title already exists, please check before running this command again"
		Return
	}

	try {
		$stream = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams" -Headers (_Get_HttpBasicHeader_) -ContentType "application/json" -Body ($hashRequest | ConvertTo-Json -Compress)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Write-Host -ForegroundColor Red "JSON body:"
		Write-Host -ForegroundColor Red ($hashRequest | ConvertTo-Json)
		Return
	}

	# By default, all newly created stream are disabled, if 'enabled' switch is used, we make a second REST call to enabled it
	if ($enabled) {
		try {
			$streamId = $stream.stream_id
			$streamEnabled = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams/$streamId/resume" -Headers (_Get_HttpBasicHeader_)
		} catch {
			Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
			Return
		}
	}

	Return $stream
}

function Get-Graylog2EnabledStream {
	<#
	.SYNOPSIS
	Get a list of all enabled streams
	.EXAMPLE
	Get-Graylog2EnabledStream
	#>

	try {
		$streams = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/enabled" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $streams.streams
}

function Get-Graylog2Stream {
	<#
	.SYNOPSIS
	Get a stream information
	.EXAMPLE
	Get-Graylog2Stream -streamId "53590485e4b02d59485deab2"
	.PARAMETER streamid
	The id of the stream
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)

	if ((Get-Graylog2Streams | ?{$_.id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$stream = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/$streamId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $stream
}

function Remove-Graylog2Stream {
	<#
	.SYNOPSIS
	Delete a stream
	.EXAMPLE
	Remove-Graylog2Stream -streamId "53590485e4b02d59485deab2"
	.PARAMETER streamId
	The stream id that you want to delete
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)

	if ((Get-Graylog2Streams | ?{$_.id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$stream = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/streams/$streamId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Write-Debug "Successfully remove stream $streamId"
	Return
}

function Update-Graylog2Stream {
	_Write_TBC_
}

function Copy-Graylog2Stream {
	_Write_TBC_
}

function Suspend-Graylog2Stream {
	<#
	.SYNOPSIS
	Pause a stream
	.EXAMPLE
	Remove-Graylog2Stream -streamId "53590485e4b02d59485deab2"
	.PARAMETER streamId
	The stream id that you want to pause
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)

	if ((Get-Graylog2Streams | ?{$_.id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$pausedStream = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams/$streamId/pause" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $pausedStream
}

function Resume-Graylog2Stream {
	<#
	.SYNOPSIS
	Resume a stream
	.EXAMPLE
	Resume-Graylog2Stream -streamId "53590485e4b02d59485deab2"
	.PARAMETER streamId
	The stream id that you want to resume
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)

	if ((Get-Graylog2Streams | ?{$_.id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$resumedStream = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/streams/$streamId/resume" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $resumedStream
}

function Test-Graylog2Stream {
	_Write_TBC_
}

function Get-Graylog2StreamThroughput {
	<#
	.SYNOPSIS
	Current throughput of this stream on this node in messages per second
	.EXAMPLE
	Get-Graylog2StreamThroughput -streamId "53590485e4b02d59485deab2"
	.PARAMETER streamId
	The stream id that you want to get infos from
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$streamId
	)

	if ((Get-Graylog2Streams | ?{$_.id -eq $streamId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on stream with streamId $streamId, please check before running this command again"
		Return
	}

	try {
		$streamThroughput = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/streams/$streamId/throughput" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $streamThroughput.throughput
}

<#
	END STREAMS
#>


<#
	SYSTEM: System information of this node
#>

function Get-Graylog2SystemOverview {
	<#
	.SYNOPSIS
	Current throughput of this stream on this node in messages per second
	.EXAMPLE
	Get-Graylog2SystemOverview
	#>

	try {
		$systemOverview = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $systemOverview
}

function Get-Graylog2SystemFields {
	<#
	.SYNOPSIS
	Get list of message fields that exist
	.EXAMPLE
	Get-Graylog2SystemFields -limit
	.PARAMETER limit
	Maximum number of fields to return. Set to 0 for all fields
	#>

	[CmdletBinding()]
	param (
		[int]$limit = 0
	)

	try {
		$systemFields = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/fields?limit=$limit" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $systemFields.fields
}

function Get-Graylog2JVMInformation {
	<#
	.SYNOPSIS
	Get JVM information
	.EXAMPLE
	Get-Graylog2JVMInformation
	#>

	try {
		$jvmInformation = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/jvm" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $jvmInformation
}

function Get-Graylog2Permissions {
	<#
	.SYNOPSIS
	Get all available user permissions
	.EXAMPLE
	Get-Graylog2Permissions
	#>

	try {
		$permissions = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/permissions" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $permissions.permissions
}

function Get-Graylog2UserPermissions {
	<#
	.SYNOPSIS
	Get the initial permissions assigned to a reader account
	.EXAMPLE
	Get-Graylog2UserPermissions
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$username
	)

	if ((Get-Graylog2Users | ?{$_.username -eq $username} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on user $username, please check before running this command again"
		Return
	}

	try {
		$userPermissions = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/permissions/reader/$username" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $userPermissions.permissions
}

function Suspend-Graylog2MessageProcessing {
	<#
	.SYNOPSIS
	Pauses message processing
	.EXAMPLE
	Suspend-Graylog2MessageProcessing
	#>

	try {
		$suspendedMessageProcessing = Invoke-RestMethod -Method Put -Uri "http://$($restInstance):$restPort/system/processing/pause" -Headers (_Get_HttpBasicHeader_)
		Write-Host "Message processing is paused"
		Write-Host -ForegroundColor Yellow "Inputs that are able to reject or requeue messages will do so, others will buffer messages in memory. Keep an eye on the heap space utilization while message processing is paused."
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $suspendedMessageProcessing
}

function Resume-Graylog2MessageProcessing {
	<#
	.SYNOPSIS
	Pauses message processing
	.EXAMPLE
	Resume-Graylog2MessageProcessing
	#>

	try {
		$resumedMessageProcessing = Invoke-RestMethod -Method Put -Uri "http://$($restInstance):$restPort/system/processing/resume" -Headers (_Get_HttpBasicHeader_)
		Write-Host -ForegroundColor Green "Message processing is resumed"
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $resumedMessageProcessing
}

function Get-Graylog2ThreadDump {
	<#
	.SYNOPSIS
	Get a thread dump
	.EXAMPLE
	Get-Graylog2ThreadDump
	#>

	try {
		$threadDump = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/threaddump" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $threadDump
}

<#
	END SYSTEM
#>


<#
	SYSTEM/BUFFERS: Buffer information of this node
#>

function Get-Graylog2BufferInformation {
	<#
	.SYNOPSIS
	Get current utilization of buffers and caches of this node
	.EXAMPLE
	Get-Graylog2BufferInformation
	#>

	try {
		$bufferInformation = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/buffers" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $bufferInformation
}

<#
	END SYSTEM/BUFFERS
#>


<#
	SYSTEM/CLUSTER: Node discovery
#>

function Get-Graylog2Node {
	<#
	.SYNOPSIS
	Information about this node
	.EXAMPLE
	Get-Graylog2Node
	#>

	try {
		$nodes = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/cluster/node" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $nodes
}


function Get-Graylog2Nodes {
	<#
	.SYNOPSIS
	List all active nodes in this cluster
	.EXAMPLE
	Get-Graylog2Nodes
	#>

	try {
		$nodes = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/cluster/nodes" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $nodes.nodes
}

function Get-Graylog2NodeInformation {
	<#
	.SYNOPSIS
	Information about a node
	.EXAMPLE
	Get-Graylog2NodeInformation -nodeId
	.PARAMETER nodeId
	Node ID to get information from
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$nodeId
	)
	
	if ((Get-Graylog2Nodes | ?{$_.ID -eq $nodeId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on node with nodeId $nodeId, please check before running this command again"
		Return
	}

	try {
		$node = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/cluster/nodes/$nodeId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $node
}


<#
	END SYSTEM/CLUSTER
#>


<#
	SYSTEM/DEFLECTOR: Index deflector management
#>

function Get-Graylog2DeflectorStatus {
	<#
	.SYNOPSIS
	Get current deflector status
	.EXAMPLE
	Get-Graylog2eflectorStatus
	#>

	try {
		$deflectorStatus = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/deflector" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $deflectorStatus
}

function Get-Graylog2DeflectorConfiguration {
	<#
	.SYNOPSIS
	Get deflector configuration. Only available on master nodes.
	.EXAMPLE
	Get-Graylog2DeflectorConfiguration
	#>

	try {
		$deflectorConfiguration = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/deflector/config" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $deflectorConfiguration
}

function New-Graylog2CycleDeflector {
	<#
	.SYNOPSIS
	Cycle deflector to new/next index
	.EXAMPLE
	New-Graylog2DeflectorConfiguration
	#>

	try {
		$newDeflector = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/system/deflector" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $newDeflector
}

<#
	END SYSTEM/DEFLECTOR
#>


<#
	SYSTEM/INPUTS: Message inputs of this node
#>

function Get-Graylog2Inputs {
	<#
	.SYNOPSIS
	Get all inputs of this node
	.EXAMPLE
	Get-Graylog2Inputs
	#>

	try {
		$nodeInput = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/inputs" -Headers (_Get_HttpBasicHeader_) -ContentType "application/json"
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	if ($nodeInput.total -eq 0) {
		Write-Host -ForegroundColor Yellow "No saved search."
		Return
	}

	Return $nodeInput.inputs
}

function New-Graylog2Input {
	<#
	.SYNOPSIS
	Launch input on this node
	.EXAMPLE
	New-Graylog2Input -inputGlobalNode -inputTitle "Dummy Syslog" -inputType "Syslog UDP" -port 9515 -bind_address "0.0.0.0"
	.PARAMETER inputGlobalNode
	Switch to define if input will be local to selected node or global (all nodes)
	.PARAMETER inputTitle
	Name of your new input that describes it
	.PARAMETER inputType
	Type of input to create (for instance "Syslog UDP")
	Use cmdlet Get-Graylog2InputTypes to check for supported types
	.PARAMETER port
	Port to listen on
	.PARAMETER bind_address
	Address to listen on. For example 0.0.0.0 or 127.0.0.1
	.PARAMETER fetch_wait_max
	Wait for this time or the configured minimum size of a message batch before fetching
	.PARAMETER threads
	Number of processor threads to spawn
	.PARAMETER zookeeper
	Host and port of the ZooKeeper that is managing your Kafka cluster
	.PARAMETER fetch_min_bytes
	Wait for a message batch to reach at least this size or the configured maximum wait time before fetching
	.PARAMETER source
	What to use as source of the generate messages
	.PARAMETER sleep
	How many milliseconds to sleep between generating messages
	.PARAMETER sleep_deviation
	The deviation is used to generate a more realistic and non-steady message flow
	.PARAMETER topic_filter
	Every topic that matches this regular expression will be consumed
	.PARAMETER allow_override_date
	Allow to override with current date if date could not be parsed? Must be one of 'true' or 'false'
	.PARAMETER store_full_message
	Store the full original syslog message as full_message? Must be one of 'true' or 'false'
	.PARAMETER force_rdns
	Force rDNS resolution of hostname? Use if hostname cannot be parsed. Must be one of 'true' or 'false'
	.PARAMETER override_source
	The source is a hostname derived from the received packet by default. Set this if you want to override it with a custom string.
	.PARAMETER headers
	Add a comma separated list of additional HTTP headers. For example: Accept: application/json, X-Requester: Graylog2
	.PARAMETER interval
	Time between every collector run
	.PARAMETER path
	Path to the value you want to extract from the JSON response. Take a look at the documentation for a more detailled explanation
	.PARAMETER target_url
	HTTP resource returning JSON on GET
	.PARAMETER timeunit
	Interval time unit. Must be one of "minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours"
	.PARAMETER duration_unit
	The time unit that will be used in for example timer values. Think of: took 15ms. Must be one of "minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours"
	.PARAMETER report_unit
	Report interval unit. Must be one of "minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours"
	.PARAMETER rate_unit
	The time unit that will be used in for example meter values. Think of: 7 per second. Must be one of "minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours"
	.PARAMETER report_interval
	Time between each report. Must be one of "minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours"
	.PARAMETER receive_buffer_size
	The size in bytes of the recvBufferSize for network connections to this input
	.PARAMETER queue
	Name of queue that is created
	.PARAMETER broker_username
	Username to connect to AMQP broker
	.PARAMETER broker_password
	PAssword to connect to AMQP broker
	.PARAMETER prefetchCount
	For advanced usage: AMQP prefetch count. Default is 0 (unlimited)
	.PARAMETER broker_hostname
	Hostname of the AMQP broker to use
	.PARAMETER broker_vhost
	Virtual host of the AMQP broker to use
	.PARAMETER broker_port
	Port of the AMQP broker to use (optional)
	.PARAMETER routing_key
	Routing key to listen for
	.PARAMETER broker_exchange
	Name of exchange to bind to
	#>

	[CmdletBinding()]
	param (
		[switch]$inputGlobalNode,
		[Parameter(Mandatory=$True)][string]$inputTitle,
		[Parameter(Mandatory=$True)][string]$inputType,
		[int]$port,
		[string]$bind_address,
		[int]$fetch_wait_max,
		[int]$threads,
		[string]$zookeeper,
		[int]$fetch_min_bytes,
		[string]$source,
		[int]$sleep,
		[int]$sleep_deviation,
		[string]$topic_filter,
		[ValidateSet("true","false")][string]$allow_override_date = "true",
		[ValidateSet("true","false")][string]$store_full_message = "false",
		[ValidateSet("true","false")][string]$force_rdns = "false",
		[string]$override_source,
		[string]$headers,
		[int]$interval = 1,
		[string]$path = "$.store.book[1].number_of_orders",
		[string]$target_url = "http://example.org/api",
		[ValidateSet("minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours")][string]$timeunit = "minutes",
		[ValidateSet("minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours")][string]$duration_unit = "milliseconds",
		[ValidateSet("minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours")][string]$report_unit = "seconds",
		[ValidateSet("minutes","milliseconds","days","seconds","microseconds","nanoseconds","hours")][string]$rate_unit = "seconds",
		[int]$report_interval,
		[int]$receive_buffer_size = 1048576,
		[string]$queue = "log-messages",
		[string]$broker_username,
		[string]$broker_password,
		[int]$prefetchCount = 0,
		[string]$broker_hostname,
		[string]$broker_vhost = "/",
		[int]$broker_port = 5672,
		[string]$routing_key = "#",
		[string]$broker_exchange = "log-messages"
	)

	$inputTypeId = (Get-Graylog2InputTypes | ?{$_.typename -match $inputType})

	if (($inputTypeId | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on inputType $inputType, please check before running this command again"
		Return
	}

	$timeunit = $timeunit.ToUpper()
	$duration_unit = $duration_unit.ToUpper()
	$report_unit = $report_unit.ToUpper()
	$rate_unit = $rate_unit.ToUpper()

	$hashRequest = @{}
	$hashRequest.Add("title",$inputTitle)
	if ($inputGlobalNode) {
		$hashRequest.Add("global","true")
	} else {
		$hashRequest.Add("global","false")
	}
	$hashRequest.Add("type",$inputTypeId.typeID)
	$hashRequest.Add("creator_user_id",$credentialRest.UserName)
	$hashAttributesRequest = @{}

	# Build JSON request based on input type
	switch ($inputTypeId.typeID) {
	    {"org.graylog2.inputs.gelf.http.GELFHttpInput", "org.graylog2.inputs.gelf.tcp.GELFTCPInput", "org.graylog2.inputs.gelf.udp.GELFUDPInput" -contains $_} {
			$hashAttributesRequest.Add("port",$port)
			$hashAttributesRequest.Add("bind_address",$bind_address)
			$hashAttributesRequest.Add("recv_buffer_size",$receive_buffer_size)
	    }
	    "org.graylog2.inputs.random.FakeHttpMessageInput" {
			$hashAttributesRequest.Add("source",$source)
			$hashAttributesRequest.Add("sleep",$sleep)
			$hashAttributesRequest.Add("sleep_deviation",$sleep_deviation)
	    }
	    "org.graylog2.inputs.kafka.KafkaInput" {
			$hashAttributesRequest.Add("topic_filter",$topic_filter)
			$hashAttributesRequest.Add("fetch_wait_max",$fetch_wait_max)
			$hashAttributesRequest.Add("threads",$threads)
			$hashAttributesRequest.Add("zookeeper",$zookeeper)
			$hashAttributesRequest.Add("fetch_min_bytes",$fetch_min_bytes)
	    }
	    {"org.graylog2.inputs.syslog.tcp.SyslogTCPInput", "org.graylog2.inputs.syslog.udp.SyslogUDPInput" -contains $_} {
			$hashAttributesRequest.Add("allow_override_date",$allow_override_date)
			$hashAttributesRequest.Add("port",$port)
			$hashAttributesRequest.Add("bind_address",$bind_address)
			$hashAttributesRequest.Add("store_full_message",$store_full_message)
			$hashAttributesRequest.Add("force_rdns",$force_rdns)
			$hashAttributesRequest.Add("recv_buffer_size",$receive_buffer_size)
	    }
	    {"org.graylog2.inputs.raw.tcp.RawTCPInput", "org.graylog2.inputs.raw.udp.RawUDPInput" -contains $_} {
			$hashAttributesRequest.Add("override_source",$override_source)
			$hashAttributesRequest.Add("port",$port)
			$hashAttributesRequest.Add("bind_address",$bind_address)
			$hashAttributesRequest.Add("recv_buffer_size",$receive_buffer_size)
	    }
	    "org.graylog2.inputs.misc.jsonpath.JsonPathInput" {
			$hashAttributesRequest.Add("headers",$headers)
			$hashAttributesRequest.Add("interval",$interval)
			$hashAttributesRequest.Add("source",$source)
			$hashAttributesRequest.Add("timeunit",$timeunit)
			$hashAttributesRequest.Add("path",$path)
			$hashAttributesRequest.Add("target_url",$target_url)
	    }
	    "org.graylog2.inputs.misc.metrics.LocalMetricsInput" {
			$hashAttributesRequest.Add("duration_unit",$duration_unit)
			$hashAttributesRequest.Add("source",$source)
			$hashAttributesRequest.Add("report_unit",$report_unit)
			$hashAttributesRequest.Add("rate_unit",$rate_unit)
			$hashAttributesRequest.Add("report_interval",$report_interval)
	    }
	    "org.graylog2.inputs.amqp.AMQPInput" {
			$hashAttributesRequest.Add("queue",$queue)
			$hashAttributesRequest.Add("broker_username",$broker_username)
			$hashAttributesRequest.Add("prefetch",$prefetchCount)
			$hashAttributesRequest.Add("broker_hostname",$broker_hostname)
			$hashAttributesRequest.Add("broker_password",$broker_password)
			$hashAttributesRequest.Add("routing_key",$routing_key)
			$hashAttributesRequest.Add("broker_vhost",$broker_vhost)
			$hashAttributesRequest.Add("broker_port",$broker_port)
			$hashAttributesRequest.Add("exchange",$broker_exchange)
	    }
	    "org.graylog2.inputs.radio.RadioAMQPInput" {
			$hashAttributesRequest.Add("broker_username",$broker_username)
			$hashAttributesRequest.Add("prefetch",$prefetchCount)
			$hashAttributesRequest.Add("broker_hostname",$broker_hostname)
			$hashAttributesRequest.Add("broker_password",$broker_password)
			$hashAttributesRequest.Add("broker_vhost",$broker_vhost)
			$hashAttributesRequest.Add("broker_port",$broker_port)
	    }
	    "org.graylog2.inputs.radio.RadioKafkaInput" {
			$hashAttributesRequest.Add("fetch_wait_max",$fetch_wait_max)
			$hashAttributesRequest.Add("threads",$threads)
			$hashAttributesRequest.Add("zookeeper",$zookeeper)
			$hashAttributesRequest.Add("fetch_min_bytes",$fetch_min_bytes)
	    }
	    default {
	    	Write-Host -ForegroundColor Red "This inputType is not yet implemented in this module."
			Return
	    }
	}

	$hashRequest.Add("configuration",$hashAttributesRequest)

	try {
		$inputId = Invoke-RestMethod -Method Post -Uri "http://$($restInstance):$restPort/system/inputs" -Headers (_Get_HttpBasicHeader_) -ContentType "application/json" -Body ($hashRequest | ConvertTo-Json -Compress)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Write-Host -ForegroundColor Red "JSON body:"
		Write-Host -ForegroundColor Red ($hashRequest | ConvertTo-Json)
		Return
	}

	Return $inputId
}

function Get-Graylog2InputTypes {
	<#
	.SYNOPSIS
	Get all input type
	.EXAMPLE
	Get-Graylog2InputTypes
	#>

	try {
		$tabInputTypes = @()
		$inputTypes = [string](Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/inputs/types" -Headers (_Get_HttpBasicHeader_)).types
		$inputTypes = $inputTypes.Substring(2,$inputTypes.Length-3)
		foreach ($inputType in $inputTypes.Split(";")) {
			$tmpLine = "" | Select typeID, typeName
			$tmpLine.typeID = $inputType.Split("=")[0].Replace(" ","")
			$tmpLine.typeName = $inputType.Split("=")[1]
			$tabInputTypes += $tmpLine
		}
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	return $tabInputTypes
}

function Get-Graylog2InputType {
	<#
	.SYNOPSIS
	Get all input type
	.EXAMPLE
	Get-Graylog2InputType -inputTypeId "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
	.PARAMETER inputTypeId
	Id of input type
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$inputTypeId
	)
	
	if ((Get-Graylog2InputTypes | ?{$_.typeID -eq $inputTypeId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on input type with typeID $inputTypeId, please check before running this command again"
		Return
	}

	try {
		$inputType = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/inputs/types/$inputTypeId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $inputType
}

function Remove-Graylog2Input {
	<#
	.SYNOPSIS
	Terminate input on this node
	.EXAMPLE
	Remove-Graylog2InputType -inputTypeId "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
	.PARAMETER inputTypeId
	Id of input type
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$inputTypeId
	)
	
	if ((Get-Graylog2InputTypes | ?{$_.typeID -eq $inputTypeId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on input type with typeID $inputTypeId, please check before running this command again"
		Return
	}

	try {
		$inputType = Invoke-WebRequest -Method Delete -Uri "http://$($restInstance):$restPort/system/inputs/types/$inputTypeId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $inputType
}

function Get-Graylog2InputInformation {
	<#
	.SYNOPSIS
	Get information of a single input on this node
	.EXAMPLE
	Get-Graylog2InputInformation -inputTypeId "org.graylog2.inputs.syslog.udp.SyslogUDPInput"
	.PARAMETER inputTypeId
	Id of input type
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$inputTypeId
	)
	
	if ((Get-Graylog2Inputs | ?{$_.message_input.input_id -eq $inputTypeId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on input type with typeID $inputTypeId, please check before running this command again"
		Return
	}

	try {
		$inputInformation = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/inputs/$inputTypeId" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $inputInformation
}

function Start-Graylog2Input {
	<#
	.SYNOPSIS
	Launch existing input on this node
	.EXAMPLE
	Start-Graylog2Input -inputTypeId "535a7e0ee4b02d59485f7766"
	.PARAMETER inputTypeId
	Id of input to launch
	#>

	[CmdletBinding()]
	param (
		[Parameter(Mandatory=$True)][string]$inputTypeId
	)
	
	if ((Get-Graylog2InputTypes | ?{$_.typeID -eq $inputTypeId} | Measure-Object).Count -ne 1) {
		Write-Host -ForegroundColor Red "Error on input type with typeID $inputTypeId, please check before running this command again"
		Return
	}	

	try {
		$inputId = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/system/inputs/$inputTypeId/launch" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $inputId
}

<#
	END SYSTEM/INPUTS
#>


<#
	USERS FUNCTIONS
#>

function Get-Graylog2Users {
	<#
	.SYNOPSIS
	List all users
	.EXAMPLE
	Get-Graylog2Users
	#>

	try {
		$users = Invoke-RestMethod -Method Get -Uri "http://$($restInstance):$restPort/users" -Headers (_Get_HttpBasicHeader_)
	} catch {
		Write-Host -ForegroundColor Red "Exception Message: $($_.Exception.Message)"
		Return
	}

	Return $users.users
}

<#
	END USERS
#>


# Hidding helper functions by exporting only available cmdlet

# COMMON FUNCTIONS
Export-ModuleMember -Function Connect-Graylog2Rest
Export-ModuleMember -Function Get-Graylog2StreamRuleType

# ALERTS
Export-ModuleMember -Function Get-Graylog2StreamAlert
Export-ModuleMember -Function Test-Graylog2StreamAlert
Export-ModuleMember -Function New-Graylog2StreamAlertConditions
Export-ModuleMember -Function Get-Graylog2StreamAlertConditions
Export-ModuleMember -Function Remove-Graylog2StreamAlertConditions
Export-ModuleMember -Function New-Graylog2StreamAlertReceivers
Export-ModuleMember -Function Remove-Graylog2StreamAlertReceivers
Export-ModuleMember -Function Send-Graylog2DummyStreamAlert

# COUNTS
Export-ModuleMember -Function Get-Graylog2MessageCounts

# DASHBOARDS
Export-ModuleMember -Function Get-Graylog2Dashboards
Export-ModuleMember -Function New-Graylog2Dashboard
Export-ModuleMember -Function Get-Graylog2Dashboard
Export-ModuleMember -Function Remove-Graylog2Dashboard
Export-ModuleMember -Function Update-Graylog2Dashboard
Export-ModuleMember -Function Update-Graylog2DashboardPositions
Export-ModuleMember -Function Add-Graylog2DashboardWidget
Export-ModuleMember -Function Remove-Graylog2DashboardWidget
Export-ModuleMember -Function Update-Graylog2DashboardWidgetCachetime
Export-ModuleMember -Function Update-Graylog2DashboardWidgetDescription
Export-ModuleMember -Function Get-Graylog2DashboardWidget

# EXTRACTORS
Export-ModuleMember -Function Get-Graylog2Extractors
Export-ModuleMember -Function New-Graylog2Extractor
Export-ModuleMember -Function Remove-Graylog2Extractor

# INDEXER/CLUSTER
Export-ModuleMember -Function Get-Graylog2ClusterHealth
Export-ModuleMember -Function Get-Graylog2ClusterName

# INDEXER/INDICES
Export-ModuleMember -Function Get-Graylog2ClosedIndices
Export-ModuleMember -Function Remove-Graylog2Index
Export-ModuleMember -Function Get-Graylog2IndexInformation
Export-ModuleMember -Function Close-Graylog2Index
Export-ModuleMember -Function Resume-Graylog2Index

# MESSAGES
Export-ModuleMember -Function Get-Graylog2MessageAnalyze
Export-ModuleMember -Function Get-Graylog2Message

# SEARCH/ABSOLUTE

# SEARCH/SAVED
Export-ModuleMember -Function Get-Graylog2SavedSearches
Export-ModuleMember -Function New-Graylog2SavedSearch
Export-ModuleMember -Function Get-Graylog2SavedSearch
Export-ModuleMember -Function Remove-Graylog2SavedSearch

# SOURCES
Export-ModuleMember -Function Get-Graylog2Sources

# STATICFIELDS
Export-ModuleMember -Function New-Graylog2InputStaticfields
Export-ModuleMember -Function Remove-Graylog2InputStaticfields

# STREAMRULES
Export-ModuleMember -Function Get-Graylog2StreamRules
Export-ModuleMember -Function New-Graylog2StreamRule
Export-ModuleMember -Function Get-Graylog2StreamRule
Export-ModuleMember -Function Remove-Graylog2StreamRule
Export-ModuleMember -Function Update-Graylog2StreamRule

# STREAMS
Export-ModuleMember -Function Get-Graylog2Streams
Export-ModuleMember -Function New-Graylog2Stream
Export-ModuleMember -Function Get-Graylog2EnabledStream
Export-ModuleMember -Function Get-Graylog2Stream
Export-ModuleMember -Function Remove-Graylog2Stream
Export-ModuleMember -Function Update-Graylog2Stream
Export-ModuleMember -Function Copy-Graylog2Stream
Export-ModuleMember -Function Suspend-Graylog2Stream
Export-ModuleMember -Function Resume-Graylog2Stream
Export-ModuleMember -Function Test-Graylog2Stream
Export-ModuleMember -Function Get-Graylog2StreamThroughput

# SYSTEM
Export-ModuleMember -Function Get-Graylog2SystemOverview
Export-ModuleMember -Function Get-Graylog2SystemFields
Export-ModuleMember -Function Get-Graylog2JVMInformation
Export-ModuleMember -Function Get-Graylog2Permissions
Export-ModuleMember -Function Get-Graylog2UserPermissions
Export-ModuleMember -Function Suspend-Graylog2MessageProcessing
Export-ModuleMember -Function Resume-Graylog2MessageProcessing
Export-ModuleMember -Function Get-Graylog2ThreadDump

# SYSTEM/BUFFERS
Export-ModuleMember -Function Get-Graylog2BufferInformation

# SYSTEM/CLUSTER
Export-ModuleMember -Function Get-Graylog2Node
Export-ModuleMember -Function Get-Graylog2Nodes
Export-ModuleMember -Function Get-Graylog2NodeInformation

# SYSTEM/DEFLECTOR
Export-ModuleMember -Function Get-Graylog2DeflectorStatus
Export-ModuleMember -Function Get-Graylog2DeflectorConfiguration
Export-ModuleMember -Function New-Graylog2CycleDeflector

# SYSTEM/INPUTS
Export-ModuleMember -Function Get-Graylog2Inputs
Export-ModuleMember -Function New-Graylog2Input
Export-ModuleMember -Function Get-Graylog2InputTypes
Export-ModuleMember -Function Get-Graylog2InputType
Export-ModuleMember -Function Remove-Graylog2Input
Export-ModuleMember -Function Get-Graylog2InputInformation
Export-ModuleMember -Function Start-Graylog2Input

# USERS FUNCTIONS
Export-ModuleMember -Function Get-Graylog2Users