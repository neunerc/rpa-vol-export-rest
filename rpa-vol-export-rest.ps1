<#
CREATED BY: Christopher Neuner
DESCRIPTION: This script creates a comma-separated output of EMC RecoverPoint replication set details. REST API
			 is used for data collection.
CREATED ON: 01/01/2017
UPDATED ON: 03/21/2017
DEPENDENCIES: EMC RecoverPoint credentials to run REST API queries.
COMPATABILITY: Tested against RecoverPoint 4.1.x and 4.3.x.
USE: .\rpa-vol-export-rest.ps1 -IPaddress "<source_path>" [-Output "<target_path>"] [-Credential (Get-Credential)] [-NoHeader]
     .\rpa-vol-export-rest.ps1 -IPaddress XXX.XXX.XXX.XXX -Output .\rpa_vols.txt -Credential "user123" -NoHeader
PARAMETERS:
	IPaddress	[Mandatory]	: The IP Address of a RecoverPoint cluster. If ommitted, the user will be prompted.
	Credential	[Mandatory]	: Takes a PSCredential or string credential value. If ommitted, the user will be prompted.
	Output		[Optional]	: A valid output file name. If ommitted, output will be written to the host.
	NoHeader	[Optional]	: If exists, output will not include the standard header.

----------------------------------------------------------------------------------------------------------------------	

LICENSE: BSD 3-Clause

Copyright (c) 2017, Christopher Neuner

All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation
and/or other materials provided with the distribution.
* Neither the name of the <ORGANIZATION> nor the names of its contributors
may be used to endorse or promote products derived from this software
without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, 
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR 
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#>


param(
	[Parameter(Mandatory=$True,Position=1)]
		[ValidateScript({$_ -match [IPAddress]$_ })][string]$IPAddress,
	[Parameter(Mandatory=$True,Position=2)]
		[System.Management.Automation.PSCredential]$Credential,
	[ValidateScript({
		if (($_ -eq "") -or (Test-Path $_ -PathType leaf -IsValid))
		{$True}
		else
		{Write-Error "Invalid path given: $_"}
		})][string]$Output = "",
	[switch]$NoHeader = $False
)

function Disable-SSLValidation{
	<#
	.SYNOPSIS
		Disables SSL certificate validation
	.DESCRIPTION
		Disable-SSLValidation disables SSL certificate validation by using reflection to implement the System.Net.ICertificatePolicy class.
		Author: Matthew Graeber (@mattifestation)
		License: BSD 3-Clause
	.NOTES
		Reflection is ideal in situations when a script executes in an environment in which you cannot call csc.ese to compile source code. If compiling code is an option, then implementing System.Net.ICertificatePolicy in C# and Add-Type is trivial.
	.LINK
		http://www.exploit-monday.com
	#>

    Set-StrictMode -Version 2
 
    # You have already run this function
    if ([System.Net.ServicePointManager]::CertificatePolicy.ToString() -eq 'IgnoreCerts') { Return }
 
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('IgnoreCerts')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('IgnoreCerts', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('IgnoreCerts', 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit', [System.Object], [System.Net.ICertificatePolicy])
    $TypeBuilder.DefineDefaultConstructor('PrivateScope, Public, HideBySig, SpecialName, RTSpecialName') | Out-Null
    $MethodInfo = [System.Net.ICertificatePolicy].GetMethod('CheckValidationResult')
    $MethodBuilder = $TypeBuilder.DefineMethod($MethodInfo.Name, 'PrivateScope, Public, Virtual, HideBySig, VtableLayoutMask', $MethodInfo.CallingConvention, $MethodInfo.ReturnType, ([Type[]] ($MethodInfo.GetParameters() | % {$_.ParameterType})))
    $ILGen = $MethodBuilder.GetILGenerator()
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ldc_I4_1)
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ret)
    $TypeBuilder.CreateType() | Out-Null
 
    # Disable SSL certificate validation
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object IgnoreCerts
}

function InvokeRest([string]$uri)
{
	# Execute REST GET command
	# PARAM: $uri: Valid HTTP REST Path
	try 
	{
		$result = Invoke-RestMethod -Uri $uri -Method Get -Credential $script:Credential
	}
	catch
	{
		throw $_
		exit
	}
	return ($result)
}

function Get-RPGroupIDs([string]$strIPAddress)
{
	$result = InvokeRest "https://${strIPAddress}:443/fapi/rest/4_1/groups"
	return ($result.innerSet | % { $_.id })
}

function Get-RPGroupSettings([string]$strIPAddress, [string]$strGroupID)
{
	$result = InvokeRest "https://${strIPAddress}:443/fapi/rest/4_1/groups/${strGroupID}/settings"
	return ($result)
}

function Get-RPRepSets([string]$strIPAddress, [string]$strGroupID) 
{
	$result = InvokeRest "https://${strIPAddress}:443/fapi/rest/4_1/groups/${strGroupID}/replication_sets"
	return ($result.innerSet)
}

function Get-RPCopySettings([string]$strIPAddress, [string]$strGroupID)
{
	$result = InvokeRest "https://${strIPAddress}:443/fapi/rest/4_1/groups/${strGroupID}/copies/settings"
	return ($result.innerSet)
}

function Get-RPSystemSettings([string]$strIPAddress)
{
	$result = InvokeRest "https://${strIPAddress}:443/fapi/rest/4_1/system/settings"
	return ($result)
}

function Create-RPClusterHashTable([string]$strIPAddress)
{
	# Create a hash table based on the RP Cluster IDs/Names
	$result = Get-RPSystemSettings($strIPAddress)
	$ar = @{}
	foreach ($res in $result.clustersSettings)
	{
		$ar.Add(($res | % {$_.clusterUID.id}), ($res | % {$_.clusterName}))
	}
	return ($ar)
}


function SignedToHexUID($signedArray)
{
	# Converted signed value to hex
	# Used for creating a valid UID based on signed values
	# USE: Convert LUN WWNs to from signed valid hex format
	$uids_array =@()
	foreach ($uid in $signedArray)
	{
		$uid_converted = [Convert]::ToString($uid,16)
		if ($uid -lt 0)
		{$uids_array += $uid_converted.substring($uid_converted.length - 2)}
		else
		{$uids_array += $uid_converted.PadLeft(2, '0')}
	}
	return ($uids_array -join ':')
}

function main()
{
	Disable-SSLValidation
	Set-StrictMode -Version 2.0

	$Groups = @()
	$maxcopies = 0
	$header = "CG,RSET"
	$body = ""
	
	# Loop through RP Consistency Groups
	$RPGroups = Get-RPGroupIDs($IPaddress)
	foreach ($id in $RPGroups)
	{
		$prefix = ""
		try
		{
			$RPRPGroupSettings = Get-RPGroupSettings $IPaddress $id
			$ClusterHash = Create-RPClusterHashTable($IPaddress)
			$copies = Get-RPCopySettings $IPaddress $id
		}
		catch
		{
			throw $_
			exit
		}
		
		# *** OUTPUT START [ CG Name] ***
		$prefix += $RPRPGroupSettings | % { $_.name }
		# *** OUTPUT END [ CG Name] ***
		
		# Get and loop through Replication Sets related to applicable RP Consistency Group
		$rsets = Get-RPRepSets $IPaddress $id | sort-object { $_.replicationSetName }
		foreach ($rset in $rsets)
		{
			$copycount = 0
			$line = ($rset | % { $_.replicationSetName })
			$copy = $copies | sort-object { $_.roleInfo.role }
			$copycount += ($copy | measure | % {$_.Count })
			if ($copycount -gt $maxcopies) {$maxcopies = $copycount}
			# Loop through Copies related to applicable RP Consistency Group
			foreach ($cpy in $copy)
			{
				# *** OUTPUT START [ Copy Name ] ***
				$cp = @()
				$cp = $cpy | % { $_.name, $_.roleInfo.role }
				$line += ',' + $($cp[0]) + "," + $($cp[1])
				# *** OUTPUT END [ Copy Name ] ***			
				
				$cpyuid = $cpy | % { $_.copyUID.globalCopyUID.copyUID }
				$cluster = $cpy | % { $_.copyUID.globalCopyUID.clusterUID.id }
				
				$line += ',' + $ClusterHash.Get_Item($cluster)
				
				$vol = $rset | % { $_.volumes } |  where { $_.clusterUID.id -eq $cluster -and  $_.groupCopyUID.globalCopyUID.copyUID -eq $cpyuid} | % { $_.volumeInfo }
				$uids = ($vol | % { $_.naaUID })
				$line += ',' + (SignedToHexUID($uids))
				$line += ',' + ($vol | % { $_.arraySerialNumber })
				$line += ',' + ($vol | % { $_.volumeName })
				$line += ',' + ($vol | % { $_.sizeInBytes })
				$line += ',' + (($vol | % { $_.sizeInBytes })/1024/1024/1024)
			}
			$body += $prefix + "," + $line + "`n"
		}
	}
	
	# OUTPUT RESULTS
	if ($maxcopies -eq 0) {write-host "ERROR: No Data Found. Exiting..."; exit}
	# DETERMINE WHETHER THE HEADER SHOULD BE INCLUDED IN OUTPUT
	if ($NoHeader -eq $False) {$results = ($header + ",COPY,COPY_STATE,CLUSTER,COPY_VOL,ARRAY_SER,VOL_NAME,VOL_BYTES,VOL_GiB"*$maxcopies + "`n")} else {$results = ""}
	$results = ($results + $body)
	# Output file if param supplied or host if not
	if ($Output -eq "") {$results} else {$results | Out-File  -FilePath $Output}
}

# EXECUTE MAIN SCRIPT FUNCTION
main