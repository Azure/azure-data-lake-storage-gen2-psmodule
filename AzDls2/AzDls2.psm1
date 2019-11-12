function Encode-UriCharacters {

    [CmdletBinding()]
    
    Param(
        [Parameter(Mandatory=$true,Position=0)]
        [string]$String
    )

    $String = $String.Replace('%','%25')

    $String = $String.Replace(' ','%20')
    $String = $String.Replace('@','%40')
    $String = $String.Replace('#','%23')
    $String = $String.Replace('$','%24')
    $String = $String.Replace('^','%5E')
    $String = $String.Replace('&','%26')
    $String = $String.Replace('+','%2B')
    $String = $String.Replace('`','%60')
    $String = $String.Replace('=','%3D')
    $String = $String.Replace('<','%3C')
    $String = $String.Replace('>','%3E')
    $string = $String.Replace(':','%3A')
    $String = $String.Replace('"','%22')
    $String = $String.Replace('{','%7B')
    $String = $String.Replace('}','%7D')
    $String = $String.Replace('|','%7C')
    $string = $String.Replace(',','%2C')
    $String = $String.Replace(';','%3B')
    $String = $String.Replace('[','%5B')
    $String = $String.Replace(']','%5D')

    #$string = $String.Replace('*','%2A')
    #$string = $String.Replace('!','%21')
    #$string = $String.Replace('(','%28')
    #$string = $String.Replace(')','%29')
    #$string = $String.Replace('_','%5F')
    #$string = $String.Replace('-','%2D')
    #$string = $String.Replace('~','%7E')
    #$string = $String.Replace('?','%3F')
    #$string = $String.Replace('.','%2E')
    #$string = $String.Replace("'",'%27')

    $String = $String.Replace('\','/')

    if ($String.Length -gt 1) {
        $String = $String.trim("/")
    }

    return $String
}

function ConvertFrom-xMsAcl {
    [CmdletBinding()]

    Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
      $InputObject
    )

    $return = @{
        acl = @{
            users = [ordered]@{}
            groups = [ordered]@{}
            masks = [ordered]@{}
            others = [ordered]@{}
        }
        default = @{
            users = [ordered]@{}
            groups = [ordered]@{}
            masks = [ordered]@{}
            others = [ordered]@{}
        }
    }

    switch ($InputObject.replace('::',':<built-in>:') -split(',')) {
        { $_.startswith('user') } { $return.acl.users.Add($_.split(':')[1],$_.split(':')[2]) }
        { $_.startswith('group') } { $return.acl.groups.Add($_.split(':')[1],$_.split(':')[2]) }
        { $_.startswith('mask') } { $return.acl.masks.Add($_.split(':')[1],$_.split(':')[2]) }
        { $_.startswith('other') } {$return.acl.others.Add($_.split(':')[1],$_.split(':')[2]) }
        { $_.startswith('default:user') } { $return.default.users.Add($_.split(':')[2],$_.split(':')[3]) }
        { $_.startswith('default:group') } { $return.default.groups.Add($_.split(':')[2],$_.split(':')[3]) }
        { $_.startswith('default:mask') } { $return.default.masks.Add($_.split(':')[2],$_.split(':')[3]) }
        { $_.startswith('default:other') } { $return.default.others.Add($_.split(':')[2],$_.split(':')[3]) }
    }

    return $return
}

function ConvertTo-xMsAcl {
    [CmdletBinding()]

    Param(
      [Parameter(Mandatory=$true,ValueFromPipeline=$true,Position=0)]
      $InputObject
    )

    $return = @()

    foreach ($key in $InputObject.acl.users.keys) {
        $return += "user:{0}:{1}" -f $key, $InputObject.acl.users[$key]
    }
    foreach ($key in $InputObject.acl.groups.keys) {
        $return += "group:{0}:{1}" -f $key, $InputObject.acl.groups[$key]
    }
    foreach ($key in $InputObject.acl.masks.keys) {
        $return += "mask:{0}:{1}" -f $key, $InputObject.acl.masks[$key]
    }
    foreach ($key in $InputObject.acl.others.keys) {
        $return += "other:{0}:{1}" -f $key, $InputObject.acl.others[$key]
    }

    foreach ($key in $InputObject.default.users.keys) {
        $return += "default:user:{0}:{1}" -f $key, $InputObject.default.users[$key]
    }
    foreach ($key in $InputObject.default.groups.keys) {
        $return += "default:group:{0}:{1}" -f $key, $InputObject.default.groups[$key]
    }
    foreach ($key in $InputObject.default.masks.keys) {
        $return += "default:mask:{0}:{1}" -f $key, $InputObject.default.masks[$key]
    }
    foreach ($key in $InputObject.default.others.keys) {
        $return += "default:other:{0}:{1}" -f $key, $InputObject.default.others[$key]
    }

    return ($return -join ',').replace(':<built-in>:','::')
}

function New-AzDls2AuthHeader {
    
    [CmdletBinding()]
    
    Param(
        [Parameter(Mandatory=$True,Position=0)]
        [ValidateSet("GET", "PUT", "DELETE","HEAD","PATCH")] 
        [string]$Method,
        [Parameter(Mandatory=$True,Position=1)]
        [string]$Target,
        [Parameter(Mandatory=$false,Position=2)]
        [psobject]$Headers,
        [Parameter(Mandatory=$false,Position=3)]
        [psobject]$Resources,
        [Parameter(Mandatory=$false,Position=4)]
        [string]$AccessKey
    )

    $return = @{method=$Method; string = ""; signature = ""}
 
    $return.string  = "$method" +"`n"
    $return.string += "`n`n`n`n`n`n`n`n`n`n" +"`n"

    foreach ($key in $Headers.Keys) {
        $return.string += "{0}:{1}`n" -f $key, $Headers[$key]
    }
    $return.string += $Target +"`n"

    foreach ($key in $Resources.Keys) {
        $return.string += "{0}:{1}`n" -f $key, $Resources[$key]
    }
    $return.string = $return.string.trim("`n")

    $sharedKey = [System.Convert]::FromBase64String($AccessKey)
    $hasher = New-Object System.Security.Cryptography.HMACSHA256
    $hasher.Key = $sharedKey
 
    $return.signature = [System.Convert]::ToBase64String($hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($return.string)))

    return $return
}

function Get-AzDls2ChildItem {

    [CmdletBinding()]

    Param(
      [Parameter(Mandatory=$true,Position=0)] 
      [string]$StorageAccountName,
      [Parameter(Mandatory=$true,Position=1)] 
      [string]$FileSystemName,
      [Parameter(Mandatory=$true,Position=2)] 
      [string]$AccessKey,
      [Parameter(Mandatory=$false,Position=3)] 
      [string]$Directory="",
      [Parameter(Mandatory=$false,Position=4)] 
      [switch]$Recurse
    )

    $headers = [ordered]@{}
    $headers.Add("x-ms-date",[System.DateTime]::UtcNow.ToString("R"))
    $headers.Add("x-ms-version","2018-11-09")

    $resources = [ordered]@{}
    if ($Directory.Length -gt 0) {
        $resources.Add('directory',$Directory)
    }
    if ($Recurse) {
        $resources.Add('recursive','true')
    } 
    else {
        $resources.Add('recursive','false')
    }
    $resources.Add('resource','filesystem')

    $authHeader = New-AzDls2AuthHeader -Method GET -Target "/$StorageAccountName/$FileSystemName" -Headers $headers -Resources $resources -AccessKey $AccessKey
    $headers.Add('Authorization',"SharedKey $($StorageAccountName):$($authHeader.signature)")
    
    if ($Directory.Length -gt 0) {
        $resources.directory = Encode-UriCharacters -String $Directory
    }
    $uri = "https://$StorageAccountName.dfs.core.windows.net/" + $FileSystemName + "?"
    foreach ($key in $resources.Keys) {
        $uri += "{0}={1}&" -f $key, $resources[$key]
    }
    $uri = $uri.trim('&')

    Invoke-RestMethod -Method $authHeader.Method -Uri $uri -Headers $headers |
        Select-Object -ExpandProperty paths
}

function Get-AzDls2ItemAccessControl {

    [CmdletBinding()]

    Param(
      [Parameter(Mandatory=$true,Position=0)] 
      [string]$StorageAccountName,
      [Parameter(Mandatory=$True,Position=1)] 
      [string]$FileSystemName,
      [Parameter(Mandatory=$True,Position=2)] 
      [string]$AccessKey,
      [Parameter(Mandatory=$True,Position=3)] 
      [string]$Path
    )

    $headers = [ordered]@{}
    $headers.Add("x-ms-date",[System.DateTime]::UtcNow.ToString("R"))
    $headers.Add("x-ms-version","2018-11-09")

    $resources = [ordered]@{}
    $resources.Add('action','getAccessControl')
    $resources.Add('upn','true')

    $Path = Encode-UriCharacters -String $Path

    $authHeader = New-AzDls2AuthHeader -Method HEAD -Target "/$StorageAccountName/$FileSystemName/$Path" -Headers $headers -Resources $resources -AccessKey $AccessKey
    $headers.Add('Authorization',"SharedKey $($StorageAccountName):$($authHeader.signature)")

    $uri = "https://$StorageAccountName.dfs.core.windows.net/" + $FileSystemName + "/" + $Path + "?"
    foreach ($key in $resources.Keys) {
        $uri += "{0}={1}&" -f $key, $resources[$key]
    }
    $uri = $uri.trim('&')

    (Invoke-WebRequest -Method $authHeader.method -Uri $uri -Headers $headers |
        Select-Object -ExpandProperty Headers).'x-ms-acl'
}

function Set-AzDls2ItemAccessControl {

    [CmdletBinding()]

    Param(
      [Parameter(Mandatory=$true,Position=0)] 
      [string]$StorageAccountName,
      [Parameter(Mandatory=$True,Position=1)] 
      [string]$FileSystemName,
      [Parameter(Mandatory=$True,Position=2)] 
      [string]$AccessKey,
      [Parameter(Mandatory=$True,Position=3)] 
      [string]$Path,
      [Parameter(Mandatory=$True,Position=4)] 
      [string]$xMsAcl
    )

    $headers = [ordered]@{}
    $headers.Add("x-ms-acl",$xMsAcl)
    $headers.Add("x-ms-date",[System.DateTime]::UtcNow.ToString("R"))
    $headers.Add("x-ms-version","2018-11-09")

    $resources = [ordered]@{}
    $resources.Add('action','setAccessControl')

    $Path = Encode-UriCharacters -String $Path

    $authHeader = New-AzDls2AuthHeader -Method PATCH -Target "/$StorageAccountName/$FileSystemName/$Path" -Headers $headers -Resources $resources -AccessKey $AccessKey
    $headers.Add('Authorization',"SharedKey $($StorageAccountName):$($authHeader.signature)")

    $uri = "https://$StorageAccountName.dfs.core.windows.net/" + $FileSystemName + "/" + $Path + "?"
    foreach ($key in $resources.Keys) {
        $uri += "{0}={1}&" -f $key, $resources[$key]
    }
    $uri = $uri.trim('&')

    Invoke-RestMethod -Method $authHeader.method -Uri $uri -Headers $headers | Out-Null
}

function Push-AzDls2ItemAccessControl {
    
    [CmdletBinding()]

    Param(
      [Parameter(Mandatory=$true,Position=0)] 
      [string]$StorageAccountName,
      [Parameter(Mandatory=$true,Position=1)] 
      [string]$FileSystemName,
      [Parameter(Mandatory=$true,Position=2)] 
      [string]$AccessKey,
      [Parameter(Mandatory=$false,Position=3)] 
      [string]$Directory="",
      [Parameter(Mandatory=$false,Position=4)] 
      [switch]$Recurse
    )

    $xMsAcl = Get-AzDls2ItemAccessControl -StorageAccountName $StorageAccountName -FileSystemName $FileSystemName -AccessKey $AccessKey -Path $Directory
    $fxMsAcl = (($xMsAcl -split ',' | where { !$_.startswith('default:') }) -join ',')

    Get-AzDls2ChildItem -StorageAccountName $StorageAccountName -FileSystemName $FileSystemName -AccessKey $AccessKey -Recurse:$Recurse -Directory $Directory |
        ForEach-Object {
            if ($_.isDirectory) {
                Set-AzDls2ItemAccessControl -StorageAccountName $StorageAccountName -FileSystemName $FileSystemName -AccessKey $AccessKey -Path $_.Name -xMsAcl $xMsAcl
            }
            else {
                Set-AzDls2ItemAccessControl -StorageAccountName $StorageAccountName -FileSystemName $FileSystemName -AccessKey $AccessKey -Path $_.Name -xMsAcl $fxMsAcl
            }
        }
}
