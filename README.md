---
page_type: sample
languages:
- powershell
products:
- v5.1
description: "PowerShell module to wrap the Azure Data Lake Store REST API."
urlFragment: ""
---

# Official Microsoft Sample

A sample (basic) PowerShell module that wraps the Azure Data Lake Store REST API.

## Contents

| File/folder       | Description                                |
|-------------------|--------------------------------------------|
| `AzDls2`          | Sample AzDls2 PowerShell module.           |
| `.gitignore`      | Define what to ignore at commit time.      |
| `CHANGELOG.md`    | List of changes to the sample.             |
| `CONTRIBUTING.md` | Guidelines for contributing to the sample. |
| `README.md`       | This README file.                          |
| `LICENSE`         | The license for the sample.                |

## Prerequisites

This module was written using PowerShell v5.1.

## Setup

Install the module by copying the `AzDls2` folder to one of the PowerShell module directories. These directories are saved in the environment variable `%PSModulePath%`. Default locations include:

* C:\Program Files\WindowsPowerShell\Modules
* C:\Windows\system32\WindowsPowerShell\v1.0\Modules

## Runnning the sample

``` PowerShell
# Example: Show the current permissions
Get-AzDls2ChildItem -StorageAccountName 'azdls172' -FileSystemName 'container1' -AccessKey $key -Recurse | 
    ForEach-Object {
        $_ | Add-Member -Force -Type NoteProperty -Name AccessControl -Value ( Get-AzDls2ItemAccessControl -StorageAccountName 'azdls172' -FileSystemName 'container1' -AccessKey $key -Path $_.Name )
        $_
    } |
    Out-GridView

# Example: Take the ACL from each folder in the root of the file system and apply it to it's children
Get-AzDls2ChildItem -StorageAccountName 'azdls172' -FileSystemName 'container1' -AccessKey $key | 
    Where-Object {
        $_.isDirectory
    } |
    ForEach-Object {
        Push-AzDls2ItemAccessControl -StorageAccountName 'azdls172' -FileSystemName 'container1' -AccessKey $key -Directory $_.Name -Recurse
    }
```

## Key concepts

The [Azure Data Lake Store REST API](https://docs.microsoft.com/en-us/rest/api/storageservices/data-lake-storage-gen2) provides an interface to administrate Azure Data Lake Storage Gen2. This sample PowerShell module demonstrates how the API can be used to recursively act on a file system instance.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
