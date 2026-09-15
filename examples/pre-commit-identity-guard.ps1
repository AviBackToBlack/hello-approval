#requires -Version 5.1
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Get-OneLocalConfigValue {
    param([string]$Key)
    $values = @(git config --local --get-all $Key 2>$null)
    if ($LASTEXITCODE -ne 0 -or $values.Count -ne 1 -or [string]::IsNullOrWhiteSpace([string]$values[0])) {
        throw "Repo-local '$Key' must be configured exactly once."
    }
    return [string]$values[0]
}

function Parse-GitIdent {
    param([string]$Value, [string]$Kind)
    if ($Value -notmatch '^(?<name>.+) <(?<email>[^<>]+)> \d+ [+-]\d{4}$') {
        throw "Could not parse $Kind identity returned by git var: $Value"
    }
    return [pscustomobject]@{ name = $Matches.name; email = $Matches.email }
}

try {
    $expectedName = Get-OneLocalConfigValue -Key 'hello-approval.expectedName'
    $expectedEmail = Get-OneLocalConfigValue -Key 'hello-approval.expectedEmail'
    $author = Parse-GitIdent -Value ([string](git var GIT_AUTHOR_IDENT)) -Kind 'author'
    if ($LASTEXITCODE -ne 0) { throw 'git var GIT_AUTHOR_IDENT failed.' }
    $committer = Parse-GitIdent -Value ([string](git var GIT_COMMITTER_IDENT)) -Kind 'committer'
    if ($LASTEXITCODE -ne 0) { throw 'git var GIT_COMMITTER_IDENT failed.' }

    foreach ($pair in @(@('author', $author), @('committer', $committer))) {
        if ($pair[1].name -cne $expectedName -or $pair[1].email -cne $expectedEmail) {
            throw "$($pair[0]) identity '$($pair[1].name) <$($pair[1].email)>' does not match expected '$expectedName <$expectedEmail>'."
        }
    }
    exit 0
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}
