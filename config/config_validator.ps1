# SafeOps Configuration Validator
# Purpose: Validate configuration files, check dependencies, detect errors
# Version: 2.0

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ConfigPath = "D:\SafeOpsFV2\config",
    
    [Parameter(Mandatory = $false)]
    [string]$ConfigFile = "",
    
    [Parameter(Mandatory = $false)]
    [switch]$Full,
    
    [Parameter(Mandatory = $false)]
    [switch]$Quiet,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportReport,
    
    [Parameter(Mandatory = $false)]
    [string]$ReportPath = ".\validation_report.json"
)

# ==============================================================================
# GLOBAL VARIABLES
# ==============================================================================

$script:ErrorCount = 0
$script:WarningCount = 0
$script:ValidationResults = @()

# ==============================================================================
# COLOR OUTPUT FUNCTIONS
# ==============================================================================

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Type = "INFO"
    )
    
    if ($Quiet) { return }
    
    switch ($Type) {
        "ERROR" {
            Write-Host "[ERROR] " -ForegroundColor Red -NoNewline
            Write-Host $Message
            $script:ErrorCount++
        }
        "WARNING" {
            Write-Host "[WARN]  " -ForegroundColor Yellow -NoNewline
            Write-Host $Message
            $script:WarningCount++
        }
        "SUCCESS" {
            Write-Host "[OK]    " -ForegroundColor Green -NoNewline
            Write-Host $Message
        }
        "INFO" {
            Write-Host "[INFO]  " -ForegroundColor Cyan -NoNewline
            Write-Host $Message
        }
        default {
            Write-Host $Message
        }
    }
}

function Write-ValidationResult {
    param(
        [string]$File,
        [string]$Check,
        [bool]$Passed,
        [string]$Message = "",
        [string]$Suggestion = ""
    )
    
    $result = @{
        File       = $File
        Check      = $Check
        Passed     = $Passed
        Message    = $Message
        Suggestion = $Suggestion
        Timestamp  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
    
    $script:ValidationResults += $result
    
    if (-not $Passed) {
        Write-ColorOutput "$File - $Check`: $Message" -Type "ERROR"
        if ($Suggestion) {
            Write-ColorOutput "  → Suggestion: $Suggestion" -Type "INFO"
        }
    }
}

# ==============================================================================
# TOML PARSING FUNCTIONS
# ==============================================================================

function Test-TomlSyntax {
    param(
        [string]$FilePath
    )
    
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction Stop
        
        # Basic TOML syntax checks
        $lineNumber = 0
        foreach ($line in ($content -split "`n")) {
            $lineNumber++
            $line = $line.Trim()
            
            # Skip comments and empty lines
            if ($line -match "^\s*#" -or $line -eq "") { continue }
            
            # Check for unclosed quotes
            $quoteCount = ([regex]::Matches($line, '"')).Count
            if ($quoteCount % 2 -ne 0) {
                Write-ValidationResult -File $FilePath -Check "TOML Syntax" -Passed $false `
                    -Message "Line $lineNumber`: Unclosed quote" `
                    -Suggestion "Ensure all strings are properly quoted"
                return $false
            }
            
            # Check for invalid key-value pairs
            if ($line -match "^[a-zA-Z0-9_-]+\s*=\s*$") {
                Write-ValidationResult -File $FilePath -Check "TOML Syntax" -Passed $false `
                    -Message "Line $lineNumber`: Key without value" `
                    -Suggestion "Provide a value for the key"
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-ValidationResult -File $FilePath -Check "TOML Syntax" -Passed $false `
            -Message "Failed to read file: $_" `
            -Suggestion "Check file permissions and encoding"
        return $false
    }
}

function Get-TomlValue {
    param(
        [string]$FilePath,
        [string]$Key
    )
    
    try {
        $content = Get-Content $FilePath -Raw
        if ($content -match "$Key\s*=\s*`"([^`"]+)`"") {
            return $Matches[1]
        }
        elseif ($content -match "$Key\s*=\s*(\S+)") {
            return $Matches[1]
        }
    }
    catch {
        return $null
    }
    
    return $null
}

# ==============================================================================
# YAML PARSING FUNCTIONS
# ==============================================================================

function Test-YamlSyntax {
    param(
        [string]$FilePath
    )
    
    try {
        $content = Get-Content $FilePath -Raw -ErrorAction Stop
        
        # Basic YAML syntax checks
        $lineNumber = 0
        $indentStack = @(0)
        
        foreach ($line in ($content -split "`n")) {
            $lineNumber++
            
            # Skip comments and empty lines
            if ($line -match "^\s*#" -or $line -match "^\s*$") { continue }
            
            # Check for tabs (YAML forbids tabs)
            if ($line -match "`t") {
                Write-ValidationResult -File $FilePath -Check "YAML Syntax" -Passed $false `
                    -Message "Line $lineNumber`: Tabs not allowed in YAML, use spaces" `
                    -Suggestion "Replace tabs with spaces (2 or 4 spaces per indent level)"
                return $false
            }
            
            # Check for unclosed quotes
            $singleQuotes = ([regex]::Matches($line, "(?<!\\)'")).Count
            $doubleQuotes = ([regex]::Matches($line, '(?<!\\)"')).Count
            
            if ($singleQuotes % 2 -ne 0 -or $doubleQuotes % 2 -ne 0) {
                Write-ValidationResult -File $FilePath -Check "YAML Syntax" -Passed $false `
                    -Message "Line $lineNumber`: Unclosed quote" `
                    -Suggestion "Ensure all strings are properly quoted"
                return $false
            }
        }
        
        return $true
    }
    catch {
        Write-ValidationResult -File $FilePath -Check "YAML Syntax" -Passed $false `
            -Message "Failed to read file: $_" `
            -Suggestion "Check file permissions and encoding"
        return $false
    }
}

# ==============================================================================
# FILE VALIDATION FUNCTIONS
# ==============================================================================

function Test-FilePermissions {
    param(
        [string]$FilePath
    )
    
    try {
        $acl = Get-Acl $FilePath -ErrorAction Stop
        
        # Check if file is readable
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        $hasRead = $false
        
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -eq $currentUser -and 
                $access.FileSystemRights -match "Read") {
                $hasRead = $true
                break
            }
        }
        
        if (-not $hasRead) {
            Write-ValidationResult -File $FilePath -Check "File Permissions" -Passed $false `
                -Message "File not readable by current user" `
                -Suggestion "Grant read permissions to $currentUser"
            return $false
        }
        
        # Warning if file is world-writable
        foreach ($access in $acl.Access) {
            if ($access.IdentityReference -eq "Everyone" -and 
                $access.FileSystemRights -match "Write") {
                Write-ColorOutput "$FilePath - World-writable file detected (security risk)" -Type "WARNING"
            }
        }
        
        return $true
    }
    catch {
        Write-ValidationResult -File $FilePath -Check "File Permissions" -Passed $false `
            -Message "Failed to check permissions: $_"
        return $false
    }
}

function Test-RequiredFields {
    param(
        [string]$FilePath,
        [string[]]$RequiredFields
    )
    
    $content = Get-Content $FilePath -Raw
    $allFieldsPresent = $true
    
    foreach ($field in $RequiredFields) {
        if ($content -notmatch "$field\s*=") {
            Write-ValidationResult -File $FilePath -Check "Required Fields" -Passed $false `
                -Message "Missing required field: $field" `
                -Suggestion "Add '$field = <value>' to the configuration"
            $allFieldsPresent = $false
        }
    }
    
    return $allFieldsPresent
}

# ==============================================================================
# NETWORK VALIDATION FUNCTIONS
# ==============================================================================

function Test-IPAddress {
    param(
        [string]$IP
    )
    
    try {
        [System.Net.IPAddress]::Parse($IP) | Out-Null
        return $true
    }
    catch {
        return $false
    }
}

function Test-CIDR {
    param(
        [string]$CIDR
    )
    
    if ($CIDR -match "^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/(\d{1,2})$") {
        $ip = $Matches[1]
        $prefix = [int]$Matches[2]
        
        return (Test-IPAddress $ip) -and ($prefix -ge 0 -and $prefix -le 32)
    }
    
    return $false
}

function Test-IPOverlap {
    param(
        [string]$FilePath,
        [string[]]$Networks
    )
    
    # Simple overlap detection (would need proper CIDR library for production)
    $networkMap = @{}
    
    foreach ($network in $Networks) {
        if ($network -match "^(\d{1,3}\.\d{1,3}\.\d{1,3})\.") {
            $subnet = $Matches[1]
            
            if ($networkMap.ContainsKey($subnet)) {
                Write-ValidationResult -File $FilePath -Check "IP Overlap" -Passed $false `
                    -Message "Potential IP overlap detected: $network and $($networkMap[$subnet])" `
                    -Suggestion "Review network topology for overlapping subnets"
                return $false
            }
            
            $networkMap[$subnet] = $network
        }
    }
    
    return $true
}

function Test-PortConflicts {
    param(
        [string]$FilePath,
        [hashtable]$PortMap
    )
    
    $conflicts = @{}
    
    foreach ($service in $PortMap.Keys) {
        $port = $PortMap[$service]
        
        if ($conflicts.ContainsKey($port)) {
            Write-ValidationResult -File $FilePath -Check "Port Conflicts" -Passed $false `
                -Message "Port $port conflict: $service and $($conflicts[$port])" `
                -Suggestion "Assign unique ports to each service"
            return $false
        }
        
        $conflicts[$port] = $service
    }
    
    return $true
}

# ==============================================================================
# DEPENDENCY VALIDATION FUNCTIONS
# ==============================================================================

function Test-FileReferences {
    param(
        [string]$FilePath
    )
    
    $content = Get-Content $FilePath -Raw
    $allReferencesExist = $true
    
    # Find file paths in configuration
    $pathMatches = [regex]::Matches($content, '(?:path|file|directory)\s*=\s*"([^"]+)"')
    
    foreach ($match in $pathMatches) {
        $referencedPath = $match.Groups[1].Value
        
        # Expand environment variables
        $referencedPath = [System.Environment]::ExpandEnvironmentVariables($referencedPath)
        
        # Convert to absolute path if relative
        if (-not [System.IO.Path]::IsPathRooted($referencedPath)) {
            $referencedPath = Join-Path $ConfigPath $referencedPath
        }
        
        if (-not (Test-Path $referencedPath)) {
            Write-ValidationResult -File $FilePath -Check "File References" -Passed $false `
                -Message "Referenced path does not exist: $referencedPath" `
                -Suggestion "Create the missing file/directory or update the path"
            $allReferencesExist = $false
        }
    }
    
    return $allReferencesExist
}

function Test-ServiceDependencies {
    param(
        [string]$ConfigPath
    )
    
    # Define service dependencies
    $dependencies = @{
        "firewall_engine" = @("kernel_driver", "threat_intel")
        "ids_ips"         = @("threat_intel", "firewall_engine")
        "dns_server"      = @("threat_intel")
        "tls_proxy"       = @("certificate_manager")
        "orchestrator"    = @("firewall_engine", "threat_intel", "dns_server")
    }
    
    $allDependenciesMet = $true
    
    foreach ($service in $dependencies.Keys) {
        $configFile = Join-Path $ConfigPath "templates\$service.toml"
        
        if (Test-Path $configFile) {
            $enabled = Get-TomlValue -FilePath $configFile -Key "enabled"
            
            if ($enabled -eq "true") {
                foreach ($dependency in $dependencies[$service]) {
                    $depConfigFile = Join-Path $ConfigPath "templates\$dependency.toml"
                    
                    if (-not (Test-Path $depConfigFile)) {
                        Write-ValidationResult -File $configFile -Check "Service Dependencies" -Passed $false `
                            -Message "$service requires $dependency but config not found" `
                            -Suggestion "Create configuration for $dependency or disable $service"
                        $allDependenciesMet = $false
                    }
                    else {
                        $depEnabled = Get-TomlValue -FilePath $depConfigFile -Key "enabled"
                        if ($depEnabled -ne "true") {
                            Write-ValidationResult -File $configFile -Check "Service Dependencies" -Passed $false `
                                -Message "$service requires $dependency but it is disabled" `
                                -Suggestion "Enable $dependency or disable $service"
                            $allDependenciesMet = $false
                        }
                    }
                }
            }
        }
    }
    
    return $allDependenciesMet
}

function Test-CircularDependencies {
    param(
        [hashtable]$DependencyGraph
    )
    
    function Find-Cycle {
        param(
            [string]$Node,
            [hashtable]$Graph,
            [System.Collections.Generic.HashSet[string]]$Visited,
            [System.Collections.Generic.HashSet[string]]$RecStack
        )
        
        $Visited.Add($Node) | Out-Null
        $RecStack.Add($Node) | Out-Null
        
        if ($Graph.ContainsKey($Node)) {
            foreach ($neighbor in $Graph[$Node]) {
                if (-not $Visited.Contains($neighbor)) {
                    if (Find-Cycle -Node $neighbor -Graph $Graph -Visited $Visited -RecStack $RecStack) {
                        return $true
                    }
                }
                elseif ($RecStack.Contains($neighbor)) {
                    return $true
                }
            }
        }
        
        $RecStack.Remove($Node) | Out-Null
        return $false
    }
    
    $visited = New-Object 'System.Collections.Generic.HashSet[string]'
    $recStack = New-Object 'System.Collections.Generic.HashSet[string]'
    
    foreach ($node in $DependencyGraph.Keys) {
        if (-not $visited.Contains($node)) {
            if (Find-Cycle -Node $node -Graph $DependencyGraph -Visited $visited -RecStack $recStack) {
                Write-ColorOutput "Circular dependency detected in service dependencies" -Type "ERROR"
                return $false
            }
        }
    }
    
    return $true
}

# ==============================================================================
# ENVIRONMENT VARIABLE VALIDATION
# ==============================================================================

function Test-EnvironmentVariables {
    param(
        [string]$FilePath
    )
    
    $content = Get-Content $FilePath -Raw
    $allVarsExist = $true
    
    # Find environment variable references
    $envVarMatches = [regex]::Matches($content, '\$\{([A-Z_]+)\}')
    
    foreach ($match in $envVarMatches) {
        $varName = $match.Groups[1].Value
        
        if (-not (Test-Path "env:$varName")) {
            Write-ValidationResult -File $FilePath -Check "Environment Variables" -Passed $false `
                -Message "Environment variable not set: $varName" `
                -Suggestion "Set environment variable: `$env:$varName = '<value>'"
            $allVarsExist = $false
        }
    }
    
    return $allVarsExist
}

# ==============================================================================
# SPECIFIC CONFIG FILE VALIDATORS
# ==============================================================================

function Test-FirewallConfig {
    param(
        [string]$FilePath
    )
    
    Write-ColorOutput "Validating firewall configuration..." -Type "INFO"
    
    $valid = $true
    
    # Test syntax
    $valid = $valid -and (Test-TomlSyntax $FilePath)
    
    # Test required fields
    $requiredFields = @("enabled", "default_action", "log_level")
    $valid = $valid -and (Test-RequiredFields $FilePath $requiredFields)
    
    # Test file references
    $valid = $valid -and (Test-FileReferences $FilePath)
    
    if ($valid) {
        Write-ColorOutput "Firewall configuration is valid" -Type "SUCCESS"
    }
    
    return $valid
}

function Test-NetworkTopology {
    param(
        [string]$FilePath
    )
    
    Write-ColorOutput "Validating network topology..." -Type "INFO"
    
    $valid = $true
    
    # Test syntax
    $valid = $valid -and (Test-YamlSyntax $FilePath)
    
    # Parse networks and test for overlaps
    $content = Get-Content $FilePath -Raw
    $networkMatches = [regex]::Matches($content, 'network:\s*"([^"]+)"')
    
    $networks = @()
    foreach ($match in $networkMatches) {
        $networks += $match.Groups[1].Value
        
        # Validate CIDR format
        if (-not (Test-CIDR $match.Groups[1].Value)) {
            Write-ValidationResult -File $FilePath -Check "Network Format" -Passed $false `
                -Message "Invalid CIDR format: $($match.Groups[1].Value)" `
                -Suggestion "Use format: xxx.xxx.xxx.xxx/xx"
            $valid = $false
        }
    }
    
    # Test for overlaps
    $valid = $valid -and (Test-IPOverlap $FilePath $networks)
    
    if ($valid) {
        Write-ColorOutput "Network topology is valid" -Type "SUCCESS"
    }
    
    return $valid
}

function Test-SuricataVars {
    param(
        [string]$FilePath
    )
    
    Write-ColorOutput "Validating Suricata variables..." -Type "INFO"
    
    $valid = $true
    
    # Test syntax
    $valid = $valid -and (Test-YamlSyntax $FilePath)
    
    # Check for required variables
    $content = Get-Content $FilePath -Raw
    $requiredVars = @("HOME_NET", "EXTERNAL_NET", "HTTP_PORTS", "DNS_SERVERS")
    
    foreach ($var in $requiredVars) {
        if ($content -notmatch "$var\s*:") {
            Write-ValidationResult -File $FilePath -Check "Required Variables" -Passed $false `
                -Message "Missing required variable: $var" `
                -Suggestion "Add $var definition to vars section"
            $valid = $false
        }
    }
    
    if ($valid) {
        Write-ColorOutput "Suricata variables are valid" -Type "SUCCESS"
    }
    
    return $valid
}

# ==============================================================================
# MAIN VALIDATION LOGIC
# ==============================================================================

function Invoke-Validation {
    param(
        [string]$Path
    )
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  SafeOps Configuration Validator v2.0" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    $startTime = Get-Date
    
    if ($ConfigFile) {
        # Validate single file
        Write-ColorOutput "Validating single file: $ConfigFile" -Type "INFO"
        
        if (-not (Test-Path $ConfigFile)) {
            Write-ColorOutput "File not found: $ConfigFile" -Type "ERROR"
            return $false
        }
        
        Test-FilePermissions $ConfigFile
        
        $extension = [System.IO.Path]::GetExtension($ConfigFile)
        switch ($extension) {
            ".toml" { Test-TomlSyntax $ConfigFile }
            ".yaml" { Test-YamlSyntax $ConfigFile }
            ".yml" { Test-YamlSyntax $ConfigFile }
            default { Write-ColorOutput "Unknown file type: $extension" -Type "WARNING" }
        }
    }
    else {
        # Validate configuration directory
        Write-ColorOutput "Validating configuration directory: $Path" -Type "INFO"
        Write-Host ""
        
        if (-not (Test-Path $Path)) {
            Write-ColorOutput "Configuration path not found: $Path" -Type "ERROR"
            return $false
        }
        
        # Test network topology
        $topologyFile = Join-Path $Path "network_topology.yaml"
        if (Test-Path $topologyFile) {
            Test-NetworkTopology $topologyFile
        }
        
        # Test Suricata variables
        $suricataVarsFile = Join-Path $Path "ids_ips\suricata_vars.yaml"
        if (Test-Path $suricataVarsFile) {
            Test-SuricataVars $suricataVarsFile
        }
        
        # Test all TOML files in templates directory
        $templatesPath = Join-Path $Path "templates"
        if (Test-Path $templatesPath) {
            Write-Host ""
            Write-ColorOutput "Validating template configurations..." -Type "INFO"
            
            Get-ChildItem -Path $templatesPath -Filter "*.toml" | ForEach-Object {
                Test-TomlSyntax $_.FullName
                Test-FilePermissions $_.FullName
                Test-EnvironmentVariables $_.FullName
            }
        }
        
        # Test service dependencies
        if ($Full) {
            Write-Host ""
            Test-ServiceDependencies $Path
        }
    }
    
    # Summary
    $endTime = Get-Date
    $duration = ($endTime - $startTime).TotalSeconds
    
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Validation Summary" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:ErrorCount -eq 0 -and $script:WarningCount -eq 0) {
        Write-Host "  ✓ All validations passed!" -ForegroundColor Green
    }
    else {
        Write-Host "  Errors:   " -NoNewline
        Write-Host $script:ErrorCount -ForegroundColor Red
        
        Write-Host "  Warnings: " -NoNewline
        Write-Host $script:WarningCount -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "  Duration: $([math]::Round($duration, 2)) seconds" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host ""
    
    # Export report if requested
    if ($ExportReport) {
        $report = @{
            Timestamp    = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Duration     = $duration
            ErrorCount   = $script:ErrorCount
            WarningCount = $script:WarningCount
            Results      = $script:ValidationResults
        }
        
        $report | ConvertTo-Json -Depth 10 | Out-File $ReportPath
        Write-ColorOutput "Report exported to: $ReportPath" -Type "SUCCESS"
    }
    
    return ($script:ErrorCount -eq 0)
}

# ==============================================================================
# ENTRY POINT
# ==============================================================================

try {
    $validationPassed = Invoke-Validation -Path $ConfigPath
    
    if ($validationPassed) {
        exit 0
    }
    else {
        exit 1
    }
}
catch {
    Write-Host ""
    Write-Host "FATAL ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor Red
    exit 2
}
