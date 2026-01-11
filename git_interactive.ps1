# SafeOps Git Automation - Enhanced Version
# Full-featured Git workflow with version control

param(
    [string]$ProjectPath = ""
)

$ErrorActionPreference = "Stop"

# ---------- Helper Functions ----------
function Write-Success {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Yellow
}

# ---------- Main Menu ----------
Write-Host ""
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host " SafeOps Git Automation - Interactive Mode" -ForegroundColor Cyan
Write-Host "====================================================" -ForegroundColor Cyan
Write-Host ""

# Check if Git is installed
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Git is not installed!" -ForegroundColor Red
    Write-Host "Please install Git first using:" -ForegroundColor Yellow
    Write-Host "  .\safeops_installer.ps1" -ForegroundColor Cyan
    exit 1
}

# Check if GitHub CLI is installed
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Warning-Custom "GitHub CLI (gh) is not installed - some features will be limited."
    Write-Host ""
}

# Ask what action to perform
Write-Host "What would you like to do?" -ForegroundColor Yellow
Write-Host "  1) Initialize repository (first time setup)" -ForegroundColor Green
Write-Host "  2) Quick sync (fast commit and push)" -ForegroundColor Green
Write-Host "  3) Sync changes (advanced - with version control)" -ForegroundColor Green
Write-Host "  4) Create version tag" -ForegroundColor Green
Write-Host "  5) Delete version tag" -ForegroundColor Green
Write-Host "  6) Clone existing repository" -ForegroundColor Green
Write-Host "  7) Exit" -ForegroundColor Gray
Write-Host ""

$actionChoice = Read-Host "Enter choice (1-7)"

# Get project path if not provided
if ($ProjectPath -eq "") {
    Write-Host ""
    Write-Host "===== Project Path Selection =====" -ForegroundColor Cyan
    Write-Host "  1) Use current directory: $((Get-Location).Path)"
    Write-Host "  2) Enter a different path"
    Write-Host ""
    
    $pathChoice = Read-Host "Enter choice (1/2)"
    
    if ($pathChoice -eq "1") {
        $ProjectPath = (Get-Location).Path
    }
    else {
        $ProjectPath = Read-Host "Enter full path to project directory"
        if (-not (Test-Path $ProjectPath)) {
            $create = Read-Host "Directory doesn't exist. Create it? (Y/n)"
            if ($create -eq "" -or $create -eq "Y" -or $create -eq "y") {
                New-Item -ItemType Directory -Path $ProjectPath -Force | Out-Null
                Write-Success "Created directory: $ProjectPath"
            }
            else {
                Write-Host "Cancelled." -ForegroundColor Red
                exit 1
            }
        }
    }
}

switch ($actionChoice) {
    "1" {
        # Initialize Repository
        Write-Host ""
        Write-Host "===== Initialize Repository =====" -ForegroundColor Cyan
        
        Push-Location $ProjectPath
        
        # Check if already a git repo
        if (Test-Path ".git") {
            Write-Warning-Custom "This directory is already a Git repository."
            $continue = Read-Host "Continue with existing repo? (y/N)"
            if ($continue -ne "y" -and $continue -ne "Y") {
                Write-Host ""
                $createNew = Read-Host "Would you like to create a NEW repository instead? (Y/n)"
                if ($createNew -eq "" -or $createNew -eq "Y" -or $createNew -eq "y") {
                    Write-Info "Removing existing .git directory..."
                    Remove-Item -Path ".git" -Recurse -Force
                    Write-Success "Removed existing Git repository. Starting fresh..."
                }
                else {
                    Write-Host "Cancelled." -ForegroundColor Gray
                    Pop-Location
                    exit 0
                }
            }
        }
        
        # Initialize git
        if (-not (Test-Path ".git")) {
            git init
            Write-Success "Initialized Git repository"
        }
        
        # Ask for repository details
        Write-Host ""
        $repoName = Read-Host "Enter repository name"
        
        Write-Host ""
        $private = Read-Host "Make it private? (Y/n)"
        if ($private -eq "" -or $private -eq "Y" -or $private -eq "y") {
            $privateFlag = "--private"
            $privacyText = "Private"
        }
        else {
            $privateFlag = "--public"
            $privacyText = "Public"
        }
        
        Write-Host ""
        Write-Host "===== Summary =====" -ForegroundColor Yellow
        Write-Host "Repository: $repoName"
        Write-Host "Privacy: $privacyText"
        Write-Host "Path: $ProjectPath"
        Write-Host ""
        
        $proceed = Read-Host "Proceed? (Y/n/c to change name)"
        
        if ($proceed -eq "c" -or $proceed -eq "C") {
            Write-Host ""
            $repoName = Read-Host "Enter new repository name"
            
            Write-Host ""
            Write-Host "===== Updated Summary =====" -ForegroundColor Yellow
            Write-Host "Repository: $repoName"
            Write-Host "Privacy: $privacyText"
            Write-Host "Path: $ProjectPath"
            Write-Host ""
            
            $proceed = Read-Host "Proceed now? (Y/n)"
        }
        
        if ($proceed -ne "" -and $proceed -ne "Y" -and $proceed -ne "y") {
            Write-Host "Cancelled."
            Pop-Location
            exit 0
        }
        
        # Add all files and commit
        git add -A
        $commitMsg = "Initial commit"
        git commit -m $commitMsg
        git branch -M main
        
        # Create repository on GitHub
        if (Get-Command gh -ErrorAction SilentlyContinue) {
            Write-Info "Creating repository on GitHub..."
            gh repo create $repoName $privateFlag --source=. --remote=origin --push
            Write-Success "Repository created and pushed!"
        }
        else {
            Write-Warning-Custom "GitHub CLI not available. Please create repository manually."
            Write-Host "Then run: git remote add origin <repo-url>"
            Write-Host "And: git push -u origin main"
        }
        
        Pop-Location
        Write-Success "`nRepository initialization complete!"
    }
    
    "2" {
        # Quick Sync (Fast Daily Backup)
        Write-Host ""
        Write-Host "===== Quick Sync =====" -ForegroundColor Cyan
        
        Push-Location $ProjectPath
        
        if (-not (Test-Path ".git")) {
            Write-Host "ERROR: Not a Git repository!" -ForegroundColor Red
            Write-Host "Run option 1 (Initialize repository) first."
            Pop-Location
            exit 1
        }
        
        Write-Info "Adding all changes (including deletions)..."
        git add -A
        
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $commitMsg = "Quick sync $timestamp"
        git commit -m $commitMsg -ErrorAction SilentlyContinue
        
        Write-Info "Pulling latest changes..."
        git pull --rebase origin main 2>$null
        
        Write-Info "Pushing to remote..."
        git push origin main
        
        Write-Success "Quick sync complete!"
        Pop-Location
    }
    
    "3" {
        # Sync Changes (Advanced)
        Write-Host ""
        Write-Host "===== Sync Changes (Advanced) =====" -ForegroundColor Cyan
        
        Push-Location $ProjectPath
        
        if (-not (Test-Path ".git")) {
            Write-Host "ERROR: Not a Git repository!" -ForegroundColor Red
            Write-Host "Run option 1 (Initialize repository) first."
            Pop-Location
            exit 1
        }
        
        # Ask pull or push first
        Write-Host ""
        $pullFirst = Read-Host "Pull latest changes first? (Y/n)"
        
        if ($pullFirst -ne "n" -and $pullFirst -ne "N") {
            Write-Info "Pulling latest changes..."
            git pull --rebase origin main 2>$null
        }
        
        # Show current changes
        Write-Host ""
        Write-Host "===== Current Changes =====" -ForegroundColor Yellow
        git status --short
        Write-Host ""
        
        # Add all changes (including deletions)
        Write-Info "Adding all changes (including deletions)..."
        git add -A
        
        # Ask for version tag
        Write-Host ""
        $createTag = Read-Host "Create version tag? (y/N)"
        
        if ($createTag -eq "y" -or $createTag -eq "Y") {
            $version = Read-Host "Enter version tag (e.g., v1.0.0)"
            $versionMsg = Read-Host "Enter version message (optional)"
            
            if ($versionMsg -eq "") {
                $versionMsg = "Release $version"
            }
            
            $commitMsg = "Release $version"
            git commit -m $commitMsg
            git tag -a $version -m $versionMsg
            
            Write-Success "Version tag $version created!"
        }
        else {
            $commitMsg = Read-Host "Enter commit message (or press Enter for auto)"
            if ($commitMsg -eq "") {
                $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
                $commitMsg = "Update $timestamp"
            }
            git commit -m $commitMsg -ErrorAction SilentlyContinue
        }
        
        # Push
        Write-Info "Pushing to remote..."
        git push origin main
        
        if ($createTag -eq "y" -or $createTag -eq "Y") {
            Write-Info "Pushing version tag..."
            git push origin $version
        }
        
        Write-Success "Sync complete!"
        Pop-Location
    }
    
    "4" {
        # Create Version Tag
        Write-Host ""
        Write-Host "===== Create Version Tag =====" -ForegroundColor Cyan
        
        Push-Location $ProjectPath
        
        if (-not (Test-Path ".git")) {
            Write-Host "ERROR: Not a Git repository!" -ForegroundColor Red
            Pop-Location
            exit 1
        }
        
        # Show existing tags
        Write-Host ""
        Write-Host "Existing tags:" -ForegroundColor Yellow
        git tag -l
        Write-Host ""
        
        $version = Read-Host "Enter new version tag (e.g., v1.0.0)"
        $message = Read-Host "Enter version message"
        
        if ($message -eq "") {
            $message = "Version $version"
        }
        
        git tag -a $version -m $message
        git push origin $version
        
        Write-Success "Version tag $version created and pushed!"
        Pop-Location
    }
    
    "5" {
        # Delete Version Tag
        Write-Host ""
        Write-Host "===== Delete Version Tag =====" -ForegroundColor Cyan
        
        Push-Location $ProjectPath
        
        if (-not (Test-Path ".git")) {
            Write-Host "ERROR: Not a Git repository!" -ForegroundColor Red
            Pop-Location
            exit 1
        }
        
        # Show existing tags
        Write-Host ""
        Write-Host "Existing tags:" -ForegroundColor Yellow
        git tag -l
        Write-Host ""
        
        $version = Read-Host "Enter version tag to delete"
        
        if ($version -eq "") {
            Write-Host "Cancelled."
            Pop-Location
            exit 0
        }
        
        $confirm = Read-Host "Delete $version locally and remotely? (y/N)"
        
        if ($confirm -eq "y" -or $confirm -eq "Y") {
            git tag -d $version
            git push origin :refs/tags/$version
            
            Write-Success "Version tag $version deleted!"
        }
        else {
            Write-Host "Cancelled."
        }
        
        Pop-Location
    }
    
    "6" {
        # Clone Repository
        Write-Host ""
        Write-Host "===== Clone Repository =====" -ForegroundColor Cyan
        
        if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
            Write-Host "ERROR: GitHub CLI (gh) is required for this feature!" -ForegroundColor Red
            Write-Host "Please install it using:" -ForegroundColor Yellow
            Write-Host "  .\safeops_installer.ps1" -ForegroundColor Cyan
            exit 1
        }
        
        Write-Info "Fetching your repositories..."
        $repos = gh repo list --limit 100 --json name, sshUrl | ConvertFrom-Json
        
        if ($repos.Count -eq 0) {
            Write-Host "No repositories found." -ForegroundColor Yellow
            exit 0
        }
        
        Write-Host ""
        Write-Host "Your repositories:" -ForegroundColor Yellow
        Write-Host "------------------"
        for ($i = 0; $i -lt $repos.Count; $i++) {
            Write-Host ("{0,3}) {1}" -f ($i + 1), $repos[$i].name)
        }
        Write-Host "------------------"
        Write-Host ""
        
        $pick = Read-Host "Enter number of repo to clone"
        $pickNum = 0
        if ([int]::TryParse($pick, [ref]$pickNum)) {
            if ($pickNum -ge 1 -and $pickNum -le $repos.Count) {
                $selectedRepo = $repos[$pickNum - 1]
                
                Write-Host ""
                $clonePath = Read-Host "Enter destination path (or press Enter for current directory)"
                if ($clonePath -eq "") {
                    $clonePath = Join-Path (Get-Location).Path $selectedRepo.name
                }
                
                Write-Info "Cloning $($selectedRepo.name)..."
                git clone $selectedRepo.sshUrl $clonePath
                Write-Success "Repository cloned to: $clonePath"
            }
        }
    }
    
    "7" {
        Write-Host "Exiting..." -ForegroundColor Gray
        exit 0
    }
    
    default {
        Write-Host "Invalid choice. Please run the script again." -ForegroundColor Red
        exit 1
    }
}

Write-Host ""
Write-Host "Done!" -ForegroundColor Green
Write-Host ""
