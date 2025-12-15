# SafeOps GitHub Repository Setup Script
# This script helps you create and push to a new private GitHub repository

Write-Host "🚀 SafeOps GitHub Repository Setup" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan
Write-Host ""

# Configuration
$RepoName = "SafeOps-FW"
$RepoDescription = "SafeOps v2.0 - Enterprise-grade Windows Firewall with Advanced Threat Intelligence"
$RepoVisibility = "private"

Write-Host "Repository Configuration:" -ForegroundColor Yellow
Write-Host "  Name: $RepoName" -ForegroundColor White
Write-Host "  Description: $RepoDescription" -ForegroundColor White
Write-Host "  Visibility: $RepoVisibility" -ForegroundColor White
Write-Host ""

# Check if GitHub CLI is installed
Write-Host "Checking for GitHub CLI (gh)..." -ForegroundColor Yellow
$ghInstalled = Get-Command gh -ErrorAction SilentlyContinue

if (-not $ghInstalled) {
    Write-Host "❌ GitHub CLI (gh) is not installed." -ForegroundColor Red
    Write-Host ""
    Write-Host "Please install GitHub CLI:" -ForegroundColor Yellow
    Write-Host "  winget install GitHub.cli" -ForegroundColor White
    Write-Host ""
    Write-Host "After installation, authenticate with:" -ForegroundColor Yellow
    Write-Host "  gh auth login" -ForegroundColor White
    Write-Host ""
    Write-Host "Alternative: Manual Setup" -ForegroundColor Yellow
    Write-Host "1. Go to https://github.com/new" -ForegroundColor White
    Write-Host "2. Create a new private repository named: $RepoName" -ForegroundColor White
    Write-Host "3. Do NOT initialize with README, .gitignore, or license" -ForegroundColor White
    Write-Host "4. Run these commands:" -ForegroundColor White
    Write-Host "   git remote add origin https://github.com/YOUR_USERNAME/$RepoName.git" -ForegroundColor Cyan
    Write-Host "   git branch -M main" -ForegroundColor Cyan
    Write-Host "   git push -u origin main --tags" -ForegroundColor Cyan
    exit
}

Write-Host "✅ GitHub CLI found" -ForegroundColor Green
Write-Host ""

# Check if authenticated
Write-Host "Checking GitHub authentication..." -ForegroundColor Yellow
$authStatus = gh auth status 2>&1

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Not authenticated with GitHub" -ForegroundColor Red
    Write-Host ""
    Write-Host "Please authenticate with:" -ForegroundColor Yellow
    Write-Host "  gh auth login" -ForegroundColor White
    exit
}

Write-Host "✅ Authenticated with GitHub" -ForegroundColor Green
Write-Host ""

# Prompt for confirmation
Write-Host "This will:" -ForegroundColor Yellow
Write-Host "  1. Create a new private GitHub repository: $RepoName" -ForegroundColor White
Write-Host "  2. Add it as remote origin" -ForegroundColor White
Write-Host "  3. Rename branch to 'main'" -ForegroundColor White
Write-Host "  4. Push all commits and tags" -ForegroundColor White
Write-Host ""

$confirmation = Read-Host "Do you want to proceed? (yes/no)"

if ($confirmation -ne "yes") {
    Write-Host "❌ Operation cancelled" -ForegroundColor Red
    exit
}

# Create GitHub repository
Write-Host ""
Write-Host "Creating GitHub repository..." -ForegroundColor Yellow

try {
    gh repo create $RepoName --description $RepoDescription --$RepoVisibility --source=. --remote=origin --push
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Repository created and pushed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Repository URL:" -ForegroundColor Yellow
        $repoUrl = gh repo view --json url -q .url
        Write-Host "  $repoUrl" -ForegroundColor Cyan
        Write-Host ""
        
        # Rename branch to main if needed
        $currentBranch = git branch --show-current
        if ($currentBranch -ne "main") {
            Write-Host "Renaming branch to 'main'..." -ForegroundColor Yellow
            git branch -M main
            git push -u origin main --tags
            Write-Host "✅ Branch renamed to 'main'" -ForegroundColor Green
        }
        
        Write-Host ""
        Write-Host "✅ Setup complete!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Visit your repository: $repoUrl" -ForegroundColor White
        Write-Host "  2. Add collaborators if needed" -ForegroundColor White
        Write-Host "  3. Configure branch protection rules" -ForegroundColor White
        Write-Host "  4. Set up GitHub Actions (optional)" -ForegroundColor White
    }
    else {
        throw "GitHub repository creation failed"
    }
}
catch {
    Write-Host "❌ Error: $_" -ForegroundColor Red
    Write-Host ""
    Write-Host "Manual Setup Instructions:" -ForegroundColor Yellow
    Write-Host "1. Go to https://github.com/new" -ForegroundColor White
    Write-Host "2. Create a new private repository named: $RepoName" -ForegroundColor White
    Write-Host "3. Do NOT initialize with README, .gitignore, or license" -ForegroundColor White
    Write-Host "4. Run these commands:" -ForegroundColor White
    Write-Host "   git remote add origin https://github.com/YOUR_USERNAME/$RepoName.git" -ForegroundColor Cyan
    Write-Host "   git branch -M main" -ForegroundColor Cyan
    Write-Host "   git push -u origin main --tags" -ForegroundColor Cyan
}
