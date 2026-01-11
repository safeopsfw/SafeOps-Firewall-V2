# SafeOps Development Logs

This directory is for storing development and testing logs.

## Purpose

- Store service logs during development and testing
- Capture debugging information for troubleshooting
- Keep build and test output for analysis

## Important Notes

⚠️ **Development Only**: This directory is for local development logs only.

⚠️ **Not for Production**: Production logs should be stored in:
- Windows: `C:\ProgramData\SafeOps\logs\`
- As configured in service TOML files

⚠️ **Git Ignored**: Log files (*.log) are ignored by git to keep repository clean.

## Log File Naming Convention

- `{service_name}_{date}.log` - Daily rotating logs
- `{service_name}_error.log` - Error-only logs
- `{service_name}_debug.log` - Debug-level logs
- `build_{timestamp}.log` - Build logs
- `test_{timestamp}.log` - Test logs

---

*Last Updated: 2024-12-13*
