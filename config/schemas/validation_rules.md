# SafeOps Configuration Validation Rules

## Overview
This document defines validation rules for SafeOps configuration files.

## General Rules

### File Format
- **TOML**: All template files must use TOML format
- **YAML**: Example configurations use YAML format
- **JSON**: Schema definitions use JSON format

validation_rules.json** contains JSON Schema definitions for validation

### Required Fields
All configuration files must include:
- `name`: Unique identifier
- `version`: Semantic version (e.g., "2.0.0")
- `enabled`: Boolean flag

## Component-Specific Rules

### Network Configuration
```
- IP addresses must be valid IPv4 or IPv6
- CIDR notation must be valid (e.g., 192.168.1.0/24)
- Port numbers: 1-65535
- VLAN IDs: 1-4094
```

### Firewall Rules
```
- Priority: 1-9999 (lower = higher priority)
- Action: ALLOW, DENY, DROP, REJECT
- Direction: INBOUND, OUTBOUND, BOTH
- Protocol: TCP, UDP, ICMP, ALL
```

### TLS/SSL
```
- Minimum TLS version: 1.2 recommended
- Certificate files must exist and be readable
- Private keys must have restrictive permissions (0600)
```

### Authentication
```
- Password minimum length: 12 characters
- Session timeout: 15-1440 minutes
- Max login attempts: 3-10
- Lockout duration: 5-120 minutes
```

### Logging
```
- Log level: DEBUG, INFO, WARN, ERROR
- Max log size: 100-10000 MB
- Retention: 7-365 days
```

## Validation Process

### 1. Syntax Validation
```powershell
# TOML validation
.\config_validator.ps1 templates\*.toml

# YAML validation
.\config_validator.ps1 examples\*.yaml
```

### 2. Schema Validation
```powershell
# Validate against JSON schema
.\config_validator.ps1 -schema schemas\config_schema.json
```

### 3. Logical Validation
- Ensure referenced files exist
- Check for circular dependencies
- Validate IP ranges don't overlap
- Ensure firewall rules don't conflict

## Common Errors

### Error: Invalid IP Address
```
Fix: Ensure IP addresses are in correct format
Example: "192.168.1.1" not "192.168.1.256"
```

### Error: Port Out of Range
```
Fix: Use ports between 1-65535
Avoid: Well-known ports (1-1023) unless necessary
```

### Error: Missing Required Field
```
Fix: Add all required fields as specified in schema
Check: config_schema.json for requirements
```

### Error: Invalid CIDR Notation
```
Fix: Use valid subnet masks
Example: 192.168.1.0/24 not 192.168.1.0/33
```

## Best Practices

### Security
1. Never commit passwords or API keys
2. Use environment variables for secrets
3. Enable TLS/SSL for all services
4. Implement least privilege access
5. Regular security audits

### Performance
1. Limit log verbosity in production
2. Set appropriate timeouts
3. Configure resource limits
4. Enable caching where applicable

### Maintainability
1. Use descriptive names
2. Add comments for complex rules
3. Version control all configs
4. Document custom configurations

## Testing Configurations

### Before Deployment
```powershell
# 1. Validate syntax
.\config_validator.ps1

# 2. Test in staging
Copy-Item config\templates\*.toml -Destination staging\

# 3. Verify services start
Start-Service SafeOps*

# 4. Check logs
Get-Content C:\SafeOps\logs\*.log -Tail 50
```

### After Changes
```powershell
# 1. Backup current config
Copy-Item C:\SafeOps\config -Destination C:\SafeOps\backups\

# 2. Apply new config
Copy-Item config\*.toml -Destination C:\SafeOps\config\

# 3. Reload services
Restart-Service SafeOps*

# 4. Verify functionality
Test-NetConnection -ComputerName localhost -Port 8443
```

## Troubleshooting

### Config Not Loading
1. Check file permissions
2. Validate syntax
3. Review logs for errors
4. Ensure all dependencies are installed

### Service Won't Start
1. Verify config paths
2. Check for typos
3. Ensure ports aren't in use
4. Review system logs

### Performance Issues
1. Reduce log verbosity
2. Increase resource limits
3. Optimize firewall rules
4. Enable caching

## Support

For validation issues:
1. Run `.\config_validator.ps1 -Help`
2. Check documentation: `docs/configuration.md`
3. Review examples in `config/examples/`
4. Create GitHub issue with `[config]` tag

## References

- TOML Specification: https://toml.io/
- YAML Specification: https://yaml.org/
- JSON Schema: https://json-schema.org/
- SafeOps Documentation: ../docs/README.md
