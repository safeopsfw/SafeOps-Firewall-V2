@echo off
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if '%errorlevel%' NEQ '0' (powershell -Command "Start-Process '%~f0' -Verb RunAs" & exit /b)
title SafeOps ES Setup
echo ============================================
echo   SafeOps Elasticsearch Index Templates
echo ============================================
echo.
echo Checking Elasticsearch at http://127.0.0.1:9200 ...

REM Wait for ES
:wait_es
curl -s -o nul -w "%%{http_code}" http://127.0.0.1:9200 > %TEMP%\es_status.txt 2>nul
set /p ES_STATUS=<%TEMP%\es_status.txt
if "%ES_STATUS%" NEQ "200" (
    echo   ES not ready, retrying in 5s...
    timeout /t 5 /nobreak >nul
    goto wait_es
)
echo   Elasticsearch is UP.
echo.

echo [1/4] Creating index template: firewall ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/firewall" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"firewall-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"ts\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"src\":{\"type\":\"ip\"},\"dst\":{\"type\":\"ip\"},\"sp\":{\"type\":\"integer\"},\"dp\":{\"type\":\"integer\"},\"proto\":{\"type\":\"keyword\"},\"action\":{\"type\":\"keyword\"},\"detector\":{\"type\":\"keyword\"},\"domain\":{\"type\":\"keyword\"},\"severity\":{\"type\":\"keyword\"},\"dir\":{\"type\":\"keyword\"},\"ttype\":{\"type\":\"keyword\"},\"cid\":{\"type\":\"keyword\"},\"event_type\":{\"type\":\"keyword\"},\"flags\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"long\"},\"size\":{\"type\":\"integer\"},\"ttl\":{\"type\":\"integer\"},\"src_geo\":{\"type\":\"keyword\"},\"dst_geo\":{\"type\":\"keyword\"},\"src_asn\":{\"type\":\"keyword\"},\"dst_asn\":{\"type\":\"keyword\"},\"reason\":{\"type\":\"text\",\"fields\":{\"keyword\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo [2/4] Creating index template: ids ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/ids" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"ids-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"timestamp\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"src_ip\":{\"type\":\"ip\"},\"dst_ip\":{\"type\":\"ip\"},\"src_port\":{\"type\":\"integer\"},\"dst_port\":{\"type\":\"integer\"},\"proto\":{\"type\":\"keyword\"},\"event_type\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"keyword\"},\"community_id\":{\"type\":\"keyword\"},\"direction\":{\"type\":\"keyword\"},\"app_proto\":{\"type\":\"keyword\"},\"dns\":{\"type\":\"object\"},\"http\":{\"type\":\"object\"},\"tls\":{\"type\":\"object\"},\"src_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"dst_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo [3/4] Creating index template: east-west ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/east-west" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"east-west-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"timestamp\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"flow_start\":{\"type\":\"date\"},\"flow_end\":{\"type\":\"date\"},\"src_ip\":{\"type\":\"ip\"},\"dst_ip\":{\"type\":\"ip\"},\"src_port\":{\"type\":\"integer\"},\"dst_port\":{\"type\":\"integer\"},\"proto\":{\"type\":\"integer\"},\"protocol\":{\"type\":\"keyword\"},\"app_proto\":{\"type\":\"keyword\"},\"direction\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"keyword\"},\"community_id\":{\"type\":\"keyword\"},\"initiator\":{\"type\":\"keyword\"},\"flow_end_reason\":{\"type\":\"keyword\"},\"tcp_state\":{\"type\":\"keyword\"},\"tcp_flags_ts\":{\"type\":\"keyword\"},\"tcp_flags_tc\":{\"type\":\"keyword\"},\"pkts_toserver\":{\"type\":\"long\"},\"pkts_toclient\":{\"type\":\"long\"},\"bytes_toserver\":{\"type\":\"long\"},\"bytes_toclient\":{\"type\":\"long\"},\"flow_duration_sec\":{\"type\":\"float\"},\"tos\":{\"type\":\"integer\"},\"dscp\":{\"type\":\"integer\"},\"src_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"dst_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo [4/4] Creating index template: north-south ...
curl -s -X PUT "http://127.0.0.1:9200/_index_template/north-south" -H "Content-Type: application/json" -d "{\"index_patterns\":[\"north-south-*\"],\"priority\":100,\"template\":{\"settings\":{\"number_of_shards\":1,\"number_of_replicas\":0},\"mappings\":{\"dynamic\":true,\"properties\":{\"timestamp\":{\"type\":\"date\"},\"@timestamp\":{\"type\":\"date\"},\"forwarded_at\":{\"type\":\"date\"},\"flow_start\":{\"type\":\"date\"},\"flow_end\":{\"type\":\"date\"},\"src_ip\":{\"type\":\"ip\"},\"dst_ip\":{\"type\":\"ip\"},\"src_port\":{\"type\":\"integer\"},\"dst_port\":{\"type\":\"integer\"},\"proto\":{\"type\":\"integer\"},\"protocol\":{\"type\":\"keyword\"},\"app_proto\":{\"type\":\"keyword\"},\"direction\":{\"type\":\"keyword\"},\"flow_id\":{\"type\":\"keyword\"},\"community_id\":{\"type\":\"keyword\"},\"initiator\":{\"type\":\"keyword\"},\"flow_end_reason\":{\"type\":\"keyword\"},\"tcp_state\":{\"type\":\"keyword\"},\"tcp_flags_ts\":{\"type\":\"keyword\"},\"tcp_flags_tc\":{\"type\":\"keyword\"},\"pkts_toserver\":{\"type\":\"long\"},\"pkts_toclient\":{\"type\":\"long\"},\"bytes_toserver\":{\"type\":\"long\"},\"bytes_toclient\":{\"type\":\"long\"},\"flow_duration_sec\":{\"type\":\"float\"},\"tos\":{\"type\":\"integer\"},\"dscp\":{\"type\":\"integer\"},\"src_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"dst_geo\":{\"type\":\"object\",\"properties\":{\"country\":{\"type\":\"keyword\"},\"country_name\":{\"type\":\"keyword\"},\"lat\":{\"type\":\"float\"},\"lon\":{\"type\":\"float\"},\"asn\":{\"type\":\"long\"},\"asn_org\":{\"type\":\"keyword\"}}},\"log_type\":{\"type\":\"keyword\"},\"source_file\":{\"type\":\"keyword\"}}}}}" >nul 2>&1
echo   Done.

echo.
echo Creating Kibana data views...

REM Wait for Kibana
:wait_kibana
curl -s -o nul -w "%%{http_code}" http://127.0.0.1:5601/api/status > %TEMP%\kb_status.txt 2>nul
set /p KB_STATUS=<%TEMP%\kb_status.txt
if "%KB_STATUS%" NEQ "200" (
    echo   Kibana not ready, retrying in 10s...
    timeout /t 10 /nobreak >nul
    goto wait_kibana
)
echo   Kibana is UP.
echo.

REM Delete existing data views first (idempotent - safe to re-run)
echo Removing old data views (if any)...
curl -s -X DELETE "http://127.0.0.1:5601/api/data_views/data_view/firewall" -H "kbn-xsrf: true" >nul 2>&1
curl -s -X DELETE "http://127.0.0.1:5601/api/data_views/data_view/ids" -H "kbn-xsrf: true" >nul 2>&1
curl -s -X DELETE "http://127.0.0.1:5601/api/data_views/data_view/east-west" -H "kbn-xsrf: true" >nul 2>&1
curl -s -X DELETE "http://127.0.0.1:5601/api/data_views/data_view/north-south" -H "kbn-xsrf: true" >nul 2>&1
echo   Done.

echo Creating data views...
curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"id\":\"firewall\",\"title\":\"firewall-*\",\"name\":\"Firewall\",\"timeFieldName\":\"ts\"}}" >nul 2>&1
echo   [1/4] Created: Firewall (firewall-* / ts)
curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"id\":\"ids\",\"title\":\"ids-*\",\"name\":\"IDS/IPS\",\"timeFieldName\":\"timestamp\"}}" >nul 2>&1
echo   [2/4] Created: IDS/IPS (ids-* / timestamp)
curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"id\":\"east-west\",\"title\":\"east-west-*\",\"name\":\"East-West\",\"timeFieldName\":\"timestamp\"}}" >nul 2>&1
echo   [3/4] Created: East-West (east-west-* / timestamp)
curl -s -X POST "http://127.0.0.1:5601/api/data_views/data_view" -H "kbn-xsrf: true" -H "Content-Type: application/json" -d "{\"data_view\":{\"id\":\"north-south\",\"title\":\"north-south-*\",\"name\":\"North-South\",\"timeFieldName\":\"timestamp\"}}" >nul 2>&1
echo   [4/4] Created: North-South (north-south-* / timestamp)

echo.
echo ============================================
echo   Setup Complete!
echo ============================================
echo.
echo   4 index templates created in Elasticsearch
echo   4 data views created in Kibana
echo.
echo   This script is safe to re-run anytime.
echo   After this, just use start-all.bat
echo ============================================
pause
