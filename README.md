# Splunk Mini-SOC using Sysmon and Threat Intelligence Correlation

## Project Overview

This project implements a lightweight Security Operations Center (SOC) using Splunk and Sysmon logs. It enhances endpoint visibility by collecting detailed event data and enriching it with threat intelligence feeds. The solution is designed to help security analysts detect, visualize, and investigate malicious network activity.

## Objectives

- Monitor Windows endpoint network activity using Sysmon Event ID 3.
- Detect and correlate outbound connections with known malicious IP addresses.
- Use a custom threat intelligence lookup table to enrich detection results.
- Build dashboards to visualize threat distribution, severity, and trends.
- Demonstrate the functionality through PDF reports and exported visualizations.

## Components

### 1. Sysmon Log Collection

- **Tool:** Sysmon (System Monitor by Sysinternals)
- **Configuration:** Custom XML configuration file defining which events to capture.
- **Event Type Monitored:** Event ID 3 (Network Connection)
- **Forwarding:** Logs forwarded from Windows endpoint to Splunk via Universal Forwarder.
- **Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### 2. Threat Intelligence Lookup

- File: `lookup/threat_ip_lookup.csv`
- Columns: `threat_ip`, `threat_type`, `source`, `severity`
- Uploaded into Splunk as a lookup table and referenced using the name `threat_ip_lookup`.
- Used to enrich raw Sysmon logs with threat metadata and prioritization.

### 3. Threat Detection Query

Location: `detection/threat_intel_correlation_query.txt`

This SPL query performs the core correlation between Sysmon logs and the lookup:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=_raw "<DestinationIp>(?P<dest_ip>.*?)</DestinationIp>"
| lookup threat_ip_lookup threat_ip as dest_ip OUTPUT threat_type, source, severity
| where isnotnull(threat_type)
| table _time, dest_ip, threat_type, source, severity, Computer
Purpose: Extract destination IP from XML logs, match against threat intelligence, and display enriched results.

 ### 4. Dashboards and Visualizations
Location: dashboards/

Each file contains the SPL query for a dashboard panel:

File	                              Visualization Title	                                    Description
threat_activity_overview.txt	      Threat Activity Overview	                                Tabular view of all detected malicious connections
ip_severity_chart.txt	              Threat IP Severity Chart	                                Bar chart showing frequency by severity level
threat_timeline_chart.txt	          Threat Timeline by Type                               	Time-based visualization of threat activity trends
source_breakdown_chart.txt	          Source Feed Breakdown	                                    Pie chart showing the source distribution of threat intel

### 5. Report
Location: report/Threat_IP_Detected_Dashboard.pdf

This PDF contains screenshots of the implemented dashboard, showing:

Threat severity breakdown by destination IP

Bar and pie charts summarizing threat activity

Timeline view of malicious IP detections

Geographic distribution of detected threats


# Skills Demonstrated
Log forwarding using Splunk Universal Forwarder

XML log parsing and extraction using regular expressions

Correlation of threat intelligence with live endpoint logs

Dashboard design and data visualization in Splunk

Use of lookup tables for enrichment and alert scoring

Structured security monitoring implementation

## Tags

`Splunk` `Sysmon` `Threat Intelligence` `SIEM` `Cybersecurity` `Security Operations Center` `XML Log Parsing` `Lookup Table` `Regex` `Network Monitoring` `Incident Detection`


Author
Keshav Yadav
DSCE, Bengaluru# Splunk Mini-SOC using Sysmon and Threat Intelligence Correlation

## Project Overview

This project implements a lightweight Security Operations Center (SOC) using Splunk and Sysmon logs. It enhances endpoint visibility by collecting detailed event data and enriching it with threat intelligence feeds. The solution is designed to help security analysts detect, visualize, and investigate malicious network activity.

## Objectives

- Monitor Windows endpoint network activity using Sysmon Event ID 3.
- Detect and correlate outbound connections with known malicious IP addresses.
- Use a custom threat intelligence lookup table to enrich detection results.
- Build dashboards to visualize threat distribution, severity, and trends.
- Demonstrate the functionality through PDF reports and exported visualizations.

## Components

### 1. Sysmon Log Collection

- **Tool:** Sysmon (System Monitor by Sysinternals)
- **Configuration:** Custom XML configuration file defining which events to capture.
- **Event Type Monitored:** Event ID 3 (Network Connection)
- **Forwarding:** Logs forwarded from Windows endpoint to Splunk via Universal Forwarder.
- **Sourcetype:** `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`

### 2. Threat Intelligence Lookup

- File: `lookup/threat_ip_lookup.csv`
- Columns: `threat_ip`, `threat_type`, `source`, `severity`
- Uploaded into Splunk as a lookup table and referenced using the name `threat_ip_lookup`.
- Used to enrich raw Sysmon logs with threat metadata and prioritization.

### 3. Threat Detection Query

Location: `detection/threat_intel_correlation_query.txt`

This SPL query performs the core correlation between Sysmon logs and the lookup:

index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=3
| rex field=_raw "<DestinationIp>(?P<dest_ip>.*?)</DestinationIp>"
| lookup threat_ip_lookup threat_ip as dest_ip OUTPUT threat_type, source, severity
| where isnotnull(threat_type)
| table _time, dest_ip, threat_type, source, severity, Computer
Purpose: Extract destination IP from XML logs, match against threat intelligence, and display enriched results.

 ### 4. Dashboards and Visualizations
Location: dashboards/

Each file contains the SPL query for a dashboard panel:

File	                              Visualization Title	                                    Description
threat_activity_overview.txt	      Threat Activity Overview	                                Tabular view of all detected malicious connections
ip_severity_chart.txt	              Threat IP Severity Chart	                                Bar chart showing frequency by severity level
threat_timeline_chart.txt	          Threat Timeline by Type                               	Time-based visualization of threat activity trends
source_breakdown_chart.txt	          Source Feed Breakdown	                                    Pie chart showing the source distribution of threat intel

### 5. Report
Location: report/Threat_IP_Detected_Dashboard.pdf

This PDF contains screenshots of the implemented dashboard, showing:

Threat severity breakdown by destination IP

Bar and pie charts summarizing threat activity

Timeline view of malicious IP detections

Geographic distribution of detected threats


# Skills Demonstrated
Log forwarding using Splunk Universal Forwarder

XML log parsing and extraction using regular expressions

Correlation of threat intelligence with live endpoint logs

Dashboard design and data visualization in Splunk

Use of lookup tables for enrichment and alert scoring

Structured security monitoring implementation

## Tags

`Splunk` `Sysmon` `Threat Intelligence` `SIEM` `Cybersecurity` `Security Operations Center` `XML Log Parsing` `Lookup Table` `Regex` `Network Monitoring` `Incident Detection`


Author
Keshav Yadav
DSCE, Bengaluru
