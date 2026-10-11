# Threat Hunting with AWS Network Firewall

A hands-on AWS Builder Lab where I built firewall and DNS controls in a hub-and-spoke network, then used CloudWatch to hunt for compromised EC2 instances, decode a DNS exfiltration attempt, and quarantine the affected instances.

## Scenario
A company had re-architected its network into three VPCs connected by AWS Transit Gateway: two spoke VPCs for workloads and one Inspection + Egress VPC where AWS Network Firewall inspects traffic before it continues to its destination. My task was to harden it with firewall rules and DNS controls, then investigate suspicious activity.

## What I did

### 1. Explored the architecture
- Used Reachability Analyzer to create two paths, **Spoke A to Internet** (Spoke-VPC-TestInstance1) and **Spoke B to Internet** (Spoke-VPC-TestInstance2), both to Inspection-Egress-VPC-IGW. Both returned Reachable
- Traced the path: security group and NACL, Transit Gateway, firewall endpoint in the Inspection + Egress VPC, InspectionFirewall, NAT Gateway, Internet Gateway

### 2. Built stateful rules in AWS Network Firewall
- **RestrictedDomains** domain list rule group (capacity 100): nine low-reputation domains such as `.example.xyz` and `.example.net`, source 10.0.0.0/8, HTTP and HTTPS, action Deny
- Tested from the Spoke-VPC-Command-Host through Session Manager: `curl https://www.example.net --max-time 5` timed out after 5000 ms
- **NonTlsTrafficOn443** Suricata rule group (capacity 10, `HOME_NET` = 10.0.0.0/8, action order) with sid 2271003 to alert on non-TLS traffic on port 443, added to InspectionFirewall-Policy as an unmanaged rule group
- Added AWS managed rule groups: all four Domain and IP groups plus ThreatSignaturesMalwareWebActionOrder. Capacity used: 4,310 of 30,000

### 3. Added Route 53 Resolver DNS Firewall
- Domain list **RestrictedDomains** using the `*.` wildcard format (DNS Firewall differs from Network Firewall here)
- Rule group **Spoke-VPC-DNS-Firewall** with two rules: **Blocklist** (custom list) and **ManagedBlocklist** (AWS Aggregate Threat List), both BLOCK with an NXDOMAIN response
- Associated it with Spoke-VPC-A and Spoke-VPC-B
- Enabled query logging (**Spoke-VPC-Query-Logs**) to the CloudWatch log group `/Lab/Route53/QueryLogs`

### 4. Hunted for compromised instances in CloudWatch
- Created a Contributor Insights rule **Blocked-DNS-Queries** (JSON, keys `srcids.instance` and `query_name`, filter `firewall_rule_action` in BLOCK, count)
- Ran Log Analytics queries against `/Lab/NetworkFirewall/Alert`:
  - Denylisted FQDNs: one hit, my own curl test, ruled out
  - ICMP: regular intervals from 10.2.1.85, possibly a port scan
  - SURICATA signature: FTP being used on port 443
- Contributor Insights showed one instance sending many blocked queries to subdomains of example.xyz that looked base64-encoded

### 5. Decoded the DNS exfiltration
```
awk -F "." '{print $1}' dnsqueries.txt | base64 --decode
```
The decoded text was a sample report listing names with access keys and secret access keys, which the DNS firewall had blocked from leaving.

### 6. Quarantined the instances
Replaced the security groups on Spoke-VPC-TestInstance1, 2 and 3 with **QuarantineSG** instead of terminating them, preserving them for investigation.

## Key takeaways
- Each control has a blind spot another one covers: the domain list covers HTTP and HTTPS only, DNS Firewall covers name resolution, and Suricata catches protocol misuse
- Wildcard syntax differs between services (`.example.xyz` in Network Firewall, `*.example.xyz` in DNS Firewall)
- Blocking an exfiltration attempt and being able to see it in the logs are separate wins
- Treat each alert as a lead and look for combined patterns before drawing conclusions
- Quarantine before terminating so evidence is preserved
- Lab values (short domain lists, rule capacities, sample data) are simplified and would be tuned in a real environment

## Tools
AWS Network Firewall, Suricata rules, Route 53 Resolver DNS Firewall, AWS Transit Gateway, Reachability Analyzer, Amazon CloudWatch (Log Analytics, Contributor Insights), AWS Systems Manager Session Manager, Amazon EC2

---
*Completed as an AWS Builder Lab (Threat Hunting with AWS Network Firewall Deployment).*
