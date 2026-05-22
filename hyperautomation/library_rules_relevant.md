# Library rules relevant to Claroty x Palo Alto drift

Filtered by keywords: claroty, palo alto, panos, pan-os, firewall, ot device, ics, scada, operational technology, modbus, dnp3, iec61850, ot asset, industrial, external dynamic list, edl, dynamic address group

**Matches: 218 / 2144 total Library rules**

## ADExplorer Full Active Directory Snapshot Saved to DAT File
- id: `2274627327015189603`
- severity: Medium
- status: Active
- description: Detects the use of ADExplorer to write a complete Active Directory snapshot into a '.dat' file. This behavior is indicative of directory reconnaissance or data exfiltration activities, as adversaries may leverage ADExplorer to capture sensitive domain information for offline anal
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'File Creation' and (src.process.name in:anycase ('ADExp.exe', 'ADExplorer.exe', 'ADExplorer64.exe', 'ADExplorer64a.exe')) and tgt.file.extension in:anycase ('dat')
`

## AWS CloudTrail Backup Vault Lockout Attempt
- id: `2224180602685568629`
- severity: High
- status: Active
- description: Detects an attempt to apply a deny-all access policy to an AWS Backup Vault. The policy denies all actions to all principals, effectively locking out access to backup data. This activity may indicate an adversary's effort to prevent recovery operations by isolating or disabling b
- query: ``

## AWS CloudTrail EBS Snapshot Access Removal
- id: `2254457521312083313`
- severity: Low
- status: Disabled
- description: Detects when permissions are removed from Amazon Elastic Block Store (EBS) snapshots through AWS CloudTrail logs. This activity could indicate an adversary attempting to prevent data recovery or hide malicious actions by restricting access to backup snapshots. EBS snapshots are p
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ec2.amazonaws.com' and activity_name = 'ModifySnapshotAttribute' and unmapped.requestParameters.createVolumePermission.remove.items contains '"userId"' and not (api.response.error = *) and not (unmapped.userIdentity.arn conta`

## AWS CloudTrail EBS Volume Deletion
- id: `2203626833083932336`
- severity: Info
- status: Disabled
- description: Detects when an Amazon Elastic Block Store (EBS) volume is deleted through AWS CloudTrail. This action permanently removes the storage volume and its data, which could indicate legitimate cleanup operations or potential malicious activity. Adversaries might delete EBS volumes to 
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ec2.amazonaws.com' and activity_name = 'DeleteVolume' and not (api.response.error = *)
`

## AWS CloudTrail EC2 AMI Block Public Access Removed
- id: `2325322826555703368`
- severity: Medium
- status: Active
- description: Detects when restrictions on allowed Amazon Machine Images (AMIs) are disabled in AWS through the DisableImageBlockPublicAccess API call. This security control typically limits which AMIs can be launched in an environment, ensuring only pre-approved and validated images are used.
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ec2.amazonaws.com' and activity_name = 'DisableImageBlockPublicAccess' and not (api.response.error = *)
`

## AWS CloudTrail ECS Cluster with Container Insights Disabled
- id: `2315200444478798476`
- severity: Low
- status: Disabled
- description: Detects the creation of Amazon Elastic Container Service (ECS) clusters with Container Insights monitoring disabled. Container Insights is an important monitoring and diagnostic feature that collects, aggregates, and summarizes metrics and logs from containerized applications and
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ecs.amazonaws.com' and activity_name = 'CreateCluster' and unmapped.responseElements.cluster.settings contains '"containerInsights","value":"disabled"' and not (api.response.error = *)
`

## AWS CloudTrail EMR Public Access Block Disabled
- id: `2325322909552591848`
- severity: Medium
- status: Active
- description: Detects when the 'Block public access' (BPA) setting is disabled for Amazon EMR. This critical security control prevents EMR clusters from being configured with public IP addresses and publicly accessible security groups, which could expose sensitive data processing environments 
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'elasticmapreduce.amazonaws.com' and activity_name='PutBlockPublicAccessConfiguration' and not (api.response.error = *) 
`

## AWS CloudTrail EventBridge Rule Creation
- id: `2203626833377533649`
- severity: Low
- status: Disabled
- description: Detects the creation of new EventBridge rules within AWS. EventBridge is an event-driven service that enables automation by routing events to targets such as Lambda functions, Step Functions, or SNS topics. While commonly used for legitimate workflows and resource orchestration, 
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'events.amazonaws.com' and activity_name = 'PutRule' and not (api.response.error = *) and not (src_endpoint.ip = 'backup.amazonaws.com' and actor.session.issuer in ('AWSBackupRole','AWSBackupDefaultServiceRole'))
`

## AWS CloudTrail GuardDuty Detector Modification
- id: `2174786348543990002`
- severity: Low
- status: Disabled
- description: Detects modifications to AWS GuardDuty detector settings. GuardDuty detectors are responsible for analyzing data sources and generating security findings. Changes to detector configurations may indicate attempts to manipulate threat detection capabilities or disable specific moni
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'guardduty.amazonaws.com' and activity_name = 'UpdateDetector' and not (api.response.error = *)
`

## AWS CloudTrail GuardDuty Monitoring Disabled
- id: `2193712709540632674`
- severity: High
- status: Active
- description: Detects attempts to disable AWS GuardDuty member monitoring, which could indicate defense evasion tactics. GuardDuty is a critical threat detection service that analyzes AWS CloudTrail, VPC Flow Logs, and DNS logs to identify malicious or unauthorized behavior. Disabling member m
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'guardduty.amazonaws.com' and activity_name = 'StopMonitoringMembers' and not (api.response.error = *)
`

## AWS CloudTrail Invalid Authentication Provided
- id: `2416777937735048585`
- severity: Medium
- status: Active
- description: Detects unauthorized or failed authentication attempts across AWS services by monitoring CloudTrail for credential-related anomalies. This rule identifies the use of expired, malformed, or revoked authentication material, as well as cryptographic signature mismatches. These event
- query: `dataSource.name = 'CloudTrail' and api.response.error in ('ExpiredToken', 'InvalidAccessKeyId', 'InvalidToken', 'MissingAuthenticationToken', 'SignatureDoesNotMatch', 'TokenRefreshRequired', 'UnsupportedSignature', 'InvalidSignature')
`

## AWS CloudTrail Macie Service Disablement
- id: `2254456169068464968`
- severity: Medium
- status: Active
- description: Detects attempts to disable Amazon Macie, a crucial security service that automatically discovers and protects sensitive data within AWS environments. Disabling Macie can indicate an adversary's effort to obscure data exposure activities and evade detection, potentially setting t
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'macie2.amazonaws.com' and activity_name = 'DisableMacie' and not (api.response.error = *)
`

## AWS CloudTrail Multiple Failed MFA Requests
- id: `2254449306910202399`
- severity: High
- status: Active
- description: Detects multiple failed multi-factor authentication (MFA) requests directed at an AWS Console for a single user within a short time window. An adversary can abuse this by employing an MFA fatigue attack, repeatedly sending MFA prompts to the target user's device in an attempt to 
- query: ``

## AWS CloudTrail Network ACL Creation or Modification
- id: `2203626876276876143`
- severity: Info
- status: Disabled
- description: Detects the creation of a network access control list (ACL) or the modification of entries within an ACL in AWS Elastic Compute Cloud (EC2). Network ACLs function as stateless firewalls at the subnet level, managing inbound and outbound traffic through defined rules. Adversaries 
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ec2.amazonaws.com' and activity_name in ('CreateNetworkAcl', 'CreateNetworkAclEntry', 'ReplaceNetworkAclEntry', 'ReplaceNetworkAclAssociation') and not (api.response.error = *)
`

## AWS CloudTrail RDS Security Group Creation
- id: `2098026332566327144`
- severity: Low
- status: Disabled
- description: Detects the creation of new database security groups in Amazon Relational Database Service (RDS). These security groups act as firewalls, controlling access to RDS instances by specifying permitted EC2 instances or IP address ranges. Unauthorized or misconfigured usage of this AP
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'rds.amazonaws.com' and activity_name = 'CreateDBSecurityGroup' and not (api.response.error = *)
`

## AWS CloudTrail RDS Security Group Deletion
- id: `2124062870568931515`
- severity: Medium
- status: Active
- description: Detects the deletion of an RDS security group, which can be abused by attackers to bypass network access controls for databases, potentially exposing RDS instances to unauthorized access or data exfiltration. By removing security groups, adversaries can disrupt firewall rules and
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'rds.amazonaws.com' and activity_name = 'DeleteDBSecurityGroup' and not (api.response.error.= *)
`

## AWS CloudTrail Region Disabled
- id: `2154658955155967151`
- severity: Medium
- status: Active
- description: Detects when a region is disabled in AWS CloudTrail, which could indicate evasion tactics by adversaries attempting to limit security visibility. AWS regions provide isolated environments for cloud resources, and disabling a region's monitoring capabilities through CloudTrail sig
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'account.amazonaws.com' and activity_name = 'DisableRegion' and. not (api.response.error = *)
`

## AWS CloudTrail S3 Bucket Cross-Origin Resource Sharing (CORS) Policy Modified
- id: `2315200518768313165`
- severity: Info
- status: Disabled
- description: Detects modifications to Cross-Origin Resource Sharing (CORS) policies on Amazon S3 buckets through AWS CloudTrail logs. CORS is a security mechanism that allows web applications running at one origin to access resources from a different origin. It controls which external domains
- query: `dataSource.name = 'CloudTrail' and api.service.name = 's3.amazonaws.com' and activity_name = 'PutBucketCors' and not (api.response.error = *)
`

## AWS CloudTrail S3 Potential Enumeration of Bucket URIs
- id: `2416777919338828550`
- severity: Medium
- status: Active
- description: Detects potential enumeration of S3 bucket URIs by the same user within a short timeframe. This behavior may indicate reconnaissance activity, where an adversary is attempting to gather information about the AWS environment, such as resources, configurations, or permissions, as p
- query: ``

## AWS CloudTrail Security Group Egress Rule for ICMP Opened
- id: `2254455650744762410`
- severity: Medium
- status: Active
- description: Detects the creation or modification of a security group egress rule in AWS that allows outbound ICMP traffic. While ICMP is typically used for network diagnostics, adversaries may abuse it as an alternative protocol for data exfiltration to evade traditional monitoring and egres
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ec2.amazonaws.com' and activity_name = 'AuthorizeSecurityGroupEgress' and unmapped.requestParameters.ipPermissions.items contains 'icmp' and unmapped.requestParameters.ipPermissions.items contains ('"cidrIpv6":"::\\/0"','"cid`

## AWS CloudTrail Service Access Disablement Attempt
- id: `2254455995952760409`
- severity: Medium
- status: Active
- description: Detects when AWS Organizations service access is disabled through CloudTrail events. AWS Organizations allows services like AWS Config, AWS Firewall Manager, and AWS Security Hub to manage resources across multiple accounts. When service access is disabled, these services lose th
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'organizations.amazonaws.com' and activity_name = 'DisableAWSServiceAccess' and not (api.response.error = *)
`

## AWS CloudTrail SES Logging Destination Modification or Deletion
- id: `2184096571790172434`
- severity: Medium
- status: Active
- description: Detects updates or deletions of Amazon SES logging destinations. Adversaries may attempt to modify or remove logging destinations to prevent email activity from being logged, thereby evading detection. This can indicate malicious actions, such as obfuscating phishing or spam camp
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ses.amazonaws.com' and activity_name in ('DeleteConfigurationSetEventDestination', 'UpdateConfigurationSetEventDestination', 'UpdateConfigurationSetReputationMetricsEnabled')
`

## AWS CloudTrail SNS Subscription Activity
- id: `2067579405614282015`
- severity: Info
- status: Disabled
- description: Detects activities in AWS CloudTrail where a subscription is created for an Amazon Simple Notification Service (SNS) topic. Adversaries may attempt to subscribe unauthorized endpoints, such as email addresses, HTTP/S endpoints, or Lambda functions, to SNS topics in order to inter
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'sns.amazonaws.com' and activity_name = 'Subscribe'
`

## AWS CloudTrail SSH Key Modification for Glue DevEndpoint
- id: `2144452792233019683`
- severity: Medium
- status: Active
- description: Detects the modification of an SSH public key for an AWS Glue DevEndpoint. Glue DevEndpoints enable users to develop and test ETL scripts, and SSH keys are used to securely access these endpoints. Updating the SSH key for a DevEndpoint can potentially provide unauthorized access 
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'glue.amazonaws.com' and activity_name = 'UpdateDevEndpoint' and not (api.response.error = *)
`

## AWS CloudTrail VPC Modified or Deleted
- id: `2134237849588287646`
- severity: Low
- status: Disabled
- description: Detects modification or deletion of Amazon Virtual Private Cloud (VPC) resources through AWS CloudTrail logs. VPCs are foundational networking components that provide isolated cloud environments for AWS resources, controlling network traffic and security boundaries. When VPCs are
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ec2.amazonaws.com' and activity_name in ('DeleteVpc', 'ModifyVpcAttribute') and not (api.response.error = *) 
`

## AWS CloudTrail VPC Peering Modified or Deleted
- id: `2315200601907808523`
- severity: Low
- status: Disabled
- description: Detects the creation, acceptance, or deletion of Amazon VPC peering connections through AWS CloudTrail logs. VPC peering allows direct network connectivity between two Virtual Private Clouds, enabling resources in different VPCs to communicate as if they were within the same netw
- query: `dataSource.name = 'CloudTrail' and api.service.name = 'ec2.amazonaws.com' and activity_name in ('CreateVpcPeeringConnection', 'AcceptVpcPeeringConnection', 'DeleteVpcPeeringConnection') and not (api.response.error = *) 
`

## AWS CloudTrail WAF ACL Deletion or Disassociation
- id: `2067579405647836460`
- severity: Low
- status: Disabled
- description: Detects the deletion or disassociation of a Web Application Firewall (WAF) Access Control List (ACL). Adversaries may delete WAF ACLs to bypass protections designed to secure web-hosted applications, including those hosted in Amazon Elastic Container Service (ECS). By removing th
- query: `dataSource.name = 'CloudTrail' and api.service.name in ('waf.amazonaws.com', 'waf-regional.amazonaws.com', 'wafv2.amazonaws.com') and activity_name in ('DeleteWebACL', 'DisassociateWebACL') and not (api.response.error = *)
`

## AWS CloudTrail WAF IPSet Deletion
- id: `2067579405664613683`
- severity: Medium
- status: Active
- description: Detects the deletion of a Web Application Firewall (WAF) IPSet. Adversaries may delete IP Sets to bypass protections in place for web-hosted application resources, including those hosted in Amazon Elastic Container Service (ECS). By removing IP Sets, attackers can allow unauthori
- query: `dataSource.name = 'CloudTrail' and api.service.name in ('waf.amazonaws.com', 'waf-regional.amazonaws.com', 'wafv2.amazonaws.com') and activity_name = 'DeleteIPSet' and not (api.response.error = *)
`

## AWS CloudTrail WAF Logging Configuration Deletion
- id: `2067579405681390906`
- severity: Medium
- status: Active
- description: Detects the deletion of Web Application Firewall (WAF) Access Control List (ACL) Logging Configurations. WAF logging provides detailed information about traffic analyzed by web ACLs. Adversaries may delete these logging configurations to evade detection by obscuring ACL-related a
- query: `dataSource.name = 'CloudTrail' and api.service.name in ('waf.amazonaws.com', 'waf-regional.amazonaws.com', 'wafv2.amazonaws.com') and activity_name = 'DeleteLoggingConfiguration' and not (api.response.error = *)
`

## AWS CloudTrail WAF Rule or Role Group Deletion
- id: `2067579405622670628`
- severity: Medium
- status: Active
- description: Detects the deletion of a specific Web Application Firewall (WAF) rule or rule group. Adversaries may delete WAF rules or rule groups to bypass protections for web-hosted application resources, including those hosted in Amazon Elastic Container Service (ECS). By removing these ru
- query: `dataSource.name = 'CloudTrail' and api.service.name in ('waf.amazonaws.com', 'waf-regional.amazonaws.com', 'wafv2.amazonaws.com') and activity_name in ('DeleteRule', 'DeleteRuleGroup') and not (api.response.error = *)
`

## AWS WAF Allowed Cross Site Scripting Attempts
- id: `2284867210993166053`
- severity: Medium
- status: Active
- description: Detects HTTP requests containing common XSS attack patterns such as embedded scripts, event handlers, and suspicious JavaScript or VBScript code that have bypassed existing WAF protections. These payloads pose a risk because they can execute malicious scripts in users’ browsers, 
- query: `dataSource.name='AWS Web Application Firewall' and http_request.args contains ('%3Cscript', '%3C%2Fscript', '%3Ciframe', '%3Cembed', '%3Cform', '%3Cinput', '%3Cframe', '%3Cframeset', 'javascript%3A', 'vbscript%3A', 'onerror%3D', 'onload%3D', 'onclick%3D', 'onchange%3D', 'alert%28`

## AWS WAF Allowed Encoded XXE Indicators
- id: `2335486111582859570`
- severity: Medium
- status: Active
- description: Detects URL-encoded patterns related to XML External Entity (XXE) injection attempts within HTTP request arguments. Attackers may encode malicious XML payloads to bypass input filters or WAF signatures, using entities such as <!ENTITY>, <!DOCTYPE>, or SYSTEM "file://" to referenc
- query: `dataSource.name = 'AWS Web Application Firewall' and http_request.args contains ('%3C!ENTITY', '%3C!DOCTYPE', '%3CSYSTEM', 'file%3A%2F%2F', 'php%3A%2F%2Ffilter', 'expect%3A%2F%2F', 'data%3A%2F%2F', 'SYSTEM%20%22file%3A', 'SYSTEM%20%22http%3A') and unmapped.action = 'ALLOW'
`

## AWS WAF Allowed Local File Inclusion Activity
- id: `2294975064669740889`
- severity: Low
- status: Disabled
- description: Detects potential Local File Inclusion (LFI) attempts in HTTP requests that were allowed by AWS WAF. It identifies suspicious URL paths containing common sensitive file references or system paths often targeted in LFI attacks, such as /etc/passwd, other configuration files, and v
- query: `dataSource.name = 'AWS Web Application Firewall' and web_resources.url.path contains ('/etc/passwd', '/etc/shadow', '/proc/self/environ', '/proc/version', '/var/log/', '/.bash_history', '\\boot.ini', '\\win.ini', 'system32\\config\\') and unmapped.action = 'ALLOW' and not (http_r`

## AWS WAF Allowed Null Byte Injection
- id: `2335486067223900067`
- severity: Low
- status: Disabled
- description: Detects requests containing literal or encoded null bytes in URL paths or query string values. Null-byte injection is commonly used to bypass filename or extension checks, truncate server-side string processing, or evade input validation — enabling attackers to access unintended 
- query: `dataSource.name = 'AWS Web Application Firewall' and (http_request.args contains ('%00', '\\u0000') or web_resources.url.path contains ('%00', '\\u0000')) and unmapped.action = 'ALLOW' and not (http_request.http_headers contains 'User-Agent","value":"SentinelOne-CNS')
`

## AWS WAF Allowed Path Traversal Activity
- id: `2294975000463333815`
- severity: Low
- status: Disabled
- description: Detects potential path traversal attempts in HTTP requests that were allowed by AWS WAF. It detects suspicious patterns in the URL path such as encoded or repeated directory traversal sequences. These patterns may indicate an attempt to access files or directories outside the int
- query: `dataSource.name = 'AWS Web Application Firewall' and (web_resources.url.path matches '\\.\\.%[0-9a-fA-F%]+\\.\\.' OR web_resources.url.path contains ('../../','..\\..\\', '.../')) and unmapped.action = 'ALLOW' not (http_request.http_headers contains 'User-Agent","value":"Sentinel`

## AWS WAF Allowed Possible Unauthorized Upload Activity
- id: `2335486111608025396`
- severity: Medium
- status: Active
- description: Detects POST requests to upload-related endpoints that include script or executable MIME types but lack authentication headers such as Cookie or Authorization. Such unauthenticated uploads are uncommon in normal web application use and may indicate attempts to deploy malicious fi
- query: `dataSource.name = 'AWS Web Application Firewall' and web_resources.url.path matches '\\/(images|files|upload|media)\\/' and http_request.http_headers contains ('application\\/x-php', 'text\\/x-php', 'application\\/x-httpd-php', 'text\\/x-asp', 'application\\/x-jsp', 'text\\/x-cfm`

## AWS WAF Allowed Potential Buffer Overflow Attempt
- id: `2335486111616414005`
- severity: Medium
- status: Active
- description: Detects unusually long runs of the same character in URL query string values which are commonly used by fuzzers and exploit attempts to locate buffer overflow vulnerabilities or to probe input-handling boundaries. Such repetitive payloads can indicate automated fuzzing, naive ove
- query: `dataSource.name = 'AWS Web Application Firewall' and http_request.args matches '(.)\\1{18,}' and unmapped.action = 'ALLOW' and not (http_request.http_headers contains 'User-Agent","value":"SentinelOne-CNS')
`

## AWS WAF Allowed Potential Double Extension File Access
- id: `2335486111624802614`
- severity: Medium
- status: Active
- description: Detects requests accessing filenames that contain multiple extensions (for example name.ext1.ext2), a common technique attackers use to bypass simple extension-based upload filters or hide executable files behind benign-looking extensions. Such requests may indicate attempts to a
- query: `dataSource.name = 'AWS Web Application Firewall' and web_resources.url.path matches '\\.(jpg|jpeg|txt|xml|php|asp|aspx|jsp|war|png|exe)\\.(jpg|jpeg|txt|xml|php|asp|aspx|jsp|war|png|exe)$' and http_request.http_method = 'GET' and unmapped.action = 'ALLOW'
`

## AWS WAF Allowed Potential Header Injection Attempts
- id: `2335486111633191223`
- severity: Medium
- status: Active
- description: Detects HTTP requests where header values contain suspicious server-side code or template markers (for example, language-specific or template fragments that do not normally appear in headers). Such strings in headers often indicate attempts to smuggle code into places that may be
- query: `dataSource.name = 'AWS Web Application Firewall' and http_request.http_headers contains ('<script>', '</script>', 'alert(', '<img src', 'javascript:alert(', '<iframe>', '<svg onload', '<?php', 'eval(', 'base64_decode(', 'UNION SELECT', "' OR '1'='1", 'etc/passwd', '\\r\\n') and u`

## AWS WAF Allowed Potential Uploaded Executable Content
- id: `2335486111977124173`
- severity: Low
- status: Disabled
- description: Detects potential web shell or malicious script access attempts in HTTP requests that were allowed by AWS WAF. It identifies suspicious requests targeting files within common upload or media directories that appear to be executable or script-based. Such activity may indicate succ
- query: `dataSource.name = 'AWS Web Application Firewall' and web_resources.url.path matches '\\/(images|files|upload|media)\\/.*\\.(php|phtml|jsp|asp|aspx|exe|sh|pl)$' and  http_request.http_method = 'GET' and unmapped.action = 'ALLOW'
`

## AWS WAF Allowed Potential WebShell Upload
- id: `2335486111641579832`
- severity: High
- status: Active
- description: Detects HTTP requests where header values include a filename="..." pattern indicating a file name (as logged in headers such as Content-Disposition). Presence of executable/script-like filenames in headers is a strong indicator that an upload attempt may have included server-side
- query: `dataSource.name = 'AWS Web Application Firewall' and http_request.http_headers matches 'filename=\\\\"[A-Za-z0-9]+\\.(php|asp|war|jsp|phtml|sh|py|pl|exe|ps1)' and unmapped.action = 'ALLOW'
`

## AWS WAF Allowed SQL Injection Attempts
- id: `2284867211001554664`
- severity: Low
- status: Disabled
- description: Detects potential SQL injection attempts that were allowed through based on analysis of AWS WAF logs. These requests contain patterns commonly associated with SQL injection but were not blocked by existing WAF rules, potentially exposing backend systems to exploitation. Such acti
- query: `dataSource.name = 'AWS Web Application Firewall' and http_request.args contains (' OR ', '1=1', 'OR TRUE', 'AND TRUE', "'a'='a'", "'1'='1'", 'sleep(', 'benchmark(', '%20OR%20', '1%3D1', 'OR%20TRUE', 'AND%20TRUE', '%27a%27%3D%27a%27', '%271%27%3D%271%27', 'sleep%28', 'benchmark%28`

## AWS WAF Allowed Suspicious User Agents
- id: `2315200819684476842`
- severity: Medium
- status: Active
- description: Detects HTTP requests in AWS WAF logs that use suspicious or non-browser User-Agent values commonly associated with automated tools, scanners, or scripting environments. These requests were allowed by the WAF and may indicate reconnaissance or vulnerability scanning activity. Mon
- query: `dataSource.name = 'AWS Web Application Firewall' and http_request.http_headers matches 'User-Agent","value":"(burp|burpcollaborator|qualys|nexpose|openvas|nikto|meterpreter|iceweasel|dirb|comodo|tripwire|retina|mbsa|immuniweb|netsparker|acunetix|intruder|winhttp\\.winhttprequest|`

## AWS WAF Allowed Uncommon HTTP Methods
- id: `2335486111666745658`
- severity: Medium
- status: Active
- description: Detects potentially dangerous or uncommon HTTP methods such as TRACE, TRACK, PUT, or DELETE being used against web application endpoints. These methods are rarely used in normal web interactions and may indicate attempts to perform unauthorized actions, probe for server misconfig
- query: `dataSource.name = 'AWS Web Application Firewall' and http_request.http_method in:anycase ('TRACE', 'TRACK', 'PUT', 'DELETE') and unmapped.action = 'ALLOW'
`

## AWS WAF Possible Webshell Command Execution
- id: `2294975000849209806`
- severity: High
- status: Active
- description: Detects possible remote command execution (RCE) attempts resembling webshell behavior, where attackers pass system commands directly as arguments in web requests. Commands like whoami, id, and curl are commonly used for system enumeration or further exploitation, and their presen
- query: `dataSource.name = 'AWS Web Application Firewall' and (http_request.args matches '=(whoami|powershell.exe|cmd.exe|pwsh.exe|ipconfig|ifconfig)' or http_request.args matches '=(curl%20|wget%20)(h|-|%2d)' or http_request.args matches '=(bash|sh)%20(-|%2d)(i|c|l)%20' or http_request.a`

## Azure Application Abuse Reconnaissance via Graph API
- id: `2457204587879822260`
- severity: High
- status: Active
- description: Detects a correlated chain of Microsoft Graph API calls that enumerate application registrations, their owners, and federated identity credentials — a pattern used to identify application-level abuse opportunities in Entra ID. An actor first lists all applications, then iterates 
- query: ``

## Azure Diagnostic Logging and Metrics Disabled on Resource
- id: `2103845100170974933`
- severity: High
- status: Active
- description: Detects when diagnostic logging and metrics are disabled or cleared on Azure resources. This action disrupts the collection of critical security and operational data, impairing monitoring and incident response capabilities. Adversaries may exploit this to evade detection, obscure
- query: `dataSource.name = 'Azure Platform' and api.operation = 'MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/WRITE' and unmapped.properties.requestbody matches '(metrics.{2}\\[\\])|(logs.{2}\\[\\])'
`

## Azure Diagnostic Settings Deletion
- id: `2046485288575303435`
- severity: Low
- status: Disabled
- description: Detects the deletion of diagnostic settings in Azure. Diagnostic settings are critical for collecting and streaming logs and metrics to monitoring solutions like Azure Monitor, Log Analytics, or external storage accounts. Removing these settings disables the collection of key tel
- query: `dataSource.name = 'Azure Platform' and category_name = 'Application Activity' and unmapped.properties.message contains 'microsoft.insights/diagnosticsettings/delete' and unmapped.resultType = 'Success'
`

## Azure Firewall Deleted
- id: `2193712724782736378`
- severity: High
- status: Active
- description: Detects the deletion of an Azure Firewall, which can expose cloud resources to unauthorized access and reduce network security controls. Adversaries may delete firewalls to disable traffic filtering, allowing unrestricted inbound and outbound communication. This could facilitate 
- query: `dataSource.name = 'Azure Platform' and category_name = 'Application Activity' and unmapped.properties.message = 'Microsoft.Network/azureFirewalls/delete' and unmapped.resultType = 'Success'
`

## Azure Firewall Policy Deletion
- id: `2053136761737624014`
- severity: Low
- status: Disabled
- description: Detects the successful deletion of firewall policies in Azure. An adversary may delete firewall policies to disable security controls, allowing unauthorized network traffic to flow undetected or reducing the organization's ability to identify and respond to malicious activities. 
- query: `dataSource.name='Azure Platform' and category_name = 'Application Activity' and unmapped.properties.message contains 'microsoft.network/firewallpolicies/delete' and unmapped.resultType = 'Success'
`

## Azure Firewall Policy Modification
- id: `2053136761762789839`
- severity: Low
- status: Disabled
- description: Detects successful write operations to firewall policies in Azure, which may indicate unauthorized modifications intended to weaken network security or evade defenses. Adversaries may alter firewall rules to allow malicious traffic, disable critical protections, or conceal their 
- query: `dataSource.name = 'Azure Platform' and category_name = 'Application Activity' and unmapped.properties.message contains ('microsoft.network/firewallpolicies/write', 'microsoft.network/firewallpolicies/join/action', 'microsoft.network/firewallpolicies/certificates/action') and unma`

## Azure Firewall Policy Rule Group Deletion
- id: `2053136761813121488`
- severity: Low
- status: Disabled
- description: Detects successful deletions of rule groups within firewall policies in Azure. An adversary may exploit this action to disable specific network security rules, potentially allowing unauthorized traffic or malicious activities to bypass the firewall. By removing key rule groups, a
- query: `dataSource.name = 'Azure Platform' and category_name = 'Application Activity' and unmapped.properties.message contains 'Microsoft.Network/firewallPolicies/ruleCollectionGroups/delete' and unmapped.resultType = 'Success'
`

## Azure Identity Protection Anomalous Token Activity
- id: `2224180806008651130`
- severity: Medium
- status: Active
- description: Detects anomalous token activity in Microsoft Entra ID environments using Identity Protection risk detections. Adversaries may abuse stolen or forged tokens to maintain persistence, bypass authentication mechanisms, or move laterally without repeatedly authenticating with valid c
- query: `dataSource.name = 'Azure Platform' and unmapped.operationName = 'User Risk Detection' and unmapped.properties.riskEventType contains 'anomalousToken' and not (unmapped.properties.riskDetail in ('aiConfirmedSigninSafe', 'adminConfirmedSigninSafe', 'adminDismissedAllRiskForUser'))
`

## Azure Identity Protection Primary Refresh Token Access Attempt
- id: `2294975366147937443`
- severity: High
- status: Active
- description: Detects attempts to access Microsoft Entra ID Primary Refresh Token (PRT) resource through Identity Protection risk detections. Adversaries who gain access to a PRT can abuse it to impersonate legitimate users, escalate privileges, and move laterally within an environment without
- query: `dataSource.name = 'Azure Platform' and unmapped.operationName = 'User Risk Detection' and unmapped.properties.riskEventType contains 'attemptedPrtAccess' and unmapped.properties.riskState in ('atRisk', 'confirmedCompromised')
`

## Azure Identity Protection Unusual User Activity - Threat Intelligence
- id: `2294975367095850210`
- severity: High
- status: Active
- description: Detects unusual user activity in Microsoft Entra ID using Identity Protection risk detections. This activity may include patterns that are atypical for the legitimate user or that align with known adversary tactics, such as anomalous sign-in behavior, risky access attempts, or ac
- query: `dataSource.name = 'Azure Platform' and unmapped.operationName = 'User Risk Detection' and unmapped.properties.riskEventType contains 'investigationsThreatIntelligence' and not (unmapped.properties.riskDetail in ('aiConfirmedSigninSafe', 'adminConfirmedSigninSafe', 'adminDismissed`

## Azure P2S VPN Gateway Modification
- id: `2046485288650800914`
- severity: Low
- status: Disabled
- description: Detects the modification of a Point-to-Site (P2S) VPN Gateway in Azure. P2S VPN Gateways enable secure remote access for users and administrators to Azure resources. Modifying a P2S VPN Gateway can disrupt connectivity, impacting operational continuity. This action may indicate m
- query: `dataSource.name = 'Azure Platform' and category_name = 'Application Activity' and unmapped.properties.message contains ('microsoft.network/p2svpngateways/write', 'microsoft.network/p2svpngateways/reset/action', 'microsoft.network/p2svpngateways/generatevpnprofile/action', 'micros`

## Azure SQL Server Firewall Rule Deletion
- id: `2053136761938950616`
- severity: Medium
- status: Active
- description: Detects the deletion of firewall rules from Azure SQL Servers. Firewall rules control access to the SQL server by specifying allowed IP address ranges. These rules are configured at the server level within Azure to protect databases from unauthorized access. Attackers with suffic
- query: `dataSource.name = 'Azure Platform' and category_name = 'Application Activity' and unmapped.properties.message contains 'microsoft.sql/servers/firewallrules/delete' and unmapped.resultType = 'Success'
`

## Azure Storage Account Default Network Access Enabled
- id: `2103845149957363965`
- severity: High
- status: Active
- description: Detects when the firewall configuration of an Azure Storage Account is set to allow default access, effectively disabling its firewall protection. Default network access in Azure Storage Accounts determines whether all traffic, including from the public internet, is permitted by 
- query: `dataSource.name = 'Azure Platform' and api.operation = 'MICROSOFT.STORAGE/STORAGEACCOUNTS/WRITE' and unmapped.properties.requestbody matches 'bypass.{3}AzureServices.{3}defaultAction.{3}Allow'
`

## Cato Networks Anti-Malware Rule Match
- id: `2386410262244596227`
- severity: Low
- status: Disabled
- description: Detects file transfers that matched a configured anti-malware policy rule in Cato Network. A rule match typically indicates deliberate blocking based on file characteristics, behavior patterns, or policy-defined restrictions, helping enforce organizational security controls.
- query: `dataSource.name = 'Cato Networks' and event.type = 'Security' and metadata.log_name contains 'NG Anti Malware' and risk_details = 'match'
`

## Cato Networks DNS Blocked IP Observed in Allowed Traffic
- id: `2437001241425474703`
- severity: Low
- status: Disabled
- description: Detects destination IPs that were blocked by DNS protection but later allowed by the Internet firewall. This correlation highlights potential attempts to bypass DNS security controls, indicating suspicious or unauthorized access that may be used for data exfiltration, command-and
- query: ``

## Cato Networks Malicious File Detected
- id: `2386410262252984836`
- severity: Medium
- status: Active
- description: Detects file transfers flagged as malicious by Cato Network’s anti-malware inspection. A malicious verdict indicates the file matches known malware characteristics or high-confidence indicators and was blocked before reaching the destination. This behavior typically reflects an a
- query: `dataSource.name = 'Cato Networks' and event.type = 'Security' and metadata.log_name contains 'NG Anti Malware' and risk_details = 'virus_found'
`

## Cato Networks Multiple Anti-Malware Alerts from Single Host
- id: `2437001241475806356`
- severity: Medium
- status: Active
- description: Detects multiple anti-malware events generated by the same device within a short period. A rapid series of detections may indicate an active infection, automated malware propagation, or repeated attempts to download malicious content. In Cato Networks, multiple alerts in quick su
- query: ``

## Cato Networks Repeated Malicious File Download Attempts
- id: `2437001241408697486`
- severity: Medium
- status: Active
- description: Detects when the same endpoint repeatedly attempts to download the same file identified as potential malware within a short window. This behavior often indicates a user ignoring warnings, social engineering influence, or malware delivery attempts where the attacker prompts multip
- query: ``

## Cato Networks Suspicious TLS Errors on Allowed HTTPS Traffic
- id: `2437001241467417747`
- severity: Low
- status: Disabled
- description: Detects destination IPs where outbound HTTPS traffic (port 443) is allowed by the Internet Firewall but TLS inspection reports certificate validation problems such as unknown certificate authority, bad certificate, or expired certificate. This correlation highlights potentially m
- query: ``

## Check Point NGFW Allowed Access to Spyware or Malicious Sites
- id: `2315201548990070899`
- severity: High
- status: Active
- description: Detects events where the Check Point next-generation firewall permits traffic to applications or destinations categorized as 'spyware' or 'malicious sites'. Such allowed flows can indicate policy gaps or misconfigurations that enable potential command-and-control, malware deliver
- query: `dataSource.name = 'Check Point Next Generation Firewall' and (unmapped.app_properties contains 'Spyware' or unmapped.app_properties contains 'Malicious Sites') and (unmapped.app_properties contains 'Critical Risk' or unmapped.app_properties contains 'High risk') and unmapped.acti`

## Check Point NGFW Allowed Critical Risk Traffic
- id: `2315201548998459508`
- severity: Medium
- status: Active
- description: Detects Check Point Next Generation Firewall events where traffic rated as critical severity was permitted by policy. This condition indicates risk acceptance or misconfiguration that allows high-impact threats or high-risk applications to traverse protected segments, increasing 
- query: `dataSource.name = 'Check Point Next Generation Firewall' and unmapped.app_properties contains 'Critical Risk' and unmapped.action in ('Allow','Accept')
`

## Check Point NGFW Allowed Download of Executables or Scripts
- id: `2315201549015236725`
- severity: Low
- status: Disabled
- description: Detects allowed downloads of executable or script files as reported by Check Point NGFW telemetry. This activity can indicate potential malware delivery, weak content filtering, or policy gaps enabling risky file transfer from untrusted sources. The alert highlights exposure poin
- query: `dataSource.name = 'Check Point Next Generation Firewall' and (evidences\[0\].connection_info.direction = 'outbound') and unmapped.action in ('Allow','Accept') and event.type in ('URL Filtering', 'Application Control', 'Anti Malware', 'New Anti Virus', 'Smart Defense') and (unmapp`

## Check Point NGFW Allowed Egress to Anonymizer Services
- id: `2315201549023625334`
- severity: Medium
- status: Active
- description: Detects Check Point NGFW events where outbound access to anonymizer services such as public VPNs, web proxies, or Tor is allowed by policy. Such egress can enable command-and-control obfuscation, data exfiltration, and evasion of network-based controls by masking source attributi
- query: `dataSource.name = 'Check Point Next Generation Firewall' and (evidences\[0\].connection_info.direction = 'outbound') and unmapped.action in ('Allow','Accept') and unmapped.app_properties contains 'Anonymizer'
`

## Check Point NGFW Allowed Outbound SMB Traffic
- id: `2315201549073956988`
- severity: Medium
- status: Active
- description: Detects firewall events where a Check Point NGFW permits outbound SMB traffic from internal hosts to external networks. Exposing SMB beyond the perimeter is high risk and can facilitate data exfiltration, credential exposure, or malware propagation, often indicating weak egress c
- query: `dataSource.name = 'Check Point Next Generation Firewall' and event.type = 'VPN-1 & FireWall-1' and evidences\[0\].connection_info.direction = 'outbound' and unmapped.action in ('Allow','Accept') and (evidences\[0\].connection_info.protocol_name in ('SMB','CIFS') or evidences\[0\]`

## Check Point NGFW Allowed Outbound Threat Events
- id: `2315201549032013943`
- severity: High
- status: Active
- description: Detects outbound traffic on Check Point Next Generation Firewalls that is flagged as malicious by threat prevention yet permitted by the access policy. This condition indicates a potential egress control gap or detect-only posture that could enable command and control, malware re
- query: `dataSource.name = 'Check Point Next Generation Firewall' and evidences\[0\].connection_info.direction = 'outbound' and unmapped.action in ('Allow','Accept') and unmapped.attack = *
`

## Check Point NGFW Allowed Peer-to-Peer Application Connections
- id: `2315201549040402552`
- severity: High
- status: Active
- description: Detects events where a Check Point Next Generation Firewall permits peer-to-peer application connections. This activity is security-relevant because P2P traffic can enable data exfiltration, shadow IT, and evasion of traditional network controls, indicating a potential policy gap
- query: `dataSource.name = 'Check Point Next Generation Firewall' and (unmapped.app_properties contains 'P2P File Sharing' or unmapped.app_properties contains 'BitTorrent protocol') and (unmapped.app_properties contains 'High risk' or unmapped.app_properties contains 'Critical Risk') and `

## Check Point NGFW High-Severity Threat Traffic Permitted
- id: `2315201549048791161`
- severity: Low
- status: Disabled
- description: Detects Check Point Next-Generation Firewall events where network traffic rated as high-severity risk was permitted by policy. This condition indicates a potential control gap or misconfiguration allowing likely malicious or highly suspicious communications, increasing exposure t
- query: `dataSource.name = 'Check Point Next Generation Firewall' and unmapped.app_properties contains 'High risk' and unmapped.action in ('Allow','Accept')
`

## Check Point NGFW HTTP Traffic Permitted on Non-Standard Ports
- id: `2315201549057179770`
- severity: Info
- status: Disabled
- description: Detects HTTP traffic permitted by Check Point NGFW policies on non-standard ports, indicating permissive or misconfigured access controls. Such allowances expand the attack surface and can enable protocol evasion, command and control, or data exfiltration over atypical service po
- query: `dataSource.name = 'Check Point Next Generation Firewall' and event.type = 'VPN-1 & FireWall-1' and unmapped.action in ('Allow','Accept') and evidences\[0\].connection_info.protocol_name = 'HTTP' and not (evidences\[0\].src_endpoint.svc_name in (80,443,8080,8443))
`

## Check Point NGFW Permitted Outbound RDP Traffic
- id: `2315201549090734205`
- severity: High
- status: Active
- description: Detects instances where the Check Point next-generation firewall allowed outbound Remote Desktop Protocol traffic from internal hosts to external destinations. This behavior is security-relevant because RDP egress can enable unauthorized remote access, facilitate lateral movement
- query: `dataSource.name = 'Check Point Next Generation Firewall' and event.type = 'VPN-1 & FireWall-1' and evidences\[0\].connection_info.direction = 'outbound' and unmapped.action in ('Allow','Accept') and (evidences\[0\].connection_info.protocol_name = 'RDP' or evidences\[0\].src_endpo`

## Check Point NGFW Remote Administration Allowed (Critical Risk)
- id: `2315201549065568379`
- severity: High
- status: Active
- description: Detects a Check Point next-generation firewall configuration or event state where remote administrative access is allowed, elevating exposure of management services. This condition is security-relevant because it expands the attack surface and can enable unauthorized control-plan
- query: `dataSource.name = 'Check Point Next Generation Firewall' and evidences\[0\].connection_info.direction = 'outbound' and unmapped.app_properties contains 'Remote Administration' and unmapped.app_properties contains 'Critical Risk' and unmapped.action in ('Allow','Accept')
`

## Cisco Duo User Account Deletion
- id: `2254458687471207496`
- severity: Low
- status: Disabled
- description: Detects when a user is deleted from Cisco Duo. This action could be routine (e.g., user offboarding), but may also indicate malicious activity if performed unexpectedly or by an unauthorized administrator. Deleting a user removes their MFA protection, which could be used to evade
- query: `dataSource.name = 'Cisco Duo' and unmapped.action = 'user_delete'
`

## Cisco FTD Allowed Remote Access Software Detected
- id: `2396577443328196316`
- severity: Info
- status: Disabled
- description: Detects allowed network connections identified by Cisco Secure Firewall Threat Defense (FTD) that are associated with remote administration or remote desktop protocols. Adversaries may abuse remote access tools and protocols to gain interactive access, perform lateral movement, o
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Open' and status = 'Allow' and ((unmapped.Client contains ('remote admin', 'remote desktop')) or (unmapped.ApplicationProtocol contains ('remote admin', 'remote desktop'))) 
`

## Cisco FTD Binary File Type Download
- id: `2396577443344973533`
- severity: Info
- status: Disabled
- description: Detects file download events through Cisco Secure Firewall Threat Defense (FTD) involving executable file types such as scripts, binaries, shortcut files, and installer formats. Adversaries frequently use these file types to deliver malware, droppers, or secondary payloads throug
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'File events' and unmapped.FileDirection = 'Download' and unmapped.FileType in:anycase ('ISHIELD_MSI', 'BINHEX', 'BINARY_DATA', 'ELF', 'MACHO', 'JARPACK', 'TORRENT', 'AUTORUN', 'EICAR', 'SCR', 'UNIX_SCRIPT') and n`

## Cisco FTD File Sharing Domain Accessed
- id: `2396577443353362142`
- severity: Medium
- status: Active
- description: Detects outbound connections identified by Cisco Secure Firewall Threat Defense (FTD) to known public file hosting, pastebin, temporary storage, and content delivery services. Adversaries commonly abuse these platforms to host malware payloads, stage tools, exfiltrate data, or re
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Open' and url.url_string contains ('objects.githubusercontent.com', 'anonfiles.com', 'cdn.discordapp.com', 'ddns.net', 'dl.dropboxusercontent.com', 'ghostbin.co', 'glitch.me', 'gofile.io', 'hastebin.com', 'mediaf`

## Cisco FTD High Volume Blocked Connection Attempts
- id: `2396577416711141903`
- severity: Low
- status: Disabled
- description: Detects a high number of blocked network connection attempts reported by Cisco Secure Firewall Threat Defense (FTD). A surge in blocked connections may indicate reconnaissance, port scanning, brute-force attempts, or automated attack activity targeting the environment. Monitoring
- query: ``

## Cisco FTD High-Volume Intrusion Events Detected
- id: `2396577416694364686`
- severity: High
- status: Active
- description: Detects a high frequency of intrusion events reported by Cisco Secure Firewall Threat Defense (FTD) within a defined time window. A large volume of intrusion alerts may indicate coordinated attack activity, automated exploitation attempts, scanning behavior, or sustained maliciou
- query: ``

## Cisco FTD Insecure Legacy Protocol Accessed
- id: `2396577443437248229`
- severity: Low
- status: Disabled
- description: Detects outbound TCP connections identified by Cisco Secure Firewall Threat Defense (FTD) to legacy and insecure service ports such as Telnet (23), POP3 (110), and IMAP (143). These protocols transmit data in cleartext and are commonly targeted or abused by adversaries for creden
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Open' and connection_info.protocol_name = 'tcp' and dst_endpoint.port in (143, 23, 110) and status contains 'Allow'
`

## Cisco FTD Known Client Side Exploit Attempt Detected
- id: `2396577443470802664`
- severity: High
- status: Active
- description: Detects attempts to exploit known client-side vulnerabilities as identified by Cisco Secure Firewall Threat Defense (FTD). Adversaries may target web browsers, email clients, or other client applications to execute malicious code on the endpoint. Monitoring for these events helps
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and status_detail = 'Known client side exploit attempt' and unmapped.InlineResult = 'Alert'
`

## Cisco FTD Known Malware C2 Traffic
- id: `2396577443370139359`
- severity: High
- status: Active
- description: Detects network traffic identified by Cisco Secure Firewall Threat Defense (FTD) as communicating with known malware command and control (C2) servers. This activity may indicate a compromised host attempting to establish or maintain contact with an attacker-controlled infrastruct
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and status_detail = 'Known malware command and control traffic'
`

## Cisco FTD Large Scale Information Leak
- id: `2396577443495968490`
- severity: High
- status: Active
- description: Detects attempts to exfiltrate sensitive information from the network as identified by Cisco Secure Firewall Threat Defense (FTD). Large-scale information leak activity may involve repeated access to confidential data, emails, or files over various protocols. Monitoring for these
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and status_detail = 'Large Scale Information Leak'
`

## Cisco FTD Lumma Stealer Activity
- id: `2396577443504357099`
- severity: High
- status: Active
- description: Detects intrusion events generated by Cisco Secure Firewall Threat Defense (FTD) that match a set of intrusion signature IDs associated with Lumma Stealer malware activity. Lumma Stealer is a credential-harvesting and information-stealing malware commonly used to exfiltrate brows
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and unmapped.SID in (64797, 64798, 64799, 64800, 64801)
`

## Cisco FTD Malicious File Detected
- id: `2396577443378527968`
- severity: High
- status: Active
- description: Detects the identification of a malicious file by Cisco Secure Firepower Threat Defense (FTD). This may indicate the presence of malware or potentially unwanted software within the network. Monitoring these detections helps identify compromised hosts, prevent further infection, a
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'File events' and unmapped.FileDirection = 'Download' and unmapped.SHA_Disposition = 'MALWARE'
`

## Cisco FTD Malicious File or Exploit Detected
- id: `2396577443479191273`
- severity: High
- status: Active
- description: Detects intrusion events where Cisco Secure Firewall Threat Defense (FTD) identifies a known malicious file or file-based exploit. Such activity may indicate attempts to compromise endpoints or servers using malware, trojans, or exploit kits. Monitoring these events helps in earl
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and status_detail = 'Known malicious file or file based exploit' and unmapped.InlineResult = 'Alert'
`

## Cisco FTD Multiple Malicious File Downloads
- id: `2396577416669198860`
- severity: High
- status: Active
- description: Detects multiple file download events identified as malware by Cisco Secure Firewall Threat Defense (FTD). A high volume of malicious file downloads within a short period may indicate active malware delivery, drive-by downloads, or automated payload retrieval by compromised hosts
- query: ``

## Cisco FTD Multiple Privilege Escalation Attempts Detected
- id: `2396577416736307729`
- severity: High
- status: Active
- description: Detects multiple intrusion events reported by Cisco Secure Firewall Threat Defense (FTD) indicating attempted privilege escalation activity. Adversaries may attempt to exploit vulnerabilities or misconfigurations to gain elevated privileges, enabling deeper system access, lateral
- query: ``

## Cisco FTD Multiple Suspicious File Upload Activity
- id: `2396577416719530512`
- severity: Medium
- status: Active
- description: Detects multiple attempts to upload potentially malicious or suspicious files through Cisco Secure Firewall Threat Defense (FTD). Frequent uploads of unusual file types or files may indicate data exfiltration attempts, malware deployment, or misuse of network resources. Monitorin
- query: ``

## Cisco FTD Network Scan Detected
- id: `2396577443445636838`
- severity: Medium
- status: Active
- description: Detects network scanning activity identified by Cisco Secure Firepower Threat Defense (FTD) devices. Network scans may indicate reconnaissance efforts by attackers attempting to discover active hosts, open ports, or vulnerabilities within the network. Monitoring these alerts help
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and status_detail = 'Detection of a Network Scan' and unmapped.InlineResult = 'Alert'
`

## Cisco FTD Network Trojan Detected
- id: `2396577443386916577`
- severity: High
- status: Active
- description: Detects network traffic identified by Cisco Secure Firepower Threat Defense (FTD) as indicative of a trojan infection. This may signal the presence of malware attempting to establish command and control, exfiltrate data, or perform other malicious activities. Monitoring these det
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and status_detail = 'A Network Trojan was Detected' and unmapped.InlineResult = 'Alert'
`

## Cisco FTD Outbound LDAP Connection to External Network
- id: `2396577443529522925`
- severity: Low
- status: Disabled
- description: Detects allowed outbound LDAP or LDAPS connections from internal hosts to external IP addresses using Cisco Secure Firewall Threat Defense (FTD) telemetry. LDAP (port 389) and LDAPS (port 636) are typically used for directory services within trusted internal networks. Adversaries
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Open' and status contains 'Allow' (dst_endpoint.port = 389 or dst_endpoint.port = 636 or unmapped.ApplicationProtocol = 'LDAP') and not(dst_endpoint.ip matches '^(?:10\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[0-1])`

## Cisco FTD Outbound SMB Connection to External Network
- id: `2396577443512745708`
- severity: Low
- status: Disabled
- description: Detects outbound SMB network connections identified by Cisco Secure Firewall Threat Defense (FTD) originating from internal private IP addresses and communicating with external, non-private destinations. SMB traffic over ports 139 or 445 is typically intended for internal network
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Open' and status contains 'Allow' and (dst_endpoint.port=139 or dst_endpoint.port=445 or unmapped.Client contains 'SMB') and src_endpoint.ip matches '^(?:10\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[0-1])\\.)' and n`

## Cisco FTD Potential WebVPN Exploitation Attempt
- id: `2477524494895992510`
- severity: High
- status: Disabled
- description: Detects potential exploitation attempts targeting the Cisco Secure Firewall ASA and Firepower Threat Defense (FTD) WebVPN component. CVE-2025-20362 is a missing-authorization path-traversal flaw that allows unauthenticated access to restricted WebVPN endpoints via path normalizat
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and ((event.type='Intrusion event' and unmapped.SID in (65340, 46897)) or (event.type = 'Open' and unmapped.URL contains ('+CSCOU+/../+CSCOE+', '+CSCOU+//../+CSCOE+', '+CSCOU+%2f..%2f+CSCOE+', '+CSCOU+/%2e%2e/+CSCOE+', '+CSCOU+/..`

## Cisco FTD Repeated Attempts of Information Leak
- id: `2396577416744696338`
- severity: High
- status: Active
- description: Detects multiple attempts to exfiltrate sensitive information or data through the network, as identified by Cisco Secure Firewall Threat Defense (FTD). Repeated information leak attempts may indicate reconnaissance, automated data exfiltration, or insider threat activity. Monitor
- query: ``

## Cisco FTD Successful Privilege Escalation
- id: `2396577443462414055`
- severity: High
- status: Active
- description: Detects a successful privilege escalation activity identified by Cisco Secure Firepower Threat Defense (FTD) where an account has gained elevated privileges (administrator or user). Such activity may indicate that an adversary has successfully exploited a vulnerability, misconfig
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Intrusion event' and status_detail in ('Successful Administrator Privilege Gain', 'Successful User Privilege Gain')
`

## Cisco FTD Suspicious BITS Network Activity
- id: `2396577443403693794`
- severity: Medium
- status: Active
- description: Detects network connections initiated by the Background Intelligent Transfer Service (BITS) as identified by Cisco Secure Firewall Threat Defense (FTD). Adversaries may abuse BITS to stealthily download or upload malicious payloads, evade detection, and maintain persistence by le
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Open' and unmapped.Client contains 'BITS' and not (url.url_string contains '//msedge.b.tlu.dl') and not (unmapped.WebApplication in ('Microsoft Update', 'Microsoft'))
`

## Cisco FTD Suspicious File Download Over Non-Standard Port
- id: `2396577443412082403`
- severity: Info
- status: Disabled
- description: Detects file download activity identified by Cisco Secure Firewall Threat Defense (FTD) where high-risk or executable file types are transferred over non-standard ports. Adversaries may leverage uncommon ports to evade network security controls and deliver malicious payloads such
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'File events' and unmapped.FileDirection = 'Download' and not (dst_endpoint.port in (443, 80, 445)) and unmapped.FileType in:anycase ('MSEXE', 'LNK', 'ISHIELD_MSI', 'BINHEX', 'BINARY_DATA', 'ELF', 'MACHO', 'JARPAC`

## Cisco FTD TOR Network Connection Detected
- id: `2396577443428859620`
- severity: High
- status: Active
- description: Detects network connections identified as TOR traffic by Cisco Secure Firewall Threat Defense (FTD). The Tor network is commonly used to anonymize network activity and evade monitoring controls. Adversaries may leverage Tor to conceal command-and-control communications, exfiltrat
- query: `dataSource.name = 'Cisco Firewall Threat Defense' and event.type = 'Open' and status contains 'Allow' and (unmapped.Client = 'TOR' or unmapped.ApplicationProtocol = 'TOR')
`

## CyberArk EPM Multiple Execution Attempts from Blocked File
- id: `2426879487778851122`
- severity: Low
- status: Disabled
- description: Detects 10 or more Block events involving the same file hash executed by a standard user in a span of 10 minutes. Multiple execution attempts of an identical binary indicate persistence, automated retry behavior, or scripted execution attempts following enforcement denial. Attack
- query: ``

## CyberArk EPM Multiple Threat Protection Events From Same Process
- id: `2426879487745296687`
- severity: Low
- status: Disabled
- description: Detects repeated AttackAttempt or SuspiciousActivityAttempt events associated with the same process file hash in a 10 minute window. When a single executable repeatedly triggers privileged threat protection mechanisms, it may indicate automated credential probing, scripted post-e
- query: ``

## Darktrace Beacon Activity Detected
- id: `2335486727793230374`
- severity: Medium
- status: Active
- description: Detects a device repeatedly connecting to external or internal hosts. This is commonly seen during botnet compromise activity. An adversary can abuse this behavior by establishing a Command and Control (C2) channel where the compromised endpoint periodically connects back to an a
- query: `dataSource.name = 'Darktrace' and category_name = 'Findings' and event.type = 'Create' and unmapped.model.then.name contains 'Beacon'
`

## Delete RDP History via Command Line Execution
- id: `2224179665292157626`
- severity: High
- status: Active
- description: Detects attempts to delete Remote Desktop Protocol (RDP) connection history files or related registry entries via command-line utilities such as 'powershell.exe' or 'cmd.exe' on Windows endpoints. This rule identifies process or script executions that invoke deletion commands tar
- query: `dataSource.name = 'SentinelOne' AND endpoint.os = 'windows' AND event.type in ('Process Creation', 'Command Script') AND (src.process.name in:anycase ('powershell.exe', 'cmd.exe') OR src.process.displayName in:anycase ('Windows PowerShell', 'Windows Command Processor')) AND (src.`

## Doppelganger LSASS Credential Dumper Tool
- id: `2274626946071702620`
- severity: High
- status: Active
- description: Detects presence of the Doppelganger tool used for dumping credentials from the LSASS process. This activity is indicative of credential access attempts, a common objective in post-exploitation stages by adversaries seeking lateral movement or privilege escalation. The use of spe
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('Process Creation', 'Command Script', 'File Creation', 'File Modification') and (src.process.image.originalFileName in:anycase ('Doppelganger.exe') or src.process.name in:anycase ('Doppelganger.exe') o`

## EKS Container Created with Host Namespace Access
- id: `2305247540862189554`
- severity: High
- status: Active
- description: Detects the creation or modification of Kubernetes resources with host namespace access within Amazon EKS clusters. This detection specifically monitors for pods, deployments, daemonsets, jobs, replicasets, statefulsets, cronjobs, and replication controllers where hostIPC=true, h
- query: `dataSource.name = 'EKS Logs' and http_request.http_method in ('create', 'update', 'patch') and ((unmapped.responseObject.spec.template.spec.hostIPC = true or unmapped.requestObject.spec.template.spec.hostIPC = true or unmapped.responseObject.spec.hostIPC = true or unmapped.respon`

## EKS HorizontalPodAutoscaler Configuration Modified or Deleted
- id: `2335486728229438019`
- severity: Medium
- status: Active
- description: Detects the deletion or modification of HorizontalPodAutoscaler resources within an Amazon Elastic Kubernetes Service (EKS) cluster. HorizontalPodAutoscalers are Kubernetes resources that automatically scale the number of pod replicas based on observed CPU utilization or other se
- query: `dataSource.name = 'EKS Logs' and http_request.http_method in ('delete', 'patch', 'update') and not (actor.user.name matches '^(system|eks):') and resources.type = 'horizontalpodautoscalers'
`

## ESXi Audit Log Configuration Modification
- id: `2274626943588674523`
- severity: Medium
- status: Active
- description: Detects attempts to modify or delete audit logs on ESXi hosts via esxcli. Such activity may indicate efforts by adversaries to tamper with forensic evidence or conceal unauthorized actions within the virtualized environment. Attackers often target audit logs to disrupt incident r
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.name = 'esxcli' and tgt.process.cmdline contains ' config' and tgt.process.cmdline contains ' syslog' and tgt.process.cmdline contains ' set'
`

## ESXi Firewall Configuration Modification
- id: `2274626943613840349`
- severity: Medium
- status: Active
- description: Detects changes to the ESXi firewall configuration outside of standard administrative operations via esxcli. Unauthorized or unexpected modifications to firewall settings may indicate an attempt to weaken host defenses or facilitate lateral movement within the virtualized environ
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.name = 'esxcli' and tgt.process.cmdline contains ' network' and tgt.process.cmdline contains ' firewall' and not (tgt.process.cmdline contains (' list', ' get'))
`

## ESXi User Account Management Activity
- id: `2274626943378959311`
- severity: Low
- status: Disabled
- description: Detects creation, modification, or deletion of user accounts on ESXi hosts using the esxcli. Unauthorized changes to ESXi user accounts may indicate adversary attempts to establish persistence, escalate privileges, or disrupt operations within the virtualized environment. Such ac
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.name = 'esxcli' and tgt.process.cmdline contains ' system' and tgt.process.cmdline contains ' account' and not (tgt.process.cmdline contains ' list')
`

## Execution of Non-Standard SSH Client Applications
- id: `2284866662831096848`
- severity: Low
- status: Disabled
- description: Detects the execution of non-native or third-party SSH client processes on endpoints. Such activity may indicate attempts to bypass standard security controls, establish unauthorized remote access, or evade monitoring solutions. Adversaries may leverage alternative SSH clients to
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'IP Connect' and event.network.protocolName = 'ssh' and ((src.process.name = 'remmina' and src.process.cmdline contains ('-t', '-c') and src.process.cmdline contains 'ssh') or (src.process.name = 'plink' a`

## File Download and Compile via osacompile
- id: `2264064068157885365`
- severity: High
- status: Active
- description: Detects the combination of curl and osacompile commands, which may indicate an adversary downloading AppleScript payloads and compiling them locally on macOS. While curl is a legitimate tool for retrieving content from the web, and osacompile is used to compile AppleScript script
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'osx' and event.type = 'Process Creation' and tgt.process.name contains 'curl' and tgt.process.cmdline contains 'osacompile'
`

## Fileless Data Exfiltration via Unsigned Process
- id: `2345712030960026405`
- severity: High
- status: Active
- description: Detects potential fileless data exfiltration activity where unsigned processes exhibit behaviors commonly associated with advanced adversary techniques. This includes the use of obfuscated or encoded commands to evade detection, suspicious discovery actions that may indicate reco
- query: ``

## Firewall Disabled via PowerShell
- id: `2264064069760109874`
- severity: Medium
- status: Active
- description: Detects the execution of a command that programmatically disables the system's firewall by modifying its configuration settings to turn off protection. Disabling the firewall in this manner can be a deliberate action by an adversary seeking to weaken the system's security posture
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Command Script' and ((src.process.name in:anycase ('powershell.exe') or src.process.displayName = 'Windows PowerShell')) and cmdScript.content contains 'Set-NetFirewallProfile' and cmdScript.content mat`

## First Seen Firewall Disabled via Systemctl Utility
- id: `2396577457119068541`
- severity: Low
- status: Disabled
- description: Detects the first instance of disabling the iptables or firewall service using the systemctl utility by a user in a 24 hours window . Disabling firewall protections can be abused by attackers to bypass network controls, gain unauthorized access, and conduct malicious activities, 
- query: ``

## First Seen GCP Firewall Deletion
- id: `2154661691319341086`
- severity: Medium
- status: Active
- description: Detects the first instance of a firewall rule being deleted in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine by a specific user identity within a 7-day window. Firewall rules are essential for enforcing network security policies, and unauthorized delet
- query: ``

## First Seen PANW Firewall GlobalProtect Login from a Country
- id: `2396577458410914240`
- severity: Medium
- status: Active
- description: Detects the initial occurrence of a successful login via Palo Alto Networks GlobalProtect originating from a previously unseen country within a 7-day period. Such activity may signify anomalous behavior, as adversaries often exploit compromised credentials to access accounts from
- query: ``

## First Seen PANW Firewall LDAP Traffic to Public IP
- id: `2396577458385748414`
- severity: Medium
- status: Active
- description: Detects the first instance of LDAP traffic to an external IP in a 7 day window. LDAP traffic is commonly used for directory services within an organization. LDAP traffic to public IP addresses could indicate data exfiltration attempts by malicious actors.
- query: ``

## First Seen PANW Firewall RDP Connection from a Country
- id: `2396577458419302849`
- severity: Medium
- status: Active
- description: Detects the first instance of Remote Desktop Protocol (RDP) traffic originating from a country in a 7 day window. This rule highlights potentially anomalous activity. An adversary can utilize this to establish unauthorized remote access, indicating a possible system compromise or
- query: ``

## First Seen PANW Firewall SMB Traffic to Public IP
- id: `2396577458402525631`
- severity: Medium
- status: Active
- description: Detects the first instance of SMB traffic to an external IP in a 7 day window. Adversaries can abuse the SMB protocol to transfer large volumes of data from compromised internal systems to external servers under their control. This exfiltration can be performed covertly and may i
- query: ``

## FortiGate Admin User Created from Public IP
- id: `2360963577510041860`
- severity: Medium
- status: Active
- description: Detects the creation of a new administrator user account on a Fortinet FortiGate device originating from a public IP address. An adversary who gains access to the management interface may create unauthorized admin accounts to establish persistent, privileged control over the fire
- query: `dataSource.name = 'FortiGate' and event.type = 'system' and unmapped.logdesc = 'Object attribute configured' and unmapped.action = 'Add' and unmapped.cfgpath = 'system.admin' and unmapped.ui matches '^[^()]+\\((?!(?:10\\.|169\\.254\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[0-1])\\.|`

## FortiGate Firewall Virus Detected
- id: `2254458688150684782`
- severity: High
- status: Active
- description: Detects the virus in the network identified by FortiGate Firewall. This may indicate the presence of malware or a malicious file attempting to execute or transfer within the network. Threat actors may use malware to gain access, maintain persistence, or exfiltrate data. Monitorin
- query: `dataSource.name = 'FortiGate' and event.type = 'virus' and unmapped.eventtype in ('infected', '0-day-malware-stream', 'exempt-hash', 'inline-block', 'malware-list', 'mimefragmented', 'unknown-ce') and unmapped.level != 'information' and not (unmapped.action in ('blocked', 'attach`

## FortiGate FortiWeb Path Traversal Vulnerability Exploitation Attempt
- id: `2360963577317103829`
- severity: High
- status: Active
- description: Detects potential exploitation attempts targeting CVE-2025-64446, a critical path traversal vulnerability affecting Fortinet FortiWeb Web Application Firewalls (WAF). An adversary can abuse this flaw, which requires no authentication, to create new, unauthorized administrative us
- query: `dataSource.name = 'FortiGate' and http_request.http_method = 'POST' and unmapped.url matches '(?:\\/system\\/admin%3F\\/)(?:(?:\\.\\.\\/)+)(?:cgi-bin\\/fwbcgi)' and not (unmapped.action in ('blocked', 'block', 'reset', 'drop', 'dropped'))
`

## FortiGate Suspicious Config File Access from External Network
- id: `2360963577199663286`
- severity: Medium
- status: Active
- description: Detects attempts to download a FortiGate configuration file from an external or publicly accessible network source. Adversaries may abuse this behavior to obtain sensitive configuration data, including administrative credentials, network topology details, VPN settings, or firewal
- query: `dataSource.name = 'FortiGate' and unmapped.msg contains 'System config file has been downloaded' and status_detail = 'success' and unmapped.ui matches '^[^()]+\\((?!(?:10\\.|127\\.|169\\.254\\.|192\\.168\\.|172\\.(?:1[6-9]|2\\d|3[0-1])\\.|100\\.(?:6[4-9]|[7-9]\\d|1[0-1]\\d|12[0-7`

## FortiGate WAF Blocked Application by HTTP Constraints
- id: `2254458688192627825`
- severity: Low
- status: Active
- description: Detects instances where the FortiGate Web Application Firewall (WAF) has blocked HTTP requests due to violations of configured HTTP protocol constraints. While such blocks may result from legitimate misconfigurations or user errors, repeated or unexpected occurrences could indica
- query: `dataSource.name = 'FortiGate' and unmapped.eventtype = 'waf-http-constraint' and unmapped.action = 'blocked'
`

## FortiGate WAF Blocked Application via Address List
- id: `2254458688159073391`
- severity: Low
- status: Active
- description: Detects instances where the FortiGate Web Application Firewall (WAF) blocks application access based on entries in a configured address list. While this may be part of normal security operations, repeated or unexpected blocks could indicate attempted access from unauthorized or m
- query: `dataSource.name = 'FortiGate' and unmapped.eventtype = 'waf-address-list' and unmapped.action = 'blocked'
`

## FortiGate WAF Blocked Application via Custom Signature
- id: `2254458688175850608`
- severity: Low
- status: Active
- description: Detects instances where the FortiGate Web Application Firewall (WAF) has blocked application traffic based on a custom signature. This may indicate an attempt to exploit a known or organization-specific vulnerability, unauthorized access, or malicious activity targeting web appli
- query: `dataSource.name = 'FortiGate' and unmapped.eventtype = 'waf-custom-signature' and unmapped.action = 'blocked'
`

## FortiGate WAF Blocked Application via HTTP method
- id: `2254458688201016434`
- severity: Low
- status: Active
- description: Detects instances where the FortiGate Web Application Firewall (WAF) has blocked an application request based on the HTTP method used. This may indicate attempts to exploit vulnerabilities or bypass security controls using disallowed or suspicious HTTP methods. Monitoring these e
- query: `dataSource.name = 'FortiGate' and unmapped.eventtype = 'waf-http-method' and unmapped.action = 'blocked'
`

## FortiGate WAF Blocked Application via URL Access
- id: `2254458688217793651`
- severity: Low
- status: Active
- description: Detects instances where the FortiGate Web Application Firewall (WAF) has blocked access to an application based on URL filtering policies. This may indicate attempts to access restricted or malicious URLs, potential policy violations, or unauthorized access attempts. Monitoring t
- query: `dataSource.name = 'FortiGate' and unmapped.eventtype = 'waf-url-access' and unmapped.action = 'blocked'
`

## Fortinet FortiGate Suspicious Super Admin Login Detected
- id: `2193712726292685897`
- severity: Medium
- status: Active
- description: Detects a super admin login attempt to a FortiGate firewall originating from a suspicious or public IP address. This may indicate an attempt to exploit CVE-2025-24472 which allows unauthenticated attackers to gain super admin privileges on vulnerable FortiOS devices (<7.0.16) wit
- query: `dataSource.name = 'FortiGate' and event.type = 'system' and unmapped.logdesc = 'Admin login successful' and unmapped.profile = 'super_admin' and unmapped.method = 'jsconsole' and status_detail = 'success' and not (unmapped.srcip matches '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|`

## GCP Cloud Armor WAF Security Policy Creation
- id: `2154659961495722872`
- severity: Low
- status: Disabled
- description: Detects the creation of a Web Application Firewall (WAF) security policy in Google Cloud Armor. Adversaries may create WAF policies to bypass security controls, manipulate traffic filtering rules, or establish persistence within the cloud environment. Unauthorized WAF policy crea
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.securityPolicies.insert$' and unmapped.severity != 'ERROR'
`

## GCP Cloud Armor WAF Security Policy Deletion
- id: `2046485289145729394`
- severity: High
- status: Active
- description: Detects the deletion of a Web Application Firewall (WAF) security policy in Google Cloud Armor. Adversaries may delete WAF policies to bypass security controls, manipulate traffic filtering rules, or establish persistence within the cloud environment. Unauthorized WAF policy dele
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.securityPolicies.delete$' and unmapped.severity != 'ERROR'
`

## GCP Cloud Armor WAF Security Policy Rule Creation
- id: `2154659965622919091`
- severity: Low
- status: Disabled
- description: Detects the creation of a rule in a Web Application Firewall (WAF) security policy in Google Cloud Armor. Adversaries may create WAF rules to bypass security controls, manipulate traffic filtering rules, or establish persistence within the cloud environment. Unauthorized WAF rule
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.securityPolicies.addRule$' and unmapped.severity != 'ERROR'
`

## GCP Cloud Armor WAF Security Policy Rule Deletion
- id: `2154659965622919092`
- severity: High
- status: Active
- description: Detects the deletion of a rule from a Web Application Firewall (WAF) security policy in Google Cloud Armor. Adversaries may delete WAF rules to weaken security controls, manipulate traffic filtering rules, or establish persistence within the cloud environment. Unauthorized WAF ru
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.securityPolicies.removeRule$' and unmapped.severity != 'ERROR'
`

## GCP Cloud Armor WAF Security Policy Rule Update
- id: `2154659965631307703`
- severity: Medium
- status: Active
- description: Detects the modification of a rule in a Web Application Firewall (WAF) security policy in Google Cloud Armor. Adversaries may modify WAF rules to bypass security controls, manipulate traffic filtering rules, or establish persistence within the cloud environment. Unauthorized WAF 
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.securityPolicies.patchRule$' and unmapped.severity != 'ERROR'
`

## GCP Cloud Armor WAF Security Policy Update
- id: `2154659965631307705`
- severity: Medium
- status: Active
- description: Detects the modification of a Web Application Firewall (WAF) security policy in Google Cloud Armor. Adversaries may modify WAF policies to bypass security controls, manipulate traffic filtering rules, or establish persistence within the cloud environment. Unauthorized WAF policy 
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.securityPolicies.patch$' and unmapped.severity != 'ERROR'
`

## GCP Firewall Rule Creation
- id: `2053136767123110422`
- severity: Low
- status: Disabled
- description: Detects the creation of a firewall rule in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. Firewall rules control network traffic and dictate which resources can communicate within the cloud environment. Unauthorized creation of firewall rules can expos
- query: `dataSource.name = 'GCP Audit' and api.service.name in ('compute.googleapis.com', 'appengine.googleapis.com') and unmapped.protoPayload.methodName matches ('compute.firewalls.insert', 'FirewallPolicies.insert', 'Firewall.Create') and unmapped.severity != 'ERROR'
`

## GCP Firewall Rule Creation to Allow Egress To Any IP Over Any RDP
- id: `2315201559324836401`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in GCP that permits egress traffic on TCP port 3389 (RDP) to any IPv4 or IPv6 destination. While RDP is primarily used for inbound remote access, egress rules enabling RDP may signal unusual behavior or attempts to establish unauthorized ex
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.(patch|update)$' and unmapped.protoPayload.resourceOriginalState.direction = 'EGRESS' and unmapped.protoPayload.request.destinationRanges `

## GCP Firewall Rule Creation to Allow Egress To Any IP Over Any SSH
- id: `2325323341599460430`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in GCP that enables egress traffic on TCP port 22 (SSH) to any IPv4 or IPv6 destination. Although SSH is typically used for inbound administration, allowing outbound SSH traffic can facilitate lateral movement, data exfiltration, or connect
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.(patch|update)$' and unmapped.protoPayload.resourceOriginalState.direction = 'EGRESS' and unmapped.protoPayload.request.destinationRanges `

## GCP Firewall Rule Creation to Allow Egress To Any IPv4 Over Any Protocol
- id: `2315201559316447792`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in Google Cloud Platform (GCP) that permits egress traffic to any IPv4 destination over any protocol. Such changes can enable unauthorized data exfiltration, communication with external command-and-control servers, or bypass of network segm
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.(patch|update)$' and unmapped.protoPayload.resourceOriginalState.direction = 'EGRESS' and unmapped.protoPayload.request.destinationRanges `

## GCP Firewall Rule Creation to Allow Egress To Any IPv6 Over Any Protocol
- id: `2325323341641403472`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in Google Cloud Platform (GCP) that permits egress traffic to any IPv6 destination over any protocol. Such changes can enable unauthorized data exfiltration, communication with external command-and-control servers, or bypass of network segm
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.insert$' and unmapped.protoPayload.request.direction = 'EGRESS' and unmapped.protoPayload.request.destinationRanges = '[::/0]' and unmappe`

## GCP Firewall Rule Creation to Allow Ingress From Any IP Over RDP
- id: `2325323341649792081`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in Google Cloud Platform (GCP) that allows ingress traffic on TCP port 3389 (Remote Desktop Protocol) from any IPv4 or IPv6 source. Such rules expose RDP services to the public internet, increasing the attack surface and risk of brute-force
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.(patch|update)$' and unmapped.protoPayload.resourceOriginalState.direction = 'INGRESS' and unmapped.protoPayload.request.sourceRanges in (`

## GCP Firewall Rule Creation to Allow Ingress From Any IP Over SSH
- id: `2325323341666569298`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in GCP allowing ingress traffic on TCP port 22 (SSH) from any IPv4 or IPv6 source. SSH exposure to the public internet significantly raises the risk of brute-force attacks and unauthorized remote access. Adversaries may exploit this configu
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.(patch|update)$' and unmapped.protoPayload.resourceOriginalState.direction = 'INGRESS' and unmapped.protoPayload.request.sourceRanges in (`

## GCP Firewall Rule Creation to Allow Ingress from Any IPv4 Over Any Protocol
- id: `2174786602718912383`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in Google Cloud Platform (GCP) that permits ingress traffic from any IPv4 source over any protocol. Such changes can expose resources to unauthorized access, lateral movement, and exploitation of publicly accessible services. Adversaries ma
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.insert$' and unmapped.protoPayload.request.direction = 'INGRESS' and unmapped.protoPayload.request.sourceRanges = '[0.0.0.0/0]' and unmapp`

## GCP Firewall Rule Creation to Allow Ingress from Any IPv6 Over Any Protocol
- id: `2174786602718912388`
- severity: Medium
- status: Active
- description: Detects the creation of a firewall rule in Google Cloud Platform (GCP) that permits ingress traffic from any IPv6 source over any protocol. Such changes can expose resources to unauthorized access, lateral movement, and exploitation of publicly accessible services. Adversaries ma
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.insert$' and unmapped.protoPayload.request.direction = 'INGRESS' and unmapped.protoPayload.request.sourceRanges = '[::/0]' and unmapped.pr`

## GCP Firewall Rule Deletion
- id: `2053136767148276247`
- severity: Medium
- status: Active
- description: Detects the deletion of a firewall rule in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. Firewall rules control network traffic and dictate which resources can communicate within the cloud environment. Unauthorized deletion of firewall rules can expos
- query: `dataSource.name = 'GCP Audit' and api.service.name in ('compute.googleapis.com', 'appengine.googleapis.com') and unmapped.protoPayload.methodName contains ('compute.firewalls.delete', 'networkFirewallPolicies.delete', 'Firewall.Delete') and unmapped.severity != 'ERROR' and not (u`

## GCP Firewall Rule Modification
- id: `2053136767156664856`
- severity: Medium
- status: Active
- description: Detects modifications to firewall rules in Google Cloud Platform (GCP) for Virtual Private Cloud (VPC) or App Engine. Altering firewall rules can impact the flow of network traffic and may compromise security, allowing unauthorized access or malicious activities. Unauthorized or 
- query: `dataSource.name = 'GCP Audit' and api.service.name in ('compute.googleapis.com', 'appengine.googleapis.com') and unmapped.protoPayload.methodName contains ('compute.firewalls.patch', 'compute.firewalls.update', 'Firewall.Update') and unmapped.severity != 'ERROR' and not (unmapped`

## GCP Firewall Rule Modified to Allow Ingress from Any IPv4 Over Any Protocol
- id: `2103846149711694524`
- severity: Medium
- status: Active
- description: Detects the modification of a firewall rule in Google Cloud Platform (GCP) that permits ingress traffic from any IPv4 source over any protocol. Such changes can expose resources to unauthorized access, lateral movement, and exploitation of publicly accessible services. Adversarie
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.(patch|update)$' and unmapped.protoPayload.resourceOriginalState.direction = 'INGRESS' and unmapped.protoPayload.request.sourceRanges = '[`

## GCP Firewall Rule Modified to Allow Ingress from Any IPv6 Over Any Protocol
- id: `2103846149694917307`
- severity: Medium
- status: Active
- description: Detects the modification of a firewall rule in Google Cloud Platform (GCP) that permits ingress traffic from any IPv6 source over any protocol. Such changes can expose resources to unauthorized access, lateral movement, and exploitation of publicly accessible services. Adversarie
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'compute.firewalls.(patch|update)$' and unmapped.protoPayload.resourceOriginalState.direction = 'INGRESS' and unmapped.protoPayload.request.sourceRanges = '[`

## GCP Network Packet Capture Activity
- id: `2416777944571764606`
- severity: Medium
- status: Active
- description: Detects the enablement or use of full network traffic packet capture in Google Cloud Platform (GCP). Packet capture allows detailed inspection of network traffic and is commonly used for troubleshooting and performance analysis. However, adversaries may abuse packet capture capab
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'compute.googleapis.com' and unmapped.protoPayload.methodName matches 'Compute\\.PacketMirrorings\\.(Delete|Get|Insert|List|Patch|aggregatedList)' and unmapped.severity != 'ERROR'
`

## GCP Pub Sub Topic Deletion
- id: `2053136766955338258`
- severity: Low
- status: Disabled
- description: Detects the deletion of a topic in Google Cloud Platform (GCP) Pub/Sub service. An adversary can exploit this action to disrupt the flow of messages between services, potentially causing service outages, data loss, or the failure of critical event-driven workflows. Deleting topic
- query: `dataSource.name = 'GCP Audit' and api.service.name = 'pubsub.googleapis.com' and unmapped.protoPayload.methodName matches 'google.pubsub.v..Publisher.DeleteTopic$' and unmapped.severity != 'ERROR'
`

## Google Workspace Default Group Conversation Visibility to Domain Users Enabled
- id: `2184096626290965870`
- severity: Low
- status: Disabled
- description: Detects changes to Google Workspace Groups settings that configure the default visibility of group conversations to be accessible by all users within the domain upon group creation. Unauthorized modifications to this setting can lead to security risks, including unauthorized acce
- query: `dataSource.name = 'Google Workspace' and metadata.product.name = 'admin' and metadata.log_name = 'APPLICATION_SETTINGS' and event.type = 'CHANGE_APPLICATION_SETTING' and enrichments contains '"name":"SETTING_NAME","value":"GroupsSharingSettingsProto default_view_topics_access_lev`

## Google Workspace Default Group Conversation Visibility to Public Enabled
- id: `2184096626290965871`
- severity: Medium
- status: Active
- description: Detects changes to Google Workspace Groups settings that configure the default visibility of group conversations to be accessible by anyone upon group creation. Unauthorized modifications to this setting can lead to security risks, including unauthorized external access to sensit
- query: `dataSource.name = 'Google Workspace' and metadata.product.name = 'admin' and metadata.log_name = 'APPLICATION_SETTINGS' and event.type = 'CHANGE_APPLICATION_SETTING' and enrichments contains '"name":"SETTING_NAME","value":"GroupsSharingSettingsProto default_view_topics_access_lev`

## Google Workspace Multi-Factor Authentication Disabled
- id: `2174786686563086261`
- severity: High
- status: Active
- description: Detects instances where multi-factor authentication (MFA) is disabled for user accounts within Google Workspace. MFA adds an extra layer of security by requiring users to verify their identity using multiple factors, such as passwords, security tokens, or biometrics. Disabling MF
- query: `dataSource.name = 'Google Workspace' and metadata.product.name = 'admin' and event.type in ('ENFORCE_STRONG_AUTHENTICATION', 'ALLOW_STRONG_AUTHENTICATION') and enrichments contains '"name":"NEW_VALUE","value":"false"'
`

## Hping Network Utility Activity
- id: `2012256313435237084`
- severity: Low
- status: Disabled
- description: Detects the use of Hping, a network tool commonly utilized for diagnostics, testing, and firewall rule auditing on Linux systems. While Hping is a legitimate tool, adversaries can abuse it for various malicious activities, including conducting Denial of Service (DoS) attacks, por
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.name in ('hping', 'hping2', 'hping3') and not (src.process.parent.name in:anycase ('nbagent'))
`

## IIS HTTP Logging Disabled
- id: `2203626377699944576`
- severity: Low
- status: Disabled
- description: Detects instances where HTTP logging in Internet Information Services (IIS) has been disabled. This action may signify an adversary employing anti-forensics tactics to evade detection after gaining unauthorized access to the server, possibly via a web shell or other exploit. Disa
- query: `dataSource.name = 'SentinelOne' and event.type = 'Process Creation' and (src.process.name in:anycase ('appcmd.exe') or src.process.displayName in:anycase ('appcmd.exe')) and (src.process.cmdline contains '/dontLog:' and src.process.cmdline contains 'true') and not (src.process.pa`

## K8s RCE via Nodes/Proxy GET Request
- id: `2406746326696635990`
- severity: High
- status: Active
- description: Detects exploitation of the Kubernetes nodes/proxy GET permission, which can enable remote command execution on cluster nodes via direct connections to the Kubelet API. Service accounts with nodes/proxy GET access—often required by monitoring tools for reading Pod metrics and log
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.cmdline contains '10250/exec/' and tgt.process.cmdline contains 'error=1' and tgt.process.cmdline contains 'output=1' and tgt.process.cmdline contains 'command=' and k8sC`

## Latrodectus Spoofed Intel Graphics Registry Entry
- id: `2345722453025420160`
- severity: High
- status: Active
- description: Detects registry-based autorun persistence consistent with Latrodectus masquerading as Intel Graphics Media Accelerator components. This behavior enables durable startup execution while blending with legitimate graphics driver artifacts, aiding defense evasion and facilitating fo
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Behavioral Indicators' and indicator.name = 'RegistryAutorun' and indicator.metadata matches 'Key: "\\\\registry\\\\machine\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\(Run|RunOnce)"' and i`

## Masquerading via Renamed System Binaries
- id: `2254453055141634594`
- severity: High
- status: Active
- description: Detects potential bypass of security controls by renaming highly relevant binaries. This technique is often employed to disguise malicious activities under the guise of legitimate processes, making it challenging for traditional security measures to identify threats. By monitorin
- query: `dataSource.name = 'SentinelOne' and event.type = 'Behavioral Indicators' and indicator.name = 'DifferentOriginalFilename' and src.process.displayName in ('Microsoft (R) HTML Application host', 'Microsoft ® Console Based Script Host', 'Microsoft ® Windows Based Script Host', 'Cert`

## MemProcFS Execution With WinPmem Driver Load
- id: `2254452404512804322`
- severity: High
- status: Active
- description: Detects the execution of MemProcFS in conjunction with the WinPmem driver (e.g., winpmem_x64.sys). MemProcFS is a memory forensics tool that creates a filesystem representation of physical memory, and WinPmem is a driver commonly used to facilitate memory acquisition. This combin
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Driver Load' and src.process.name = 'memprocfs.exe' and tgt.file.path matches '\\\\winpmem_x64\\.sys$'
`

## Mknod Execution in Container
- id: `2254451039157783697`
- severity: High
- status: Active
- description: Detects the creation of special files within a containerized environment, which is an uncommon operation in most container workloads. This behavior can be indicative of an attempt to establish device nodes or other special file types that facilitate direct interaction with system
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.name = 'mknod' and k8sCluster.containerId = * and tgt.process.cmdline contains ' /dev/' and not (tgt.process.cmdline contains ('/dev/xconsole', '/dev/null', '/dev/zero', `

## MSHTA Launching Remote JavaScript Payload
- id: `2264064792841470475`
- severity: Medium
- status: Active
- description: Detects the use of MSHTA to execute JavaScript code from a remote URL, a technique often leveraged by adversaries to deliver and run malicious payloads. This behavior is indicative of initial access or execution tactics, as MSHTA can bypass certain security controls and facilitat
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (tgt.process.name in:anycase ('mshta.exe') or tgt.process.displayName = 'Microsoft (R) HTML Application host') and tgt.process.cmdline contains 'javascript:'
`

## OCI Notification Topic Deleted
- id: `2325323345189784848`
- severity: Low
- status: Disabled
- description: Detects the deletion of an Oracle Cloud Infrastructure (OCI) Notification Service topic. Deleting topics can disrupt alerting and notification workflows. Unauthorized or unexpected deletion of topics may indicate attempts to suppress alerts or cover tracks, potentially as part of
- query: `dataSource.name = 'Oracle Cloud Infrastructure' and event.type = 'DeleteTopic' and unmapped.data.message contains 'DeleteTopic succeeded'
`

## OCI Potential Network Security Tampering Attempt
- id: `2325323345181396239`
- severity: Medium
- status: Active
- description: Detects attempts to delete or modify Network Security Groups (NSGs) or Security Lists in Oracle Cloud Infrastructure (OCI). Adversaries can abuse this behavior to weaken or completely disable network defenses by removing segmentation, altering access controls, or deleting firewal
- query: `dataSource.name = 'Oracle Cloud Infrastructure' and event.type in ('DeleteNetworkSecurityGroup', 'UpdateNetworkSecurityGroupSecurityRules', 'DeleteSecurityList', 'UpdateSecurityList') and unmapped.data.message contains ' succeeded'
`

## OCI Successful Brute Force Attack
- id: `2325321969860719470`
- severity: High
- status: Active
- description: Detects a successful brute force attack against Oracle Cloud Infrastructure (OCI) user accounts. This indicates that an attacker has repeatedly attempted authentication and eventually gained access using valid credentials. Such activity may lead to unauthorized access, privilege 
- query: ``

## OCI VNIC Deleted
- id: `2325323345214950674`
- severity: Low
- status: Disabled
- description: Detects the deletion of a Virtual Network Interface Card (VNIC) in Oracle Cloud Infrastructure (OCI). Adversaries may delete VNICs to disrupt network connectivity, evade monitoring, or hinder incident response activities. Monitoring VNIC deletions is critical to identify potentia
- query: `dataSource.name = 'Oracle Cloud Infrastructure' and event.type='DeleteVnic' and unmapped.data.message contains 'DeleteVnic succeeded'
`

## Office 365 Successful Brute Force Attack
- id: `2074079869117370899`
- severity: High
- status: Active
- description: Detects multiple failed login attempts followed by a successful login in Office 365, potentially indicating a successful brute force attack. An adversary may use brute force techniques to guess passwords, repeatedly attempting to log in until they succeed. This behavior is a stro
- query: ``

## PANW Firewall GlobalProtect Successful Brute Force Attack
- id: `2184096444677584951`
- severity: Low
- status: Active
- description: Detects multiple failed login attempts followed by a successful login to Palo Alto Networks GlobalProtect, potentially indicating a successful brute force attack. An adversary may use brute force techniques to systematically guess passwords, repeatedly attempting to log in until 
- query: ``

## PANW Firewall High Severity Correlation Event Detected
- id: `2163942159777122690`
- severity: High
- status: Active
- description: Detects high and critical severity correlation events generated by Palo Alto Networks firewalls' automated correlation engine. The correlation engine connects isolated network events and looks for patterns that indicate a more significant event. This helps identify suspicious tra
- query: `dataSource.name = 'Palo Alto Networks Firewall' and metadata.log_name = 'CORRELATION' and unmapped.severity in ('high', 'critical')
`

## PANW Firewall Malware Allowed
- id: `2193712805984468183`
- severity: Low
- status: Disabled
- description: Detects active network communication associated with known malware that is being allowed by the Palo Alto Networks firewall. This may indicate an ongoing security threat, where malicious traffic is bypassing firewall protections, potentially leading to system compromise, data exf
- query: `dataSource.name = 'Palo Alto Networks Firewall' and metadata.log_name = 'THREAT' and unmapped.sub_type = 'virus' and not (unmapped.action contains ('deny', 'drop', 'reset', 'block') or action contains ('deny', 'drop', 'reset', 'block'))
`

## PANW Firewall Medium Severity Correlation Event Detected
- id: `2193712805992856797`
- severity: Info
- status: Disabled
- description: Detects medium severity correlation events generated by Palo Alto Networks firewall's automated correlation engine. The correlation engine connects isolated network events and looks for patterns that indicate a more significant event. This helps identify suspicious traffic patter
- query: `dataSource.name = 'Palo Alto Networks Firewall' and metadata.log_name = 'CORRELATION' and unmapped.severity = 'medium'
`

## PANW Firewall Successful RDP Brute Force Attack
- id: `2163942114336023348`
- severity: Low
- status: Disabled
- description: Detects a RDP brute force attempt followed by a successful rdp login as detected by Palo Alto Networks Firewall, indicating a potential brute force attack. An adversary may use brute force techniques to guess passwords, repeatedly attempting to log in until they succeed. This beh
- query: ``

## PANW Firewall TOR Traffic Allowed
- id: `2193712806009634018`
- severity: Info
- status: Disabled
- description: Detects allowed network traffic to the TOR network. Adversaries can use TOR to anonymize their network activity, bypass security controls, and evade detection while conducting malicious operations. This could lead to unauthorized access, data exfiltration, and compliance violatio
- query: `dataSource.name = 'Palo Alto Networks Firewall' and metadata.log_name = 'TRAFFIC' and app_name = 'tor' and unmapped.action = 'allow'
`

## PANW Firewall Traffic to Malicious URL Allowed
- id: `2163942159793899915`
- severity: Medium
- status: Active
- description: Detects when the Palo Alto Networks firewall does not block traffic to a URL associated with malware distribution or operation. This typically indicates a lapse in the firewall's threat intelligence or a misconfiguration. An adversary can abuse this by using the unblocked URL to 
- query: `dataSource.name = 'Palo Alto Networks Firewall' and metadata.log_name = 'THREAT' and unmapped.sub_type = 'url' and (unmapped.threat_category = 'malware' or unmapped.url_category = 'malware') and unmapped.severity in ('critical', 'high', 'medium') and not (unmapped.action contains`

## PANW Firewall Traffic to Phishing URL Allowed
- id: `2163942159810677134`
- severity: Medium
- status: Active
- description: Detects when the Palo Alto Networks firewall does not block traffic to a URL known to be used in phishing attacks. An adversary can abuse this by directing victims to the phishing site, potentially stealing credentials, deploying malware, or conducting other malicious activities.
- query: `dataSource.name = 'Palo Alto Networks Firewall' and metadata.log_name = 'THREAT' and unmapped.sub_type = 'url' and (unmapped.threat_category = 'malware' or unmapped.url_category = 'malware') and unmapped.severity in ('critical', 'high', 'medium') and not (unmapped.action contains`

## PANW Firewall Unauthorized Config Change
- id: `2163942159785511305`
- severity: Low
- status: Disabled
- description: Detects unauthorized modifications to the Palo Alto Networks firewall configuration, potentially indicating malicious activity or security policy violations. These changes can be leveraged to evade detection, facilitate data exfiltration, or disrupt network defenses, ultimately c
- query: `dataSource.name = 'Palo Alto Networks Firewall' and unmapped.type = 'CONFIG' and unmapped.result = 'Unauthorized'
`

## Pcalua Execution via Scheduled Task
- id: `2134236171061343266`
- severity: Medium
- status: Active
- description: Detects instances where the Program Compatibility Assistant (pcalua.exe) is executed via a scheduled task. Adversaries may exploit pcalua.exe, a signed Microsoft binary, to bypass User Account Control (UAC) and run commands with elevated privileges. This technique can facilitate 
- query: ``

## Possible Tomcat RewriteValve Path Traversal Exploit Attempt
- id: `2360964415775346190`
- severity: Medium
- status: Active
- description: Detects HTTP request patterns indicative of attempts to exploit the Tomcat RewriteValve path traversal vulnerability (CVE-2025-55752) to escape the web root and access arbitrary files. This behavior is security-relevant because successful exploitation can expose sensitive data an
- query: `(dataSource.name = 'Corelight' and http_request.http_method in:anycase ('GET', 'POST') and http_request.url.url_string contains ('/;/web-inf/', '%2fweb-inf%2f', '../web-inf/', '/;/meta-inf/', '%2fmeta-inf%2f', '../meta-inf/')) or (dataSource.name = 'AWS Web Application Firewall' `

## Potential Adversary Tooling for Discovery and Remote Access
- id: `2284866660222239470`
- severity: High
- status: Active
- description: Detects the use of tooling combinations that suggest an adversary is conducting internal reconnaissance while establishing or enabling remote access capabilities. This pattern often indicates preparation for persistence or remote control following initial compromise. In typical e
- query: ``

## Potential Application Bypass with DllRegisterServer Function
- id: `2203626293763531051`
- severity: Low
- status: Disabled
- description: Detects instances where rundll32.exe is used to execute the DllRegisterServer export function, a behavior commonly associated with adversary tactics. Adversaries can abuse this functionality to execute malicious DLLs while blending in with legitimate system processes, evading det
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (tgt.process.name in:anycase ('rundll32.exe') or tgt.process.displayName = 'Windows host process (Rundll32)') and tgt.process.cmdline contains 'DllRegisterServer' and not (src.proc`

## Potential Fortinet FortiGate Unauthorized Login Attempt (CVE-2024-55591)
- id: `2134241430190154708`
- severity: High
- status: Active
- description: Detects suspicious or unauthorized login attempts targeting Fortinet FortiGate firewalls, specifically linked to CVE-2024-55591 and the Console Chaos campaign. Adversaries exploit this vulnerability to gain administrative access, bypass authentication mechanisms, and compromise f
- query: `dataSource.name = 'FortiGate' and unmapped.ui = 'jsconsole' and unmapped.user = 'admin' and unmapped.action = 'login' and (unmapped.srcip matches '^127(?:\\.\\d{1,3}){3}$' or unmapped.srcip matches '^(\\d{1,3})\\.\\1\\.\\1\\.\\1$')
`

## Potential Hexadecimal Payload in Command Line
- id: `2264064066882816647`
- severity: Medium
- status: Active
- description: Detects the presence of long hexadecimal-encoded sequences within command line arguments on Linux endpoints. Adversaries may leverage hexadecimal encoding to obfuscate malicious payloads, scripts, or commands, making them less recognizable to traditional security controls and sta
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.cmdline matches '(\\\\x[0-9a-fA-F]{2}){20,50}'
`

## Potential Impacket AtExec Scheduled Task Execution
- id: `2457204596503311991`
- severity: High
- status: Active
- description: Detects behavioral indicators of remotely started scheduled tasks with characteristics consistent with Impacket's atexec.py tool. This includes tasks with 8-character random names executed with System integrity level, often used for lateral movement and remote code execution.
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Behavioral Indicators' and indicator.name = 'ScheduledTaskProcessStartedRemotely' and indicator.metadata matches '(?i)Task\\s*Name:\\s*"\\\\[a-zA-Z]{8}"' and indicator.metadata contains 'IntegrityLevel:`

## Potential PowerShell Image Steganography
- id: `2274627279988649908`
- severity: Low
- status: Disabled
- description: Detects potential use of PowerShell scripts or commands to load and manipulate image files from common writable directories, which may indicate steganography techniques used to hide or extract malicious content. Attackers leverage these methods to evade detection by embedding pay
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Command Script' and src.process.displayName contains ('Windows PowerShell') and cmdScript.content contains ('[System.Drawing.Image]::FromFile', '[System.Drawing.Graphics]::FromImage', 'GetPixel', 'SetPi`

## PowerShell Obfuscated Command Execution via String Slicing
- id: `2274627280022204346`
- severity: High
- status: Active
- description: Detects the use of string slicing techniques within PowerShell commands to obfuscate code execution. Adversaries employ this method to evade signature-based detection by reconstructing malicious commands at runtime. This behavior is indicative of advanced obfuscation tactics ofte
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Command Script' and (src.process.name in:anycase ('powershell.exe', 'pwsh.exe', 'powershell_ise.exe') or src.process.displayName in ('Windows PowerShell', 'PowerShell_ISE')) and cmdScript.content matche`

## PowerShell or CMD Spawned by Private Character Editor Process
- id: `2284867128860291143`
- severity: High
- status: Active
- description: Detects instances where the Private Character Editor process spawns PowerShell or CMD child processes. This behavior is uncommon in legitimate workflows and may indicate User Account Control (UAC) bypass by adversaries. Threat actors may abuse trusted system utilities like Privat
- query: `dataSource.name = 'SentinelOne' and event.type = 'Process Creation' and (src.process.name in:anycase ('eudcedit.exe') or src.process.displayName in ('Private Character Editor')) and (tgt.process.name in:anycase ('powershell.exe', 'cmd.exe') or tgt.process.displayName in ('Windows`

## Process Masquerading or Injecting into Windows Error Reporting Service
- id: `2264064597034538978`
- severity: High
- status: Active
- description: Detects possible process injection or processes attempting to masquerade as the legitimate Windows Error Reporting Service by imitating its name or characteristics. This behavior is indicative of adversaries leveraging trusted system processes to evade detection and blend malicio
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('Process Creation', 'Network Connection') and ((src.process.name in:anycase ('wermgr.exe', 'WerFault.exe') or src.process.displayName in ('Windows Problem Reporting')) or (tgt.process.name in:anycase (`

## Process Memory Corruption via DD
- id: `2254450528232831255`
- severity: Medium
- status: Active
- description: Detects the use of the dd utility to manipulate or corrupt the memory of a running process by writing directly to /proc/<pid>/mem. This technique, observed in attacks by UNC3886, can be used to patch live processes in memory—such as disabling logging or altering behavior—without 
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.name = 'dd' and tgt.process.cmdline matches '/proc/\\d+/mem' and tgt.process.cmdline contains 'conv=notrunc' and tgt.process.cmdline contains 'oseek='
`

## Registry Export Activity Targeting Third-Party Credential Storage
- id: `2274627059997393445`
- severity: High
- status: Active
- description: Detects attempts to export Windows Registry hives or keys known to store third-party credentials. This behavior may indicate credential harvesting by adversaries seeking to obtain sensitive authentication data from installed applications. Such activity is consistent with post-com
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (tgt.process.name in:anycase ('reg.exe') or tgt.process.displayName in ('Registry Console Tool')) and tgt.process.cmdline contains ('save', 'export') and tgt.process.cmdline contai`

## Remote Desktop Enabled via Netsh
- id: `2203626378069043348`
- severity: Low
- status: Disabled
- description: Detects instances where Remote Desktop Protocol (RDP) connections are enabled or allowed through the Windows Firewall using the netsh command. By modifying the firewall configuration, attackers can open RDP ports to facilitate lateral movement, maintain control over compromised h
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (tgt.process.name contains 'netsh.exe' or tgt.process.displayName = 'Network Command Shell') and tgt.process.cmdline contains 'firewall add ' and tgt.process.cmdline contains ('loc`

## RMM Tool Network Traffic to Suspicious Top-Level Domains
- id: `2386410241986106733`
- severity: Medium
- status: Active
- description: Detects network connections initiated by remote monitoring and management tooling to suspicious top-level domains. This behavior can indicate adversaries leveraging remote administration capabilities to establish command-and-control, stage follow-on actions, or exfiltrate data wh
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'DNS Resolved' and ((src.process.name matches ('screenconnect\\..*client.*\\.exe', 'meshagent.*.exe') OR src.process.name in:anycase ('AnyDesk.exe', 'TeamViewer.exe', 'TeamViewer_Service.exe', 'client32.`

## Shai-Hulud Unattended GitHub Runner Registration
- id: `2355943496148546407`
- severity: High
- status: Active
- description: Detects unattended registration of GitHub self-hosted runners with suspicious characteristics associated with the Shai-Hulud worm variant.
- query: `dataSource.name = 'SentinelOne' and event.type = 'Process Creation' and ((src.process.cmdline contains 'github.com' and src.process.cmdline contains '--unattended' and src.process.cmdline contains '--name SHA1HULUD') or (tgt.process.cmdline contains 'github.com' and tgt.process.c`

## SSH ProxyJump Multi-Hop Scheduled Task
- id: `2274626945811655758`
- severity: Medium
- status: Active
- description: Detects the scheduled task of SSH connections utilizing the ProxyJump option with multiple hops, indicating potential lateral movement or covert tunneling activity. This behavior may be leveraged by adversaries to bypass network segmentation and access internal systems through ch
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.category = 'scheduled_task' and event.type in:anycase ('Task Start', 'Task Register') and ((src.process.cmdline matches '(?:\\s|^)ssh(\\.exe)?(?:\\s|$)' and (src.process.cmdline matches:matchcase '(?:\\s|^)\\-J`

## SSH Reverse Tunnel Persistence via Remote PowerShell
- id: `2315200442784299556`
- severity: High
- status: Active
- description: Detects a remote command via WinRM (wsmprovhost.exe) creating a scheduled task to establish a persistent reverse SSH tunnel. This is a common adversary pattern for creating a durable, firewall-bypassing C2 backdoor.
- query: ``

## SSH Reverse Tunnels to Public Tunneling Services
- id: `2360951452623603430`
- severity: Medium
- status: Active
- description: Detects SSH sessions that establish reverse tunnels through known public tunneling services. This behavior is commonly used by adversaries to bypass inbound firewall restrictions, create covert remote access channels, and maintain control of internal assets from the internet. Suc
- query: `dataSource.name = 'SentinelOne' and event.type in ('Process Creation', 'Command Script') and ((tgt.process.cmdline matches '(?:\\s|^)ssh(\\.exe)?(?:\\s|$)' and tgt.process.cmdline matches:matchcase '(?:\\s|^)\\-R(?:\\s|$)' and (tgt.process.cmdline matches:matchcase '(?:(?:\\s|^)\`

## SSH Reverse Tunnel to Domain Address Command Execution
- id: `2224179798176099588`
- severity: Medium
- status: Active
- description: Detects the establishment of an SSH reverse tunnel to a domain address. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an external server, effectively bypassing inbound network restr
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('Process Creation', 'Command Script') and not (src.process.user matches:anycase '\\\\SYSTEM$|\\\\SISTEMA$|\\\\Système$') and (src.process.name in:anycase ('powershell.exe', 'cmd.exe') or src.process.di`

## SSH Reverse Tunnel to Domain Scheduled Task Command Execution
- id: `2224179798184488197`
- severity: High
- status: Active
- description: Detects the command execution that creates a scheduled task to establish an SSH reverse tunnel to domain. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an external server, effective
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (src.process.name in:anycase ('powershell.exe', 'cmd.exe') or src.process.displayName in:anycase ('Windows PowerShell', 'Windows Command Processor')) and tgt.process.cmdline contai`

## SSH Reverse Tunnel to Domain Scheduled Task Script Block Execution
- id: `2224179798201265414`
- severity: High
- status: Active
- description: Detects the powershell script block execution that creates a scheduled task to establish an SSH reverse tunnel to domain. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an external s
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Command Script' and (src.process.name in:anycase ('powershell.exe') or src.process.displayName in:anycase ('Windows PowerShell')) and cmdScript.content contains ('Register-ScheduledTask') and cmdScript.`

## SSH Reverse Tunnel to Domain Scheduled Task Trigger
- id: `2224180085318155779`
- severity: High
- status: Active
- description: Detects the trigger of a scheduled task that establishes an SSH reverse tunnel to a domain address. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an external server, effectively byp
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.category = 'scheduled_task' and event.type = 'Task Trigger' and src.process.cmdline matches:matchcase '(?:\\s|^)\\-R(?:\\s|$)' and (src.process.cmdline matches:matchcase '(?:(?:\\s|^)\\-o(?:\\s|$)|(?:\\s|^)\\-N`

## SSH Reverse Tunnel to Public IP Scheduled Task Command Execution
- id: `2203626692893512963`
- severity: High
- status: Active
- description: Detects the command execution that creates a scheduled task to establish an SSH reverse tunnel to public IPv4 or IPv6 addresses. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an ext
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (src.process.name in:anycase ('powershell.exe', 'cmd.exe') or src.process.displayName in:anycase ('Windows PowerShell', 'Windows Command Processor')) and tgt.process.cmdline contai`

## SSH Reverse Tunnel to Public IP Scheduled Task Script Block Execution
- id: `2224179876592808660`
- severity: High
- status: Active
- description: Detects the powershell script block execution that creates a scheduled task to establish an SSH reverse tunnel to public IPv4 or IPv6 addresses. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH conn
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Command Script' and (src.process.name in:anycase ('powershell.exe') or src.process.displayName in:anycase ('Windows PowerShell')) and cmdScript.content contains ('Register-ScheduledTask') and cmdScript.`

## SSH Reverse Tunnel to Public IP Scheduled Task Trigger
- id: `2203626692901901572`
- severity: High
- status: Active
- description: Detects the trigger of a scheduled task that establishes an SSH reverse tunnel to a public IPv4 or IPv6 address. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an external server, ef
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.category = 'scheduled_task' and event.type = 'Task Trigger' and src.process.cmdline matches:matchcase '(?:\\s|^)\\-R(?:\\s|$)' and (src.process.cmdline matches:matchcase '(?:(?:\\s|^)\\-o(?:\\s|$)|(?:\\s|^)\\-N`

## SSH Reverse Tunnel to Public IPv4 Address Command Execution
- id: `2203626692918678789`
- severity: Medium
- status: Active
- description: Detects the establishment of an SSH reverse tunnel to a public IPv4 address. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an external server, effectively bypassing inbound network 
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('Process Creation', 'Command Script') and not (src.process.user matches:anycase '\\\\SYSTEM$|\\\\SISTEMA$|\\\\Système$') and (src.process.name in:anycase ('powershell.exe', 'cmd.exe') or src.process.di`

## SSH Reverse Tunnel to Public IPv6 Address Command Execution
- id: `2203626692935456006`
- severity: Medium
- status: Active
- description: Detects the establishment of an SSH reverse tunnel to a public IPv6 address. Reverse SSH tunnels allow a machine behind a firewall or NAT to provide access to its local services by initiating an outbound SSH connection to an external server, effectively bypassing inbound network 
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('Process Creation', 'Command Script') and not (src.process.user matches:anycase '\\\\SYSTEM$|\\\\SISTEMA$|\\\\Système$') and (src.process.name in:anycase ('powershell.exe', 'cmd.exe') or src.process.di`

## Suspicious File Write Activity in SharePoint Layouts Directory
- id: `2305247380723647333`
- severity: High
- status: Active
- description: Detects unauthorized or unusual file write operations targeting the SharePoint 'Layouts' directory. This directory is a critical component of SharePoint's web application infrastructure and is frequently targeted by adversaries seeking to introduce malicious web shells or tamper 
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('File Creation', 'File Rename', 'File Modification') and (src.process.name in:anycase ('cmd.exe', 'powershell.exe', 'pwsh.exe') or src.process.displayName in ('Windows Command Processor', 'Windows Powe`

## Suspicious Scheduled Task Masquerading as Svchost
- id: `2264064597093259249`
- severity: Medium
- status: Active
- description: Detects the creation of a scheduled task where the task name or associated binary mimics svchost.exe, a legitimate Windows system process. Adversaries often use masquerading techniques to make malicious tasks appear benign, reducing the likelihood of detection during manual inspe
- query: `dataSource.name = 'SentinelOne' and event.type = 'Task Register' and (src.process.name in:anycase ('schtasks.exe') or src.process.displayName = 'Task Scheduler Configuration Tool') and src.process.cmdline contains 'svchost.exe'
`

## Suspicious Scheduled Task Masquerading as Windows Service
- id: `2264064596917098441`
- severity: Medium
- status: Active
- description: Detects the registration of a scheduled task on a Windows system that mimics the name of a legitimate system process (e.g., “Windows Update Security”, “Microsoft Telemetry”) while referencing suspicious file paths such as AppData, Temp, ProgramData, or Startup. This technique is 
- query: `dataSource.name = 'SentinelOne' and endpoint.os == 'windows' and event.type == 'Task Register' and (src.process.name = 'schtasks.exe' or src.process.displayName = 'Task Scheduler Configuration Tool') and task.name matches '(?i)(Windows\\s+Update\\s+Security.*|Windows\\s+Security.`

## Task Registered via Suspicious PowerShell Script File
- id: `2264064597219088397`
- severity: Medium
- status: Active
- description: Detects the registration of a scheduled task using a PowerShell script file with suspicious characteristics, such as uncommon file paths, obfuscated content, or known malicious patterns. While task registration via PowerShell can be legitimate, adversaries often leverage this tec
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Task Register' and src.process.name = 'powershell.exe' and src.process.activeContent.path matches '.*\\.(log|txt|dat|csv|inf|cfg|ini|json|xml)$' and src.process.activeContent.signedStatus = 'unsigned' a`

## User Management Event
- id: `2224179532869589801`
- severity: Info
- status: Disabled
- description: This rule detects system-level actions related to user and group account management on Linux endpoints. Such operations may include the creation of new user accounts, modification of existing accounts or their credentials, and adjustments to group memberships. While these activit
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'linux' and event.type = 'Process Creation' and tgt.process.name in ('useradd', 'adduser', 'usermod', 'passwd', 'chpasswd', 'groupadd', 'groupmod', 'gpasswd', 'deluser', 'userdel') and not (tgt.process.cmdline contains (' -h', ' -`

## WEL Potential Impacket Scheduled Task Creation
- id: `2067579409347213069`
- severity: Medium
- status: Active
- description: Detects the creation of scheduled tasks that match characteristics typically associated with the Impacket tool, including specific commands found in the task content. Attackers often use tools like atexec.py from Impacket to create stealthy, system-scheduled tasks that execute pa
- query: `dataSource.name = 'Windows Event Logs' AND winEventLog.id = 4698 AND winEventLog.data.event.eventData.taskName matches "^\\\\[A-Za-z]{8}$" AND winEventLog.data.event.eventData.taskContent contains '/c ' and winEventLog.data.event.eventData.taskContent matches '\\\\[A-Za-z]{8}\\.t`

## WEL Successful Brute Force Attack
- id: `2108140690288542595`
- severity: Low
- status: Disabled
- description: Detects 100 or more failed login attempts followed by a successful login, indicating a potential brute force attack. An adversary may use brute force techniques to guess passwords, repeatedly attempting to log in until they succeed. This behavior is a strong indicator of unauthor
- query: ``

## Windows Defender Context Menu Handler Registry Removed
- id: `2305246779168146219`
- severity: High
- status: Active
- description: Detects the removal of the Windows Defender context menu handler from the Windows Registry using reg.exe or PowerShell. This activity may indicate an attempt to weaken endpoint security controls or evade detection by disabling quick access to Windows Defender features. Adversarie
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('Process Creation', 'Command Script') and (src.process.name in:anycase ('powershell.exe', 'pwsh.exe', 'powershell_ise.exe', 'reg.exe') or src.process.displayName in:anycase ('Windows PowerShell', 'pwsh`

## Windows Defender Disable via LOLBin SystemSettingsAdminFlows
- id: `2274627280038981564`
- severity: High
- status: Active
- description: Detects execution of commands leveraging the 'SystemSettingsAdminFlows' LOLBin to disable Windows Defender. This behavior is indicative of adversaries attempting to weaken endpoint security controls by abusing legitimate system utilities. Such activity aligns with common defense 
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type in ('Process Creation', 'Command Script') and (src.process.name in:anycase ('powershell.exe', 'cmd.exe') or src.process.displayName in:anycase ('Windows PowerShell', 'Windows Command Processor')) and (src.`

## Windows Defender WdFilter and Tamper Protection Registry Alteration
- id: `2274626941516688085`
- severity: High
- status: Active
- description: Detects modification of Windows Defender 'WdFilter' and Tamper Protection registry keys. Such changes may indicate attempts to disable or weaken built-in security controls, enabling adversaries to evade detection and maintain persistence. Threat actors often target these registry
- query: ``

## Windows Firewall Disabled via Netsh
- id: `2203626378647857330`
- severity: Low
- status: Disabled
- description: Detects the use of netsh.exe to disable the local Windows firewall. Attackers can exploit this technique to weaken the security posture of the system, allowing for unrestricted network communication. Disabling the firewall can facilitate lateral movement, enable command and contr
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (src.process.name in:anycase ('netsh.exe') or src.process.displayName='Network Command Shell') and src.process.cmdline contains 'advfirewall' and src.process.cmdline contains ' sta`

## WinRAR Path Traversal File Write via Alternate Data Streams
- id: `2284866927701432351`
- severity: High
- status: Active
- description: Detects WinRAR file extraction activities that leverage path traversal combined with alternate data streams to write files outside the intended extraction directory. This technique can be used by adversaries to bypass directory restrictions and deposit malicious files in sensitiv
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Behavioral Indicators' and indicator.name = 'WriteToADS' and (src.process.name in:anycase ('winrar.exe', 'winrar') or src.process.displayName in ('WinRAR archiver', 'WinRAR.exe', 'WinRAR')) and indicato`

## WMI AntiVirus Product Enumeration
- id: `2457204594573932001`
- severity: Low
- status: Disabled
- description: Detects WMI queries to enumerate installed antivirus products, commonly used by adversaries to identify security software before deploying malware or exploits. This technique allows attackers to adjust their tactics to evade detection.
- query: `dataSource.name = 'SentinelOne' and endpoint.os = 'windows' and event.type = 'Process Creation' and (src.process.name in ('cmd.exe') or src.process.displayName = 'Windows Command Processor') and src.process.cmdline contains 'Namespace' and src.process.cmdline contains 'root' and `
