
# Pyramid-of-Pain

![1](https://github.com/user-attachments/assets/c8d98c6c-71be-482d-a5a9-c7ac4dd72fe4)


# PicoSecure Threat Simulation and Detection Engineering Engagement

## Objective
After participating in numerous incident response activities, PicoSecure decided to conduct a threat simulation and detection engineering engagement to enhance our malware detection capabilities. I was assigned to collaborate with an external penetration tester in an iterative purple-team scenario. The tester aimed to execute malware samples on a simulated internal user workstation, while my task was to configure PicoSecure’s security tools to detect and prevent the malware from executing.

Following the Pyramid of Pain's ascending priority of indicators, my objective was to increase the simulated adversaries’ cost of operations and chase them away for good. Each level of the pyramid allows for the detection and prevention of various indicators of attack.

![2](https://github.com/user-attachments/assets/ae731e81-edd3-443b-bfef-23da5d0b76e1)


## Room Prerequisites
Completing the preceding rooms in the Cyber Defence Frameworks module was beneficial before venturing into this challenge. Specifically, the following:
1. **The Pyramid of Pain**
2. **MITRE**

## Achievements at the End of the Project
1. **Malware Sandbox:** An automated analysis engine for detecting malware and malicious behavior.
2. **Manage Hashes:** Blocking threats based on file signatures.
3. **Firewall Rule Manager:** Setting firewall rules to Allow/Deny incoming and outgoing traffic based on source and destination IP addresses.
4. **DNS Rule Manager:** Configuring DNS rules to Allow/Deny incoming and outgoing traffic based on domain or subdomain names.
5. **Sigma Rule Builder:** A user-friendly interface for crafting or modifying Sigma rules.

## Getting Started
I first uploaded `sample1.exe` into the malware sandbox. The email accompanying this malware sample mentioned, "Maybe there’s a unique way for you to distinguish this file and add a detection rule to block it." It was clear that blocking this malware based on the file signature was possible. I placed one of the hashes into the Hash blocklist and soon received another email containing `sample2.exe` and the first flag.

![3](https://github.com/user-attachments/assets/da38eba8-7195-471e-9ebd-1edc337067a1)


**Question:** What is the first flag you receive after successfully detecting `sample1.exe`?  
**Answer:** THM{f3cbf08151a11a6a331db9c6cf5f4fe4}

Using the malware sandbox, I observed the suspicious process `sample2.exe` reaching out to IP 154.35.10.133. Consequently, I blocked any traffic going out to that IP with a Firewall rule and received another email from the tester.
![4](https://github.com/user-attachments/assets/866785dc-47cb-481b-812a-0b568659463d)

![5](https://github.com/user-attachments/assets/33fc838c-cc11-44bf-a016-09e61b9dadad)

**Question:** What is the second flag you receive after successfully detecting `sample2.exe`?  
**Answer:** THM{2ff48a3421a938b388418be273f4806d}

After blocking his server IP address, the attacker switched to using a cloud service provider, allowing him to change his IP over time. To detect this evolving threat in `sample3.exe`, I adjusted my approach by blocking the malicious domain associated with the threat by adding `emudyn.bresonicz.info` to the DNS Filter.

![6](https://github.com/user-attachments/assets/35ccf545-ea07-4b91-9548-efc515358220)

![7](https://github.com/user-attachments/assets/65b29cb3-a658-4c8f-b2c2-f5c6df602287)

**Question:** What is the third flag you receive after successfully detecting `sample3.exe`?  
**Answer:** THM{4eca9e2f61a19ecd5df34c788e7dce16}

At this point, I realized that relying solely on blocking hashes, IPs, or domains was insufficient, but I wasn't done yet.

With the help of our best friend, the malware sandbox, I observed the activity of `sample4.exe` making changes to Real-time Protection. I then headed to the Sigma Rule Builder, a tool I hadn't utilized before, which offers several rules to set. I used Sysmon Event Logs -> Registry Modifications to set a rule detecting the change in settings, resulting in the next email.

**Question:** What is the fourth flag you receive after successfully detecting `sample4.exe`?  
**Answer:** THM{c956f455fc076aea829799c0876ee399}

For `sample5.exe`, I focused on the log file since the threat had evolved to the point where the attacker could dynamically change various artifacts, such as IP addresses and ports. I easily spotted the behavior of this malware in the log, noting suspicious outgoing traffic of 97 bytes every 30 minutes.

Using Sigma Rule Builder -> Sysmon Event Logs -> Network Connections, I detected these network traffic patterns. The R-host and R-port were set to "Any" because the attacker could change them at any time.
![11](https://github.com/user-attachments/assets/b740bb4c-d15d-4014-9493-79021909a774)

![12](https://github.com/user-attachments/assets/8149fa2c-e9f2-4243-a9a6-7483cce66d27)

![13](https://github.com/user-attachments/assets/cae65fb7-1ee6-4d44-a200-9023da01e4fb)

**Question:** What is the fifth flag you receive after successfully detecting `sample5.exe`?  
**Answer:** THM{46b21c4410e47dc5729ceadef0fc722e}

In the last challenge with `sample6.exe`, I could see from the command history that the malware ran a series of command lines to gather information about the system and network configuration, then saved the results to a log file named "exfiltr&.log" in the "temp" directory.

To counter this, I configured Sigma Rule Builder -> Sysmon Event Logs -> File Creation and Modification to detect the creation/modification of files, preventing the malware from gathering system information. Finally, the attacker gave up and sent us the final flag.

**Question:** What is the final flag you receive from Sphinx?  
**Answer:** THM{c8951b2ad24bbcbac60c16cf2c83d92c}


SOC Prime Threat Detection Marketplace
For detection rules, SOC Prime Threat Detection Marketplace is a great platform, where security professionals share their detection rules for different kinds of threats including the latest CVE's that are being exploited in the wild by adversaries.

Fuzzy hashing is also a strong weapon against the attacker's tools. Fuzzy hashing helps you to perform similarity analysis - match two files with minor differences based on the fuzzy hash values. One of the examples of fuzzy hashing is the usage of SSDeep; on the SSDeep official website, you can also find the complete explanation for fuzzy hashing.

MITRE ATT&CK Matrix


Email tools
theHarvester - other than gathering emails, this tool is also capable of gathering names, subdomains, IPs, and URLs using multiple public data sources 
Hunter.io - this is  an email hunting tool that will let you obtain contact information associated with the domain
OSINT Framework - OSINT Framework provides the collection of OSINT tools based on various categories
Pyramid of Pain
The "Pyramid of Pain" is a concept introduced by David J. Bianco that categorizes different types of indicators of compromise (IOCs) based on the level of difficulty for an adversary to change them. It helps cybersecurity professionals understand the impact of detecting and responding to various types of IOCs. The pyramid has six levels, each representing a different type of indicator:
Hash Values (Bottom):
Description: These are unique digital fingerprints of files.
Pain to Adversary: Minimal.
Reason: Adversaries can easily change hash values by modifying the file slightly, making detection based on hash values alone relatively easy to evade.
IP Addresses:
Description: The specific IP addresses used by an adversary's infrastructure.
Pain to Adversary: Low.
Reason: While harder to change than hashes, adversaries can still switch to different IP addresses or use dynamic IPs.
Domain Names:
Description: Domains used by adversaries for C2 servers, phishing, etc.
Pain to Adversary: Moderate.
Reason: Domains require registration and setup, which can be time-consuming. Shutting down malicious domains can disrupt adversary operations more significantly.
Network/Host Artifacts:
Description: Specific characteristics of network traffic or host system changes, such as unusual protocols, ports, or registry changes.
Pain to Adversary: Moderate to high.
Reason: These artifacts are often tied to specific tools or techniques, and altering them requires changes in adversary tools or tactics.
Tools:
Description: Specific software or malware used by adversaries, such as Cobalt Strike or custom scripts.
Pain to Adversary: High.
Reason: Changing tools often involves development and testing, which is resource-intensive. Detection can also lead to identifying and blocking associated tactics.
Tactics, Techniques, and Procedures (TTPs) (Top):
Description: The overall methods used by adversaries to achieve their goals, such as phishing, lateral movement, or data exfiltration techniques.
Pain to Adversary: Very high.
Reason: Changing TTPs often requires significant alterations in the adversary's approach and strategy, which can be resource and time-consuming. Detecting and mitigating TTPs can significantly disrupt adversary operations.
The higher up the pyramid, the more impactful the detection and mitigation are to the adversary's operations. This framework helps prioritize cybersecurity efforts by focusing on the indicators that cause the most disruption to adversaries.
Cyber Threat Intelligence
Cyber Threat Intelligence (CTI) can be defined as evidence-based knowledge about adversaries, including their indicators, tactics, motivations, and actionable advice against them. These can be utilised to protect critical assets and inform cyber security teams and management business decisions.

50.22.95.9
It would be typical to use the terms “data”, “information”, and “intelligence” interchangeably. However, let us distinguish between them to understand better how CTI comes into play.
Data: Discrete indicators associated with an adversary, such as IP addresses, URLs or hashes.
Information: A combination of multiple data points that answer questions such as “How many times have employees accessed tryhackme.com within the month?”
Intelligence: The correlation of data and information to extract patterns of actions based on contextual analysis.
The primary goal of CTI is to understand the relationship between your operational environment and your adversary and how to defend your environment against any attacks. You would seek this goal by developing your cyber threat context by trying to answer the following questions:
Who’s attacking you?
What are their motivations?
What are their capabilities?
What artefacts and indicators of compromise (IOCs) should you look out for?
With these questions, threat intelligence would be gathered from different sources under the following categories:
Internal:
Corporate security events such as vulnerability assessments and incident response reports.
Cyber awareness training reports.
System logs and events.
Community:
Open web forums.
Dark web communities for cybercriminals.
External
Threat intel feeds (Commercial & Open-source)
Online marketplaces.
Public sources include government data, publications, social media, financial and industrial assessments.



What is The Diamond Model?
The Diamond Model of Intrusion Analysis was developed by cybersecurity professionals - Sergio Caltagirone, Andrew Pendergast, and Christopher Betz in 2013.
As described by its creators, the Diamond Model is composed of four core features: adversary, infrastructure, capability, and victim, and establishes the fundamental atomic element of any intrusion activity. You might have also noticed two additional components or axes of the Diamond Model - Social, Political and Technology; we will go into a little bit more detail about them later in this room. Why is it called a "Diamond Model"? The four core features are edge-connected, representing their underlying relationships and arranged in the shape of a diamond. 

The model provides various opportunities to integrate intelligence in real-time for network defence, automating correlation across events, classifying events with confidence into adversary campaigns, and forecasting adversary operations while planning and gaming mitigation strategies.

 Adversary
Who is an Adversary?

An adversary is also known as an attacker, enemy, cyber threat actor, or hacker. The adversary is the person who stands behind the cyberattack. Cyberattacks can be an instruction or a breach.
According to the creators of the Diamond Model,  an adversary is an actor or organization responsible for utilizing a capability against the victim to achieve their intent. 

Adversary Operator is the “hacker” or person(s) conducting the intrusion activity.

Adversary Customer is the entity that stands to benefit from the activity conducted in the intrusion. It may be the same person who stands behind the adversary operator, or it may be a separate person or group.

Victim
Victim – is a target of the adversary. A victim can be an organization, person, target email address, IP address, domain, etc. It's essential to understand the difference between the victim persona and the victim assets because they serve different analytic functions.
Capability
Capability – is also known as the skill, tools, and techniques used by the adversary in the event. The capability highlights the adversary’s tactics, techniques, and procedures (TTPs).
Capability Capacity is all of the vulnerabilities and exposures that the individual capability can use. 

An Adversary Arsenal is a set of capabilities that belong to an adversary. The combined capacities of an adversary's capabilities make it the adversary's arsenal.
Infrastructure
Infrastructure – is also known as software or hardware. Infrastructure is the physical or logical interconnections that the adversary uses to deliver a capability or maintain control of capabilities. For example, a command and control centre (C2) and the results from the victim (data exfiltration). 

The infrastructure can also be IP addresses, domain names, email addresses, or even a malicious USB device found in the street that is being plugged into a workstation. 

Type 1 Infrastructure is the infrastructure controlled or owned by the adversary. 

Type 2 Infrastructure is the infrastructure controlled by an intermediary. Sometimes the intermediary might or might not be aware of it. This is the infrastructure that a victim will see as the adversary. Type 2 Infrastructure has the purpose of obfuscating the source and attribution of the activity. Type 2 Infrastructure includes malware staging servers, malicious domain names, compromised email accounts, etc.

Service Providers are organizations that provide services considered critical for the adversary availability of Type 1 and Type 2 Infrastructures, for example, Internet Service Providers, domain registrars, and webmail providers.

5. Event Meta Features





Six possible meta-features can be added to the Diamond Model. Meta-features are not required, but they can add some valuable information or intelligence to the Diamond Model.

Timestamp - is the date and time of the event. Each event can be recorded with a date and time that it occurred, such as 2021-09-12 02:10:12.136. The timestamp can include when the event started and stopped. Timestamps are essential to help determine the patterns and group the malicious activity. For example, if the intrusion or breach happened at 3 am in the United States, it might be possible that the attack was carried out from a specific country with a different time zone and standard business hours. 
Phase - these are the phases of an intrusion, attack, or breach. According to the Diamond Model creators and the Axiom 4, "Every malicious activity contains two or more phases which must be successfully executed in succession to achieve the desired result." Malicious activities do not occur as single events, but rather as a sequence of events. A great example can be the Cyber Kill Chain developed by Lockheed Martin. You can find out more about the Cyber Kill Chain by visiting the Cyber Kill Chain room on TryHackMe 
The phases can be: 
 1. Reconnaissance
2. Weaponization
3. Delivery
4. Exploitation
5. Installation
6. Command & Control
7. Actions on Objective
For example, an attacker needs to do some research to discover the target or a victim. Then they would try to exploit the target, establish a command-and-control centre and, lastly, exfiltrate the sensitive information. 
Result - While the results and post-conditions of an adversary’s operations will not always be known or have a high confidence value when they are known, they are helpful to capture. It is crucial to capture the results and post-conditions of an adversary's operations, but sometimes they might not always be known. The event results can be labelled as "success," "failure," or "unknown." The event results can also be related to the CIA (confidentiality, integrity, and availability) triad, such as Confidentiality Compromised, Integrity Compromised, and Availability Compromised. Another approach can also be documenting all of the post-conditions resulting from the event, for example, information gathered in the reconnaissance stage or successful passwords/sensitive data exfiltration.
Direction - This meta-feature helps describe host-based and network-based events and represents the direction of the intrusion attack. The Diamond Model of Intrusion Analysis defines seven potential values for this meta-feature: Victim-to-Infrastructure, Infrastructure-to-Victim, Infrastructure-to-Infrastructure, Adversary-to-Infrastructure, Infrastructure-to-Adversary, Bidirectional or Unknown.
Methodology - This meta-feature will allow an analyst to describe the general classification of intrusion, for example, phishing, DDoS, breach, port scan, etc. 
Resources - According to the Diamond Model, every intrusion event needs one or more external resources to be satisfied to succeed. Examples of the resources can include the following: software (e.g., operating systems, virtualization software, or Metasploit framework), knowledge (e.g., how to use Metasploit to execute the attack and run the exploit), information (e.g., a username/password to masquerade), hardware (e.g., servers, workstations, routers), funds (e.g., money to purchase domains), facilities (e.g., electricity or shelter), access (e.g., a network path from the source host to the victim and vice versa, network access from an Internet Service Provider (ISP)).

6. Social-Political Component
The social-political component describes the needs and intent of the adversary, for example, financial gain, gaining acceptance in the hacker community, hacktivism, or espionage.

7. Technology Component
Technology – the technology meta-feature or component highlights the relationship between the core features: capability and infrastructure. The capability and infrastructure describe how the adversary operates and communicates. A scenario can be a watering-hole attack which is a methodology where the adversary compromises legitimate websites that they believe their targeted victims will visit.

TTP is an acronym for Tactics, Techniques, and Procedures, but what does each of these terms mean?
The Tactic is the adversary's goal or objective.
The Technique is how the adversary achieves the goal or objective.
The Procedure is how the technique is executed.

MITRE ENGAGE
Per the website, "MITRE Engage is a framework for planning and discussing adversary engagement operations that empowers you to engage your adversaries and achieve your cybersecurity goals."

MITRE Engage is considered an Adversary Engagement Approach. This is accomplished by the implementation of Cyber Denial and Cyber Deception. 

With Cyber Denial we prevent the adversary's ability to conduct their operations and with Cyber Deception we intentionally plant artifacts to mislead the adversary.

D3FEND
What is this MITRE resource? Per the D3FEND website, this resource is "A knowledge graph of cybersecurity countermeasures."
D3FEND is still in beta and is funded by the Cybersecurity Directorate of the NSA. 
D3FEND stands for Detection, Denial, and Disruption Framework Empowering Network Defense.
Use this link to draft your portfolio for this chapter
https://medium.com/@niceselol/tryhackme-summit-walkthrough-b14cd75fb910




Network Security and Network Data

Network Security
The essential concern of Network Security focuses on two core concepts: authentication and authorisation.

Network security operations contain three base control levels to ensure the maximum available security management.
Base Network Security Control Levels:
Physical
Physical security controls prevent unauthorised physical access to networking devices, cable boards, locks, and all linked components.
Technical
Data security controls prevent unauthorised access to network data, like installing tunnels and implementing security layers.
Administrative
Administrative security controls provide consistency in security operations like creating policies, access levels and authentication processes.


Threat Intelligence Tools
Room Outline
This room will cover the concepts of Threat Intelligence and various open-source tools that are useful. The learning objectives include:
Understanding the basics of threat intelligence & its classifications.
Using UrlScan.io to scan for malicious URLs.
Using Abuse.ch to track malware and botnet indicators.
Investigate phishing emails using PhishTool
Using Cisco's Talos Intelligence platform for intel gathering.
Threat Intelligence
Threat Intelligence is the analysis of data and information using tools and techniques to generate meaningful patterns on how to mitigate against potential risks associated with existing or emerging threats targeting organisations, industries, sectors or governments.
To mitigate against risks, we can start by trying to answer a few simple questions:
Who's attacking you?
What's their motivation?
What are their capabilities?
What artefacts and indicators of compromise should you look out for?
Threat Intelligence Classifications:
Threat Intel is geared towards understanding the relationship between your operational environment and your adversary. With this in mind, we can break down threat intel into the following classifications: 
Strategic Intel: High-level intel that looks into the organisation's threat landscape and maps out the risk areas based on trends, patterns and emerging threats that may impact business decisions.
Technical Intel: Looks into evidence and artefacts of attack used by an adversary. Incident Response teams can use this intel to create a baseline attack surface to analyse and develop defence mechanisms.
Tactical Intel: Assesses adversaries' tactics, techniques, and procedures (TTPs). This intel can strengthen security controls and address vulnerabilities through real-time investigations.
Operational Intel: Looks into an adversary's specific motives and intent to perform an attack. Security teams may use this intel to understand the critical assets available in the organisation (people, processes, and technologies) that may be targeted.
UrlScan.io
Urlscan.io is a free service developed to assist in scanning and analysing websites. It is used to automate the process of browsing and crawling through websites to record activities and interactions.
Abuse.ch
Abuse.ch is a research project hosted by the Institue for Cybersecurity and Engineering at the Bern University of Applied Sciences in Switzerland. It was developed to identify and track malware and botnets through several operational platforms developed under the project. These platforms are:
Malware Bazaar:  A resource for sharing malware samples.
Feodo Tracker:  A resource used to track botnet command and control (C2) infrastructure linked with Emotet, Dridex and TrickBot.
SSL Blacklist:  A resource for collecting and providing a blocklist for malicious SSL certificates and JA3/JA3s fingerprints.
URL Haus:  A resource for sharing malware distribution sites.
Threat Fox:  A resource for sharing indicators of compromise (IOCs).

Phshtool for email analysis
https://app.phishtool.com/
PhishTool seeks to elevate the perception of phishing as a severe form of attack and provide a responsive means of email security. Through email analysis, security analysts can uncover email IOCs, prevent breaches and provide forensic reports that could be used in phishing containment and training engagements.

Additional features are available on the Enterprise version:
Manage user-reported phishing events.
Report phishing email findings back to users and keep them engaged in the process.
Email stack integration with Microsoft 365 and Google Workspac
Yara

Yara is an open-source tool primarily used for identifying and classifying malware. It allows security researchers and analysts to create rules that describe patterns or characteristics of malicious files. These rules can then be used to scan and match files, processes, or other data for specific traits indicative of malware or suspicious activities.
Key features of Yara include:
Rule-Based Matching: Yara rules consist of a set of conditions that specify what patterns to look for in a file or data. These conditions can include strings, byte sequences, regular expressions, and more.
Flexible Syntax: Yara provides a flexible syntax for defining rules, making it easier to describe complex patterns. Users can combine multiple conditions using logical operators like AND, OR, and NOT.
Wide Applicability: Yara can be used to scan files, processes, memory dumps, network traffic, and more, making it a versatile tool for various security tasks.
Community Contributions: Being open-source, Yara benefits from community contributions, including rule sets shared by other researchers and organizations.
Integration with Security Tools: Yara is often integrated into other security tools and platforms, enhancing threat detection capabilities.
Overall, Yara is a powerful and widely-used tool in cybersecurity for detecting and classifying malware and other suspicious activities based on user-defined rules.


Traffic Analysis / Network Traffic Analysis
Traffic Analysis is a method of intercepting, recording/monitoring, and analysing network data and communication patterns to detect and respond to system health issues, network anomalies, and threats. The network is a rich data source, so traffic analysis is useful for security and operational matters. The operational issues cover system availability checks and measuring performance, and the security issues cover anomaly and suspicious activity detection on the network.

There are two main techniques used in Traffic Analysis:
Flow Analysis
Packet Analysis
Collecting data/evidence from the networking devices. This type of analysis aims to provide statistical results through the data summary without applying in-depth packet-level investigation.
Advantage: Easy to collect and analyse.
Challenge: Doesn't provide full packet details to get the root cause of a case.
Collecting all available network data. Applying in-depth packet-level investigation (often called Deep Packet Inspection (DPI) ) to detect and block anomalous and malicious packets.
Advantage: Provides full packet details to get the root cause of a case.
Challenge: Requires time and skillset to analyse.

SNORT is an open-source, rule-based Network Intrusion Detection and Prevention System (NIDS/NIPS). It was developed and still maintained by Martin Roesch, open-source contributors, and the Cisco Talos team. 
Snort2 Operation Logic: Points to Remember
Points to Remember
Main Components of Snort
Packet Decoder - Packet collector component of Snort. It collects and prepares the packets for pre-processing. 
Pre-processors - A component that arranges and modifies the packets for the detection engine.
Detection Engine - The primary component that process, dissect and analyse the packets by applying the rules. 
Logging and Alerting - Log and alert generation component.
Outputs and Plugins - Output integration modules (i.e. alerts to syslog/mysql) and additional plugin (rule management detection plugins) support is done with this component. 
There are three types of rules available for snort
Community Rules - Free ruleset under the GPLv2. Publicly accessible, no need for registration.
Registered Rules - Free ruleset (requires registration). This ruleset contains subscriber rules with 30 days delay.
Subscriber Rules (Paid) - Paid ruleset (requires subscription). This ruleset is the main ruleset and is updated twice a week (Tuesdays and Thursdays).
You can download and read more on the rules here.
Note: Once you install Snort2, it automatically creates the required directories and files. However, if you want to use the community or the paid rules, you need to indicate each rule in the snort.conf file.
Since it is a long, all-in-one configuration file, editing it without causing misconfiguration is troublesome for some users. That is why Snort has several rule updating modules and integration tools. To sum up, never replace your configured Snort configuration files; you must edit your configuration files manually or update your rules with additional tools and modules to not face any fail/crash or lack of feature.
snort.conf: Main configuration file.
local.rules: User-generated rules file.
Let's start with overviewing the main configuration file (snort.conf) sudo gedit /etc/snort/snort.conf
Navigate to the "Step #1: Set the network variables." section.
This section manages the scope of the detection and rule paths.
TAG NAME
INFO
EXAMPLE
HOME_NET
That is where we are protecting.
 'any' OR '192.168.1.1/24'
EXTERNAL_NET 
This field is the external network, so we need to keep it as 'any' or '!$HOME_NET'.
'any' OR '!$HOME_NET'
RULE_PATH
Hardcoded rule path.
/etc/snort/rules
SO_RULE_PATH
These rules come with registered and subscriber rules.
$RULE_PATH/so_rules
PREPROC_RULE_PATH
These rules come with registered and subscriber rules.
$RULE_PATH/plugin_rules


Navigate to the "Step #2: Configure the decoder." section.
In this section, you manage the IPS mode of snort. The single-node installation model IPS model works best with "afpacket" mode. You can enable this mode and run Snort in IPS.
TAG NAME
INFO
EXAMPLE
#config daq:
IPS mode selection.
afpacket
#config daq_mode:
Activating the inline mode
inline
#config logdir:
Hardcoded default log path.
/var/logs/snort

Data Acquisition Modules (DAQ) are specific libraries used for packet I/O, bringing flexibility to process packets. It is possible to select DAQ type and mode for different purposes.
There are six DAQ modules available in Snort;
Pcap: Default mode, known as Sniffer mode.
Afpacket: Inline mode, known as IPS mode.
Ipq: Inline mode on Linux by using Netfilter. It replaces the snort_inline patch.  
Nfq: Inline mode on Linux.
Ipfw: Inline on OpenBSD and FreeBSD by using divert sockets, with the pf and ipfw firewalls.
Dump: Testing mode of inline and normalisation.
The most popular modes are the default (pcap) and inline/IPS (Afpacket).
Navigate to the "Step #6: Configure output plugins" section.
This section manages the outputs of the IDS/IPS actions, such as logging and alerting format details. The default action prompts everything in the console application, so configuring this part will help you use the Snort more efficiently. 
Navigate to the "Step #7: Customise your ruleset" section.
TAG NAME
INFO
EXAMPLE
# site specific rules
Hardcoded local and user-generated rules path.
include $RULE_PATH/local.rules
#include $RULE_PATH/
Hardcoded default/downloaded rules path.
include $RULE_PATH/rulename

Note that "#" is commenting operator. You should uncomment a line to activate it.
Snort has three main use models;
Sniffer Mode - Read IP packets and prompt them in the console application.
Packet Logger Mode - Log all IP packets (inbound and outbound) that visit the network.
NIDS (Network Intrusion Detection System)  and NIPS (Network Intrusion Prevention System) Modes - Log/drop the packets that are deemed as malicious according to the user-defined rules.
Verify Snort Installation
snort -V
Test snort
sudo snort -c /etc/snort/snort.conf -T
Sniffer mode
verbose mode (-v) and use the interface (-i) "eth0"; sudo snort -v -i eth0 
Snort instance in dumping packet data mode (-d); sudo snort -d
 dump (-d) and link-layer header grabbing (-e) mode; snort -d -e
Snort instance in full packet dump mode (-X); sudo snort -X

sudo snort -v -l .

Let's run Snort in Logger Mode
Packet logger parameters are explained in the table below;
Parameter
Description
-l
Logger mode, target log and alert output directory. Default output folder is /var/log/snort
The default action is to dump as tcpdump format in /var/log/snort
-K ASCII
Log packets in ASCII format.
-r
Reading option, read the dumped logs in Snort.
-n
Specify the number of packets that will process/read. Snort will stop after reading the specified number of packets.




Change ownership
 sudo chown username file or sudo chown username -R directory The "-R" parameter helps recursively process the files and directories.

Logging with parameter "-l"
First, start the Snort instance in packet logger mode; sudo snort -dev -l .
The -l . part of the command creates the logs in the current directory. 
sudo snort -dev -l .
Reading generated logs with parameter "-r"
Start the Snort instance in packet reader mode; sudo snort -r
reading log files with -r
user@ubuntu$ sudo snort -r snort.log.1638459842
Opening log file with tcpdump.
Opening the log file with tcpdump 
user@ubuntu$ sudo tcpdump -r snort.log.1638459842 -ntc 10
Reading with port
"-r" parameter also allows users to filter the binary log files. You can filter the processed log to see specific packets with the "-r" parameter and Berkeley Packet Filters (BPF). 
sudo snort -r logname.log -X
sudo snort -r logname.log icmp
sudo snort -r logname.log tcp
sudo snort -r logname.log 'udp and port 53'
The output will be the same as the above, but only packets with the chosen protocol will be shown. Additionally, you can specify the number of processes with the parameter "-n". The following command will process only the first 10 packets:

 snort -dvr logname.log -n 10
filtering
sudo snort -r snort.log.1638459842 port 22
sudo apt install wireshark
sudo wireshark snort.log.1638459842
sudo tcpdump -r snort.log.1638459842 port 22








Snort in IDS/IPS Mode
Let's run Snort in IDS/IPS Mode
NIDS mode parameters are explained in the table below;
Parameter
Description
-c
Defining the configuration file.
-T
Testing the configuration file.
-N
Disable logging.
-D
Background mode.
-A
Alert modes;
full: Full alert mode, providing all possible information about the alert. This one also is the default mode; once you use -A and don't specify any mode, snort uses this mode.
fast:  Fast mode shows the alert message, timestamp, source and destination IP, along with port numbers.
console: Provides fast style alerts on the console screen.
cmg: CMG style, basic header details with payload in hex and text format.
none: Disabling alerting.



Let's start using each parameter and see the difference between them. Snort needs active traffic on your interface, so we need to generate traffic to see Snort in action. To do this, use the traffic-generator script and sniff the traffic. 
Once you start running IDS/IPS mode, you need to use rules. As we mentioned earlier, we will use a pre-defined ICMP rule as an example. The defined rule will only generate alerts in any direction of ICMP packet activity.
alert icmp any any <> any any  (msg: "ICMP Packet Found"; sid: 100001; rev:1;)
This rule is located in "/etc/snort/rules/local.rules".
Remember, in this module, we will focus only on the operating modes. The rules are covered in TASK9&10. Snort will create an "alert" file if the traffic flow triggers an alert. One last note; once you start running IPS/IDS mode, the sniffing and logging mode will be semi-passive. However, you can activate the functions using the parameters discussed in previous tasks. (-i, -v, -d, -e, -X, -l, -K ASCII) If you don't remember the purpose of these commands, please revisit TASK4.

IDS/IPS mode with parameter "-c and -T"
Start the Snort instance and test the configuration file. sudo snort -c /etc/snort/snort.conf -T  This command will check your configuration file and prompt it if there is any misconfiguratioın in your current setting. You should be familiar with this command if you covered TASK3. If you don't remember the output of this command, please revisit TASK4.

IDS/IPS mode with parameter "-N"
Start the Snort instance and disable logging by running the following command: sudo snort -c /etc/snort/snort.conf -N
Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. This command will disable logging mode. The rest of the other functions will still be available (if activated).
The command-line output will provide the information requested with the parameters. So, if you activate verbosity (-v) or full packet dump (-X) you will still have the output in the console, but there will be no logs in the log folder.

IDS/IPS mode with parameter "-D"
Start the Snort instance in background mode with the following command: sudo snort -c /etc/snort/snort.conf -D
Now run the traffic-generator script as sudo and start ICMP/HTTP traffic. Once the traffic is generated, snort will start processing the packets and accomplish the given task with additional parameters.
IDS/IPS mode with parameter "-A"
Remember that there are several alert modes available in snort;
console: Provides fast style alerts on the console screen.
cmg: Provides basic header details with payload in hex and text format.
full: Full alert mode, providing all possible information about the alert.
fast: Fast mode, shows the alert message, timestamp, source and destination ıp along with port numbers.
none: Disabling alerting.
In this section, only the "console" and "cmg" parameters provide alert information in the console. It is impossible to identify the difference between the rest of the alert modes via terminal. Differences can be identified by looking at generated logs. 
At the end of this section, we will compare the "full", "fast" and "none" modes. Remember that these parameters don't provide console output, so we will continue to identify the differences through log formats.

IDS/IPS mode with parameter "-A console"
Console mode provides fast style alerts on the console screen. Start the Snort instance in console alert mode (-A console ) with the following command sudo snort -c /etc/snort/snort.conf -A console
IDS/IPS mode with parameter "-A cmg"
Cmg mode provides basic header details with payload in hex and text format. Start the Snort instance in cmg alert mode (-A cmg ) with the following command sudo snort -c /etc/snort/snort.conf -A cmg
IDS/IPS mode with parameter "-A fast"
Fast mode provides alert messages, timestamps, and source and destination IP addresses. Remember, there is no console output in this mode. Start the Snort instance in fast alert mode (-A fast ) with the following command sudo snort -c /etc/snort/snort.conf -A fast
IDS/IPS mode with parameter "-A full"
Full alert mode provides all possible information about the alert. Remember, there is no console output in this mode. Start the Snort instance in full alert mode (-A full ) with the following command sudo snort -c /etc/snort/snort.conf -A full
IDS/IPS mode with parameter "-A none"
Disable alerting. This mode doesn't create the alert file. However, it still logs the traffic and creates a log file in binary dump format. Remember, there is no console output in this mode. Start the Snort instance in none alert mode (-A none) with the following command sudo snort -c /etc/snort/snort.conf -A none
IPS mode and dropping packets
Snort IPS mode activated with -Q --daq afpacket parameters. You can also activate this mode by editing snort.conf file. However, you don't need to edit snort.conf file in the scope of this room. Review the bonus task or snort manual for further information on daq and advanced configuration settings: -Q --daq afpacket
Activate the Data Acquisition (DAQ) modules and use the afpacket module to use snort as an IPS: -i eth0:eth1
Identifying interfaces note that Snort IPS require at least two interfaces to work. Now run the traffic-generator script as sudo and start ICMP/HTTP traffic.
runningIPSmode
user@ubuntu$ sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A console


Or 
sudo snort -c /etc/snort/snort.conf -q -Q --daq afpacket -i eth0:eth1 -A full








NetworkMiner

Learn how to use NetworkMiner to analyse recorded traffic files and practice network forensics activities

NetworkMiner is an open-source traffic sniffer, pcap handler and protocol analyser. Developed and still maintained by Netresec.

The official description;
 
"NetworkMiner is an open source Network Forensic Analysis Tool (NFAT) for Windows (but also works in Linux / Mac OS X / FreeBSD). NetworkMiner can be used as a passive network sniffer/packet capturing tool to detect operating systems, sessions, hostnames, open ports etc. without putting any traffic on the network. NetworkMiner can also parse PCAP files for off-line analysis and to regenerate/reassemble transmitted files and certificates from PCAP files.
The investigation tries to answer the 5W;
Who (Source IP and port)
What (Data/payload)
Where (Destination IP and port)
When (Time and data)
Why (How/What happened)
Note that the network evidence capture and investigation process should be systematic. Having enough data and the right timeline capture for a successful network forensics investigation is crucial.
Network Forensics Use Cases
The most common network forensics use cases are explained below;
Network discovery: Discovering the network to overview connected devices, rogue hosts and network load. 


Packets reassembling: Reassembling the packets to investigate the traffic flow. This use case is helpful in unencrypted traffic flows.


Data leakage detection: Reviewing packet transfer rates for each host and destination address helps detect possible data leakage. 


Anomaly and malicious activity detection: Reviewing overall network load by focusing on used ports, source and destination addresses, and data helps detect possible malicious activities along with vulnerabilities. This use case covers the correlation of indicators and hypotheses as well.


Policy/Regulation compliance control: Reviewing overall network behaviour helps detect policy/regulation compliance.


Advantages of Network Forensics 
General advantages of network forensics are explained below;
Availability of network-based evidence in the wild: Capturing network traffic is collecting evidence, so it is easier than other types of evidence collections such as logs and IOCs.
Ease of data/evidence collection without creating noise: Capturing and working with network traffic is easier than investigating unfiltered events by EDRs, EPPs and log systems. Usually, sniffing doesn't create much noise, logs and alerts. The other thing is that network traffic is not destructible like logs and alerts generated by security systems.  
It is hard to destroy the network evidence, as it is the transferred data: Since the evidence is the traffic itself, it is impossible to do anything without creating network noise. Still, it is possible to hide the artefacts by encrypting, tunnelling and manipulating the packets. So, the second fact is the challenge of this advantage. 
Availability of log sources: Logs provide valuable information which helps to correlate the chain of events and support the investigation hypothesis. The majority of the EDRs, EPPs and network devices create logs by default. Having log files is easy if the attacker/threat/malware didn't erase/destroy them.
It is possible to gather evidence for memory and non-residential malicious activities: The malware/threat might reside in the memory to avoid detection. However, the series of commands and connections live in the network. So it is possible to detect non-residential threats with network forensics tools and tactics.
NetworkMiner in a Nutshell
Capability
Description
Traffic sniffing
It can intercept the traffic, sniff it, and collect and log packets that pass through the network.
Parsing PCAP files
It can parse pcap files and show the content of the packets in detail.
Protocol analysis
It can identify the used protocols from the parsed pcap file.
OS fingerprinting
It can identify the used OS by reading the pcap file. This feature strongly relies on Satori and p0f.
 File Extraction
It can extract images, HTML files and emails from the parsed pcap file.
Credential grabbing
It can extract credentials from the parsed pcap file.
Clear text keyword parsing
It can extract cleartext keywords and strings from the parsed pcap file.






Next Github Readme


### Network Security
- **Traffic Monitoring**
  - Snort (Real-time traffic monitoring)
  - NetworkMiner (Traffic monitoring through recorded traffic files)
  - Zeek (Network monitoring)
  - Wireshark (Protocol and PCAP analysis for monitoring)
  - TShark (Protocol and PCAP analysis in CLI)

### Vulnerability Management
- Snort (Detecting vulnerabilities in traffic)

### Threat Intelligence
- **Intrusion Detection**
  - Snort (Real-time threat detection)
  - Zeek (Threat detection)
- **Threat Hunting**
  - Zeek (Threat detection and hunting)
  - Brim (Threat hunting)
  - NetworkMiner (Network forensics and threat detection)
  - Wireshark (Traffic anomaly detection and threat hunting)
  - TShark (Traffic anomaly detection in CLI)

### SIEM (Security Information and Event Management)
- Zeek (Log analysis and monitoring)
- Brim (Log investigation and threat hunting)

### Compliance Monitoring
- Snort (Ensuring traffic complies with security policies)

### Web Analytics
- Not explicitly covered by the listed tools; however, tools like Zeek can be adapted for some web traffic analysis through log analysis and monitoring.



Zeek (formerly Bro) is an open-source and commercial network monitoring tool (traffic analyser).

The official description; "Zeek (formerly Bro) is the world's leading platform for network security monitoring. Flexible, open-source, and powered by defenders." "Zeek is a passive, open-source network traffic analyser. Many operators use Zeek as a network security monitor (NSM) to support suspicious or malicious activity investigations. Zeek also supports a wide range of traffic analysis tasks beyond the security domain, including performance measurement and troubleshooting."

There are two operation options for Zeek. The first one is running it as a service, and the second option is running the Zeek against a pcap. 

zeek -v  

The default log path is: /opt/zeek/logs/ 

Primary management of the Zeek service is done with three commands; "status", "start", and "stop". 
You can also use the "ZeekControl" mode with the following commands as well;
zeekctl status
zeekctl start 
zeekctl stop 
The only way to listen to the live network traffic is using Zeek as a service.

In pcap processing mode, logs are saved in the working directory. You can view the generated logs using the ls -l command.  

Main Zeek command line parameters are explained below;
Parameter
Description
-r
 Reading option, read/process a pcap file.
-C
 Ignoring checksum errors.
-v
 Version information.
zeekctl
ZeekControl module.



Using cat command and zeek-cut
cat dhcp.log | zeek-cut host_name
cat dhcp.log


BRIM
BRIM is an open-source desktop application that processes pcap files and logs files. Its primary focus is providing search and analytics. 


What is Brim?
Brim is an open-source desktop application that processes pcap files and logs files, with a primary focus on providing search and analytics. It uses the Zeek log processing format. It also supports Zeek signatures and Suricata Rules for detection.
It can handle two types of data as an input;
Packet Capture Files: Pcap files created with tcpdump, tshark and Wireshark like applications.
Log Files: Structured log files like Zeek logs.
Brim is built on open-source platforms:
Zeek: Log generating engine.
Zed Language: Log querying language that allows performing keywoırd searches with filters and pipelines.
ZNG Data Format: Data storage format that supports saving data streams.
Electron and React: Cross-platform UI.
Why Brim?
Ever had to investigate a big pcap file? Pcap files bigger than one gigabyte are cumbersome for Wireshark. Processing big pcaps with tcpdump and Zeek is efficient but requires time and effort. Brim reduces the time and effort spent processing pcap files and investigating the log files by providing a simple and powerful GUI application.
Wireshark: The Basics


Wireshark is an open-source, cross-platform network packet analyser tool capable of sniffing and investigating live traffic and inspecting packet captures (PCAP). It is commonly used as one of the best packet analysis tools.

﻿Use Cases
Wireshark is one of the most potent traffic analyser tools available in the wild. There are multiple purposes for its use:
Detecting and troubleshooting network problems, such as network load failure points and congestion.
Detecting security anomalies, such as rogue hosts, abnormal port usage, and suspicious traffic.
Investigating and learning protocol details, such as response codes and payload data. 
Wireshark Filter
Protocol Filters
As mentioned in the previous task, Wireshark supports 3000 protocols and allows packet-level investigation by filtering the protocol fields. This task shows the creation and usage of filters against different protocol fields. 
IP Filters
IP filters help analysts filter the traffic according to the IP level information from the packets (Network layer of the OSI model). This is one of the most commonly used filters in Wireshark. These filters filter network-level information like IP addresses, version, time to live, type of service, flags, and checksum values.

The common filters are shown in the given table.
Filter
Description
ip
Show all IP packets.
ip.addr == 10.10.10.111
Show all packets containing IP address 10.10.10.111.
ip.addr == 10.10.10.0/24
Show all packets containing IP addresses from 10.10.10.0/24 subnet.
ip.src == 10.10.10.111
Show all packets originated from 10.10.10.111
ip.dst == 10.10.10.111
Show all packets sent to 10.10.10.111
ip.addr vs ip.src/ip.dst
Note: The ip.addr filters the traffic without considering the packet direction. The ip.src/ip.dst filters the packet depending on the packet direction.


TCP and UDP Filters
TCP filters help analysts filter the traffic according to protocol-level information from the packets (Transport layer of the OSI model). These filters filter transport protocol level information like source and destination ports, sequence number, acknowledgement number, windows size, timestamps, flags, length and protocol errors.
Filter
Description
Filter
Expression
tcp.port == 80
Show all TCP packets with port 80 
udp.port == 53
Show all UDP packets with port 53
tcp.srcport == 1234
Show all TCP packets originating from port 1234
udp.srcport == 1234
Show all UDP packets originating from port 1234
tcp.dstport == 80
Show all TCP packets sent to port 80
udp.dstport == 5353
Show all UDP packets sent to port 5353


Application Level Protocol Filters | HTTP and DNS
Application-level protocol filters help analysts filter the traffic according to application protocol level information from the packets (Application layer of the OSI model ). These filters filter application-specific information, like payload and linked data, depending on the protocol type.
Filter
Description
Filter
Description
http
Show all HTTP packets
dns
Show all DNS packets
http.response.code == 200
Show all packets with HTTP response code "200"
dns.flags.response == 0
Show all DNS requests
http.request.method == "GET"
Show all HTTP GET requests
dns.flags.response == 1
Show all DNS responses
http.request.method == "POST"
Show all HTTP POST requests
dns.qry.type == 1
Show all DNS "A" records


Display Filter Expressions
As mentioned earlier, Wireshark has a built-in option (Display Filter Expression) that stores all supported protocol structures to help analysts create display filters. When an analyst can't recall the required filter for a specific protocol or is unsure about the assignable values for a filter, the Display Filter Expressions menu provides an easy-to-use display filter builder guide. It is available under the "Analyse --> Display Filter Expression" menu.
It is impossible to memorise all details of the display filters for each protocol. Each protocol can have different fields and can accept various types of values. The Display Filter Expressions menu shows all protocol fields, accepted value types (integer or string) and predefined values (if any). Note that it will take time and require practice to master creating filters and learning the protocol filter fields.

Nmap Scans
Nmap is an industry-standard tool for mapping networks, identifying live hosts and discovering the services. As it is one of the most used network scanner tools, a security analyst should identify the network patterns created with it. This section will cover identifying the most common Nmap scan types.
TCP connect scans
SYN scans
UDP scans
It is essential to know how Nmap scans work to spot scan activity on the network. However, it is impossible to understand the scan details without using the correct filters. Below are the base filters to probe Nmap scan behaviour on the network. 
TCP flags in a nutshell.
Notes
Wireshark Filters
Global search.
tcp
udp
Only SYN flag.
SYN flag is set. The rest of the bits are not important.
tcp.flags == 2
tcp.flags.syn == 1
Only ACK flag.
ACK flag is set. The rest of the bits are not important.
tcp.flags == 16
tcp.flags.ack == 1
Only SYN, ACK flags.
SYN and ACK are set. The rest of the bits are not important.
tcp.flags == 18
(tcp.flags.syn == 1) and (tcp.flags.ack == 1)
Only RST flag.
RST flag is set. The rest of the bits are not important.

tcp.flags == 4
tcp.flags.reset == 1
Only RST, ACK flags.
RST and ACK are set. The rest of the bits are not important.
tcp.flags == 20
(tcp.flags.reset == 1) and (tcp.flags.ack == 1)
Only FIN flag
FIN flag is set. The rest of the bits are not important.
tcp.flags == 1
tcp.flags.fin == 1

TCP Connect Scans
TCP Connect Scan in a nutshell:
Relies on the three-way handshake (needs to finish the handshake process).
Usually conducted with nmap -sT command.
Used by non-privileged users (only option for a non-root user).
Usually has a windows size larger than 1024 bytes as the request expects some data due to the nature of the protocol.
Open TCP Port
Open TCP Port
Closed TCP Port
SYN -->
<-- SYN, ACK
ACK -->
SYN -->
<-- SYN, ACK
ACK -->
RST, ACK -->
SYN -->
<-- RST, ACK

The images below show the three-way handshake process of the open and close TCP ports. Images and pcap samples are split to make the investigation easier and understand each case's details.
Open TCP port (Connect):

Closed TCP port (Connect):

The above images provide the patterns in isolated traffic. However, it is not always easy to spot the given patterns in big capture files. Therefore analysts need to use a generic filter to view the initial anomaly patterns, and then it will be easier to focus on a specific traffic point. The given filter shows the TCP Connect scan patterns in a capture file.
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size > 1024 

SYN Scans
TCP SYN Scan in a nutshell:
Doesn't rely on the three-way handshake (no need to finish the handshake process).
Usually conducted with nmap -sS command.
Used by privileged users.
Usually have a size less than or equal to 1024 bytes as the request is not finished and it doesn't expect to receive data.
Open TCP Port
Close TCP Port
SYN -->
<-- SYN,ACK
RST-->
SYN -->
<-- RST,ACK

Open TCP port (SYN):

Closed TCP port (SYN):

The given filter shows the TCP SYN scan patterns in a capture file.
tcp.flags.syn==1 and tcp.flags.ack==0 and tcp.window_size <= 1024  

UDP Scans
UDP Scan in a nutshell:
Doesn't require a handshake process
No prompt for open ports
ICMP error message for close ports
Usually conducted with nmap -sU command.
Open UDP Port
Closed UDP Port
UDP packet -->
UDP packet -->
ICMP Type 3, Code 3 message. (Destination unreachable, port unreachable)

Closed (port no 69) and open (port no 68) UDP ports:

The above image shows that the closed port returns an ICMP error packet. No further information is provided about the error at first glance, so how can an analyst decide where this error message belongs? The ICMP error message uses the original request as encapsulated data to show the source/reason of the packet. Once you expand the ICMP section in the packet details pane, you will see the encapsulated data and the original request, as shown in the below image.

The given filter shows the UDP scan patterns in a capture file.
icmp.type==3 and icmp.code==3     

Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!
ARP Poisoning/Spoofing (A.K.A. Man In The Middle Attack)
ARP protocol, or Address Resolution Protocol (ARP), is the technology responsible for allowing devices to identify themselves on a network. Address Resolution Protocol Poisoning (also known as ARP Spoofing or Man In The Middle (MITM) attack) is a type of attack that involves network jamming/manipulating by sending malicious ARP packets to the default gateway. The ultimate aim is to manipulate the "IP to MAC address table" and sniff the traffic of the target host.
There are a variety of tools available to conduct ARP attacks. However, the mindset of the attack is static, so it is easy to detect such an attack by knowing the ARP protocol workflow and Wireshark skills.    
ARP analysis in a nutshell:
Works on the local network
Enables the communication between MAC addresses
Not a secure protocol
Not a routable protocol
It doesn't have an authentication function
Common patterns are request & response, announcement and gratuitous packets.
To log a browser session's full details
how do i make the browser to log the full section details in my local folder so that I can decrypt the traffic with wireshark?
ChatGPT
To log a browser session's full details, including encrypted traffic, and later decrypt it using Wireshark, you need to perform a few steps. This process involves logging TLS/SSL session keys that are used to encrypt HTTPS traffic so that Wireshark can decrypt the captured traffic.
Steps to Log TLS/SSL Session Keys
1. Set Up Environment Variables for TLS Key Logging
Most modern web browsers (like Chrome and Firefox) support logging TLS session keys via an environment variable. Here’s how you can set it up:
For Linux/MacOS:
Open a terminal.
Set the SSLKEYLOGFILE environment variable to the path where you want to save the TLS keys:
bash
Copy code
export SSLKEYLOGFILE=~/path/to/save/folder/sslkeys.log
Start your browser from the same terminal session. For example, to start Firefox:
bash
Copy code
firefox &
Now, all the session keys for HTTPS traffic will be logged to the specified file.
For Windows:
Open a Command Prompt.
Set the SSLKEYLOGFILE environment variable:
cmd
Copy code
set SSLKEYLOGFILE=C:\path\to\save\folder\sslkeys.log
Start your browser from the same Command Prompt:
cmd
Copy code
start chrome
The session keys will be logged to the specified file.
2. Capture the Network Traffic
While browsing, you can capture the network traffic using Wireshark or tcpdump.
Using Wireshark:
Open Wireshark and start capturing on the appropriate network interface.
Browse the web as usual.
Using tcpdump:
Run the following command to capture traffic and save it to a file:
bash
Copy code
sudo tcpdump -i <interface> -w /path/to/save/folder/capture.pcap
Stop the capture when done browsing.
3. Load the TLS Session Keys in Wireshark
Once you have captured the traffic and logged the session keys, you can use Wireshark to decrypt the HTTPS traffic:
Open Wireshark.
Load the .pcap File:
Open the .pcap file that contains the captured network traffic.
Load the SSL Key Log File:
Go to Edit > Preferences.
Under Protocols, scroll down to TLS (or SSL for older versions).
In the (Pre)-Master-Secret log filename field, enter the path to your sslkeys.log file.
Click OK.
Decrypt the Traffic:
Wireshark will automatically decrypt the HTTPS traffic using the session keys.
You should now see the decrypted content in the packet details pane.
4. Analyze the Decrypted Traffic
You can now analyze the decrypted traffic just like any other network traffic in Wireshark.
Use filters like http, https, or specific IP addresses to narrow down the analysis.
Important Considerations
Security: The sslkeys.log file contains sensitive information. Anyone with access to this file can decrypt the corresponding captured traffic, so it should be handled securely and deleted when no longer needed.
Privacy: Ensure you have the legal right and permission to capture and decrypt traffic, especially if you are analyzing traffic that is not your own.
Browser Compatibility: The method described works with browsers like Chrome, Firefox, and derivatives (e.g., Chromium-based browsers). Some browsers may not support this, or they might need additional configuration.
By following these steps, you can log the full details of a browsing session, including encrypted HTTPS traffic, and decrypt it later with Wireshark for analysis.
can the logged section keys be used to anlyse traffic of browsing history?
ChatGPT
Yes, the logged session keys can be used to analyze the traffic corresponding to the browsing history, provided you have the associated network capture file (e.g., a .pcap file) that contains the encrypted traffic.
How It Works:
When you log the TLS/SSL session keys using the method described earlier, those keys are specific to the HTTPS sessions that occur during that browsing session. Here's how you can use these keys to analyze the traffic:
Capture Traffic and Log Keys Simultaneously:
While you browse the web, the traffic is captured in a .pcap file, and the session keys are logged in a separate sslkeys.log file.
Analyzing the Traffic Later:
Even if you revisit the browsing history later, as long as the session keys are valid for the corresponding captured sessions, you can decrypt and analyze the traffic.
Note that the session keys are only valid for the specific sessions they were logged for, so you need the traffic captured at the same time those keys were generated.
Steps to Analyze Historical Traffic:
Capture and Log During Browsing:
Ensure that you are capturing traffic (using Wireshark or tcpdump) and logging TLS session keys as you browse.
Save the Capture and Log Files:
Save the captured traffic (.pcap file) and the TLS session keys (sslkeys.log file) in a secure location.
Analyze Later:
At a later time, you can load both the .pcap file and the sslkeys.log file into Wireshark.
Wireshark will use the session keys to decrypt the HTTPS traffic, allowing you to see the contents of the browsing sessions.
Use Wireshark Filters:
You can apply filters in Wireshark to focus on specific traffic, such as:
http or https to see web traffic.
ip.addr == <IP address> to filter traffic to/from a specific IP.
tcp.port == 443 to focus on HTTPS traffic.
Limitations and Considerations:
Session-Specific: The session keys are only valid for the sessions during which they were captured. If you try to analyze traffic from a different session without the corresponding keys, the traffic will remain encrypted.
Retention of Logs: If the sslkeys.log file is deleted or lost, you will not be able to decrypt the traffic, even if you have the .pcap file.
Security Implications: The sslkeys.log file contains sensitive information. It should be protected and deleted when no longer needed to prevent unauthorized decryption of traffic.
Conclusion:
Yes, the logged session keys can be used to analyze the traffic of your browsing history, as long as you have captured the traffic at the same time and have the corresponding .pcap file. This allows you to decrypt HTTPS traffic and view the details of your browsing sessions later in Wireshark.

Notes
Wireshark filter
Global search
arp
"ARP" options for grabbing the low-hanging fruits:
Opcode 1: ARP requests.
Opcode 2: ARP responses.
Hunt: Arp scanning
Hunt: Possible ARP poisoning detection
Hunt: Possible ARP flooding from detection:






arp.opcode == 1
arp.opcode == 2
arp.dst.hw_mac==00:00:00:00:00:00
arp.duplicate-address-detected or arp.duplicate-address-frame
((arp) && (arp.opcode == 1)) && (arp.src.hw_mac == target-mac-address)




Here, knowing the network architecture and inspecting the traffic for a specific time frame can help detect the anomaly. As an analyst, you should take notes of your findings before going further. This will help you be organised and make it easier to correlate the further findings. Look at the given picture; there is a conflict; the MAC address that ends with "b4" crafted an ARP request with the "192.168.1.25" IP address, then claimed to have the "192.168.1.1" IP address.
Notes
Detection Notes
Findings
Possible IP address match.
1 IP address announced from a MAC address.
MAC: 00:0c:29:e2:18:b4
IP: 192.168.1.25
Possible ARP spoofing attempt.
2 MAC addresses claimed the same IP address (192.168.1.1).
The " 192.168.1.1" IP address is a possible gateway address.
MAC1: 50:78:b3:f3:cd:f4
MAC 2: 00:0c:29:e2:18:b4
Possible ARP flooding attempt.
The MAC address that ends with "b4" claims to have a different/new IP address.
MAC: 00:0c:29:e2:18:b4
IP: 192.168.1.1

Let's keep inspecting the traffic to spot any other anomalies. Note that the case is split into multiple capture files to make the investigation easier.

At this point, it is evident that there is an anomaly. A security analyst cannot ignore a flood of ARP requests. This could be malicious activity, scan or network problems. There is a new anomaly; the MAC address that ends with "b4" crafted multiple ARP requests with the "192.168.1.25" IP address. Let's focus on the source of this anomaly and extend the taken notes. 
Notes
Detection Notes
Findings
Possible IP address match.
1 IP address announced from a MAC address.
MAC: 00:0c:29:e2:18:b4
IP: 192.168.1.25
Possible ARP spoofing attempt.
2 MAC addresses claimed the same IP address (192.168.1.1).
The " 192.168.1.1" IP address is a possible gateway address.
MAC1: 50:78:b3:f3:cd:f4
MAC 2: 00:0c:29:e2:18:b4
Possible ARP spoofing attempt.
The MAC address that ends with "b4" claims to have a different/new IP address.
MAC: 00:0c:29:e2:18:b4
IP: 192.168.1.1
Possible ARP flooding attempt.
The MAC address that ends with "b4" crafted multiple ARP requests against a range of IP addresses.
MAC: 00:0c:29:e2:18:b4
IP: 192.168.1.xxx

Up to this point, it is evident that the MAC address that ends with "b4" owns the "192.168.1.25" IP address and crafted suspicious ARP requests against a range of IP addresses. It also claimed to have the possible gateway address as well. Let's focus on other protocols and spot the reflection of this anomaly in the following sections of the time frame. 

There is HTTP traffic, and everything looks normal at the IP level, so there is no linked information with our previous findings. Let's add the MAC addresses as columns in the packet list pane to reveal the communication behind the IP addresses.

One more anomaly! The MAC address that ends with "b4" is the destination of all HTTP packets! It is evident that there is a MITM attack, and the attacker is the host with the MAC address that ends with "b4". All traffic linked to "192.168.1.12" IP addresses is forwarded to the malicious host. Let's summarise the findings before concluding the investigation.  
Detection Notes
Findings


IP to MAC matches.
3  IP to MAC address matches. 
MAC: 00:0c:29:e2:18:b4 = IP: 192.168.1.25
MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.1
MAC: 00:0c:29:98:c7:a8 = IP: 192.168.1.12
Attacker
The attacker created noise with ARP packets.
MAC: 00:0c:29:e2:18:b4 = IP: 192.168.1.25
Router/gateway
Gateway address.
MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.1
Victim
The attacker sniffed all traffic of the victim.
MAC: 50:78:b3:f3:cd:f4 = IP: 192.1681.12

Detecting these bits and pieces of information in a big capture file is challenging. However, in real-life cases, you will not have "tailored data" ready for investigation. Therefore you need to have the analyst mindset, knowledge and tool skills to filter and detect the anomalies. 
Note: In traffic analysis, there are always alternative solutions available. The solution type and the approach depend on the analyst's knowledge and skill level and the available data sources. 
Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!








USEFUL RESOURCE:
https://medium.com/@huglertomgaw/thm-wireshark-traffic-analysis-3bd1b31c99b


Wireshark: Traffic Analysis

task3

https://medium.com/@huglertomgaw/thm-wireshark-traffic-analysis-3bd1b31c99b


arp.duplicate-address-detected or arp.duplicate-address-frame


arp.opcode == 1 and arp.src.hw_mac == 00:0c:29:e2:18:b4


http and eth.addr == 00:0c:29:e2:18:b4
Search for user credentilas


urlencoded-form matches ".Client354"


Identifying Hosts
When investigating a compromise or malware infection activity, a security analyst should know how to identify the hosts on the network apart from IP to MAC address match. One of the best methods is identifying the hosts and users on the network to decide the investigation's starting point and list the hosts and users associated with the malicious traffic/activity.
Usually, enterprise networks use a predefined pattern to name users and hosts. While this makes knowing and following the inventory easier, it has good and bad sides. The good side is that it will be easy to identify a user or host by looking at the name. The bad side is that it will be easy to clone that pattern and live in the enterprise network for adversaries. There are multiple solutions to avoid these kinds of activities, but for a security analyst, it is still essential to have host and user identification skills.
Protocols that can be used in Host and User identification:
Dynamic Host Configuration Protocol (DHCP) traffic
NetBIOS (NBNS) traffic 
Kerberos traffic
DHCP Analysis
DHCP protocol, or Dynamic Host Configuration Protocol (DHCP), is the technology responsible for managing automatic IP address and required communication parameters assignment.
DHCP investigation in a nutshell:
Notes
Wireshark Filter
Global search.
dhcp or bootp
Filtering the proper DHCP packet options is vital to finding an event of interest. 

"DHCP Request" packets contain the hostname information
"DHCP ACK" packets represent the accepted requests
"DHCP NAK" packets represent denied requests
Due to the nature of the protocol, only "Option 53" ( request type) has predefined static values. You should filter the packet type first, and then you can filter the rest of the options by "applying as column" or use the advanced filters like "contains" and "matches".
Request: dhcp.option.dhcp == 3
ACK: dhcp.option.dhcp == 5
NAK: dhcp.option.dhcp == 6
"DHCP Request" options for grabbing the low-hanging fruits:
Option 12: Hostname.
Option 50: Requested IP address.
Option 51: Requested IP lease time.
Option 61: Client's MAC address.
dhcp.option.hostname contains "keyword"
"DHCP ACK" options for grabbing the low-hanging fruits:
Option 15: Domain name.
Option 51: Assigned IP lease time.
dhcp.option.domain_name contains "keyword"
"DHCP NAK" options for grabbing the low-hanging fruits:
Option 56: Message (rejection details/reason).
As the message could be unique according to the case/situation, It is suggested to read the message instead of filtering it. Thus, the analyst could create a more reliable hypothesis/result by understanding the event circumstances.


NetBIOS (NBNS) Analysis
NetBIOS or Network Basic Input/Output System is the technology responsible for allowing applications on different hosts to communicate with each other. 
NBNS investigation in a nutshell:
Notes
Wireshark Filter
Global search.
nbns
"NBNS" options for grabbing the low-hanging fruits:
Queries: Query details.
Query details could contain "name, Time to live (TTL) and IP address details"
nbns.name contains "keyword"


Kerberos Analysis
Kerberos is the default authentication service for Microsoft Windows domains. It is responsible for authenticating service requests between two or more computers over the untrusted network. The ultimate aim is to prove identity securely.
Kerberos investigation in a nutshell:
Notes
Wireshark Filter
Global search.
kerberos
User account search:
CNameString: The username.
Note: Some packets could provide hostname information in this field. To avoid this confusion, filter the "$" value. The values end with "$" are hostnames, and the ones without it are user names.
kerberos.CNameString contains "keyword" 
kerberos.CNameString and !(kerberos.CNameString contains "$" )
"Kerberos" options for grabbing the low-hanging fruits:
pvno: Protocol version.
realm: Domain name for the generated ticket.
sname: Service and domain name for the generated ticket.
addresses: Client IP address and NetBIOS name.
Note: the "addresses" information is only available in request packets.
kerberos.pvno == 5
kerberos.realm contains ".org" 
kerberos.SNameString == "krbtg"


Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!










dhcp.option.dhcp == 3 && dhcp.option.requested_ip_address == 172.16.13.85
Tunnelling Traffic: ICMP and DNS 
Traffic tunnelling is (also known as "port forwarding") transferring the data/resources in a secure method to network segments and zones. It can be used for "internet to private networks" and "private networks to internet" flow/direction. There is an encapsulation process to hide the data, so the transferred data appear natural for the case, but it contains private data packets and transfers them to the final destination securely.


Tunnelling provides anonymity and traffic security. Therefore it is highly used by enterprise networks. However, as it gives a significant level of data encryption, attackers use tunnelling to bypass security perimeters using the standard and trusted protocols used in everyday traffic like ICMP and DNS. Therefore, for a security analyst, it is crucial to have the ability to spot ICMP and DNS anomalies.


ICMP Analysis 
Internet Control Message Protocol (ICMP) is designed for diagnosing and reporting network communication issues. It is highly used in error reporting and testing. As it is a trusted network layer protocol, sometimes it is used for denial of service (DoS) attacks; also, adversaries use it in data exfiltration and C2 tunnelling activities.
ICMP analysis in a nutshell:
Usually, ICMP tunnelling attacks are anomalies appearing/starting after a malware execution or vulnerability exploitation. As the ICMP packets can transfer an additional data payload, adversaries use this section to exfiltrate data and establish a C2 connection. It could be a TCP, HTTP or SSH data. As the ICMP protocols provide a great opportunity to carry extra data, it also has disadvantages. Most enterprise networks block custom packets or require administrator privileges to create custom ICMP packets.
A large volume of ICMP traffic or anomalous packet sizes are indicators of ICMP tunnelling. Still, the adversaries could create custom packets that match the regular ICMP packet size (64 bytes), so it is still cumbersome to detect these tunnelling activities. However, a security analyst should know the normal and the abnormal to spot the possible anomaly and escalate it for further analysis.
Notes
Wireshark filters
Global search
icmp
"ICMP" options for grabbing the low-hanging fruits:
Packet length.
ICMP destination addresses.
Encapsulated protocol signs in ICMP payload.
data.len > 64 and icmp


DNS Analysis 
Domain Name System (DNS) is designed to translate/convert IP domain addresses to IP addresses. It is also known as a phonebook of the internet. As it is the essential part of web services, it is commonly used and trusted, and therefore often ignored. Due to that, adversaries use it in data exfiltration and C2 activities.
DNS analysis in a nutshell:


Similar to ICMP tunnels, DNS attacks are anomalies appearing/starting after a malware execution or vulnerability exploitation. Adversary creates (or already has) a domain address and configures it as a C2 channel. The malware or the commands executed after exploitation sends DNS queries to the C2 server. However, these queries are longer than default DNS queries and crafted for subdomain addresses. Unfortunately, these subdomain addresses are not actual addresses; they are encoded commands as shown below:


"encoded-commands.maliciousdomain.com"


When this query is routed to the C2 server, the server sends the actual malicious commands to the host. As the DNS queries are a natural part of the networking activity, these packets have the chance of not being detected by network perimeters. A security analyst should know how to investigate the DNS packet lengths and target addresses to spot these anomalies. 
Notes
Wireshark Filter
Global search
dns
"DNS" options for grabbing the low-hanging fruits:
Query length.
Anomalous and non-regular names in DNS addresses.
Long DNS addresses with encoded subdomain addresses.
Known patterns like dnscat and dns2tcp.
Statistical analysis like the anomalous volume of DNS requests for a particular target.
!mdns: Disable local link device queries.
dns contains "dnscat"
dns.qry.name.len > 15 and !mdns


Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!
HTTP Analysis 
Hypertext Transfer Protocol (HTTP) is a cleartext-based, request-response and client-server protocol. It is the standard type of network activity to request/serve web pages, and by default, it is not blocked by any network perimeter. As a result of being unencrypted and the backbone of web traffic, HTTP is one of the must-to-know protocols in traffic analysis. Following attacks could be detected with the help of HTTP analysis:


Phishing pages
Web attacks
Data exfiltration
Command and control traffic (C2)
HTTP analysis in a nutshell:
Notes
Wireshark Filter
Global search
Note: HTTP2 is a revision of the HTTP protocol for better performance and security. It supports binary data transfer and request&response multiplexing.
http
http2
"HTTP Request Methods" for grabbing the low-hanging fruits:
GET
POST
Request: Listing all requests
http.request.method == "GET"
http.request.method == "POST"
http.request
"HTTP Response Status Codes" for grabbing the low-hanging fruits:
200 OK: Request successful.
301 Moved Permanently: Resource is moved to a new URL/path (permanently).
302 Moved Temporarily: Resource is moved to a new URL/path (temporarily).
400 Bad Request: Server didn't understand the request.
401 Unauthorised: URL needs authorisation (login, etc.).
403 Forbidden: No access to the requested URL. 
404 Not Found: Server can't find the requested URL.
405 Method Not Allowed: Used method is not suitable or blocked.
408 Request Timeout:  Request look longer than server wait time.
500 Internal Server Error: Request not completed, unexpected error.
503 Service Unavailable: Request not completed server or service is down.
http.response.code == 200
http.response.code == 401
http.response.code == 403
http.response.code == 404
http.response.code == 405
http.response.code == 503
"HTTP Parameters" for grabbing the low-hanging fruits:
User agent: Browser and operating system identification to a web server application.
Request URI: Points the requested resource from the server.
Full *URI: Complete URI information.
*URI: Uniform Resource Identifier.
http.user_agent contains "nmap"
http.request.uri contains "admin"
http.request.full_uri contains "admin"
"HTTP Parameters" for grabbing the low-hanging fruits:
Server: Server service name.
Host: Hostname of the server
Connection: Connection status.
Line-based text data: Cleartext data provided by the server.
HTML Form URL Encoded: Web form information.
http.server contains "apache"
http.host contains "keyword"
http.host == "keyword"
http.connection == "Keep-Alive"
data-text-lines contains "keyword"

User Agent Analysis 
As the adversaries use sophisticated technics to accomplish attacks, they try to leave traces similar to natural traffic through the known and trusted protocols. For a security analyst, it is important to spot the anomaly signs on the bits and pieces of the packets. The "user-agent" field is one of the great resources for spotting anomalies in HTTP traffic. In some cases, adversaries successfully modify the user-agent data, which could look super natural. A security analyst cannot rely only on the user-agent field to spot an anomaly. Never whitelist a user agent, even if it looks natural. User agent-based anomaly/threat detection/hunting is an additional data source to check and is useful when there is an obvious anomaly. If you are unsure about a value, you can conduct a web search to validate your findings with the default and normal user-agent info (example site).


User Agent analysis in a nutshell:
Notes
Wireshark Filter
Global search.
http.user_agent
Research outcomes for grabbing the low-hanging fruits:
Different user agent information from the same host in a short time notice.
Non-standard and custom user agent info.
Subtle spelling differences. ("Mozilla" is not the same as  "Mozlilla" or "Mozlila")
Audit tools info like Nmap, Nikto, Wfuzz and sqlmap in the user agent field.
Payload data in the user agent field.
(http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")


Log4j Analysis 
A proper investigation starts with prior research on threats and anomalies going to be hunted. Let's review the knowns on the "Log4j" attack before launching Wireshark.


Log4j vulnerability analysis in a nutshell:
Notes
Wireshark Filters
Research outcomes for grabbing the low-hanging fruits:
The attack starts with a "POST" request
There are known cleartext patterns: "jndi:ldap" and "Exploit.class".
http.request.method == "POST"
(ip contains "jndi") or ( ip contains "Exploit")
(frame contains "jndi") or ( frame contains "Exploit")
(http.user_agent contains "$") or (http.user_agent contains "==")


Detecting suspicious activities in chunked files is eas


Decrypting HTTPS Traffic
When investigating web traffic, analysts often run across encrypted traffic. This is caused by using the Hypertext Transfer Protocol Secure (HTTPS) protocol for enhanced security against spoofing, sniffing and intercepting attacks. HTTPS uses TLS protocol to encrypt communications, so it is impossible to decrypt the traffic and view the transferred data without having the encryption/decryption key pairs. As this protocol provides a good level of security for transmitting sensitive data, attackers and malicious websites also use HTTPS. Therefore, a security analyst should know how to use key files to decrypt encrypted traffic and investigate the traffic activity.
The packets will appear in different colours as the HTTP traffic is encrypted. Also, protocol and info details (actual URL address and data returned from the server) will not be fully visible. The first image below shows the HTTP packets encrypted with the TLS protocol. The second and third images demonstrate filtering HTTP packets without using a key log file.
Additional information for HTTPS :
Notes
Wireshark Filter
"HTTPS Parameters" for grabbing the low-hanging fruits:
Request: Listing all requests
TLS: Global TLS search
TLS Client Request
TLS Server response
Local Simple Service Discovery Protocol (SSDP)
Note: SSDP is a network protocol that provides advertisement and discovery of network services.
http.request
tls
tls.handshake.type == 1
tls.handshake.type == 2
ssdp


Similar to the TCP three-way handshake process, the TLS protocol has its handshake process. The first two steps contain "Client Hello" and "Server Hello" messages. The given filters show the initial hello packets in a capture file. These filters are helpful to spot which IP addresses are involved in the TLS handshake.
Client Hello: (http.request or tls.handshake.type == 1) and !(ssdp) 
Server Hello: (http.request or tls.handshake.type == 2) and !(ssdp)  

An encryption key log file is a text file that contains unique key pairs to decrypt the encrypted traffic session. These key pairs are automatically created (per session) when a connection is established with an SSL/TLS-enabled webpage. As these processes are all accomplished in the browser, you need to configure your system and use a suitable browser (Chrome and Firefox support this) to save these values as a key log file. To do this, you will need to set up an environment variable and create the SSLKEYLOGFILE, and the browser will dump the keys to this file as you browse the web. SSL/TLS key pairs are created per session at the connection time, so it is important to dump the keys during the traffic capture. Otherwise, it is not possible to create/generate a suitable key log file to decrypt captured traffic. You can use the "right-click" menu or "Edit --> Preferences --> Protocols --> TLS" menu to add/remove key log files.
Adding key log files with the "right-click" menu:

Adding key log files with the "Edit --> Preferences --> Protocols --> TLS" menu:

Viewing the traffic with/without the key log files:

The above image shows that the traffic details are visible after using the key log file. Note that the packet details and bytes pane provides the data in different formats for investigation. Decompressed header info and HTTP2 packet details are available after decrypting the traffic. Depending on the packet details, you can also have the following data formats:
Frame
Decrypted TLS
Decompressed Header
Reassembled TCP
Reassembled SSL
Detecting suspicious activities in chunked files is easy and a great way to learn how to focus on the details. Now use the exercise files to put your skills into practice against a single capture file and answer the questions below!
TShark: The Basics

TShark Fundamentals I | Main Parameters I
Command-Line Interface and Parameters
TShark is a text-based (command-line) tool. Therefore, conducting an in-depth and consecutive analysis of the obtained results is easy. Multiple built-in options are ready to use to help analysts conduct such investigations. However, learning the parameters is essential; you will need the built-in options and associated parameters to keep control of the output and not be flooded with the detailed output of TShark. The most common parameters are explained in the given table below. Note that TShark requires superuser privileges to sniff live traffic and list all available interfaces. 
Parameter
Purpose
-h
Display the help page with the most common features.
tshark -h
-v
Show version info.
tshark -v
-D
List available sniffing interfaces.
tshark -D
-i
Choose an interface to capture live traffic.
tshark -i 1
tshark -i ens55
No Parameter
Sniff the traffic like tcpdump.
tshark

Let's view the version info of the TShark instance in the given VM. Open the terminal and follow the given instructions.
View version
user@ubuntu$ tshark -v                           
TShark (Wireshark) 3 (Git v3. packaged as 3.)

Copyright 1998-2020 Gerald Combs and contributors. License GPLv2+: GNU GPL version 2 or later.
This is free software; see the source for copying conditions.
..


Sniffing


Sniffing is one of the essential functionalities of TShark. A computer node can have multiple network interfaces that allow the host to communicate and sniff the traffic through the network. Specific interfaces might be associated with particular tasks/jobs. Therefore, the ability to choose a sniffing interface helps users decide and set the proper interface for sniffing.
Let's view the available interfaces in the given VM.
List interfaces
user@ubuntu$ sudo tshark -D
1. ens5
2. lo (Loopback)
3. any
4. bluetooth-monitor
5. nflog
..
Sniffing can be done with and without selecting a specific interface. When a particular interface is selected, TShark uses that interface to sniff the traffic. TShark will use the first available interface when no interface is selected, usually listed as 1 in the terminal. Having no interface argument is an alias for -i 1. You can also set different sniffing interfaces by using the parameter -i. TShark always echoes the used interface name at the beginning of the sniffing.
Sniff traffic
# Sniffing with the default interface.
user@ubuntu$ tshark                           
Capturing on 'ens5'
    1   0.000000 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 
    2   0.911310 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1 
    3   0.911310 aaa.aaa.aaa.aaa ? bbb.bbb.bbb.bbb TCP 3372 ? 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0 
...
100 packets captured

# Choosing an interface
user@ubuntu$ tshark -i 2
Capturing on 'Loopback: lo'
...


﻿﻿Command-Line Interface and Parameters II
Let's continue discovering main parameters of TShark. 
Parameter
Purpose
-r
Read/input function. Read a capture file.
tshark -r demo.pcapng
-c
Packet count. Stop after capturing a specified number of packets.
E.g. stop after capturing/filtering/reading 10 packets.
tshark -c 10
-w
Write/output function. Write the sniffed traffic to a file.
tshark -w sample-capture.pcap
-V
Verbose.
Provide detailed information for each packet. This option will provide details similar to Wireshark's "Packet Details Pane".
tshark -V
-q
Silent mode.
Suspress the packet outputs on the terminal.
tshark -q
-x
Display packet bytes.
Show packet details in hex and ASCII dump for each packet.
tshark -x


Read Capture Files
TShark can also process PCAP files. You can use the -r parameter to process the file and investigate the packets. You can limit the number of shown packets using the -c parameter.
Read data
user@ubuntu$ tshark -r demo.pcapng
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 
    2   0.911310 65.208.228.223 ? 145.254.160.237 TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1 
    3   0.911310 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [ACK] Seq=1 Ack=1 Win=9660 Len=0 

..

# Read by count, show only the first 2 packets.
user@ubuntu$ tshark -r demo.pcapng -c 2
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 
    2   0.911310 65.208.228.223 ? 145.254.160.237 TCP 80 ? 3372 [SYN, ACK] Seq=0 Ack=1 Win=5840 Len=0 MSS=1380 SACK_PERM=1

Write Data
TShark can also write the sniffed or filtered packets to a file. You can save the sniffed traffic to a file using the -w parameter. This option helps analysts to separate specific packets from the file/traffic and save them for further analysis. It also allows analysts to share only suspicious packets/scope with higher-level investigators.
Write data
# Read the first packet of the demo.pcapng, create write-demo.pcap and save the first packet there.
user@ubuntu$ tshark -r demo.pcapng -c 1 -w write-demo.pcap

# List the contents of the current folder.
user@ubuntu$ ls
demo.pcapng  write-demo.pcap

# Read the write-demo.pcap and show the packet bytes/details.
user@ubuntu$ tshark -r write-demo.pcap 
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1

Show Packet Bytes
TShark can show packet details in hex and ASCII format. You can view the dump of the packets by using the -x parameter. Once you use this parameter, all packets will be shown in hex and ASCII format. Therefore, it might be hard to spot anomalies at a glance, so using this option after reducing the number of packets will be much more efficient.
Show packet bytes
# Read the packets from write-demo.pcap
user@ubuntu$ tshark -r write-demo.pcap 
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 

# Read the packets from write-demo.pcap and show the packet bytes/details.
user@ubuntu$ tshark -r write-demo.pcap -x
0000  fe ff 20 00 01 00 00 00 01 00 00 00 08 00 45 00   .. ...........E.
0010  00 30 0f 41 40 00 80 06 91 eb 91 fe a0 ed 41 d0   .0.A@.........A.
0020  e4 df 0d 2c 00 50 38 af fe 13 00 00 00 00 70 02   ...,.P8.......p.
0030  22 38 c3 0c 00 00 02 04 05 b4 01 01 04 02         "8............

Verbosity
Default TShark packet processing and sniffing operations provide a single line of information and exclude verbosity. The default approach makes it easy to follow the number of processed/sniffed packets; however, TShark can also provide verbosity for each packet when instructed. Verbosity is provided similarly to Wireshark's "Packet Details Pane". As verbosity offers a long list of packet details, it is suggested to use that option for specific packets instead of a series of packets.  
Verbosity
# Default view
user@ubuntu$ tshark -r demo.pcapng -c 1
    1   0.000000 145.254.160.237 ? 65.208.228.223 TCP 3372 ? 80 [SYN] Seq=0 Win=8760 Len=0 MSS=1460 SACK_PERM=1 

# Verbosity
user@ubuntu$ tshark -r demo.pcapng -c 1 -V
Frame 1: 62 bytes on wire (496 bits), 62 bytes captured (496 bits)
...
Ethernet II, Src: 00:00:01:00:00:00, Dst: fe:ff:20:00:01:00
...
Internet Protocol Version 4, Src: 145.254.160.237, Dst: 65.208.228.223
    0100 .... = Version: 4
    .... 0101 = Header Length: 20 bytes (5)
    Total Length: 48
    Identification: 0x0f41 (3905)
    Flags: 0x4000, Don't fragment
    Fragment offset: 0
    Time to live: 128
    Protocol: TCP (6)
    Source: 145.254.160.237
    Destination: 65.208.228.223
Transmission Control Protocol, Src Port: 3372, Dst Port: 80, Seq: 0, Len: 0
 ...
Verbosity provides full packet details and makes it difficult to investigate (long and complex terminal output for each packet). However, it is still helpful for in-depth packet analysis and scripting, making TShark stand out. Remember, the best utilisation time of verbosity is after filtering the packets. You can compare the above output with the below screenshot and see the scripting, carving, and correlation opportunities you have!



Capture Condition Parameters
As a network sniffer and packet analyser, TShark can be configured to count packets and stop at a specific point or run in a loop structure. The most common parameters are explained below.
Parameter
Purpose


Define capture conditions for a single run/loop. STOP after completing the condition. Also known as "Autostop".
-a

Duration: Sniff the traffic and stop after X seconds. Create a new file and write output to it.
tshark -w test.pcap -a duration:1
Filesize: Define the maximum capture file size. Stop after reaching X file size (KB).
tshark -w test.pcap -a filesize:10
Files: Define the maximum number of output files. Stop after X files.
tshark -w test.pcap -a filesize:10 -a files:3


Ring buffer control options. Define capture conditions for multiple runs/loops. (INFINITE LOOP). 
-b

Duration: Sniff the traffic for X seconds, create a new file and write output to it. 
tshark -w test.pcap -b duration:1
Filesize: Define the maximum capture file size. Create a new file and write output to it after reaching filesize X (KB).
tshark -w test.pcap -b filesize:10
Files: Define the maximum number of output files. Rewrite the first/oldest file after creating X files.
tshark -w test.pcap -b filesize:10 -b files:3

Capture condition parameters only work in the "capturing/sniffing" mode. You will receive an error message if you try to read a pcap file and apply the capture condition parameters. The idea is to save the capture files in specific sizes for different purposes during live capturing. If you need to extract sorts of packets from a specific capture file, you will need to use the read&write options discussed in the previous task. 
Hint: TShark supports combining autostop (-a) parameters with ring buffer control parameters (-b). You can combine the parameters according to your needs. Use the infinite loop options carefully; remember, you must use at least one autostop parameter to stop the infinite loop. 
Sample autostop query
# Start sniffing the traffic and stop after 2 seconds, and save the dump into 5 files, each 5kb.

user@ubuntu$ tshark -w autostop-demo.pcap -a duration:2 -a filesize:5 -a files:5
Capturing on 'ens5'
13 

# List the contents of the current folder.
user@ubuntu$ ls
-rw------- 1 ubuntu ubuntu   autostop-demo_..1_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..2_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..3_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..4_2022.pcap
-rw------- 1 ubuntu ubuntu   autostop-demo_..5_2022.pcap

TShark Fundamentals IV | Packet Filtering Options: Capture Filters
Capture Filters
Wireshark's capture filter syntax is used here. The basic syntax for the Capture/BPF filter is shown below. You can read more on capture filter syntax here and here. Boolean operators can also be used in both types of filters. 
Qualifier
Details and Available Options
Type
Target match type. You can filter IP addresses, hostnames, IP ranges, and port numbers. Note that if you don't set a qualifier, the "host" qualifier will be used by default.
host | net | port | portrange
Filtering a host
tshark -f "host 10.10.10.10"
Filtering a network range 
tshark -f "net 10.10.10.0/24"
Filtering a Port
tshark -f "port 80"
Filtering a port range
tshark -f "portrange 80-100"
Direction
Target direction/flow. Note that if you don't use the direction operator, it will be equal to "either" and cover both directions.
src | dst
Filtering source address
tshark -f "src host 10.10.10.10"
Filtering destination address
tshark -f "dst host 10.10.10.10"
Protocol
Target protocol.
arp | ether | icmp | ip | ip6 | tcp | udp
Filtering TCP
tshark -f "tcp"
Filtering MAC address
tshark -f "ether host F8:DB:C5:A2:5D:81"
You can also filter protocols with IP Protocol numbers assigned by IANA.
Filtering IP Protocols 1 (ICMP)
tshark -f "ip proto 1"
Assigned Internet Protocol Numbers

We need to create traffic noise to test and simulate capture filters. We will use the "terminator" terminal instance to have a split-screen view in a single terminal. The "terminator" will help you craft and sniff packets using a single terminal interface. Now, run the terminator command and follow the instructions using the new terminal instance. 
First, run the given TShark command in Terminal-1 to start sniffing traffic.
Then, run the given cURL command in Terminal-2 to create network noise.
View sniffed packets results in Terminal-1.
"Terminator" Terminal Emulator Application
Terminal-1
user@ubuntu$ tshark -f "host 10.10.10.10"
Capturing on 'ens5'
    1 0.000000000 YOUR-IP → 10.10.10.10  TCP 74 36150 → 80 [SYN] Seq=0 Win=62727 Len=0 MSS=8961 SACK_PERM=1 TSval=2045205701 TSecr=0 WS=128
    2 0.003452830  10.10.10.10 → YOUR-IP TCP 74 80 → 36150 [SYN, ACK] Seq=0 Ack=1 Win=62643 Len=0 MSS=8961 SACK_PERM=1 TSval=744450747 TSecr=2045205701 WS=64
    3 0.003487830 YOUR-IP → 10.10.10.10  TCP 66 36150 → 80 [ACK] Seq=1 Ack=1 Win=62848 Len=0 TSval=2045205704 TSecr=744450747
    4 0.003610800 YOUR-IP → 10.10.10.10  HTTP 141 GET / HTTP/1.1
Terminal-2
user@ubuntu$ curl -v 10.10.10.10
*   Trying 10.10.10.10:80...
* TCP_NODELAY set
* Connected to 10.10.10.10 (10.10.10.10) port 80 (#0)
> GET / HTTP/1.1
> Host: 10.10.10.10
> User-Agent: curl/7.68.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 OK
< Accept-Ranges: bytes
< Content-Length: 1220
< Content-Type: text/html; charset=utf-8


Being comfortable with the command line and TShark filters requires time and practice. You can use the below table to practice TShark capture filters.
Capture Filter Category
Details
Host Filtering
Capturing traffic to or from a specific host.
Traffic generation with cURL. This command sends a default HTTP query to a specified address.
curl tryhackme.com
TShark capture filter for a host
tshark -f "host tryhackme.com"
IP Filtering
Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.
Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.
nc 10.10.10.10 4444 -vw 5
TShark capture filter for specific IP address
tshark -f "host 10.10.10.10"
Port Filtering
Capturing traffic to or from a specific port. We will use the Netcat tool to create noise on specific ports.
Traffic generation with Netcat. Here Netcat is instructed to provide details (verbosity), and timeout is set to 5 seconds.
nc 10.10.10.10 4444 -vw 5
TShark capture filter for port 4444
tshark -f "port 4444"
Protocol Filtering
Capturing traffic to or from a specific protocol. We will use the Netcat tool to create noise on specific ports.
Traffic generation with Netcat. Here Netcat is instructed to use UDP, provide details (verbosity), and timeout is set to 5 seconds.
nc -u 10.10.10.10 4444 -vw 5
TShark capture filter for
tshark -f "udp"

Display Filters
Wireshark's display filter syntax is used here. You can use the official Display Filter Reference to find the protocol breakdown for filtering. Additionally, you can use Wireshark's build-in "Display Filter Expression" menu to break down protocols for filters. Note that Boolean operators can also be used in both types of filters. Common filtering options are shown in the given table below.
Note: Using single quotes for capture filters is recommended to avoid space and bash expansion problems. Once again, you can check the Wireshark: Packet Operations room (Task 4 & 5) if you want to review the principles of packet filtering.
Display Filter Category
Details and Available Options
Protocol: IP
Filtering an IP without specifying a direction.
tshark -Y 'ip.addr == 10.10.10.10'
Filtering a network range 
tshark -Y 'ip.addr == 10.10.10.0/24'
Filtering a source IP
tshark -Y 'ip.src == 10.10.10.10'
Filtering a destination IP
tshark -Y 'ip.dst == 10.10.10.10'
Protocol: TCP
Filtering TCP port
tshark -Y 'tcp.port == 80'
Filtering source TCP port
tshark -Y 'tcp.srcport == 80'
Protocol: HTTP
Filtering HTTP packets
tshark -Y 'http'
Filtering HTTP packets with response code "200"
tshark -Y "http.response.code == 200"
Protocol: DNS
Filtering DNS packets
tshark -Y 'dns'
Filtering all DNS "A" packets
tshark -Y 'dns.qry.type == 1'

We will use the "demo.pcapng" to test display filters. Let's see the filters in action!
Sample filtering query
user@ubuntu$ tshark -r demo.pcapng -Y 'ip.addr == 145.253.2.203'
13 2.55 145.254.160.237 ? 145.253.2.203 DNS Standard query 0x0023 A ..
17 2.91 145.253.2.203 ? 145.254.160.237 DNS Standard query response 0x0023 A ..
The above terminal demonstrates using the "IP filtering" option. TShark filters the packets and provides the output in our terminal. It is worth noting that TShark doesn't count the "total number of filtered packets"; it assigns numbers to packets according to the capture time, but only displays the packets that match our filter. 
Look at the above example. There are two matched packets, but the associated numbers don't start from zero or one; "13" and "17" are assigned to these filtered packets. Keeping track of these numbers and calculating the "total number of filtered packets" can be confusing if your filter retrieves more than a handful of packets. Another example is shown below.
Sample filtering query
user@ubuntu$ tshark -r demo.pcapng -Y 'http'
  4   0.911 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1  
 18   2.984 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client... 
 27   3.955 216.239.59.99 ? 145.254.160.237 HTTP HTTP/1.1 200 OK  (text/html) 
 38   4.846 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK
You can use the nl command to get a numbered list of your output. Therefore you can easily calculate the "total number of filtered packets" without being confused with "assigned packet numbers". The usage of the nl command is shown below.
Sample filtering query
user@ubuntu$ tshark -r demo.pcapng -Y 'http' | nl
1    4  0.911 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1  
2   18  2.984 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client... 
3   27   3.955 216.239.59.99 ? 145.254.160.237 HTTP HTTP/1.1 200 OK (text/html) 
4   38   4.846 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK
Display Filter Reference:https://www.wireshark.org/docs/dfref/

TShark: CLI Wireshark Features


Command-Line Wireshark Features I | Statistics I
Command-Line Wireshark Features I | Statistics
At the beginning of this module, we mentioned that TShark is considered a command line version of Wireshark. In addition to sharing the same display filters, TShark can accomplish several features of Wireshark explained below.
Three important points when using Wireshark-like features:
These options are applied to all packets in scope unless a display filter is provided.
Most of the commands shown below are CLI versions of the Wireshark features discussed in Wireshark: Packet Operations (Task 2).
TShark explains the parameters used at the beginning of the output line.
For example, you will use the phs option to view the protocol hierarchy. Once you use this command, the result will start with the "Packet Hierarchy Statistics" header.
Parameter
Purpose
--color
Wireshark-like colourised output.
tshark --color
-z
Statistics
There are multiple options available under this parameter. You can view the available filters under this parameter with:
tshark -z help
Sample usage.
tshark -z filter
Each time you filter the statistics, packets are shown first, then the statistics provided. You can suppress packets and focus on the statistics by using the -q parameter.


Colourised Output
TShark can provide colourised outputs to help analysts speed up the analysis and spot anomalies quickly. If you are more of a Wireshark person and feel the need for a Wireshark-style packet highlighting this option does that. The colour option is activated with the --color parameter, as shown below.
View in colour
user@ubuntu$ tshark -r colour.pcap --color


Statistics | Protocol Hierarchy
Protocol hierarchy helps analysts to see the protocols used, frame numbers, and size of packets in a tree view based on packet numbers. As it provides a summary of the capture, it can help analysts decide the focus point for an event of interest. Use the -z io,phs -q parameters to view the protocol hierarchy.
View protocol hierarchy
user@ubuntu$ tshark -r demo.pcapng -z io,phs -q
===================================================================
Protocol Hierarchy Statistics
Filter: 

  eth                                    frames:43 bytes:25091
    ip                                   frames:43 bytes:25091
      tcp                                frames:41 bytes:24814
        http                             frames:4 bytes:2000
          data-text-lines                frames:1 bytes:214
            tcp.segments                 frames:1 bytes:214
          xml                            frames:1 bytes:478
            tcp.segments                 frames:1 bytes:478
      udp                                frames:2 bytes:277
        dns                              frames:2 bytes:277
===================================================================
After viewing the entire packet tree, you can focus on a specific protocol as shown below. Add the udp keyword to the filter to focus on the UDP protocol.
View protocol hierarchy
user@ubuntu$ tshark -r demo.pcapng -z io,phs,udp -q
===================================================================
Protocol Hierarchy Statistics
Filter: udp

  eth                                    frames:2 bytes:277
    ip                                   frames:2 bytes:277
      udp                                frames:2 bytes:277
        dns                              frames:2 bytes:277
===================================================================

Statistics | Packet Lengths Tree
The packet lengths tree view helps analysts to overview the general distribution of packets by size in a tree view. It allows analysts to detect anomalously big and small packets at a glance! Use the -z plen,tree -q parameters to view the packet lengths tree.
View packet lengths tree
user@ubuntu$ tshark -r demo.pcapng -z plen,tree -q

=========================================================================================================================
Packet Lengths:
Topic / Item       Count     Average       Min val       Max val     Rate (ms)     Percent     Burst rate    Burst start  
-------------------------------------------------------------------------------------------------------------------------
Packet Lengths     43        583.51        54            1484        0.0014        100         0.0400        2.554        
 0-19              0         -             -             -           0.0000        0.00        -             -            
 20-39             0         -             -             -           0.0000        0.00        -             -            
 40-79             22        54.73         54            62          0.0007        51.16       0.0200        0.911        
 80-159            1         89.00         89            89          0.0000        2.33        0.0100        2.554        
 160-319           2         201.00        188           214         0.0001        4.65        0.0100        2.914        
 320-639           2         505.50        478           533         0.0001        4.65        0.0100        0.911        
 640-1279          1         775.00        775           775         0.0000        2.33        0.0100        2.984        
 1280-2559         15        1440.67       1434          1484        0.0005        34.88       0.0200        2.554        
 2560-5119         0         -             -             -           0.0000        0.00        -             -            
 5120 and greater  0         -             -             -           0.0000        0.00        -             -            
-------------------------------------------------------------------------------------------------------------------------

Statistics | Endpoints
The endpoint statistics view helps analysts to overview the unique endpoints. It also shows the number of packets associated with each endpoint. If you are familiar with Wireshark, you should know that endpoints can be viewed in multiple formats. Similar to Wireshark, TShark supports multiple source filtering options for endpoint identification. Use the -z endpoints,ip -q parameters to view IP endpoints. Note that you can choose other available protocols as well.
Filters for the most common viewing options are explained below.
Filter
Purpose
eth
Ethernet addresses
ip
IPv4 addresses
ipv6
IPv6 addresses
tcp
TCP addresses
Valid for both IPv4 and IPv6
udp
UDP addresses
Valid for both IPv4 and IPv6
wlan
IEEE 802.11 addresses

View IPv4 endpoints
user@ubuntu$ tshark -r demo.pcapng -z endpoints,ip -q
================================================================================
IPv4 Endpoints
Filter:
                       |  Packets  | |  Bytes  | | Tx Packets | | Tx Bytes | | Rx Packets | | Rx Bytes |
145.254.160.237               43         25091         20            2323          23           22768   
65.208.228.223                34         20695         18           19344          16            1351   
216.239.59.99                  7          4119          4            3236           3             883   
145.253.2.203                  2           277          1             188           1              89   
================================================================================

Statistics | Conversations
The conversations view helps analysts to overview the traffic flow between two particular connection points. Similar to endpoint filtering, conversations can be viewed in multiple formats. This filter uses the same parameters as the "Endpoints" option. Use the -z conv,ip -q parameters to view IP conversations.
View IPv4 conversations
user@ubuntu$ tshark -r demo.pcapng -z conv,ip -q  
================================================================================
IPv4 Conversations
Filter:
                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration
                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |             65.208.228.223   <-> 145.254.160.237           16      1351      18     19344      34     20695     0.000000000        30.3937
145.254.160.237  <-> 216.239.59.99              4      3236       3       883       7      4119     2.984291000         1.7926
145.253.2.203    <-> 145.254.160.237            1        89       1       188       2       277     2.553672000         0.3605
================================================================================

Statistics | Expert Info
The expert info view helps analysts to view the automatic comments provided by Wireshark. If you are unfamiliar with the "Wireshark Expert Info", visit task 4 in the Wireshark: The Basics room of the Wireshark module. Use the -z expert -q parameters to view the expert information.


View expert info
user@ubuntu$ tshark -r demo.pcapng -z expert -q

Notes (3)
=============
   Frequency      Group           Protocol  Summary
           1   Sequence                TCP  This frame is a (suspected) spurious retransmission
           1   Sequence                TCP  This frame is a (suspected) retransmission
           1   Sequence                TCP  Duplicate ACK (#1)

Chats (8)
=============
   Frequency      Group           Protocol  Summary
           1   Sequence                TCP  Connection establish request (SYN): server port 80
           1   Sequence                TCP  Connection establish acknowledge (SYN+ACK): server port 80
           1   Sequence               HTTP  GET /download.html HTTP/1.1\r\n
           1   Sequence               HTTP  GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&lmt=1082467020
           2   Sequence               HTTP  HTTP/1.1 200 OK\r\n
           2   Sequence                TCP  Connection finish (FIN)
Cyber Defence Frameworks
Discover frameworks and policies that help establish a good security posture. Learn how organisations use these in defensive strategies.
Junior Security Analyst Intro
Play through a day in the life of a Junior Security Analyst, their responsibilities and qualifications needed to land a role as an analyst.
Pyramid Of Pain
Learn what is the Pyramid of Pain and how to utilize this model to determine the level of difficulty it will cause for an adversary to change the indicators associated with them, and their campaign.
Cyber Kill Chain
The Cyber Kill Chain framework is designed for identification and prevention of the network intrusions. You will learn what the adversaries need to do in order to achieve their goals.
Unified Kill Chain
The Unified Kill Chain is a framework which establishes the phases of an attack, and a means of identifying and mitigating risk to IT assets.
Diamond Model
Learn about the four core features of the Diamond Model of Intrusion Analysis: adversary, infrastructure, capability, and victim.
MITRE
This room will discuss the various resources MITRE has made available for the cybersecurity community.
Summit
Can you chase a simulated adversary up the Pyramid of Pain until they finally back down?
Eviction
Unearth the monster from under your bed.

Cyber Threat Intelligence
Learn about identifying and using available security knowledge to mitigate and manage potential adversary actions.
Intro to Cyber Threat Intel
Introducing cyber threat intelligence and related topics, such as relevant standards and frameworks.
Threat Intelligence Tools
Explore different OSINT tools used to conduct security threat assessments and investigations.
Yara
Learn the applications and language that is Yara for everything threat intelligence, forensics, and threat hunting!
OpenCTI
Provide an understanding of the OpenCTI Project
MISP
Walkthrough on the use of MISP as a Threat Sharing Platform
Friday Overtime
Step into the shoes of a Cyber Threat Intelligence Analyst and put your investigation skills to the test.
Trooper
Use Cyber Threat Intelligence knowledge and skills to identify a threat based on a report.

Network Security and Traffic Analysis
Understand the core concepts of Network Security and Traffic Analysis to spot and probe network anomalies using industry tools and techniques.
Traffic Analysis Essentials
Learn Network Security and Traffic Analysis foundations and take a step into probing network anomalies.
Snort
Learn how to use Snort to detect real-time threats, analyse recorded traffic files and identify anomalies.
Snort Challenge - The Basics
Put your snort skills into practice and write snort rules to analyse live capture network traffic.
Snort Challenge - Live Attacks
Put your snort skills into practice and defend against a live attack
NetworkMiner
Learn how to use NetworkMiner to analyse recorded traffic files and practice network forensics activities.
Zeek
Introduction to hands-on network monitoring and threat detection with Zeek (formerly Bro).
Zeek Exercises
Put your Zeek skills into practice and analyse network traffic.
Brim
Learn and practice log investigation, pcap analysis and threat hunting with Brim.
Wireshark: The Basics
Learn the basics of Wireshark and how to analyse protocols and PCAPs.
Wireshark: Packet Operations
Learn the fundamentals of packet analysis with Wireshark and how to find the needle in the haystack!
Wireshark: Traffic Analysis
Learn the basics of traffic analysis with Wireshark and how to find anomalies on your network!
TShark: The Basics
Learn the basics of TShark and take your protocol and PCAP analysis skills a step further.
TShark: CLI Wireshark Features
Take your TShark skills to the next level by implementing Wireshark functionalities in the CLI.
TShark Challenge I: Teamwork
Put your TShark skills into practice and analyse some network traffic.
TShark Challenge II: Directory
Put your TShark skills into practice and analyse some network traffic.


Advanced Filtering Options | Contains, Matches and Fields
Advanced Filtering Options | Contains, Matches and Extract Fields
Accomplishing in-depth packet analysis sometimes ends up with a special filtering requirement that cannot be covered with default filters. TShark supports Wireshark's "contains" and "matches" operators, which are the key to the advanced filtering options. You can visit the Wireshark: Packet Operations room (Task 6) if you are unfamiliar with these filters. 
A quick recap from the Wireshark: Packet Operations room:
Filter
Details
Contains
Search a value inside packets.
Case sensitive.
Similar to Wireshark's "find" option.
Matches
Search a pattern inside packets.
Supports regex.
Case insensitive.
Complex queries have a margin of error.

Note: The "contains" and "matches" operators cannot be used with fields consisting of "integer" values.
Tip: Using HEX and regex values instead of ASCII always has a better chance of a match.

Extract Fields
This option helps analysts to extract specific parts of data from the packets. In this way, analysts have the opportunity to collect and correlate various fields from the packets. It also helps analysts manage the query output on the terminal. The query structure is explained in the table given below.
Main Filter
Target Field
Show Field Name
-T fields
-e <field name>
-E header=y

Note: You need to use the -e parameter for each field you want to display.
You can filter any field by using the field names as shown below.
-T fields -e ip.src -e ip.dst -E header=y
Extract fields
user@ubuntu$ tshark -r demo.pcapng -T fields -e ip.src -e ip.dst -E header=y -c 5         
ip.src	ip.dst
145.254.160.237	65.208.228.223
65.208.228.223	145.254.160.237
145.254.160.237	65.208.228.223
145.254.160.237	65.208.228.223
65.208.228.223	145.254.160.237

Filter: "contains"
Filter
contains
Type
Comparison operator
Description
Search a value inside packets. It is case-sensitive and provides similar functionality to the "Find" option by focusing on a specific field.
Example
Find all "Apache" servers.
Workflow
List all HTTP packets where the "server" field contains the "Apache" keyword.
Usage
http.server contains "Apache"

Contains filter
user@ubuntu$ tshark -r demo.pcapng -Y 'http.server contains "Apache"'                          
   38   4.846969 65.208.228.223 ? 145.254.160.237 HTTP/XML HTTP/1.1 200 OK 

user@ubuntu$ tshark -r demo.pcapng -Y 'http.server contains "Apache"' -T fields -e ip.src -e ip.dst -e http.server -E header=y
ip.src	ip.dst	http.server
65.208.228.223	145.254.160.237	Apache

Filter: "matches"
Filter
matches
Type
Comparison operator
Description
Search a pattern of a regular expression. It is case-insensitive, and complex queries have a margin of error.
Example
Find all .php and .html pages.
Workflow
List all HTTP packets where the "request method" field matches the keywords "GET" or "POST".
Usage
http.request.method matches "(GET|POST)"

Matches filter
user@ubuntu$ tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"'               
    4   0.911310 145.254.160.237 ? 65.208.228.223 HTTP GET /download.html HTTP/1.1 
   18   2.984291 145.254.160.237 ? 216.239.59.99 HTTP GET /pagead/ads?client=ca-pub-2309191948673629&random=1084443430285&

user@ubuntu$ tshark -r demo.pcapng -Y 'http.request.method matches "(GET|POST)"' -T fields -e ip.src -e ip.dst -e http.request.method -E header=y
ip.src	ip.dst	http.request.method
145.254.160.237	65.208.228.223	GET
145.254.160.237	216.239.59.99	GET




Use this youtube video to answer the tryhack TShark Challenge II: Directory
https://www.youtube.com/watch?v=RkbjwF4N4jU


Endpoint Security Monitoring

Intro to Endpoint Security
Learn about fundamentals, methodology, and tooling for endpoint security monitoring.


Endpoint Security Fundamentals
Core Windows Processes
﻿Before we deal with learning how to deep-dive into endpoint logs, we need first to learn the fundamentals of how the Windows Operating System works. Without prior knowledge, differentiating an outlier from a haystack of events could be problematic. 
To learn more about Core Windows Processes, a built-in Windows tool named Task Manager may aid us in understanding the underlying processes inside a Windows machine. 
Task Manager is a built-in GUI-based Windows utility that allows users to see what is running on the Windows system. It also provides information on resource usage, such as how much each process utilizes CPU and memory. When a program is not responding, the Task Manager is used to terminate the process.

A Task Manager provides some of the Core Windows Processes running in the background. Below is a summary of running processes that are considered normal behaviour.
Note: ">" symbol represents a parent-child relationship. System (Parent) > smss.exe (Child)
System
System > smss.exe
csrss.exe
wininit.exe
wininit.exe > services.exe
wininit.exe > services.exe > svchost.exe
lsass.exe
winlogon.exe
explorer.exe
In addition, the processes with no depiction of a parent-child relationship should not have a Parent Process under normal circumstances, except for the System process, which should only have System Idle Process (0) as its parent process.
﻿You may refer to the Core Windows Processes Room to learn more about this topic.
Sysinternals
With the prior knowledge of Core Windows Processes, we can now proceed to discuss the available toolset for analyzing running artefacts in the backend of a Windows machine.
The Sysinternals tools are a compilation of over 70+ Windows-based tools. Each of the tools falls into one of the following categories:
File and Disk Utilities
Networking Utilities
Process Utilities
Security Utilities
System Information
Miscellaneous
We will introduce two of the most used Sysinternals tools for endpoint investigation for this task.
TCPView - Networking Utility tool.
Process Explorer - Process Utility tool.
TCPView
"TCPView is a Windows program that will show you detailed listings of all TCP and UDP endpoints on your system, including the local and remote addresses and state of TCP connections. On Windows Server 2008, Vista, and XP, TCPView also reports the name of the process that owns the endpoint. TCPView provides a more informative and conveniently presented subset of the Netstat program that ships with Windows. The TCPView download includes Tcpvcon, a command-line version with the same functionality." (official definition)

﻿As shown above, every connection initiated by a process is listed by the tool, which may aid in correlating the network events executed concurrently.
Process Explorer
"The Process Explorer display consists of two sub-windows. The top window always shows a list of the currently active processes, including the names of their owning accounts, whereas the information displayed in the bottom window depends on the mode that Process Explorer is in: if it is in handle mode, you'll see the handles that the process selected in the top window has opened; if Process Explorer is in DLL mode you'll see the DLLs and memory-mapped files that the process has loaded." (official definition)

Process Explorer enables you to inspect the details of a running process, such as:
Associated services
Invoked network traffic
Handles such as files or directories opened
DLLs and memory-mapped files loaded
﻿To learn more about Sysinternals, you may refer to the Sysinternals Room.
Core Windows Processes
Explore the core processes within a Windows operating system and understand what normal behaviour is. This foundational knowledge will help you identify malicious processes running on an endpoint!

Task Manager
Task Manager is a built-in GUI-based Windows utility that allows users to see what is running on the Windows system. It also provides information on resource usage, such as how much each process utilizes CPU and memory. When a program is not responding, Task Manager is used to end (kill) the process. 
We'll give a brief overview if you're unfamiliar with Task Manager.
To open Task Manager, right-click the Taskbar. When the new window appears, select Task Manager (as shown below).

If you don't have any explicitly opened apps, you should see the same message as shown below.

Weird. Not seeing much, eh? Within a Windows system, many processes are running. Click on More details. 

Ok, now we're getting somewhere. Notice the five tabs within Task Manager. By default, the current tab is Processes. 
Note: If you're running Task Manager on your Windows machine, you might see additional tabs. 
As shown above, you may notice the processes are categorized as follows: Apps and Background processes. Another category that is not visible in the above image is Windows processes. 
The columns are very minimal. The columns Name, Status, CPU, and Memory are the only ones visible. To view more columns, right-click on any column header to open more options. 


The view looks a little better. Let's briefly go over each column (excluding Name, of course): 
Type - Each process falls into 1 of 3 categories (Apps, Background process, or Windows process).
Publisher - Think of this column as the name of the author of the program/file.
PID - This is known as the process identifier number. Windows assigns a unique process identifier each time a program starts. If the same program has multiple running processes, each will have its unique process identifier (PID).
Process name - This is the file name of the process. In the above image, the file name for Task Manager is Taskmrg.exe. 
Command line - The full command used to launch the process. 
CPU - The amount of CPU (processing power) the process uses.
Memory - The amount of physical working memory utilized by the process. 
Task Manager is a utility you should be comfortable using, whether you're troubleshooting or performing analysis on the endpoint. 
Let's move to the Details tab. This view provides some core processes that will be discussed in this room. Sort the PID column so that the PIDs are in ascending order.

Add some additional columns to see more information about these processes. Good columns to add are Image path name and Command line.
These two columns can quickly alert an analyst of any outliers with a given process. In the below image, PID 384 is paired with a process named svchost.exe, a Windows process, but if the Image path name or Command line is not what it's expected to be, then we can perform a deeper analysis of this process. 

Of course, you can add as many columns as you wish, but adding the columns that would be pertinent to your current task is recommended. 
Task Manager is a powerful built-in Windows utility but lacks certain important information when analyzing processes, such as parent process information. It is another key column when identifying outliers. Back to svchost.exe, if the parent process for PID 384 is not services.exe, this will warrant further analysis. 
To further prove this point, where is services.exe? 

Based on the above image, the PID for services.exe is 632. But wait, one of the svchost.exe processes has a PID of 384. How did svchost.exe start before services.exe? Well, it didn't. Task Manager doesn't show a Parent-Child process view. That is where other utilities, such as Process Hacker and Process Explorer, come to the rescue.
Process Hacker

Process Explorer

Moving forward, we'll use Process Hacker and Process Explorer instead of Task Manager to obtain information about each Windows process. 
As always, it's encouraged that you inspect and familiarize yourself with all information available within Task Manager. It's a built-in utility that is available in every Windows system. You might find yourself in a situation where you can't bring your tools to the fight and rely on the tools native to the system.
Aside from Task Manager, it would be best if you also familiarize yourself with the command-line equivalent of obtaining information about the running processes on a Windows system: tasklist, Get-Process or ps (PowerShell), and wmic.
System
The first Windows process on the list is System. It was mentioned in a previous section that a PID for any given process is assigned at random, but that is not the case for the System process. The PID for System is always 4. What does this process do exactly?


The official definition from Windows Internals 6th Edition:


"The System process (process ID 4) is the home for a special kind of thread that runs only in kernel mode a kernel-mode system thread. System threads have all the attributes and contexts of regular user-mode threads (such as a hardware context, priority, and so on) but are different in that they run only in kernel-mode executing code loaded in system space, whether that is in Ntoskrnl.exe or in any other loaded device driver. In addition, system threads don't have a user process address space and hence must allocate any dynamic storage from operating system memory heaps, such as a paged or nonpaged pool."


What is user mode? Kernel-mode? Visit the following link to understand each of these.


Now, what is normal behaviour for this process? Let's use Process Explorer and view the properties of the System.





Image Path:  N/A
Parent Process:  None
Number of Instances:  One
User Account:  Local System
Start Time:  At boot time


The information is slightly different if we view the System properties using Process Hacker. 





Image Path: C:\Windows\system32\ntoskrnl.exe (NT OS Kernel)
Parent Process: System Idle Process (0)


Technically this is correct. You may notice that Process Hacker confirms this is legit (Verified) Microsoft Windows. 


What is unusual behaviour for this process?
A parent process (aside from System Idle Process (0))
Multiple instances of System. (Should only be one instance) 
A different PID. (Remember that the PID will always be PID 4)
Not running in Session 0


