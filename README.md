![6](https://github.com/user-attachments/assets/f2dddd41-69d8-4e4f-9204-d7ced30466dc)# Pyramid-of-Pain

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

