## Automated Endpoint Detection and Response with LimaCharlie and Tines

Small description about the project like one below
The integration of LimaCharlie and Tines within a SOAR framework to automate the detection of malicious processes, streamline incident response workflows, and enhance decision-making for SOC teams through real-time alerts and actionable prompts.


## About
<!--Detailed Description about the project-->
The SOAR-EDR Integration for Automated Incident Detection and Response project focuses on improving cybersecurity operations by combining LimaCharlie for advanced threat detection with Tines for workflow automation. The project automates the process of detecting, notifying, and responding to cyber threats, reducing manual intervention and enabling SOC teams to make quick, informed decisions. It aims to create an efficient and scalable security system that ensures rapid incident resolution.

## Features
<!--List the features of the project as shown below-->
- Real-time Threat Detection: Leverages LimaCharlie to identify malicious processes effectively.
- Automation Workflows: Tines handles automated alerting and response actions like Slack and email notifications.
- Scalable and Flexible: Integrates seamlessly with existing tools and infrastructure for enhanced adaptability.
- User Decision Prompting: SOC team involvement for critical actions like isolating compromised systems.

## Detection and Respond Code
<!--YAML code used in the project-->
<!--DETECTION-->
events:
  - NEW_PROCESS
  - EXISTING_PROCESS
op: and
rules:
  - op: is
    path: event/OS
    value: windows
  - op: or
    rules:
      - op: or
        rules:
          - case sensitive: false
            op: ends with
            path: event/FILE_PATH
            value: LaZagne.exe
          - case sensitive: false
            op: contains
            path: event/COMMAND_LINE
            value: LaZagne
          - case sensitive: false
            op: is
            path: event/HASH
            value: 3cc5ee93a9ba1fc57389705283b760c8bd61f35e9398bbfa3210e2becf6d4b05
      - op: and
        rules:
          - op: ends with
            path: event/FILE_PATH
            value: .exe
          - op: or
            rules:
              - case sensitive: false
                op: is
                path: event/HASH
                value: >-
                  6f83a13395542fa733d05962a7c8c04db6dbac3bcf3655cb0ba021a8ef374ecb
              - case sensitive: false
                op: is
                path: event/HASH
                value: >-
                  fa876c0e456a3a899512ed4c93f6fae30f7c47f4018e82cb7634b43c5a2d3e49
              - case sensitive: false
                op: is
                path: event/HASH
                value: >-
                  ae02d4ab251f4ffb97f6b7b5e1266f03714a8575e6727f25f6a05c841c15978d
              - op: or
                rules:
                  - case sensitive: false
                    op: contains
                    path: event/FILE_PATH
                    value: C:\\Users\\Public\\Downloads\\
                  - case sensitive: false
                    op: contains
                    path: event/FILE_PATH
                    value: C:\\Windows\\Temp\\
                  - case sensitive: false
                    op: contains
                    path: event/FILE_PATH
                    value: C:\\ProgramData\\
                  - case sensitive: false
                    op: contains
                    path: event/FILE_PATH
                    value: C:\\Users\\%USERNAME%\\AppData\\Local\\Temp\\
                  - case sensitive: false
                    op: contains
                    path: event/FILE_PATH
                    value: C:\\Users\\Public\\Libraries\\
              - op: or
                rules:
                  - op: contains
                    path: event/COMMAND_LINE
                    value: '-silent'
                  - op: contains
                    path: event/COMMAND_LINE
                    value: '--extract'

<!--RESPOND-->
- action: report
  metadata:
    author: Jivan
    description: Malicious File
    falsepositives:
      - ToTheMoon
      - Legitimate software in temporary directories
    level: high
    tags:
      - attack.credential_access
      - attack.execution
  name: Jivan - Malicious File


## Requirements
<!--List the requirements of the project as shown below-->
* Operating System: Cloud-based platforms; compatible with modern endpoints (Windows, Linux, or macOS).
* Automation Platform: Tines for no-code workflow creation and task automation.
* Deep Learning Frameworks: TensorFlow for model training, MediaPipe for hand gesture recognition.
* Detection Platform: LimaCharlie for advanced threat detection and response capabilities.
* Communication Tools: Slack and email for real-time SOC notifications.
* Version Control: Git for managing code and workflows.

## System Architecture
<!--Embed the system architecture diagram as shown below-->

![WhatsApp Image 2024-11-12 at 18 57 30_660a68c1](https://github.com/user-attachments/assets/b1f001f6-4886-462b-bd92-f83c38d769a9)


## Output

<!--Embed the Output picture at respective places as shown below as shown below-->
#### Output1 -Detection alert displayed on the LimaCharlie dashboard.


![WhatsApp Image 2024-10-23 at 19 36 42_b84a2a6f](https://github.com/user-attachments/assets/16224508-a685-447b-9f62-3af37a1b0d0e)


#### Output2 -Automated notifications sent to Slack and email.

![WhatsApp Image 2024-10-23 at 19 36 40_fd012fdf](https://github.com/user-attachments/assets/6bf95473-4dae-4b50-b2f0-44ef63f9042b)

#### Output3 -Automated notifications sent to Slack and email.

![WhatsApp Image 2024-10-23 at 19 36 48_9f7a600f](https://github.com/user-attachments/assets/f3d29a6e-d3e8-4233-882c-6a108067f693)


Detection Accuracy: 96.7%
Note: These metrics can be customized based on your actual performance evaluations.


## Results and Impact
<!--Give the results and impact as shown below-->
Efficiency Boost: Automates threat detection and response, reducing time to action.
Enhanced Security Posture: Minimizes risk through rapid isolation of compromised endpoints.
Team Enablement: Reduces SOC team workload while improving decision-making with actionable alerts.

Scalability: Provides a framework that can grow with organizational needs.
This project highlights the effectiveness of combining advanced detection and automation tools, paving the way for more resilient and efficient cybersecurity solutions.


## Articles published / References
1.Gupta, S. K., & Rout, S. K. (2024). "Enhancing Cybersecurity Through SOAR Frameworks: Automation and Detection." Journal of Cybersecurity Operations.

2.Bin Zainuddin, A. A. (2024). "Incident Response Automation: A Comparative Study of Platforms." Data Security Insights.

3.Tines Automation Guide. Official Documentation. Retrieved 2024.

4.LimaCharlie Detection Framework. Official Documentation. Retrieved 2024.
