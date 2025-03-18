# Threat-Detection-Using-Sysmon-integrating-Machine-learning-model

# Introduction
The cyber security threats are on the rise, and this brings risks to organizations and individuals. The traditional threat detection systems are based on the rules and do not recognize new and advanced threats. The use of AI in threat detection helps the system to learn from previous events or attacks and detect the threats. 
In this project, we use Sysmon to collect system logs and give these logs to Splunk to preprocess them. This processed data will be input for the ML model. Our project's main goal is to develop a fully working AI-based threat detection system that can make automatic decisions on threats using Sysmon logs, Splunk, and machine learning models. We also want to ensure that there are no disturbances in the data flow from logging to detection and that the analysis and visualization are real-time.
Data collection & preprocessing:
- Enable Sysmon for system events tracking such as process creation, network connections, and file changes.
- Employ Splunk to gather and analyze Sysmon logs eliminate unnecessary information and prepare it for analysis.
AI-Powered threat detection:
- Export the preprocessed logs from Splunk into a Jupyter notebook for training the ML models.
- Train multiple ML models on the attacks based on their patterns in the past.
- Assess the models by their precision, recall, F1 score, and AUC-ROC to achieve optimal results.
Security insights & visualization:
- Develop Splunk dashboards that can present security patterns, identified threats, and system exceptions for better visualization.
By using this, we can create a real-time AI-based threat detection system to enhance the security team's ability to easily identify and respond to the threats.

# Problem Statement
The traditional cybersecurity approaches are slow, inelegant, and require more effort to implement, security analysts review logs using SIEM and other endpoint detection tools to identify threats. This is a slow process and can result in increased incident response time, more vulnerabilities, and financial loss; sometimes it can take weeks or months to detect a threat. 
Organizations need intelligent and faster systems to detect these threats to avoid the consequences discussed above. 
The main aim of our project is to design an AI-based threat detection system using Sysmon logs, Splunk, and ML models to automate this security monitoring task. This helps in reducing the human errors, enhance the threat detection, and decreases response time.

# Credits
This project was developed by:
Malavika Reddy Kotha



