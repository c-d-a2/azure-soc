# Building a SOC with Azure Sentinel: Detection Engineering & SOAR Automation

This project demonstrates how to establish a basic Security Operations Center (SOC) using Azure Sentinel, focusing on detection engineering and Security Orchestration, Automation, and Response (SOAR).

## Setup

### Prerequisites

- Terraform: Infrastructure provisioning.
- Azure CLI: Azure resource management.

### Deployment Steps

1. Clone the Repository:  
   `git clone https://github.com/c-d-a2/azure-soc-net.git`

2. Navigate to Terraform Directory:  
   `cd azure-soc-net/Terraform`

3. Initialize and Apply Terraform Configuration:  
   `terraform init`  
   `terraform plan`  
   `terraform apply`

4. Verify Deployment:  
   Confirm resources in the Azure portal.

## Detection Rules

Implemented detection queries based on MITRE ATT&CK techniques:

- T1562.004: Modify System Firewall.
- T1543.002: Create or Modify System Process.

## Workbook

Custom dashboards provide visual insights into security events and alerts.


