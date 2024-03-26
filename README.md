# aws-shibboleth-sp-jwt

This repository contains functional code for deploying a custom Shibboleth compatible SP using SustainSys in AWS ECS that converts the SAML assertion to a JWT token. There are additional requirements that will be noted in the readme.

# AWS Explanation and Configuration

We're us a handful of AWS tools and services to configure and deploy this application. It is assumed you have an AWS account with appropriate admin access to deploy the application. The following tools are required:

`AWS CLI` - https://awscli.amazonaws.com/AWSCLIV2.msi
`AWS Copilot` - https://github.com/aws/copilot-cli/releases/latest/download/copilot-windows.exe

You will have needed to setup your `AWS CLI` with your account profile either through a key/secret combination or through existing SSO within your org. You will want to configure `AWS Copilot` to be available on your path via the Environment Path variable.

## Configuration

To configure the application, we need to utilize the `Secrets Manager` service of AWS. This service allows us to store credentials and/or configurations specific to those credentials. AWS also has `Parameter Store` for non-credential based secrets and configurations, but our configurations are closely linked with credentials or certificates, so we'll be sticking to `Secrets Manager`

## Deployment
