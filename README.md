# goons
Job for pulling findings from Security Command Center

## Description
CronJob running in the `nais-system` namespace, pulling findings from Security Command Center and sending valid findings to slack.

## Configuration
Organization ID will be fetched from environment
Folder ID is optional and can be used where we don't have organizational access.
