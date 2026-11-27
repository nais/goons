# Goons

Job for pulling and publishing findings from Security Command Center.

## Description

CronJob running in the `nais-system` namespace, pulling findings from Security Command Center and sending valid findings to Slack.

## Fasit Configuration

- `projectIDs`: Projects to fetch findings from. Must be provided. Use comma as delimiter.
- `residency`: Data residency. eu for v2 and global for v1 of Security Command Center. Must be provided.
- `slackToken`: Slack API token. Must be provided.
- `slackChannel`: Slack alert channel. Default value from values.yaml.
- `tenant`: Tenant name - fetched from environment.

## Local env

A `local.env` file is provided as a template for local development.
Copy it to `.env` and fill in the values; `mise run local` loads it as a dotenv file and runs the job with Google Application Default Credentials.
You will also need to set a quota project to be able to call the Security Command Center API, either with `gcloud auth application-default set-quota-project <projectId>` or by setting `GOOGLE_CLOUD_QUOTA_PROJECT` in `.env`.
