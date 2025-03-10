# IaC Custom Scanner

This is a FastAPI-based application that analyzes security vulnerabilities in Knative service definitions and Infrastructure as Code (IaC) JSON files.

## Features

Detects security misconfigurations in Knative service definitions.

Identifies potential security risks in IaC resources.

Provides remediation recommendations following CIS best practices.

## Installation

### Requirements

Python 3.9+

FastAPI

Uvicorn

### Install Dependencies

To install the necessary dependencies, run:

```pip install -r requirements.txt```

## Usage

### Running Locally

To run the application locally, use the following command:

```uvicorn main:app --host 0.0.0.0 --port 8000```

The application will be available at http://localhost:8000.

### API Endpoint

* POST /analyze: Upload a JSON file containing a Knative service definition or an IaC configuration for analysis.

## Deploying to Google Cloud Run

### Prerequisites

1. Install the Google Cloud SDK

2. Authenticate with GCP:

```
bashgcloud auth login
gcloud config set project [PROJECT_ID]
```

### Build and Push Docker Image

To build and push the Docker image, run:

```gcloud builds submit --tag gcr.io/[PROJECT_ID]/knative-iac-analyzer```

### Deploy to Cloud Run

To deploy the application to Cloud Run, use the following command:

```
gcloud run deploy knative-iac-analyzer \
  --image gcr.io/[PROJECT_ID]/knative-iac-analyzer \
  --platform managed \
  --region [REGION] \
  --allow-unauthenticated
 ```

Replace [PROJECT_ID] and [REGION] with your actual GCP project ID and desired region.

### Accessing the Service

Once deployed, Cloud Run will provide a URL where the service can be accessed.

## License

This project is open source. Usage is allowed, but redistribution or modification should follow open-source principles.
