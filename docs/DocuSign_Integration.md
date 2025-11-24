# DocuSign Integration Guide

This guide explains how to receive event updates and download signed documents from DocuSign.

## Overview

The Document Vault service integrates with DocuSign to:
1. Send documents for signature via email
2. Receive webhook notifications when signatures are completed
3. Download the signed documents
4. Publish events to your event system

## Event Updates

### 1. Webhook Configuration (DocuSign Connect)

To receive real-time updates when documents are signed, you need to configure DocuSign Connect webhooks:

#### Step 1: Configure DocuSign Connect

1. Log in to your DocuSign Admin Console (demo: https://admindemo.docusign.com)
2. Navigate to **Connect** → **Event Notifications**
3. Click **Add Configuration**
4. Configure the webhook:
   - **Name**: Document Vault Webhook
   - **URL**: `https://your-domain.com/api/v1/documents/signatures/webhook/docusign`
   - **Events to Send**: Select at minimum:
     - `Envelope Sent`
     - `Recipient Signed`
     - `Envelope Completed`
     - `Envelope Declined`
   - **Include Documents**: Optional (if you want documents in webhook payload)
   - **Include Certificate of Completion**: Recommended
   - **Logging**: Enable for debugging

#### Step 2: Webhook Security (Optional but Recommended)

If you set `DOCUSIGN_WEBHOOK_SECRET` in your environment, you can verify webhook authenticity:

```python
# The webhook secret is used to verify requests come from DocuSign
# You can implement HMAC verification in the webhook handler if needed
```

#### Step 3: Test the Webhook

DocuSign will send a test notification. Check your logs to ensure it's received.

### 2. Event Flow

When a document is signed:

1. **DocuSign sends webhook** → `POST /api/v1/documents/signatures/webhook/docusign`
2. **Service updates document status** → Updates `signature_state` and individual signer status
3. **Events are published**:
   - **SQS Event**: `document.signature_completed` published to `DOCUMENT_EVENTS_QUEUE_URL`
   - **Audit Event**: Published to EPR service API

### 3. Monitoring Signature Status

#### Check Status via API

```bash
GET /api/v1/documents/{document_id}/signatures/status
```

Response includes:
- `signature_state`: `NOT_REQUESTED`, `PENDING`, `PARTIAL`, or `COMPLETED`
- `signatures`: Array with each signer's status:
  - `signed`: boolean
  - `signature_requested_at`: timestamp
  - `signature_completed_at`: timestamp (when signed)

#### Example Response

```json
{
  "id": "6df3eb66-83a9-45c3-afc7-22ea25069473",
  "signature_state": "COMPLETED",
  "signatures": [
    {
      "email": "signer1@example.com",
      "name": "First Signer",
      "signed": true,
      "signature_requested_at": "2025-11-20T21:42:29Z",
      "signature_completed_at": "2025-11-20T21:45:12Z"
    }
  ]
}
```

### 4. Consuming Events from SQS

Events are published to your SQS queue (`DOCUMENT_EVENTS_QUEUE_URL`):

```json
{
  "event_type": "document.signature_completed",
  "occurred_at": "2025-11-20T21:45:12.123456+00:00",
  "payload": {
    "document_id": "6df3eb66-83a9-45c3-afc7-22ea25069473",
    "signers": ["signer1@example.com"]
  }
}
```

## Downloading Signed Documents

### API Endpoint

Once all signatures are completed, you can download the signed document:

```bash
GET /api/v1/documents/{document_id}/signatures/signed-document
```

**Requirements:**
- Document must have `signature_state = COMPLETED`
- Document must have a `signature_envelope_id`

**Response:**
- Content-Type: `application/pdf`
- File download with filename: `signed_{original_filename}`

### Example Usage

```bash
# 1. Check if signatures are completed
curl -X GET "http://localhost:8007/api/v1/documents/6df3eb66-83a9-45c3-afc7-22ea25069473/signatures/status"

# 2. Download the signed document
curl -X GET "http://localhost:8007/api/v1/documents/6df3eb66-83a9-45c3-afc7-22ea25069473/signatures/signed-document" \
  --output signed_document.pdf
```

### Programmatic Download

```python
import httpx

async with httpx.AsyncClient() as client:
    # Check status
    status_response = await client.get(
        f"http://localhost:8007/api/v1/documents/{document_id}/signatures/status"
    )
    status = status_response.json()
    
    if status["signature_state"] == "COMPLETED":
        # Download signed document
        signed_doc_response = await client.get(
            f"http://localhost:8007/api/v1/documents/{document_id}/signatures/signed-document"
        )
        with open("signed_document.pdf", "wb") as f:
            f.write(signed_doc_response.content)
```

## Webhook Payload Format

DocuSign sends webhooks in JSON format. The service expects:

```json
{
  "envelopeId": "c40e1637-b7ec-831c-81a8-eda939bd145d",
  "recipients": {
    "signers": [
      {
        "recipientId": "1",
        "status": "completed",
        "email": "signer1@example.com"
      }
    ]
  }
}
```

The service handles both camelCase (`envelopeId`) and PascalCase (`EnvelopeID`) formats.

## Troubleshooting

### Webhook Not Received

1. **Check DocuSign Connect Configuration**:
   - Verify the webhook URL is correct and accessible
   - Ensure events are enabled
   - Check DocuSign logs for delivery failures

2. **Check Your Service Logs**:
   ```bash
   # Look for webhook-related logs
   grep "DocuSign webhook" logs/
   ```

3. **Test Webhook Manually**:
   ```bash
   curl -X POST "http://localhost:8007/api/v1/documents/signatures/webhook/docusign" \
     -H "Content-Type: application/json" \
     -d '{
       "envelopeId": "test-envelope-id",
       "recipients": {
         "signers": [{"recipientId": "1", "status": "completed"}]
       }
     }'
   ```

### Document Download Fails

1. **Verify Envelope Status**:
   - The envelope must be in "completed" status in DocuSign
   - Check DocuSign dashboard for envelope status

2. **Check Service Logs**:
   ```bash
   grep "download.*DocuSign" logs/
   ```

3. **Verify JWT Token**:
   - Ensure DocuSign authentication is working
   - Check for consent errors

## Best Practices

1. **Polling vs Webhooks**:
   - Use webhooks for real-time updates (recommended)
   - Use status endpoint for manual checks or fallback

2. **Error Handling**:
   - Always check `signature_state` before downloading
   - Handle partial signatures gracefully
   - Implement retry logic for failed downloads

3. **Security**:
   - Use HTTPS for webhook endpoints
   - Verify webhook signatures if `DOCUSIGN_WEBHOOK_SECRET` is set
   - Implement rate limiting on webhook endpoint

4. **Storage**:
   - Consider storing signed documents back to S3 for long-term retention
   - Update document metadata with signed document location

## Next Steps

- [ ] Configure DocuSign Connect webhook
- [ ] Test webhook with a sample signature flow
- [ ] Set up SQS consumer for signature completion events
- [ ] Implement signed document storage (optional)
- [ ] Add webhook signature verification (optional)


