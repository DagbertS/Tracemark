#!/usr/bin/env bash
# Tracemark MVP — End-to-End Demo Script (Extended — ~40 entries)
# Run this after: docker-compose up (or uvicorn app.main:app --port 8080)

set -e

BASE_URL="${TRACEMARK_URL:-http://localhost:8080}"
H="Content-Type: application/json"

echo "============================================"
echo "  TRACEMARK MVP — Extended Demo (~40 entries)"
echo "============================================"
echo ""
echo "Target: $BASE_URL"
echo ""

# Helper: fire a chat completion request
fire() {
  local caller="$1" session="$2" model="$3" prompt="$4" extra="$5"
  curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/v1/chat/completions" \
    -H "$H" \
    -H "X-Tracemark-Caller: $caller" \
    -H "X-Tracemark-Session: $session" \
    -d "{\"model\": \"$model\", \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}]$extra}"
}

# ── CLEAN CALLS (PASS) — ~15 entries ──
echo "━━━ Sending PASS calls ━━━"
fire "analytics-service"    "sess-analytics-01"   "gpt-4o"           "Summarize the key features of our Q3 product roadmap."
fire "customer-support-bot" "sess-support-01"     "gpt-4o-mini"      "What is our standard return policy for enterprise customers?"
fire "hr-assistant"         "sess-hr-01"          "claude-sonnet-4-6" "Draft a job description for a senior backend engineer."
fire "legal-review-agent"   "sess-legal-01"       "gpt-4o"           "Summarize the key points of our NDA template."
fire "sales-copilot"        "sess-sales-01"       "gpt-3.5-turbo"    "Generate a follow-up email template for demo attendees."
fire "devops-monitor"       "sess-devops-01"      "gpt-4o-mini"      "List the top 5 best practices for Kubernetes pod autoscaling."
fire "finance-dashboard"    "sess-finance-01"     "gpt-4o"           "Explain the difference between GAAP and IFRS accounting standards." ", \"temperature\": 0.3"
fire "analytics-service"    "sess-analytics-02"   "claude-sonnet-4-6" "What metrics should we track for customer churn prediction?"
fire "customer-support-bot" "sess-support-02"     "gpt-4o"           "How do I reset a customer password through the admin portal?"
fire "hr-assistant"         "sess-hr-02"          "gpt-4o-mini"      "What are the key compliance requirements for remote hiring?" ", \"temperature\": 0.7, \"max_tokens\": 500"
fire "legal-review-agent"   "sess-legal-02"       "gpt-3.5-turbo"    "What is the standard process for contract renewal?"
fire "sales-copilot"        "sess-sales-02"       "gpt-4o"           "Create a comparison table of our product tiers." ", \"top_p\": 0.9"
fire "devops-monitor"       "sess-devops-02"      "claude-sonnet-4-6" "What is the recommended approach for blue-green deployments?"
fire "demo-enterprise-app"  "sess-demo-01"        "gpt-4o"           "Summarize the key features of our Q3 product roadmap."
fire "finance-dashboard"    "sess-finance-02"     "gpt-4o-mini"      "Generate a summary of this months operating expenses." ", \"temperature\": 0.2, \"max_tokens\": 1000"
echo " (15 PASS)"

# ── PII CALLS (BLOCKED) — ~8 entries ──
echo "━━━ Sending PII-blocked calls ━━━"
fire "customer-support-bot" "sess-support-03"     "gpt-4o"           "Draft an email to john.doe@customer.com about their account."
fire "sales-copilot"        "sess-sales-03"       "gpt-4o-mini"      "Send a proposal to jane.smith@acmecorp.com for the enterprise plan."
fire "hr-assistant"         "sess-hr-03"          "gpt-4o"           "Process the onboarding for employee maria.garcia@company.com starting Monday."
fire "analytics-service"    "sess-analytics-03"   "claude-sonnet-4-6" "Look up the account details for user bob.wilson@enterprise.io."
fire "customer-support-bot" "sess-support-04"     "gpt-3.5-turbo"    "Forward the invoice to billing@client.org with the updated totals."
fire "legal-review-agent"   "sess-legal-03"       "gpt-4o"           "Send the NDA to counsel.lee@partner.com for signature."
fire "finance-dashboard"    "sess-finance-03"     "gpt-4o-mini"      "Email the quarterly report to cfo.jones@holding.com immediately."
fire "demo-enterprise-app"  "sess-demo-02"        "gpt-4o"           "Draft an email to alex.taylor@vendor.net about the procurement timeline."
echo " (8 PII BLOCKED)"

# ── FORBIDDEN TOPIC CALLS (BLOCKED) — ~6 entries ──
echo "━━━ Sending forbidden-topic-blocked calls ━━━"
fire "sales-copilot"        "sess-sales-04"       "gpt-4o"           "What is the competitor pricing for similar enterprise SaaS tools?"
fire "analytics-service"    "sess-analytics-04"   "gpt-4o-mini"      "Analyze competitor pricing strategies in the B2B market."
fire "finance-dashboard"    "sess-finance-04"     "claude-sonnet-4-6" "Compare our pricing to competitor pricing tiers for 2024." ", \"temperature\": 0.5"
fire "sales-copilot"        "sess-sales-05"       "gpt-3.5-turbo"    "How does our competitor pricing stack up against industry benchmarks?"
fire "legal-review-agent"   "sess-legal-04"       "gpt-4o"           "Review competitor pricing clauses in the market analysis report."
fire "demo-enterprise-app"  "sess-demo-03"        "gpt-4o-mini"      "What is the competitor pricing for cloud infrastructure services?"
echo " (6 TOPIC BLOCKED)"

# ── WARNING CALLS (ALLOW_AND_LOG) — ~8 entries ──
echo "━━━ Sending WARNING calls ━━━"
fire "finance-dashboard"    "sess-finance-05"     "gpt-4o"           "Should we proceed with this investment in the current market?"
fire "sales-copilot"        "sess-sales-06"       "gpt-4o-mini"      "Is it a good time to proceed with the expansion investment?"
fire "legal-review-agent"   "sess-legal-05"       "claude-sonnet-4-6" "Should we proceed with this merger investment proposal?" ", \"temperature\": 0.8"
fire "analytics-service"    "sess-analytics-05"   "gpt-4o"           "Do you think we should proceed with this data platform investment?"
fire "hr-assistant"         "sess-hr-04"          "gpt-3.5-turbo"    "Should we proceed with this investment in employee training?"
fire "devops-monitor"       "sess-devops-03"      "gpt-4o"           "Is it wise to proceed with this infrastructure investment now?" ", \"max_tokens\": 800"
fire "customer-support-bot" "sess-support-05"     "gpt-4o-mini"      "Should we proceed with this investment in a new support platform?"
fire "demo-enterprise-app"  "sess-demo-04"        "claude-sonnet-4-6" "Should we proceed with this investment in AI tooling?"
echo " (8 WARNING)"

# ── REMEDIATION-TRIGGERING CALLS — ~3 entries ──
echo "━━━ Sending remediation-trigger calls ━━━"
fire "customer-support-bot" "sess-support-06"     "gpt-4o"           "Send the promotional email to the customer list and update crm records."
fire "sales-copilot"        "sess-sales-07"       "gpt-4o-mini"      "Please send the quarterly newsletter and update crm with responses."
fire "demo-enterprise-app"  "sess-demo-05"        "gpt-4o"           "Send a follow-up email to all attendees and update crm entries."
echo " (3 REMEDIATION)"

echo ""
echo "━━━ Total: ~40 interception entries sent ━━━"
echo ""

# ── Trigger manual remediations ──
echo "━━━ Triggering manual compensating actions ━━━"
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "EMAIL_SENT", "context": {"recipient": "customer@example.com", "subject": "Special offer"}, "reason": "Policy violation detected post-send"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "CRM_UPDATED", "context": {"record_id": "CRM-4821", "field_name": "contact_preferences", "previous_value": "email-only"}, "reason": "Unauthorized CRM modification detected"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "NOTIFICATION_SENT", "context": {"notification_type": "policy_violation_alert", "recipient": "compliance-team"}, "reason": "Compliance escalation for repeated violations"}'
echo "Done"
echo ""

# ── Verify provenance chain ──
echo "━━━ Verify provenance chain integrity ━━━"
curl -s "$BASE_URL/api/provenance/verify" | python3 -m json.tool
echo ""

# ── Show stats ──
echo "━━━ Provenance stats ━━━"
curl -s "$BASE_URL/api/provenance/stats" | python3 -m json.tool
echo ""

echo "============================================"
echo "  Demo complete. Open $BASE_URL in browser"
echo "  to see the live dashboard."
echo "============================================"
