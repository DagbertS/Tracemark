#!/usr/bin/env bash
# Tracemark — 200-record stress test
set -e

BASE_URL="${TRACEMARK_URL:-http://localhost:8080}"
H="Content-Type: application/json"

echo "============================================"
echo "  TRACEMARK — 200-Record Load Test"
echo "============================================"
echo ""
echo "Target: $BASE_URL"
echo ""

fire() {
  local caller="$1" session="$2" model="$3" prompt="$4" extra="$5"
  curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/v1/chat/completions" \
    -H "$H" \
    -H "X-Tracemark-Caller: $caller" \
    -H "X-Tracemark-Session: $session" \
    -d "{\"model\": \"$model\", \"messages\": [{\"role\": \"user\", \"content\": \"$prompt\"}]$extra}"
}

CALLERS=("analytics-service" "customer-support-bot" "hr-assistant" "legal-review-agent" "sales-copilot" "devops-monitor" "finance-dashboard" "demo-enterprise-app" "marketing-engine" "research-agent" "compliance-bot" "inventory-tracker")
MODELS=("gpt-4o" "gpt-4o-mini" "gpt-3.5-turbo" "claude-sonnet-4-6")

COUNT=0

# ── PASS calls (100 entries) ──
echo "━━━ Sending 100 PASS calls ━━━"
PASS_PROMPTS=(
  "Summarize the key features of our Q3 product roadmap."
  "What is our standard return policy for enterprise customers?"
  "Draft a job description for a senior backend engineer."
  "Summarize the key points of our NDA template."
  "Generate a follow-up email template for demo attendees."
  "List the top 5 best practices for Kubernetes pod autoscaling."
  "Explain the difference between GAAP and IFRS accounting standards."
  "What metrics should we track for customer churn prediction?"
  "How do I reset a customer password through the admin portal?"
  "What are the key compliance requirements for remote hiring?"
  "What is the standard process for contract renewal?"
  "Create a comparison table of our product tiers."
  "What is the recommended approach for blue-green deployments?"
  "Generate a summary of this months operating expenses."
  "Describe the onboarding process for new team members."
  "What are the SLA tiers we offer to enterprise clients?"
  "Outline the incident response procedure for P1 outages."
  "List the approved software vendors for our procurement process."
  "Summarize the quarterly revenue trends from the last four quarters."
  "Draft internal guidelines for using generative AI tools safely."
  "What are the data retention policies for customer records?"
  "Explain our API rate limiting strategy."
  "Create a checklist for production deployment readiness."
  "Describe the approval workflow for budget requests over 50k."
  "What are the best practices for securing REST APIs?"
  "Summarize the benefits package for full-time employees."
  "How do we handle GDPR data subject access requests?"
  "Generate a template for weekly team status reports."
  "What is our policy on open-source software contributions?"
  "Outline the process for vendor security assessments."
  "List the key performance indicators for the support team."
  "What training resources are available for new engineers?"
  "Summarize the disaster recovery plan for our cloud infrastructure."
  "How do we track technical debt across the engineering org?"
  "What is the escalation path for unresolved customer issues?"
  "Draft a project brief template for cross-functional initiatives."
  "Explain the CI/CD pipeline stages for our main application."
  "What are the accessibility standards we follow for the UI?"
  "Summarize the change management process for production systems."
  "Describe the architecture of our event-driven messaging system."
  "What tools do we use for monitoring application performance?"
  "How do we measure engineering team velocity?"
  "List the security controls required for SOC 2 compliance."
  "What is our approach to feature flagging and canary releases?"
  "Summarize the mobile app release process."
  "Draft a post-mortem template for incident reviews."
  "What are the coding standards for our Python services?"
  "How do we manage database schema migrations?"
  "Describe our multi-region failover strategy."
  "What is the process for requesting additional cloud resources?"
)
EXTRAS=("" ", \"temperature\": 0.3" ", \"temperature\": 0.5" ", \"temperature\": 0.7" ", \"temperature\": 0.9" ", \"max_tokens\": 500" ", \"max_tokens\": 1000" ", \"top_p\": 0.9" ", \"top_p\": 0.8" ", \"temperature\": 0.4, \"max_tokens\": 800")
for i in $(seq 1 100); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${PASS_PROMPTS[$((RANDOM % ${#PASS_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%03d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
done
echo " (100 PASS — total: $COUNT)"

# ── PII BLOCKED calls (40 entries) ──
echo "━━━ Sending 40 PII-blocked calls ━━━"
PII_PROMPTS=(
  "Draft an email to john.doe@customer.com about their account."
  "Send a proposal to jane.smith@acmecorp.com for the enterprise plan."
  "Process the onboarding for employee maria.garcia@company.com starting Monday."
  "Look up the account details for user bob.wilson@enterprise.io."
  "Forward the invoice to billing@client.org with the updated totals."
  "Send the NDA to counsel.lee@partner.com for signature."
  "Email the quarterly report to cfo.jones@holding.com immediately."
  "Draft an email to alex.taylor@vendor.net about the procurement timeline."
  "Send a welcome email to new.hire@ourcompany.com with credentials."
  "Forward the support ticket to escalation@service.com for review."
  "Send the contract to procurement@buyer.org for final approval."
  "Email the audit results to external.auditor@firm.com."
  "Notify user.admin@platform.io about the security patch schedule."
  "Send the updated terms to legal@partnerco.com for review."
  "Forward compliance report to regulator@authority.gov."
  "Email onboarding docs to intern.class2024@company.com."
  "Send API credentials to devteam@contractor.io for integration."
  "Forward the incident report to ciso@enterprise.com."
  "Email the budget proposal to finance.director@holding.com."
  "Send meeting notes to board.secretary@corporate.org."
)
for i in $(seq 101 140); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${PII_PROMPTS[$((RANDOM % ${#PII_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%03d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
done
echo " (40 PII BLOCKED — total: $COUNT)"

# ── TOPIC BLOCKED calls (30 entries) ──
echo "━━━ Sending 30 topic-blocked calls ━━━"
TOPIC_PROMPTS=(
  "What is the competitor pricing for similar enterprise SaaS tools?"
  "Analyze competitor pricing strategies in the B2B market."
  "Compare our pricing to competitor pricing tiers for 2024."
  "How does our competitor pricing stack up against industry benchmarks?"
  "Review competitor pricing clauses in the market analysis report."
  "What is the competitor pricing for cloud infrastructure services?"
  "Provide a detailed competitor pricing breakdown for the CRM segment."
  "How has competitor pricing changed over the last two quarters?"
  "Summarize competitor pricing intelligence from the latest analyst report."
  "What competitor pricing adjustments should we expect next fiscal year?"
)
for i in $(seq 141 170); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${TOPIC_PROMPTS[$((RANDOM % ${#TOPIC_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%03d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
done
echo " (30 TOPIC BLOCKED — total: $COUNT)"

# ── WARNING calls (20 entries) ──
echo "━━━ Sending 20 WARNING calls ━━━"
WARN_PROMPTS=(
  "Should we proceed with this investment in the current market?"
  "Is it a good time to proceed with the expansion investment?"
  "Should we proceed with this merger investment proposal?"
  "Do you think we should proceed with this data platform investment?"
  "Should we proceed with this investment in employee training?"
  "Is it wise to proceed with this infrastructure investment now?"
  "Should we proceed with this investment in a new support platform?"
  "Should we proceed with this investment in AI tooling?"
  "Would you recommend this real estate investment for the company?"
  "Should we proceed with the venture capital investment round?"
)
for i in $(seq 171 190); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${WARN_PROMPTS[$((RANDOM % ${#WARN_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%03d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
done
echo " (20 WARNING — total: $COUNT)"

# ── REMEDIATION-TRIGGERING calls (10 entries) ──
echo "━━━ Sending 10 remediation-trigger calls ━━━"
REMED_PROMPTS=(
  "Send the promotional email to the customer list and update crm records."
  "Please send the quarterly newsletter and update crm with responses."
  "Send a follow-up email to all attendees and update crm entries."
  "Blast the campaign email to all leads and update crm status."
  "Send the renewal reminder email and update crm deal stage."
)
for i in $(seq 191 200); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${REMED_PROMPTS[$((RANDOM % ${#REMED_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%03d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
done
echo " (10 REMEDIATION — total: $COUNT)"

echo ""
echo "━━━ Total: $COUNT interception entries sent ━━━"
echo ""

# ── Trigger manual remediations ──
echo "━━━ Triggering 5 manual compensating actions ━━━"
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "EMAIL_SENT", "context": {"recipient": "customer@example.com", "subject": "Special offer"}, "reason": "Policy violation detected post-send"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "CRM_UPDATED", "context": {"record_id": "CRM-4821", "field_name": "contact_preferences", "previous_value": "email-only"}, "reason": "Unauthorized CRM modification detected"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "NOTIFICATION_SENT", "context": {"notification_type": "policy_violation_alert", "recipient": "compliance-team"}, "reason": "Compliance escalation for repeated violations"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "EMAIL_SENT", "context": {"recipient": "partner@vendor.com", "subject": "Contract update"}, "reason": "Unapproved contract modification sent"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "CRM_UPDATED", "context": {"record_id": "CRM-7733", "field_name": "deal_stage", "previous_value": "qualified"}, "reason": "Premature deal stage advancement"}'
echo " Done (5 remediations)"
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
echo "  200-record load test complete."
echo "  Open $BASE_URL in browser to see results."
echo "============================================"
