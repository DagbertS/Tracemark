#!/usr/bin/env bash
# Tracemark — 1000-record stress test
set -e

BASE_URL="${TRACEMARK_URL:-http://localhost:8080}"
H="Content-Type: application/json"

echo "============================================"
echo "  TRACEMARK — 1,000-Record Load Test"
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

CALLERS=("analytics-service" "customer-support-bot" "hr-assistant" "legal-review-agent" "sales-copilot" "devops-monitor" "finance-dashboard" "demo-enterprise-app" "marketing-engine" "research-agent" "compliance-bot" "inventory-tracker" "onboarding-agent" "risk-analysis-bot" "procurement-assistant" "quality-assurance-agent")
MODELS=("gpt-4o" "gpt-4o-mini" "gpt-3.5-turbo" "claude-sonnet-4-6" "anthropic/claude-sonnet-4-6" "google/gemini-2.0-flash")

COUNT=0

# ── PASS calls (550 entries) ──
echo "━━━ Sending 550 PASS calls ━━━"
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
  "Explain the data classification policy for handling PCI data."
  "How does our IAM role-based access control model work?"
  "What are the integration test requirements before merging to main?"
  "Describe the architecture review process for new microservices."
  "What is the policy for third-party library vulnerability patching?"
  "Summarize the approved cloud regions and data residency rules."
  "How do we handle internationalization for the customer portal?"
  "What are the performance SLOs for the payment processing service?"
  "Draft a runbook for rotating database credentials."
  "How do we evaluate build vs buy decisions for internal tooling?"
  "Explain the capacity planning process for Black Friday traffic."
  "What compliance certifications do we currently hold?"
  "Describe the data pipeline architecture for the analytics warehouse."
  "What is the standard process for domain name management?"
  "How do we handle service mesh configuration across environments?"
  "What are the requirements for logging sensitive API calls?"
  "Draft guidelines for writing effective runbooks."
  "How do we manage feature experiments and A/B testing?"
  "Describe the customer feedback loop process with product teams."
  "What is our approach to chaos engineering and resilience testing?"
  "How do we manage cross-team dependencies in quarterly planning?"
  "What are the guidelines for writing public-facing API documentation?"
  "Summarize the process for handling a security incident involving PII."
  "How do we evaluate vendor SLAs before procurement?"
  "Draft a template for quarterly business reviews with enterprise clients."
  "What is the standard operating procedure for emergency hotfixes?"
  "How do we handle schema versioning for our GraphQL API?"
  "Describe the process for onboarding a new third-party integration."
  "What is our strategy for managing technical documentation?"
  "How do we handle backwards compatibility for public APIs?"
  "What are the guidelines for container image security scanning?"
)
EXTRAS=("" ", \"temperature\": 0.3" ", \"temperature\": 0.5" ", \"temperature\": 0.7" ", \"temperature\": 0.9" ", \"max_tokens\": 500" ", \"max_tokens\": 1000" ", \"top_p\": 0.9" ", \"top_p\": 0.8" ", \"temperature\": 0.4, \"max_tokens\": 800")
for i in $(seq 1 550); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${PASS_PROMPTS[$((RANDOM % ${#PASS_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%04d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
  # Print progress every 50
  if (( COUNT % 50 == 0 )); then echo " [$COUNT]"; fi
done
echo " (550 PASS — total: $COUNT)"

# ── PII BLOCKED calls (200 entries) ──
echo "━━━ Sending 200 PII-blocked calls ━━━"
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
  "Draft a message to sarah.chen@globalcorp.com about the partnership."
  "Send the performance review to manager.kim@enterprise.io for approval."
  "Email the training schedule to newhires@company.com for next quarter."
  "Forward the security audit to iso.officer@compliance.org for sign-off."
  "Send the integration specs to dev.lead@partner.tech for review."
  "Email the SLA report to account.manager@client.com with metrics."
  "Draft a follow-up to investor.relations@holding.com about Q4 results."
  "Send the incident update to ops.team@service.io for awareness."
  "Forward the license agreement to procurement@buyer.co for execution."
  "Email the migration plan to cto.office@enterprise.com for approval."
)
for i in $(seq 551 750); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${PII_PROMPTS[$((RANDOM % ${#PII_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%04d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
  if (( COUNT % 50 == 0 )); then echo " [$COUNT]"; fi
done
echo " (200 PII BLOCKED — total: $COUNT)"

# ── TOPIC BLOCKED calls (120 entries) ──
echo "━━━ Sending 120 topic-blocked calls ━━━"
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
  "Draft a competitor pricing comparison for the board presentation."
  "How do competitor pricing models affect our market positioning?"
  "Analyze the competitor pricing impact on our mid-market segment."
  "Review competitor pricing trends in the European market."
  "What competitor pricing data do we have from the latest trade show?"
)
for i in $(seq 751 870); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${TOPIC_PROMPTS[$((RANDOM % ${#TOPIC_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%04d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
  if (( COUNT % 50 == 0 )); then echo " [$COUNT]"; fi
done
echo " (120 TOPIC BLOCKED — total: $COUNT)"

# ── WARNING calls (80 entries) ──
echo "━━━ Sending 80 WARNING calls ━━━"
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
  "Is this the right time for a significant investment in R&D?"
  "Should we proceed with this investment in blockchain technology?"
  "Do you recommend proceeding with this cybersecurity investment?"
  "Should we proceed with this investment in a new office expansion?"
  "Is the current valuation reasonable for this investment opportunity?"
)
for i in $(seq 871 950); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${WARN_PROMPTS[$((RANDOM % ${#WARN_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%04d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
  if (( COUNT % 50 == 0 )); then echo " [$COUNT]"; fi
done
echo " (80 WARNING — total: $COUNT)"

# ── REMEDIATION-TRIGGERING calls (50 entries) ──
echo "━━━ Sending 50 remediation-trigger calls ━━━"
REMED_PROMPTS=(
  "Send the promotional email to the customer list and update crm records."
  "Please send the quarterly newsletter and update crm with responses."
  "Send a follow-up email to all attendees and update crm entries."
  "Blast the campaign email to all leads and update crm status."
  "Send the renewal reminder email and update crm deal stage."
  "Send the upsell campaign to all trial users and update crm tracking."
  "Email the product launch announcement to all customers and update crm tags."
  "Send the churn prevention email series and update crm risk scores."
  "Distribute the survey email to inactive accounts and update crm engagement."
  "Send the holiday promotion email blast and update crm purchase history."
)
for i in $(seq 951 1000); do
  c=${CALLERS[$((RANDOM % ${#CALLERS[@]}))]}
  m=${MODELS[$((RANDOM % ${#MODELS[@]}))]}
  p=${REMED_PROMPTS[$((RANDOM % ${#REMED_PROMPTS[@]}))]}
  e=${EXTRAS[$((RANDOM % ${#EXTRAS[@]}))]}
  fire "$c" "sess-load-$(printf '%04d' $i)" "$m" "$p" "$e"
  COUNT=$((COUNT + 1))
done
echo " (50 REMEDIATION — total: $COUNT)"

echo ""
echo "━━━ Total: $COUNT interception entries sent ━━━"
echo ""

# ── Trigger manual remediations ──
echo "━━━ Triggering 10 manual compensating actions ━━━"
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
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "EMAIL_SENT", "context": {"recipient": "legal@client.com", "subject": "Terms modification"}, "reason": "Unauthorized terms change communicated"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "CRM_UPDATED", "context": {"record_id": "CRM-9102", "field_name": "account_tier", "previous_value": "standard"}, "reason": "Unauthorized account tier escalation"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "NOTIFICATION_SENT", "context": {"notification_type": "data_access_alert", "recipient": "security-team"}, "reason": "Unusual data access pattern detected"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "EMAIL_SENT", "context": {"recipient": "finance@holding.com", "subject": "Budget override"}, "reason": "Budget approval bypass detected"}'
curl -s -o /dev/null -X POST "$BASE_URL/api/remediate" \
  -H "$H" \
  -d '{"action_type": "CRM_UPDATED", "context": {"record_id": "CRM-3344", "field_name": "contract_value", "previous_value": "50000"}, "reason": "Contract value modified without approval"}'
echo " Done (10 remediations)"
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
echo "  1,000-record load test complete."
echo "  Open $BASE_URL in browser to see results."
echo "============================================"
