"""CyberShield AI — Message Intelligence & Scam Classification Regression Suite

Exhaustive independent regression suite for the Message Intelligence module,
verifying evidence-grounded scoring, fraud indicator extraction, positive trust
signals, and logical score separation across real-world synthetic emails.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.services.message_analyzer import MessageAnalyzerService

client = TestClient(app)

# -----------------------------------------------------------------------------
# Part 1: Exact Three Test Emails from Audit Specification
# -----------------------------------------------------------------------------

EXACT_EMAIL_1_FAKE_JOB = """Subject: Congratulations! You Have Been Selected for a High-Paying Job
Email Body:
Dear Candidate,
Congratulations! Your profile has been shortlisted for the position of Senior Data Analyst at GlobalTech Solutions.
You are guaranteed a monthly salary of ₹85,000. To confirm your selection and secure your interview slot, you must pay a refundable registration and verification fee of ₹18,500 within the next 12 hours.
Please transfer the amount using the payment details below:
Payment UPI: globaltech.hr.fake@example.com
After payment, send your transaction screenshot along with your Aadhaar card and bank account details.
Failure to complete payment within 12 hours will result in automatic cancellation of your selection.
Regards,
HR Recruitment Team
GlobalTech Solutions"""

EXACT_EMAIL_2_FAKE_BANK_INVESTMENT = """Subject: Exclusive Bank Investment Scheme — Get 5X Returns in 24 Hours
Email Body:
Dear Valued Customer,
We are pleased to announce an exclusive investment opportunity for selected bank customers.
Deposit ₹10,000 today and receive a guaranteed return of ₹50,000 within 24 hours.
This special offer is available only for the next 6 hours.
To activate your investment account, click the verification link below and submit your bank account number, debit card details, and OTP.
Verification Portal: http://example.com/fake-bank-verification
Please do not delay. Your investment opportunity will expire shortly.
Regards,
Bank Investment Department"""

EXACT_EMAIL_3_LEGITIMATE_JOB_ACK = """Subject: Application Received — Software Developer Position
Email Body:
Dear Applicant,
Thank you for applying for the Software Developer position at Example Technologies.
We have successfully received your application. Our recruitment team will review your profile and contact you if your qualifications match the requirements of the role.
The recruitment process may include an initial screening call, a technical assessment, and an interview.
Please note that Example Technologies does not charge candidates any application, registration, interview, or recruitment fees.
You can review your application status by visiting our official careers website, which you can access through the company website you used when applying.
Thank you for your interest in joining our team.
Best regards,
Recruitment Team
Example Technologies"""

EXACT_EMAIL_4_LEGITIMATE_BANK_TRANSACTION = """Subject: Transaction Alert — Your Account Activity

Dear Customer,

This is an automated notification regarding a recent transaction on your bank account.

Transaction Details:

Transaction Type: Debit
Amount: ₹1,250
Date: 08 November 2026
Reference ID: DEMO-TXN-82641

If you recognize this transaction, no further action is required.

If you do not recognize this activity, please contact your bank using the customer support number printed on your official debit card or visit the bank's official website directly.

For your security, we will never ask you to share your password, PIN, CVV, or OTP through email.

Thank you for banking with us.

Regards,
Bank Notification Service"""


class TestAuditThreeExactEmails:
    """Verifies evidence extraction, risk classification, and score differentiation for the user emails."""

    def test_exact_email_4_legitimate_bank_transaction_false_positive_prevention(self):
        """Test 4: Legitimate banking transaction alert with routine debit and anti-phishing disclaimer.
        
        Must NOT be classified as credential theft (score 74 false positive).
        Must produce Low Risk (score <= 20) with zero suspicious indicators.
        """
        resp = client.post("/api/v1/scans/message", json={"content": EXACT_EMAIL_4_LEGITIMATE_BANK_TRANSACTION})
        assert resp.status_code == 200
        data = resp.json()

        # 1. Low Risk Classification
        assert data["risk_level"] == "Low", f"Expected Low for legitimate bank transaction, got {data['risk_level']}"
        assert data["risk_score"] <= 20, f"Expected risk_score <= 20, got {data['risk_score']} (previously 74)"

        # 2. Zero Suspicious Indicators (anti-phishing warning must not trigger credential theft)
        assert len(data["message_indicators"]) == 0, (
            f"Defensive security disclaimer must not be flagged as a threat indicator: {data['message_indicators']}"
        )

        # 3. Report Summary acknowledges legitimate banking correspondence
        summary_lower = data["report"]["summary"].lower()
        assert "banking" in summary_lower or "transaction" in summary_lower or "legitimate" in summary_lower

    def test_exact_email_1_fake_job_offer(self):
        """Test 1: Fake recruitment advance-fee fraud scenario."""
        resp = client.post("/api/v1/scans/message", json={"content": EXACT_EMAIL_1_FAKE_JOB})
        assert resp.status_code == 200
        data = resp.json()

        # 1. Classification & Score Expectations
        assert data["risk_level"] in ("High", "Critical"), f"Expected High/Critical, got {data['risk_level']}"
        assert data["risk_score"] >= 75, f"Expected risk_score >= 75, got {data['risk_score']}"
        assert data["risk_score"] != 61, "Risk score must NOT be the uncalibrated fallback constant 61"

        # 2. Extracted Indicators
        categories_found = [ind["category"].lower() for ind in data["message_indicators"]]
        descriptions_found = " ".join(ind["description"].lower() for ind in data["message_indicators"])

        assert any("fee" in c or "fee" in descriptions_found for c in categories_found), "Must identify job registration fee"
        assert any("aadhaar" in descriptions_found or "identity" in descriptions_found or "document" in descriptions_found for ind in data["message_indicators"]), "Must detect Aadhaar/PII harvesting"
        assert any("salary" in descriptions_found or "guaranteed" in descriptions_found for ind in data["message_indicators"]), "Must detect guaranteed salary claim"
        assert any("deadline" in descriptions_found or "urgency" in descriptions_found or "12 hours" in descriptions_found for ind in data["message_indicators"]), "Must detect artificial 12-hour deadline"
        assert any("screenshot" in descriptions_found for ind in data["message_indicators"]), "Must detect transaction screenshot request"

        # 3. Category & Summary
        assert "job" in data["report"]["summary"].lower() or "fee" in data["report"]["summary"].lower()

    def test_exact_email_2_fake_bank_investment_phishing(self):
        """Test 2: Fake bank investment & credential phishing scenario."""
        resp = client.post("/api/v1/scans/message", json={"content": EXACT_EMAIL_2_FAKE_BANK_INVESTMENT})
        assert resp.status_code == 200
        data = resp.json()

        # 1. Severe Threat Classification
        assert data["risk_level"] == "Critical", f"Expected Critical for credential harvesting, got {data['risk_level']}"
        assert data["risk_score"] >= 90, f"Expected risk_score >= 90, got {data['risk_score']}"
        assert data["risk_score"] != 61, "Risk score must NOT be the uncalibrated fallback constant 61"

        # 2. Extracted Indicators
        descriptions_found = " ".join(ind["description"].lower() for ind in data["message_indicators"])

        assert any("otp" in descriptions_found for ind in data["message_indicators"]), "Must detect OTP collection"
        assert any("debit card" in descriptions_found or "card" in descriptions_found for ind in data["message_indicators"]), "Must detect debit card harvesting"
        assert any("http" in descriptions_found or "unencrypted" in descriptions_found for ind in data["message_indicators"]), "Must detect unencrypted HTTP verification link"
        assert any("return" in descriptions_found or "5x" in descriptions_found for ind in data["message_indicators"]), "Must detect unrealistic 5X return promise"
        assert any("deposit" in descriptions_found for ind in data["message_indicators"]), "Must detect upfront deposit demand"

    def test_exact_email_3_legitimate_job_acknowledgement(self):
        """Test 3: Legitimate corporate recruitment acknowledgement."""
        resp = client.post("/api/v1/scans/message", json={"content": EXACT_EMAIL_3_LEGITIMATE_JOB_ACK})
        assert resp.status_code == 200
        data = resp.json()

        # 1. Low Risk Classification
        assert data["risk_level"] == "Low", f"Expected Low for legitimate job acknowledgement, got {data['risk_level']}"
        assert data["risk_score"] <= 20, f"Expected risk_score <= 20, got {data['risk_score']}"
        assert data["risk_score"] != 25, "Risk score must NOT be the uncalibrated inconclusive constant 25"

        # 2. Zero Suspicious Indicators Flagged
        assert len(data["message_indicators"]) == 0, f"Legitimate text must not flag suspicious indicators: {data['message_indicators']}"

        # 3. Report Summary acknowledges legitimate traits
        summary_lower = data["report"]["summary"].lower()
        assert "legitimate" in summary_lower or "benign" in summary_lower or "fee disclaimer" in summary_lower

    def test_score_differentiation_between_emails(self):
        """Prove that the 3 emails produce logically separated, non-identical scores."""
        r1 = client.post("/api/v1/scans/message", json={"content": EXACT_EMAIL_1_FAKE_JOB}).json()
        r2 = client.post("/api/v1/scans/message", json={"content": EXACT_EMAIL_2_FAKE_BANK_INVESTMENT}).json()
        r3 = client.post("/api/v1/scans/message", json={"content": EXACT_EMAIL_3_LEGITIMATE_JOB_ACK}).json()

        s1 = r1["risk_score"]
        s2 = r2["risk_score"]
        s3 = r3["risk_score"]

        # Fraudulent emails must NOT share identical scores
        assert s1 != s2, f"Emails 1 and 2 must receive distinct scores reflecting their individual threats: got {s1} and {s2}"

        # Email 2 (OTP + Debit card + HTTP) must score higher than Email 1 (Advance fee job scam)
        assert s2 > s1, f"Email 2 (severe credential theft) must score higher than Email 1: got {s2} vs {s1}"

        # Legitimate email must be cleanly separated from fraudulent ones by at least 50 points
        assert (s1 - s3) >= 50, f"Gap between Email 1 and Legitimate Email must be >= 50 points: got {s1} - {s3} = {s1 - s3}"
        assert (s2 - s3) >= 60, f"Gap between Email 2 and Legitimate Email must be >= 60 points: got {s2} - {s3} = {s2 - s3}"


# -----------------------------------------------------------------------------
# Part 2: Required Additional Real-World Scenarios
# -----------------------------------------------------------------------------

class TestAdditionalScenarios:
    """Verifies the 8 additional scenarios requested in Part 5 of the evaluation prompt."""

    def test_scenario_otp_phishing_email(self):
        """OTP phishing email attempting urgent account takeover."""
        content = (
            "URGENT: Suspicious activity detected on your NetBanking profile. "
            "To prevent immediate account suspension, please submit your one-time password (OTP) "
            "and debit card CVV at http://bank-security.xyz/verify immediately."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 70

    def test_scenario_fake_parcel_delivery(self):
        """Fake parcel delivery notification with advance fee demand."""
        content = (
            "Your parcel #IN83921 could not be delivered due to an incorrect address. "
            "You must pay a mandatory delivery and redelivery fee of ₹149 within the next 24 hours. "
            "Click here to confirm your address and transfer payment: http://india-post-redelivery.com/pay"
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("Medium", "High")
        assert data["risk_score"] >= 45

    def test_scenario_fake_tech_support(self):
        """Fake technical support alert with intimidation and secrecy demand."""
        content = (
            "Security Alert from Windows Support: Your computer has been infected with spyware. "
            "Contact our certified technicians at +1-800-555-0199 immediately. "
            "Keep this strictly confidential and do not inform anyone before calling our helpline."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("Medium", "High", "Critical")
        assert data["risk_score"] >= 60

    def test_scenario_normal_bank_transaction(self):
        """Normal bank transaction notification following standard regulatory format."""
        content = (
            "Dear Customer, your account XX1234 has been debited with INR 2,450.00 at Amazon India on 08-Nov-2026. "
            "Available balance is INR 45,210.00. If this transaction was not done by you, call 1800-111-222 or SMS BLOCK to 56767."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 25

    def test_scenario_legitimate_password_reset(self):
        """Legitimate password-reset notification advising inaction if unrequested."""
        content = (
            "We received a request to reset the password for your ExampleApp account. "
            "If you requested this change, you can reset your password using the link sent to your registered device. "
            "If you did not request a password reset, please ignore this email. Your account remains secure."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 25

    def test_scenario_fake_job_offer_without_explicit_fee(self):
        """Fake job offer with guaranteed salary claims but without explicit upfront fee."""
        content = (
            "Congratulations! We reviewed your resume and you have guaranteed job placement as a Cloud Architect. "
            "You are guaranteed a monthly salary of ₹150,000 without any formal interview. "
            "Please confirm your acceptance within the next 24 hours to secure your placement."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("Medium", "High")
        assert data["risk_score"] >= 45

    def test_scenario_subtle_investment_newsletter(self):
        """Educational / consultative investment newsletter with standard financial disclaimers."""
        content = (
            "Exclusive wealth management newsletter: Discover how diversified index funds consistently outperform speculative assets. "
            "Past performance does not guarantee future results. Consult a registered financial advisor before investing."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 25

    def test_scenario_legitimate_promotional_email(self):
        """Legitimate promotional email for in-store physical retail discounts."""
        content = (
            "Special Weekend Offer at TechStore! Get up to 30% off on selected headphones and smartwatches. "
            "Visit any of our physical retail stores this Saturday and Sunday. Terms and conditions apply."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 25

    def test_scenario_legitimate_bank_otp_security_warning(self):
        """Legitimate bank security awareness broadcast warning customers to never share credentials."""
        content = (
            "Security Notice from CyberBank: Never share your OTP, PIN, CVV, or netbanking passwords with anyone. "
            "Our bank officials will never ask you to disclose these details via phone, email, or unverified links. "
            "If someone requests these codes, report it immediately to our 24x7 helpline."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] == "Low"
        assert data["risk_score"] <= 20
        assert len(data["message_indicators"]) == 0

    def test_scenario_fake_bank_urgent_otp_phishing(self):
        """Fake bank alert soliciting urgent OTP and credentials to prevent termination."""
        content = (
            "URGENT: Suspicious login detected on your bank account. "
            "To prevent permanent account termination, please submit your one-time password (OTP) "
            "and debit card CVV at http://secure-bank-verify.xyz immediately."
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 88
        assert any("otp" in ind["description"].lower() for ind in data["message_indicators"])

    def test_scenario_deceptive_phishing_with_copied_disclaimer(self):
        """Malicious phishing email attempting to evade detection with a copied bank disclaimer."""
        content = (
            "Security Notice: We will never ask for your password by phone. "
            "However, you must click the link below and provide your debit card details and CVV "
            "to restore your frozen account: http://bank-unblock-portal.com"
        )
        resp = client.post("/api/v1/scans/message", json={"content": content})
        assert resp.status_code == 200
        data = resp.json()
        assert data["risk_level"] in ("High", "Critical")
        assert data["risk_score"] >= 80
        assert any("card" in ind["description"].lower() for ind in data["message_indicators"])


