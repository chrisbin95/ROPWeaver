# ROPWeaver Release Preparation — Task 4.2 Acceptance Record
## Public Read-Only Firestore Security Implementation and Local Hardening

**Acceptance Status:** ACCEPTED LOCALLY WITH DOCUMENTED LIMITATIONS
**Task Reference:** Task 4.2 / Task 4.2.1 / Task 4.2.2
**Date:** 2026-11-16
**Target Release:** v1.6.3

---

## 1. Executive Summary

During release pre-push safety audits (Tasks 3.6 and 4.1), a critical vulnerability was identified in the project's Cloud Firestore security configuration: `config/firestore.rules` granted unrestricted global read and write access (`allow read, write: if true;`) to all documents.

Task 4.1.1 evaluated alternative remediation strategies and formally approved **Architecture A: Public Read-Only Firestore with Direct Anonymous Writes Disabled**.

Task 4.2 implemented this architecture:
1. Hardened `config/firestore.rules` to enforce public unauthenticated read access for the React community explorer while strictly denying all unauthenticated creations, updates, and deletions.
2. Created standard deployment manifests (`firebase.json` and `.firebaserc`) for project `ropweaver`.
3. Hardened C++ engine upload error handling in `main.cpp` and `firebase/firebase_uploader.cpp` to decouple local analysis from network results, prevent redundant doomed batch uploads, return appropriate failure exit codes on cloud rejection, and preserve all local report and payload artifacts.

Task 4.2.1 completed an independent read-only audit and returned a verdict of **ACCEPTABLE WITH LIMITATIONS**. This document formally records the local acceptance of Task 4.2.

---

## 2. Original Security Vulnerability

The original `config/firestore.rules` contained:
```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /reports/{document=**} {
      allow read, write: if true;
    }
    match /gadgets/{document=**} {
      allow read, write: if true;
    }
  }
}
```

### Risk Analysis:
* **Caller Identification Failure:** Web API keys identify only the billing project and provide no caller identity (`request.auth == null`).
* **Database Destruction Risk:** Any anonymous caller possessing the public API key could execute HTTP `DELETE` requests to delete all reports and discovered gadgets.
* **Exploit Chain Poisoning:** Attackers could execute HTTP `PATCH` or `POST` requests to modify analysis reports, overwrite discovered gadget addresses, or inject weaponized exploit payloads into the public database.
* **Quota and Denial of Service:** Automated scripts could spam unlimited documents into the database, exhausting free quotas and inflating billing.

---

## 3. Public Read-Only Security Architecture

Under Architecture A, Cloud Firestore functions as a curated, public read-only catalog:
* **Web Explorer:** Fully preserved. Public users can browse reports, view binary metrics, inspect gadget categories, and perform searches across the `/reports` and `/gadgets` collections without authentication.
* **Write Operations:** Direct unauthenticated writes are completely disabled at the security-rules layer.
* **Local Engine Operation:** The compiled C++ binary (`ropweaver`) continues to perform full local static analysis, generating `reports/output.json` and `payload.bin` on the local machine regardless of network or cloud status.

---

## 4. Exact Firestore Security Rules Policy

File: `config/firestore.rules`

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {

    // Allow public read-only access to reports collection; deny all writes
    match /reports/{reportId} {
      allow read: if true;
      allow write: if false;
    }

    // Allow public read-only access to gadgets collection; deny all writes
    match /gadgets/{gadgetId} {
      allow read: if true;
      allow write: if false;
    }

    // Default deny for all other collections and document paths
    match /{document=**} {
      allow read, write: if false;
    }
  }
}
```

### Policy Properties:
1. **Permitted Public Read Paths:**
   * `/reports/{reportId}` (`allow read: if true;`): Permits `get` (single document) and `list` (collection queries) for all reports.
   * `/gadgets/{gadgetId}` (`allow read: if true;`): Permits `get` and `list` across all gadget records.
2. **Explicit Denial of Writes and Deletes:**
   * `allow write: if false;` explicitly denies `create`, `update`, and `delete` operations on all report and gadget documents.
3. **Least-Privilege Matching:**
   * Replaced recursive `{document=**}` matching with single-segment document wildcards (`{reportId}` and `{gadgetId}`), preventing unintended rule propagation to subcollections.
4. **Default-Deny Policy:**
   * `match /{document=**} { allow read, write: if false; }` ensures any unmapped path or future collection is unconditionally denied.
5. **No Ambiguous Schema Writes:**
   * Vulnerable pseudo-schema validation rules were completely discarded.

---

## 5. CLI Upload Handling and Local Output Preservation

### 5.1 Execution Decoupling
In `main.cpp`, `PayloadGenerator::generate()` (lines 401–423) executes and flushes all local artifacts **before** any network upload routines are initiated. Local analysis results are never conditional on cloud upload success.

### 5.2 Failure Handling and Exit Codes
* **Local Artifact Preservation:** When Firestore rejects an upload (e.g., HTTP 403 Forbidden), local analysis reports (`reports/output.json` and `reports/<binary>_<hash>.json`) and synthesized payloads (`payload.bin`) remain intact and unaltered on disk.
* **Clear User Diagnostics:** The CLI emits clear, accurate diagnostics:
  ```text
  [!] Note: 403 Forbidden indicates cloud write access is restricted by Firestore security policy.
      Local analysis reports and generated payloads remain intact.
  [x] Firebase upload failed. Cloud write access is disabled or unauthorized.
  [i] Local analysis output and payloads remain preserved in 'reports/'.
  ```
* **Redundant Batch Suppression:** If the report document upload fails, `uploader.uploadGadgets()` is skipped, eliminating redundant doomed batch network requests.
* **Accurate Exit Codes:**
  * When `--upload-report` or `--firebase` is explicitly requested and cloud upload fails, the CLI returns exit code `1`.
  * When running normal local analysis without cloud upload, the CLI completes and returns exit code `0`.
* **No False Success Reporting:** The CLI never prints `[+] Report uploaded to Firebase.` if the upload was rejected.

---

## 6. Firebase Configuration Manifests

Created standard root-level deployment manifests:

1. **`firebase.json`:**
   ```json
   {
     "firestore": {
       "rules": "config/firestore.rules"
     }
   }
   ```
2. **`.firebaserc`:**
   ```json
   {
     "projects": {
       "default": "ropweaver"
     }
   }
   ```
   Uses canonical project ID `"ropweaver"`, verified from `web-react/src/firebase/config.js` and `firebase/firebase_uploader.cpp`.

---

## 7. Verification Performed

1. **Static Rules Verification:**
   * Verified compliance with Google Cloud Firestore Rules v2 specification.
   * Confirmed rule combination logic: specific `read: if true;` combined with catch-all `read: if false;` evaluates to `true || false == true` (permitted), while writes evaluate to `false || false == false` (denied).
2. **C++ Engine Clean Build:**
   * Recompiled out-of-tree on Windows using GCC 15.2.0 (`MinGW Makefiles`, `Release` mode).
   * Verified binary executes cleanly and prints canonical version banner (`ROPWeaver v1.6.3 (Academic Research Edition | Build: 1.6.3)`).
3. **Cryptographic Artifact Verification:**
   * Verified all 4 standing protected artifacts match authoritative SHA-256 hashes bit-for-bit.

---

## 8. Documented Limitations

1. **Firebase Emulator Testing Not Executed:**
   * Automated assertions using the Firebase Local Emulator Suite were not executed locally because `firebase-tools` is not pre-installed in the offline sandbox environment.
2. **Production Deployment Not Performed:**
   * Rules have been prepared, audited, and accepted locally, but have **not** yet been deployed to the live Google Cloud Firebase project (`ropweaver`).
3. **Cloud Uploads Currently Unavailable:**
   * Under the public read-only rules, running the CLI with `--upload-report` will fail with HTTP 403. This is expected and intended for the v1.6.3 release.

---

## 9. Future Authenticated Upload Architecture Requirement

For a subsequent major release after v1.6.3:
* **Analyst Authentication:** Implement Firebase Authentication via Google Identity Toolkit REST API (`/v1/accounts:signInWithPassword`) in the C++ engine to obtain a verified ID token (`request.auth.uid`).
* **Role-Based Rules:** Transition Firestore rules to allow writes exclusively to authenticated analysts:
  ```javascript
  match /reports/{reportId} {
    allow read: if true;
    allow write: if request.auth != null;
  }
  ```
* **Alternative Ingestion:** Alternatively, implement an authorized serverless ingestion endpoint (Cloud Function) utilizing the Firebase Admin SDK to ingest and validate binary reports.

---

## 10. Acceptance Sign-Off

* **Acceptance Scope:**
  * `config/firestore.rules` (Updated)
  * `firebase.json` (Created)
  * `.firebaserc` (Created)
  * `main.cpp` (Updated)
  * `firebase/firebase_uploader.cpp` (Updated)
  * `docs/TASK_4.2_FIRESTORE_SECURITY_ACCEPTANCE_RECORD.md` (Created)
* **Verdict:** ACCEPTED LOCALLY WITH DOCUMENTED LIMITATIONS