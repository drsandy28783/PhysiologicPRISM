# 🧠 PHYSIOLOGIC PRISM – Clinical Reasoning App for Physiotherapists

**Version:** 1.0  
**Developer:** Sandeep Rao  
**Copyright:** Achieved 

---

## 📘 Description

**Physiologic PRISM** is a structured digital clinical reasoning tool developed for physiotherapists. The app streamlines patient assessment, documentation, and decision-making through a 12-stage clinical workflow. It supports both **individual** and **institutional** use with role-based login and access controls.

---

## 👥 User Roles

1. **Individual Physiotherapists**  
   - Independent use with private access to their own patients and data.

2. **Institute Admins**  
   - Create and manage institutes  
   - Approve or deactivate users  
   - Access and export institutional audit logs

3. **Institute Physiotherapists**  
   - Register under an institute (admin approval required)  
   - Manage only their assigned patients

---

## 🔐 Security Features

- Secure login system for all user types
- Password hashing using **Werkzeug**
- Admin ability to approve or deactivate users
- Role-based access control to ensure data segregation

---

## ✅ Core Features

- Patient addition with filtering by name or ID
- 12-stage structured clinical reasoning workflow:
  1. Subjective Examination  
  2. Patient Perspectives  
  3. Initial Plan of Assessment  
  4. Pathophysiological Mechanism  
  5. Chronic Disease Influences  
  6. Clinical Flags (Red, Yellow, etc.)  
  7. Objective Assessment  
  8. Provisional Diagnosis  
  9. SMART Goals  
  10. Treatment Plan  
  11. First Follow-Up  
  12. Multi-Session Follow-Up Logs  

- Follow-Up Tracking
  - First session as standalone
  - Ongoing sessions in a dynamic follow-up log

- PDF Report Generation using WeasyPrint
- Dropdowns and textareas based on custom-designed reasoning logic
- Downloadable and filtered audit logs

---

## 🔎 Audit Logging

- Logs include user logins, patient additions, edits, downloads, and follow-ups
- Logs are filterable by institute
- Admins can export logs in CSV format

---

## 🧱 Database Structure

Tables include:

- `users`  
- `patients`  
- `subjective_examination`  
- `patient_perspectives`  
- `initial_plan`  
- `patho_mechanism`  
- `chronic_diseases`  
- `clinical_flags`  
- `objective_assessment`  
- `provisional_diagnosis`  
- `smart_goals`  
- `treatment_plan`  
- `first_follow_up`  
- `follow_ups`  
- `audit_logs`

---

## 🔗 Flask Routes

| Area             | Route                          |
|------------------|--------------------------------|
| Authentication   | `/login`, `/register`          |
| Dashboard        | `/dashboard`                   |
| Patients         | `/add_patient`, `/view_patients`, `/edit_patient/<id>` |
| Follow-Ups       | `/follow_up_new/<id>`, `/view_follow_ups/<id>` |
| Reports          | `/patient_report/<id>`, `/download_report/<id>` |
| Audit Logs       | `/audit_logs`, `/export_audit_logs` |

---

## 🛠️ Hosting Environment

- **Development platform:** Replit (Python Flask)
- **Database:** Firebase Firestore
- **AI Integration:** Claude AI for context-aware suggestions (ongoing)

---

## 📈 Planned Enhancements

- ✅ Claude AI integration (in progress)
- ⏳ Progressive Web App via Bolt.new (React)
- ⏳ Mobile app version (Flutter/React Native)
- ⏳ Google Drive / OneDrive integration
- ⏳ Subscription-based SaaS model
- ⏳ Multi-language support

---

## 🧾 Licensing Notes

All logic, form structures, workflows, dropdown logic, user role flows, and audit trail mechanisms are **original intellectual property** of the developer and have been designed for educational and clinical use in physiotherapy.  

© 2025 Sandeep Rao – All Rights Reserved.  
Unauthorized distribution or reuse without permission is prohibited.

