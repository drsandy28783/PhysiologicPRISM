Title: PHYSIOLOGIC PRISM – Clinical Reasoning App for Physiotherapists
Version: 1.0
Developer: Sandeep Rao
Copyright Status: Application Submitted

Description:
Physiologic PRISM is a digital tool designed for physiotherapists to manage patients, apply clinical reasoning, and document progress using structured forms and dropdown-based logic. The app supports both individual users and institutional use with admin oversight.

User Roles:
1. Individual Physiotherapists - practice independently with full access to their own patients and data.
2. Institute Admins - create and manage an institute, approve physiotherapist registrations, and view institutional audit logs.
3. Institute Physiotherapists - register under an institute, require admin approval, and can manage only their assigned patients.

Security:
- Login system for all users
- Password hashing with Werkzeug
- Admins can deactivate users
- Route-based access restrictions in place

Features:
- Patient addition and filtering by name or ID
- 12-stage structured clinical reasoning workflow for each patient:
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
- Patient detail view
- PDF report generation from patient data
- Follow-up tracking (first session and multiple subsequent sessions)
- Dropdowns and textareas based on structured reasoning fields
- Downloadable audit logs
- Filtered views for patient lists and audit reports

Follow-Up Logic:
- First Follow-Up is recorded as a standalone form
- Ongoing follow-ups are stored in a separate table and logged session by session
- Follow-up log includes session number, date, achievement grade, patient feedback, and planned treatment

Audit Logging:
- Tracks logins, patient additions, report downloads, and other actions
- Admins can download audit logs as CSV
- Institute Admins only see logs of users within their institute

Database Tables:
- users
- patients
- subjective_examination
- patient_perspectives
- initial_plan
- patho_mechanism
- chronic_diseases
- clinical_flags
- objective_assessment
- provisional_diagnosis
- smart_goals
- treatment_plan
- first_follow_up
- follow_ups
- audit_logs

Routes:
- Authentication: /login, /register
- Dashboard: /dashboard
- Patient Management: /add_patient, /edit_patient/<id>, /view_patients
- Follow-Up: /follow_up_new/<id>, /view_follow_ups/<id>
- Reports: /patient_report/<id>, /download_report/<id>
- Audit Logs: /audit_logs, /export_audit_logs

Hosting Environment:
- Developed and tested on Replit (Python Flask)
- SQLite as the database engine

Planned Enhancements:
- Mobile App version
- Google Drive / OneDrive integration
- AI-assisted diagnosis support
- Subscription-tier SaaS platform
- Multi-language support

Notes:
All logic, form structure, flow, dropdown logic, user roles, and audit trail mechanisms have been custom-designed by the developer for educational and clinical use in physiotherapy practice.
