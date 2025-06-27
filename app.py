import os
from flask import Flask, render_template, request, redirect, session, url_for, make_response, jsonify
import io, csv
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_init import firebase_admin  # uses your existing setup
from firebase_admin import firestore
db = firestore.client()
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
import anthropic

def log_action(user_id, action, details=None):
    db.collection('audit_logs').add({
        'user_id': user_id,
        'action': action,
        'details': details,
        'timestamp': firestore.SERVER_TIMESTAMP
    })

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_default')
CORS(app)  # Enable CORS for mobile app
claude_client = anthropic.Anthropic(api_key=os.environ.get('CLAUDE_API_KEY'))


def login_required(approved_only=True):
    def wrapper(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                return redirect('/login')
            if approved_only and session.get('is_admin') != 1 and session.get('approved') == 0:
                return "Access denied. Awaiting approval by admin."
            return f(*args, **kwargs)
        return decorated_function
    return wrapper

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])
        institute = None
        is_admin = 0
        approved = 1
        active = 1  # New users are active by default

        # Check if email or phone exists
        existing = db.collection('users') \
                     .where('email', '==', email) \
                     .stream()
        existing_phone = db.collection('users') \
                           .where('phone', '==', phone) \
                           .stream()

        if any(existing) or any(existing_phone):
            return "Email or phone number already registered."

        user_data = {
            'name': name,
            'email': email,
            'password': password,
            'phone': phone,
            'is_admin': is_admin,
            'institute': institute,
            'approved': approved,
            'active': active
        }

        user_ref = db.collection('users').add(user_data)
        log_action(user_id=None, action="Register", details=f"{name} registered as Individual Physio")

        return redirect('/login')

    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        users = db.collection('users').where('email', '==', email).stream()
        user_doc = next(users, None)

        if not user_doc:
            return "Invalid login credentials."

        user = user_doc.to_dict()
        user['id'] = user_doc.id  # Store document ID

        if check_password_hash(user['password'], password_input):
            if user.get('approved') == 1 and user.get('active') == 1:
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['institute'] = user.get('institute')
                session['is_admin'] = user['is_admin']
                session['approved'] = user['approved']
                log_action(user['id'], "Login", f"{user['name']} logged in.")
                return redirect('/dashboard')
            elif user.get('active') == 0:
                return "Your account has been deactivated. Contact your admin."
            else:
                return "Your registration is pending admin approval."
        else:
            return "Invalid login credentials."

    return render_template('login.html')



@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

@app.route('/dashboard')
@login_required()
def dashboard():
    return render_template('dashboard.html', name=session['user_name'])

@app.route('/admin_dashboard')
@login_required()
def admin_dashboard():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/login_institute')

    # Fetch pending users from the same institute
    users = db.collection('users') \
              .where('is_admin', '==', 0) \
              .where('approved', '==', 0) \
              .where('institute', '==', session['institute']) \
              .stream()

    pending_physios = [dict(user.to_dict(), id=user.id) for user in users]

    return render_template(
        'admin_dashboard.html',
        pending_physios=pending_physios,
        name=session['user_name'],
        institute=session['institute']
    )

@app.route('/dashboard_data', methods=['POST'])
def dashboard_data():
    data = request.get_json()
    user_id = data.get('user_id')

    if not user_id:
        return jsonify({"error": "user_id required"}), 400

    user_doc = db.collection('users').document(user_id).get()

    if not user_doc.exists:
        return jsonify({"error": "User not found"}), 404

    user = user_doc.to_dict()
    name = user.get('name')
    is_admin = user.get('is_admin', 0)

    patients = db.collection('patients').where('physio_id', '==', user_id).stream()
    patient_list = [p.to_dict() for p in patients]

    return jsonify({
        "name": name,
        "is_admin": is_admin,
        "patients": patient_list
    })



@app.route('/view_patients')
@login_required()
def view_patients():
    query = db.collection('patients')
    
    name_filter = request.args.get('name')
    id_filter = request.args.get('patient_id')

    # Filter for admin or individual physio
    if session.get('is_admin') == 1:
        # Admin: only see patients from same institute
        physios = db.collection('users') \
                    .where('institute', '==', session['institute']) \
                    .stream()
        physio_ids = [p.id for p in physios]
        patients = []
        for pid in physio_ids:
            patients += [p for p in query.where('physio_id', '==', pid).stream()]
    else:
        # Regular physio: see their own patients
        patients = query.where('physio_id', '==', session['user_id']).stream()

    # Apply filters in-memory
    results = []
    for p in patients:
        data = p.to_dict()
        data['id'] = p.id
        if name_filter and name_filter.lower() not in data.get('name', '').lower():
            continue
        if id_filter and id_filter.lower() not in data.get('patient_id', '').lower():
            continue
        results.append(data)

    return render_template('view_patients.html', patients=results)

@app.route('/register_institute', methods=['GET', 'POST'])
def register_institute():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])
        institute = request.form['institute']
        is_admin = 1
        approved = 1
        active = 1

        # Check for duplicate email or phone
        existing = db.collection('users').where('email', '==', email).stream()
        existing_phone = db.collection('users').where('phone', '==', phone).stream()

        if any(existing) or any(existing_phone):
            return "Email or phone number already registered."

        db.collection('users').add({
            'name': name,
            'email': email,
            'phone': phone,
            'password': password,
            'institute': institute,
            'is_admin': is_admin,
            'approved': approved,
            'active': active
        })

        log_action(user_id=None, action="Register", details=f"{name} registered as Institute Admin")
        return redirect('/login_institute')

    return render_template('register_institute.html')

@app.route('/login_institute', methods=['GET', 'POST'])
def login_institute():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        users = db.collection('users').where('email', '==', email).stream()
        user_doc = next(users, None)

        if not user_doc:
            return "Invalid credentials or account doesn't exist."

        user = user_doc.to_dict()
        user['id'] = user_doc.id

        if not check_password_hash(user['password'], password_input):
            return "Invalid credentials or account doesn't exist."

        if user.get('approved') == 0:
            return "Your account is pending approval by the institute admin."

        if user.get('active') == 0:
            return "Your account has been deactivated. Please contact your admin."

        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['institute'] = user.get('institute')
        session['is_admin'] = user['is_admin']
        session['approved'] = user['approved']

        log_action(user['id'], "Login", f"{user['name']} (Admin: {user['is_admin']}) logged in.")

        return redirect('/admin_dashboard' if user['is_admin'] == 1 else '/dashboard')

    return render_template('login_institute.html')



@app.route('/approve_physios')
@login_required()
def approve_physios():
    if session.get('is_admin') != 1:
        return redirect('/login_institute')

    users = db.collection('users') \
              .where('is_admin', '==', 0) \
              .where('approved', '==', 0) \
              .where('institute', '==', session['institute']) \
              .stream()

    physios = [dict(u.to_dict(), id=u.id) for u in users]

    return render_template('approve_physios.html', physios=physios)

@app.route('/audit_logs')
@login_required()
def audit_logs():
    logs = []

    if session.get('is_admin') == 1:
        # Admin: fetch logs for all users in their institute
        users = db.collection('users') \
                  .where('institute', '==', session['institute']) \
                  .stream()
        user_map = {u.id: u.to_dict() for u in users}
        user_ids = list(user_map.keys())

        for uid in user_ids:
            entries = db.collection('audit_logs').where('user_id', '==', uid).stream()
            for e in entries:
                data = e.to_dict()
                data['name'] = user_map[uid]['name']
                logs.append(data)

    elif session.get('is_admin') == 0:
        # Individual physio: only their logs
        entries = db.collection('audit_logs').where('user_id', '==', session['user_id']).stream()
        for e in entries:
            data = e.to_dict()
            data['name'] = session['user_name']
            logs.append(data)

    # Sort by timestamp descending
    logs.sort(key=lambda x: x.get('timestamp', 0), reverse=True)

    return render_template('audit_logs.html', logs=logs)

@app.route('/export_audit_logs')
@login_required()
def export_audit_logs():
    if session.get('is_admin') != 1:
        return redirect('/login_institute')

    users = db.collection('users') \
              .where('institute', '==', session['institute']) \
              .stream()
    user_map = {u.id: u.to_dict() for u in users}
    user_ids = list(user_map.keys())

    logs = []
    for uid in user_ids:
        entries = db.collection('audit_logs').where('user_id', '==', uid).stream()
        for e in entries:
            log = e.to_dict()
            logs.append([
                user_map[uid]['name'],
                log.get('action', ''),
                log.get('details', ''),
                log.get('timestamp', '')
            ])

    # Prepare CSV
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['User', 'Action', 'Details', 'Timestamp'])
    writer.writerows(logs)

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response


@app.route('/reject_user/<user_id>')
@login_required()
def reject_user(user_id):
    if session.get('is_admin') != 1:
        return "Unauthorized", 403

    # Check the user document
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return "User not found", 404

    user_data = user_doc.to_dict()
    if user_data.get('approved') == 0:
        user_ref.delete()
        log_action(
            user_id=session['user_id'],
            action="Reject User",
            details=f"Rejected user {user_data.get('name')} (Email: {user_data.get('email')})"
        )

    return redirect('/approve_physios')

@app.route('/register_with_institute', methods=['GET', 'POST'])
def register_with_institute():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])
        institute = request.form['institute']
        is_admin = 0
        approved = 0
        active = 1

        # Check if user already exists
        existing_email = db.collection('users').where('email', '==', email).stream()
        existing_phone = db.collection('users').where('phone', '==', phone).stream()

        if any(existing_email) or any(existing_phone):
            return "Email or phone number already registered."

        # Register new user under selected institute
        db.collection('users').add({
            'name': name,
            'email': email,
            'phone': phone,
            'password': password,
            'institute': institute,
            'is_admin': is_admin,
            'approved': approved,
            'active': active
        })

        log_action(user_id=None, action="Register", details=f"{name} registered as Institute Physio (pending approval)")

        return "Registration successful! Awaiting admin approval."

    # GET method: show list of institutes (unique from admin users)
    admins = db.collection('users').where('is_admin', '==', 1).stream()
    institutes = list({admin.to_dict().get('institute') for admin in admins})

    return render_template('register_with_institute.html', institutes=institutes)

@app.route('/approve_user/<user_id>')
@login_required()
def approve_user(user_id):
    if session.get('is_admin') != 1:
        return redirect('/login_institute')

    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return "User not found", 404

    user = user_doc.to_dict()

    # Approve the user
    user_ref.update({'approved': 1})

    # Log the action
    log_action(
        user_id=session['user_id'],
        action="Approve User",
        details=f"Approved user {user.get('name')} (Email: {user.get('email')})"
    )

    return redirect('/approve_physios')

@app.route('/manage_users')
@login_required()
def manage_users():
    if session.get('is_admin') != 1:
        return "Access Denied: Admins only."

    users = db.collection('users') \
              .where('is_admin', '==', 0) \
              .where('approved', '==', 1) \
              .where('institute', '==', session['institute']) \
              .stream()

    user_list = [dict(u.to_dict(), id=u.id) for u in users]

    return render_template('manage_users.html', users=user_list)

@app.route('/deactivate_user/<user_id>')
@login_required()
def deactivate_user(user_id):
    if session.get('is_admin') != 1:
        return "Access Denied"

    db.collection('users').document(user_id).update({'active': 0})

    log_action(
        user_id=session['user_id'],
        action="Deactivate User",
        details=f"User ID {user_id} was deactivated"
    )

    return redirect('/manage_users')

@app.route('/reactivate_user/<user_id>')
@login_required()
def reactivate_user(user_id):
    if session.get('is_admin') != 1:
        return "Access Denied"

    db.collection('users').document(user_id).update({'active': 1})

    log_action(
        user_id=session['user_id'],
        action="Reactivate User",
        details=f"User ID {user_id} was reactivated"
    )

    return redirect('/manage_users')


# Patient Data Entry Routes (clinical reasoning flow)
@app.route('/add_patient', methods=['GET', 'POST'])
@login_required()
def add_patient():
    if request.method == 'POST':
        name = request.form['name']
        age_sex = request.form['age_sex']
        contact = request.form['contact']
        present_history = request.form['present_history']
        past_history = request.form['past_history']

        # Scan all patient_ids and get max PAT-nnn
        patients = db.collection('patients').stream()
        max_id = 0
        for p in patients:
            data = p.to_dict()
            pid = data.get('patient_id', '')
            if pid.startswith('PAT-'):
                try:
                    num = int(pid.split('-')[1])
                    max_id = max(max_id, num)
                except:
                    pass

        new_id = f"PAT-{max_id + 1:03d}"

        db.collection('patients').add({
            'physio_id': session['user_id'],
            'patient_id': new_id,
            'name': name,
            'age_sex': age_sex,
            'contact': contact,
            'present_history': present_history,
            'past_history': past_history
        })

        log_action(
            user_id=session['user_id'],
            action="Add Patient",
            details=f"Added patient {name} (ID: {new_id})"
        )

        return redirect(f'/subjective/{new_id}')

    return render_template('add_patient.html')



@app.route('/subjective/<patient_id>', methods=['GET', 'POST'])
@login_required()
def subjective(patient_id):
    # 🔍 Find patient by patient_id field
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    physio_id = patient.get('physio_id')

    if session.get('is_admin') == 0 and physio_id != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'body_structure': request.form['body_structure'],
            'body_function': request.form['body_function'],
            'activity_performance': request.form['activity_performance'],
            'activity_capacity': request.form['activity_capacity'],
            'contextual_environmental': request.form['contextual_environmental'],
            'contextual_personal': request.form['contextual_personal']
        }

        db.collection('subjective_examination').add(data)

        return redirect(f'/perspectives/{patient_id}')

    return render_template('subjective.html', patient_id=patient_id)


@app.route('/perspectives/<patient_id>', methods=['GET', 'POST'])
@login_required()
def perspectives(patient_id):
    # Fetch patient by ID
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'knowledge': request.form['knowledge'],
            'attribution': request.form['attribution'],
            'illness_duration': request.form['illness_duration'],
            'consequences_awareness': request.form['consequences_awareness'],
            'locus_of_control': request.form['locus_of_control'],
            'affective_aspect': request.form['affective_aspect']
        }

        db.collection('patient_perspectives').add(data)

        return redirect(f'/initial_plan/{patient_id}')

    return render_template('perspectives.html', patient_id=patient_id)


@app.route('/initial_plan/<patient_id>', methods=['GET', 'POST'])
@login_required()
def initial_plan(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        fields = [
            'active_movements',
            'passive_movements',
            'passive_over_pressure',
            'resisted_movements',
            'combined_movements',
            'special_tests',
            'neuro_dynamic_examination'
        ]

        data = {'patient_id': patient_id}
        for field in fields:
            data[field] = request.form.get(field)
            data[field + '_details'] = request.form.get(field + '_details', '')

        db.collection('initial_plan').add(data)

        return redirect(f'/patho_mechanism/{patient_id}')

    return render_template('initial_plan.html', patient_id=patient_id)


@app.route('/patho_mechanism/<patient_id>', methods=['GET', 'POST'])
@login_required()
def patho_mechanism(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'area_involved': request.form['area_involved'],
            'presenting_symptom': request.form['presenting_symptom'],
            'pain_type': request.form['pain_type'],
            'pain_nature': request.form['pain_nature'],
            'pain_severity': request.form['pain_severity'],
            'pain_irritability': request.form['pain_irritability'],
            'symptom_source': request.form['symptom_source'],
            'tissue_healing_stage': request.form['tissue_healing_stage']
        }

        db.collection('patho_mechanism').add(data)

        return redirect(f'/chronic_disease/{patient_id}')

    return render_template('patho_mechanism.html', patient_id=patient_id)


@app.route('/chronic_disease/<patient_id>', methods=['GET', 'POST'])
@login_required()
def chronic_disease(patient_id):
    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'cause': request.form['cause'],
            'cause_detail': request.form.get('cause_detail', '')
        }

        db.collection('chronic_diseases').add(data)

        return redirect(f'/clinical_flags/{patient_id}')

    return render_template('chronic_disease.html', patient_id=patient_id)


@app.route('/clinical_flags/<patient_id>', methods=['GET', 'POST'])
@login_required()
def clinical_flags(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'red_flag': request.form['red_flag'],
            'orange_flag': request.form['orange_flag'],
            'yellow_flag': request.form['yellow_flag'],
            'black_flag': request.form['black_flag'],
            'blue_flag': request.form['blue_flag']
        }

        db.collection('clinical_flags').add(data)

        return redirect(f'/objective_assessment/{patient_id}')

    return render_template('clinical_flags.html', patient_id=patient_id)


@app.route('/objective_assessment/<patient_id>', methods=['GET', 'POST'])
@login_required()
def objective_assessment(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'plan': request.form['plan'],
            'plan_details': request.form.get('plan_details', '')
        }

        db.collection('objective_assessment').add(data)

        return redirect(f'/provisional_diagnosis/{patient_id}')

    return render_template('objective_assessment.html', patient_id=patient_id)


@app.route('/provisional_diagnosis/<patient_id>', methods=['GET', 'POST'])
@login_required()
def provisional_diagnosis(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'likelihood': request.form['likelihood'],
            'structure_fault': request.form['structure_fault'],
            'symptom': request.form['symptom'],
            'findings_support': request.form['findings_support'],
            'findings_reject': request.form['findings_reject'],
            'hypothesis_supported': request.form['hypothesis_supported']
        }

        db.collection('provisional_diagnosis').add(data)

        return redirect(f'/smart_goals/{patient_id}')

    return render_template('provisional_diagnosis.html', patient_id=patient_id)


@app.route('/smart_goals/<patient_id>', methods=['GET', 'POST'])
@login_required()
def smart_goals(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'patient_goal': request.form['patient_goal'],
            'baseline_status': request.form['baseline_status'],
            'measurable_outcome': request.form['measurable_outcome'],
            'time_duration': request.form['time_duration']
        }

        db.collection('smart_goals').add(data)

        return redirect(f'/treatment_plan/{patient_id}')

    return render_template('smart_goals.html', patient_id=patient_id)



@app.route('/treatment_plan/<patient_id>', methods=['GET', 'POST'])
@login_required()
def treatment_plan(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'treatment_plan': request.form['treatment_plan'],
            'goal_targeted': request.form['goal_targeted'],
            'reasoning': request.form['reasoning'],
            'reference': request.form['reference']
        }

        db.collection('treatment_plan').add(data)

        return redirect('/dashboard')

    return render_template('treatment_plan.html', patient_id=patient_id)



@app.route('/follow_up_new/<patient_id>', methods=['GET', 'POST'])
@login_required()
def follow_up_new(patient_id):
    # Fetch patient
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        data = {
            'patient_id': patient_id,
            'session_number': request.form['session_number'],
            'session_date': request.form['session_date'],
            'grade': request.form['grade'],
            'belief_treatment': request.form['belief_treatment'],
            'belief_feedback': request.form['belief_feedback'],
            'treatment_plan': request.form['treatment_plan']
        }

        db.collection('follow_ups').add(data)

        return redirect(f'/view_follow_ups/{patient_id}')

    return render_template('follow_up_new.html', patient_id=patient_id)

@app.route('/view_follow_ups/<patient_id>')
@login_required()
def view_follow_ups(patient_id):
        patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
        patient_doc = next(patients, None)

        if not patient_doc:
            return "Patient not found."

        patient = patient_doc.to_dict()
        if session.get('is_admin') == 0 and patient.get('physio_id') != session['user_id']:
            return "Access denied."

        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.DESCENDING) \
                      .stream()

        followup_list = [f.to_dict() for f in followups]

        return render_template('view_follow_ups.html', patient_id=patient_id, followups=followup_list)

    

@app.route('/patient_report/<patient_id>')
@login_required()
def patient_report(patient_id):
    # Fetch patient
    patient_docs = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patient_docs, None)

    if not patient_doc:
        return "Patient not found."

    patient = patient_doc.to_dict()
    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        return "Access denied."

    def fetch_one(collection):
        docs = db.collection(collection).where('patient_id', '==', patient_id).stream()
        for d in docs:
            return d.to_dict()
        return None

    return render_template(
        'patient_report.html',
        patient=patient,
        subjective=fetch_one('subjective_examination'),
        perspectives=fetch_one('patient_perspectives'),
        diagnosis=fetch_one('provisional_diagnosis'),
        goals=fetch_one('smart_goals'),
        treatment=fetch_one('treatment_plan')
    )


@app.route('/download_report/<patient_id>')
@login_required()
def download_report(patient_id):
        # Fetch patient and clinical data
        patient_docs = db.collection('patients').where('patient_id', '==', patient_id).stream()
        patient_doc = next(patient_docs, None)

        if not patient_doc:
            return "Patient not found."

        patient = patient_doc.to_dict()
        if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
            return "Access denied."

        def fetch_one(collection):
            docs = db.collection(collection).where('patient_id', '==', patient_id).stream()
            for d in docs:
                return d.to_dict()
            return None

        rendered = render_template(
            'patient_report.html',
            patient=patient,
            subjective=fetch_one('subjective_examination'),
            perspectives=fetch_one('patient_perspectives'),
            diagnosis=fetch_one('provisional_diagnosis'),
            goals=fetch_one('smart_goals'),
            treatment=fetch_one('treatment_plan')
        )

        from weasyprint import HTML
        pdf = HTML(string=rendered).write_pdf()

        log_action(
            user_id=session['user_id'],
            action="Download Report",
            details=f"Downloaded PDF report for patient {patient_id}"
        )

        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename={patient_id}_report.pdf'
        return response

   



@app.route('/edit_patient/<patient_id>', methods=['GET', 'POST'])
@login_required()
def edit_patient(patient_id):
    # Fetch patient doc
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)

    if not patient_doc:
        return "Patient not found."

    doc_id = patient_doc.id
    patient = patient_doc.to_dict()

    if session.get('is_admin') != 1 and patient['physio_id'] != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        name = request.form['name']
        age_sex = request.form['age_sex']
        contact = request.form['contact']

        db.collection('patients').document(doc_id).update({
            'name': name,
            'age_sex': age_sex,
            'contact': contact
        })

        log_action(
            user_id=session['user_id'],
            action="Edit Patient",
            details=f"Edited patient {patient_id}"
        )

        return redirect('/view_patients')

    return render_template('edit_patient.html', patient=patient)

# Mobile API Endpoints - ADD THIS ENTIRE SECTION

# JWT Token Generation
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    
    users = db.collection('users').where('email', '==', email).stream()
    user_doc = next(users, None)
    
    if not user_doc:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    user = user_doc.to_dict()
    user['id'] = user_doc.id
    
    if not check_password_hash(user['password'], password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if user.get('approved') != 1 or user.get('active') != 1:
        return jsonify({'error': 'Account not approved or deactivated'}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'user_id': user['id'],
        'exp': datetime.utcnow() + timedelta(days=30)
    }, app.secret_key, algorithm='HS256')
    
    log_action(user['id'], "Mobile Login", f"{user['name']} logged in via mobile")
    
    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'name': user['name'],
            'email': user['email'],
            'is_admin': user['is_admin'],
            'institute': user.get('institute')
        }
    })

# Mobile Authentication Decorator
def mobile_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'No token provided'}), 401
        
        try:
            if token.startswith('Bearer '):
                token = token[7:]
            data = jwt.decode(token, app.secret_key, algorithms=['HS256'])
            request.user_id = data['user_id']
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

# Test API endpoint
@app.route('/api/test', methods=['GET'])
def api_test():
    return jsonify({'message': 'API is working!', 'timestamp': datetime.utcnow().isoformat()})

# Patient API Endpoints
@app.route('/api/patients', methods=['GET'])
@mobile_auth_required
def api_get_patients():
    user_doc = db.collection('users').document(request.user_id).get()
    user = user_doc.to_dict()
    
    if user.get('is_admin') == 1:
        physios = db.collection('users').where('institute', '==', user['institute']).stream()
        physio_ids = [p.id for p in physios]
        patients = []
        for pid in physio_ids:
            patients.extend(db.collection('patients').where('physio_id', '==', pid).stream())
    else:
        patients = db.collection('patients').where('physio_id', '==', request.user_id).stream()
    
    patient_list = []
    for p in patients:
        data = p.to_dict()
        data['id'] = p.id
        patient_list.append(data)
    
    return jsonify({'patients': patient_list})

# AI Test Endpoint
@app.route('/api/ai/test', methods=['POST'])
@mobile_auth_required
def api_test_ai():
    try:
        if claude_client is None:
            return jsonify({'ai_response': 'AI temporarily disabled - will enable after successful deployment'})
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=100,
            messages=[{"role": "user", "content": "Say 'AI is working for PhysiologicPRISM!'"}]
        )
        return jsonify({'ai_response': response.content[0].text})
    except Exception as e:
        return jsonify({'error': f'AI service error: {str(e)}'}), 500

# Add Patient API
@app.route('/api/patients', methods=['POST'])
@mobile_auth_required
def api_add_patient():
    try:
        data = request.get_json()
        
        # Generate patient ID (same logic as web app)
        patients = db.collection('patients').stream()
        max_id = 0
        for p in patients:
            pid = p.to_dict().get('patient_id', '')
            if pid.startswith('PAT-'):
                try:
                    num = int(pid.split('-')[1])
                    max_id = max(max_id, num)
                except:
                    pass
        
        new_id = f"PAT-{max_id + 1:03d}"
        
        patient_data = {
            'physio_id': request.user_id,
            'patient_id': new_id,
            'name': data.get('name', ''),
            'age_sex': data.get('age_sex', ''),
            'contact': data.get('contact', ''),
            'present_history': data.get('present_history', ''),
            'past_history': data.get('past_history', '')
        }
        
        db.collection('patients').add(patient_data)
        
        log_action(request.user_id, "Add Patient (Mobile)", f"Added patient {data.get('name')} (ID: {new_id})")
        
        return jsonify({'success': True, 'patient_id': new_id, 'message': 'Patient added successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Clinical Forms API - Generic endpoint for all 12 stages
@app.route('/api/clinical-form/<form_type>/<patient_id>', methods=['POST'])
@mobile_auth_required
def api_save_clinical_form(form_type, patient_id):
    try:
        data = request.get_json()
        data['patient_id'] = patient_id
        
        # Map form types to collections (same as your web app)
        collection_map = {
            'subjective': 'subjective_examination',
            'perspectives': 'patient_perspectives', 
            'initial_plan': 'initial_plan',
            'patho_mechanism': 'patho_mechanism',
            'chronic_disease': 'chronic_diseases',
            'clinical_flags': 'clinical_flags',
            'objective': 'objective_assessment',
            'diagnosis': 'provisional_diagnosis',
            'goals': 'smart_goals',
            'treatment': 'treatment_plan',
            'follow_up': 'follow_ups'
        }
        
        collection_name = collection_map.get(form_type)
        if not collection_name:
            return jsonify({'error': 'Invalid form type'}), 400
        
        # Save to Firebase
        db.collection(collection_name).add(data)
        
        log_action(request.user_id, f"Save {form_type} (Mobile)", f"Saved {form_type} for patient {patient_id}")
        
        return jsonify({'success': True, 'message': f'{form_type} saved successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Get Clinical Form Data
@app.route('/api/clinical-form/<form_type>/<patient_id>', methods=['GET'])
@mobile_auth_required
def api_get_clinical_form(form_type, patient_id):
    try:
        collection_map = {
            'subjective': 'subjective_examination',
            'perspectives': 'patient_perspectives',
            'initial_plan': 'initial_plan',
            'patho_mechanism': 'patho_mechanism',
            'chronic_disease': 'chronic_diseases',
            'clinical_flags': 'clinical_flags',
            'objective': 'objective_assessment',
            'diagnosis': 'provisional_diagnosis',
            'goals': 'smart_goals',
            'treatment': 'treatment_plan',
            'follow_up': 'follow_ups'
        }
        
        collection_name = collection_map.get(form_type)
        if not collection_name:
            return jsonify({'error': 'Invalid form type'}), 400
        
        # Get form data from Firebase
        docs = db.collection(collection_name).where('patient_id', '==', patient_id).stream()
        form_data = None
        for doc in docs:
            form_data = doc.to_dict()
            break
        
        return jsonify({'success': True, 'data': form_data})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# AI Clinical Assistant
@app.route('/api/ai/clinical-assistant', methods=['POST'])
@mobile_auth_required
def ai_clinical_assistant():
    try:
        data = request.get_json()
        prompt = data.get('prompt')
        context = data.get('context', {})
        
        # Build comprehensive prompt for Claude
        system_prompt = f"""You are an expert physiotherapy clinical assistant. 
        Patient context: {context}
        Provide professional, evidence-based responses for: {prompt}
        Keep responses concise and clinically relevant."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=500,
            messages=[{"role": "user", "content": system_prompt}]
        )
        
        return jsonify({
            'success': True, 
            'ai_response': response.content[0].text
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Simple AI Test
@app.route('/api/ai/test-simple', methods=['GET'])
def test_ai_simple():
    try:
        if claude_client is None:
            return jsonify({'error': 'Claude client not initialized'})
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=50,
            messages=[{"role": "user", "content": "Say hello"}]
        )
        
        return jsonify({
            'success': True,
            'ai_response': response.content[0].text
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# PRIVACY-COMPLIANT AI ENDPOINTS
# NO patient data is sent to Claude - only generic clinical guidance requests

# Generic ICF Guidance (No Patient Data)
@app.route('/api/ai/icf-guidance', methods=['POST'])
@mobile_auth_required
def api_icf_guidance():
    try:
        data = request.get_json()
        field_type = data.get('field_type')  # Only the ICF domain type
        # NO patient data sent to Claude
        
        # Pre-defined ICF guidance prompts (no patient data)
        icf_prompts = {
            'body_structure': """Provide expert physiotherapy guidance for ICF Body Structure assessment.
            
            List 5-6 key areas to assess and document:
            - Focus on anatomical structures and impairments
            - Use professional ICF terminology
            - Include specific examination techniques
            - Provide documentation examples
            
            Format as numbered list with brief explanations.""",
            
            'body_function': """Provide expert physiotherapy guidance for ICF Body Function assessment.
            
            List 5-6 key functional areas to assess:
            - Focus on physiological and psychological functions
            - Include range of motion, strength, pain, sensation
            - Use standardized assessment methods
            - Provide measurement guidelines
            
            Format as numbered list with brief explanations.""",
            
            'activity_performance': """Provide expert physiotherapy guidance for ICF Activity Performance assessment.
            
            List 5-6 key areas to evaluate:
            - Focus on what patients actually do in real life
            - Include daily activities and participation
            - Consider environmental factors affecting performance
            - Provide assessment techniques
            
            Format as numbered list with brief explanations.""",
            
            'activity_capacity': """Provide expert physiotherapy guidance for ICF Activity Capacity assessment.
            
            List 5-6 key areas to evaluate:
            - Focus on maximum potential in standardized conditions
            - Include standardized testing approaches
            - Consider capacity vs performance differences
            - Provide measurement guidelines
            
            Format as numbered list with brief explanations.""",
            
            'contextual_environmental': """Provide expert physiotherapy guidance for ICF Environmental Factors assessment.
            
            List 5-6 key environmental areas to assess:
            - Focus on external barriers and facilitators
            - Include physical, social, and attitudinal environment
            - Consider assistive technology and accessibility
            - Provide assessment strategies
            
            Format as numbered list with brief explanations.""",
            
            'contextual_personal': """Provide expert physiotherapy guidance for ICF Personal Factors assessment.
            
            List 5-6 key personal characteristics to consider:
            - Focus on individual attributes affecting function
            - Include lifestyle, coping strategies, motivation
            - Consider cultural and educational background
            - Provide assessment approaches
            
            Format as numbered list with brief explanations."""
        }
        
        prompt = icf_prompts.get(field_type)
        
        if not prompt:
            return jsonify({'error': 'Invalid field type'}), 400
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'guidance': response.content[0].text,
            'field_type': field_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Generic Clinical Reasoning Prompts (No Patient Data)
@app.route('/api/ai/clinical-prompts', methods=['POST'])
@mobile_auth_required
def api_clinical_prompts():
    try:
        data = request.get_json()
        completed_domains = data.get('completed_domains', [])  # Only domain names, no content
        
        # Generic prompt based only on which domains are completed
        domains_text = ", ".join(completed_domains) if completed_domains else "none"
        
        prompt = f"""You are an expert physiotherapist providing generic clinical reasoning guidance for ICF subjective examination.

        Completed ICF domains so far: {domains_text}
        
        Provide 5-6 generic clinical reasoning questions that would help complete a comprehensive subjective examination:
        1. Focus on exploring relationships between ICF domains
        2. Include questions about functional limitations
        3. Consider patient perspectives and goals
        4. Address potential red flags to screen for
        5. Include contextual factors to explore
        
        Provide general clinical reasoning questions that would apply to most musculoskeletal conditions.
        Format as numbered list with brief rationale for each question."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'prompts': response.content[0].text
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Local Red Flag Detection (No Data Sent to Claude)
@app.route('/api/ai/red-flag-check', methods=['POST'])
@mobile_auth_required
def api_red_flag_check():
    try:
        data = request.get_json()
        text_content = data.get('text_content', '').lower()
        
        # LOCAL red flag detection - no data sent to Claude
        red_flag_keywords = {
            'neurological': [
                'cauda equina', 'saddle numbness', 'bowel incontinence', 'bladder incontinence',
                'progressive weakness', 'foot drop', 'bilateral symptoms', 'gait disturbance'
            ],
            'cancer': [
                'night pain', 'constant pain', 'unexplained weight loss', 'previous cancer',
                'cancer history', 'bone pain', 'systemic symptoms', 'age over 50'
            ],
            'infection': [
                'fever', 'systemically unwell', 'hot swollen joint', 'recent infection',
                'immunocompromised', 'iv drug use', 'recent surgery'
            ],
            'fracture': [
                'significant trauma', 'minor trauma age', 'osteoporosis', 'steroid use',
                'unable to weight bear', 'deformity', 'recent fall'
            ],
            'vascular': [
                'claudication', 'cold limb', 'absent pulse', 'color change',
                'acute onset', 'severe pain rest'
            ]
        }
        
        detected_flags = []
        for category, keywords in red_flag_keywords.items():
            found_keywords = [kw for kw in keywords if kw in text_content]
            if found_keywords:
                detected_flags.append({
                    'category': category,
                    'keywords': found_keywords
                })
        
        has_red_flags = len(detected_flags) > 0
        
        if has_red_flags:
            analysis = "Red flags detected:\n\n"
            for flag in detected_flags:
                analysis += f"• {flag['category'].title()}: {', '.join(flag['keywords'])}\n"
            analysis += "\nRecommendation: Consider immediate medical review."
        else:
            analysis = "No immediate red flags identified in current assessment."
        
        return jsonify({
            'success': True,
            'has_red_flags': has_red_flags,
            'analysis': analysis,
            'detected_categories': [f['category'] for f in detected_flags]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Generic Text Enhancement (De-identified)
@app.route('/api/ai/enhance-text', methods=['POST'])
@mobile_auth_required
def api_enhance_text():
    try:
        data = request.get_json()
        text_content = data.get('text_content', '')
        field_type = data.get('field_type', '')
        
        # Remove any potential identifiers before sending
        # Basic de-identification (you may want to enhance this)
        import re
        
        # Remove potential patient identifiers
        deidentified_text = re.sub(r'\b(patient|pt|mr|mrs|ms)\s+[a-z]+\b', '[patient]', text_content, flags=re.IGNORECASE)
        deidentified_text = re.sub(r'\b\d{1,3}\s*years?\s*old\b', '[age] years old', deidentified_text, flags=re.IGNORECASE)
        deidentified_text = re.sub(r'\bPAT-\d+\b', '[patient-id]', deidentified_text)
        
        prompt = f"""Enhance this clinical documentation for ICF {field_type.replace('_', ' ')} domain.

        Text to enhance: "{deidentified_text}"
        
        Improve the text by:
        1. Using professional clinical terminology
        2. Following ICF framework guidelines
        3. Making it more specific and measurable
        4. Ensuring clarity and completeness
        5. Maintaining clinical accuracy
        
        Return only the enhanced text, no explanations."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'enhanced_text': response.content[0].text
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Generic ICF Domain Templates (No Patient Data)
@app.route('/api/ai/icf-templates', methods=['POST'])
@mobile_auth_required
def api_icf_templates():
    try:
        data = request.get_json()
        condition_type = data.get('condition_type', 'general')  # e.g., 'low_back_pain', 'shoulder', 'knee'
        field_type = data.get('field_type', '')
        
        prompt = f"""Provide a professional template for ICF {field_type.replace('_', ' ')} assessment for {condition_type.replace('_', ' ')} conditions.

        Create a template with:
        1. Key assessment areas
        2. Professional terminology
        3. Structured format
        4. Measurable criteria where applicable
        
        Return as a template that physiotherapists can customize for their patients."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'template': response.content[0].text,
            'condition_type': condition_type,
            'field_type': field_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Add these routes to your existing Flask app

@app.route('/api/ai/perspectives-guidance', methods=['POST'])
def get_perspectives_guidance():
    """Provide guidance for patient perspectives assessment fields"""
    try:
        data = request.get_json()
        field_name = data.get('field_name')
        
        # Psychology-informed guidance for each field
        guidance_map = {
            'knowledge': {
                'title': 'Assessing Patient Knowledge',
                'content': 'Explore what the patient understands about their condition. Ask open-ended questions like "What do you think is happening with your [body part]?" or "How would you explain your condition to a friend?" Look for misconceptions, gaps in understanding, or catastrophic thinking patterns.',
                'questions': [
                    'What has been explained to you about your condition?',
                    'How would you describe what\'s happening in your own words?',
                    'What concerns you most about your diagnosis?',
                    'Where did you get most of your information about this condition?'
                ]
            },
            'attribution': {
                'title': 'Understanding Causal Beliefs',
                'content': 'Explore what the patient believes caused their problem. This affects their engagement with treatment. Look for self-blame, external attributions, or unrealistic causal beliefs that might impact recovery.',
                'questions': [
                    'What do you think caused your problem?',
                    'Was there a specific incident or did it develop gradually?',
                    'Do you feel this was something you could have prevented?',
                    'How much control do you feel you had over developing this condition?'
                ]
            },
            'illness_duration': {
                'title': 'Recovery Timeline Expectations',
                'content': 'Understand patient expectations about recovery time. Unrealistic expectations (too fast or too slow) can affect treatment adherence and outcomes. Help align expectations with evidence-based timelines.',
                'questions': [
                    'How long do you expect it will take to get better?',
                    'What\'s your goal timeline for returning to normal activities?',
                    'Have you had similar problems before? How long did they take to resolve?',
                    'What would be acceptable progress for you in the next month?'
                ]
            },
            'consequences_awareness': {
                'title': 'Impact and Implications Understanding',
                'content': 'Assess how well the patient understands the potential consequences of their condition. This includes functional, social, work, and emotional impacts. Look for catastrophizing or minimizing behaviors.',
                'questions': [
                    'How is this condition affecting your daily life?',
                    'What activities are you most concerned about not being able to do?',
                    'How is this impacting your work/family/social life?',
                    'What worries you most about the future with this condition?'
                ]
            },
            'locus_of_control': {
                'title': 'Control Beliefs Assessment',
                'content': 'Determine whether the patient has internal (they can influence outcomes) or external (outcomes depend on others/fate) locus of control. Internal locus generally predicts better outcomes and engagement.',
                'questions': [
                    'How much control do you feel you have over your recovery?',
                    'What role do you think you play in getting better?',
                    'How much do you think your actions affect your symptoms?',
                    'Who or what do you think will be most important in your recovery?'
                ]
            },
            'affective_aspect': {
                'title': 'Emotional Response Assessment',
                'content': 'Explore the emotional impact of the condition. Look for signs of anxiety, depression, frustration, or fear. These emotions significantly impact recovery and may require additional support.',
                'questions': [
                    'How are you feeling emotionally about this condition?',
                    'What emotions come up when you think about your problem?',
                    'Are you feeling anxious or worried about anything specific?',
                    'How is this affecting your mood day-to-day?'
                ]
            }
        }
        
        guidance = guidance_map.get(field_name, {
            'title': 'General Perspectives Guidance',
            'content': 'Assess patient beliefs, understanding, and emotional responses to their condition.',
            'questions': ['How do you feel about your current situation?']
        })
        
        return jsonify({
            'success': True,
            'guidance': guidance
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/perspectives-prompts', methods=['POST'])
def get_perspectives_clinical_prompts():
    """Generate clinical reasoning prompts for patient perspectives"""
    try:
        data = request.get_json()
        current_responses = data.get('responses', {})
        
        # Generate psychology-focused clinical reasoning prompts
        prompts = []
        
        # Knowledge assessment prompts
        if current_responses.get('knowledge'):
            prompts.append({
                'category': 'Knowledge Assessment',
                'prompt': 'Based on the patient\'s understanding, are there any misconceptions that need addressing? How might their current knowledge level affect treatment compliance?'
            })
        
        # Attribution analysis
        if current_responses.get('attribution'):
            prompts.append({
                'category': 'Causal Beliefs',
                'prompt': 'Does the patient\'s belief about causation suggest self-blame or external attribution? How might this impact their engagement with self-management strategies?'
            })
        
        # Timeline expectations
        if current_responses.get('illness_duration'):
            prompts.append({
                'category': 'Recovery Expectations',
                'prompt': 'Are the patient\'s timeline expectations realistic? Do they suggest impatience that might lead to treatment dropout or despair that might reduce effort?'
            })
        
        # Consequences awareness
        if current_responses.get('consequences_awareness'):
            prompts.append({
                'category': 'Impact Understanding',
                'prompt': 'Is the patient catastrophizing or minimizing their condition? How well do they understand the broader implications beyond just physical symptoms?'
            })
        
        # Control beliefs
        if current_responses.get('locus_of_control'):
            prompts.append({
                'category': 'Control Assessment',
                'prompt': 'Does the patient demonstrate internal or external locus of control? How might this affect their willingness to engage in active treatment strategies?'
            })
        
        # Emotional response
        if current_responses.get('affective_aspect'):
            prompts.append({
                'category': 'Emotional Impact',
                'prompt': 'Are there signs of significant emotional distress that might require additional support? How might their emotional state impact their recovery?'
            })
        
        # Overall integration prompts
        prompts.extend([
            {
                'category': 'Therapeutic Relationship',
                'prompt': 'Based on these perspectives, how should you adapt your communication style and treatment approach to best engage this patient?'
            },
            {
                'category': 'Psychosocial Factors',
                'prompt': 'What psychosocial factors emerge as potential barriers or facilitators to recovery? What additional support might be beneficial?'
            },
            {
                'category': 'Patient-Centered Care',
                'prompt': 'How can you incorporate the patient\'s beliefs and concerns into a collaborative treatment plan that respects their perspective while promoting evidence-based care?'
            }
        ])
        
        return jsonify({
            'success': True,
            'prompts': prompts
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/perspectives-patterns', methods=['POST'])
def analyze_perspectives_patterns():
    """Analyze patterns in patient perspectives for clinical insights"""
    try:
        data = request.get_json()
        responses = data.get('responses', {})
        
        patterns = []
        
        # Analyze for concerning patterns
        knowledge = responses.get('knowledge', '').lower()
        attribution = responses.get('attribution', '').lower()
        consequences = responses.get('consequences_awareness', '').lower()
        control = responses.get('locus_of_control', '').lower()
        emotion = responses.get('affective_aspect', '').lower()
        
        # Check for catastrophic thinking
        catastrophic_terms = ['terrible', 'awful', 'disaster', 'ruined', 'never', 'always', 'worst', 'hopeless']
        if any(term in knowledge + consequences + emotion for term in catastrophic_terms):
            patterns.append({
                'type': 'warning',
                'category': 'Catastrophic Thinking',
                'message': 'Patient may be exhibiting catastrophic thinking patterns. Consider cognitive restructuring techniques and realistic expectation setting.',
                'recommendation': 'Address unrealistic negative thoughts with evidence-based information and gradual exposure to positive outcomes.'
            })
        
        # Check for external locus of control
        external_terms = ['doctor will fix', 'nothing I can do', 'up to you', 'fate', 'bad luck']
        if any(term in control + attribution for term in external_terms):
            patterns.append({
                'type': 'info',
                'category': 'External Control Beliefs',
                'message': 'Patient appears to have external locus of control. This may impact engagement with self-management.',
                'recommendation': 'Emphasize patient agency and provide clear examples of how their actions directly impact outcomes.'
            })
        
        # Check for depression/anxiety indicators
        mood_concerns = ['depressed', 'anxious', 'scared', 'worried', 'hopeless', 'frustrated', 'angry']
        if any(term in emotion for term in mood_concerns):
            patterns.append({
                'type': 'warning',
                'category': 'Emotional Distress',
                'message': 'Patient reports emotional distress that may impact recovery. Consider psychological support.',
                'recommendation': 'Monitor emotional wellbeing closely and consider referral to mental health services if appropriate.'
            })
        
        # Check for unrealistic recovery expectations
        duration = responses.get('illness_duration', '').lower()
        if any(term in duration for term in ['immediately', 'right away', 'few days', 'week']):
            patterns.append({
                'type': 'info',
                'category': 'Unrealistic Timeline',
                'message': 'Patient may have unrealistic expectations about recovery timeline.',
                'recommendation': 'Provide evidence-based timeline information and set realistic milestones.'
            })
        
        # Positive patterns
        positive_terms = ['understand', 'willing', 'committed', 'optimistic', 'confident']
        if any(term in knowledge + control for term in positive_terms):
            patterns.append({
                'type': 'success',
                'category': 'Positive Engagement',
                'message': 'Patient demonstrates good understanding and positive engagement indicators.',
                'recommendation': 'Build on this positive foundation with collaborative goal setting.'
            })
        
        return jsonify({
            'success': True,
            'patterns': patterns
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/ai/enhance-perspectives-text', methods=['POST'])
def enhance_perspectives_text():
    """Enhance patient perspectives documentation with professional language"""
    try:
        data = request.get_json()
        text = data.get('text', '')
        field_name = data.get('field_name', '')
        
        if not text.strip():
            return jsonify({'success': False, 'error': 'No text provided'})
        
        # Field-specific enhancement prompts
        enhancement_prompts = {
            'knowledge': 'Rewrite this patient knowledge assessment using professional clinical language while preserving the patient\'s actual understanding and misconceptions',
            'attribution': 'Enhance this documentation of patient causal beliefs using appropriate psychological and clinical terminology',
            'illness_duration': 'Improve this documentation of patient recovery expectations using professional language that captures timeline beliefs',
            'consequences_awareness': 'Rewrite this assessment of patient impact awareness using clinical terminology for functional and psychosocial consequences',
            'locus_of_control': 'Enhance this documentation of patient control beliefs using appropriate psychological terminology',
            'affective_aspect': 'Improve this emotional response documentation using professional mental health and clinical language'
        }
        
        prompt = enhancement_prompts.get(field_name, 'Enhance this patient perspectives documentation using professional clinical language')
        
        # Call Claude API for text enhancement
        headers = {
            'Content-Type': 'application/json',
            'X-API-Key': os.environ.get('CLAUDE_API_KEY')
        }
        
        claude_payload = {
            'model': 'claude-3-sonnet-20240229',
            'max_tokens': 300,
            'messages': [{
                'role': 'user',
                'content': f'''{prompt}: "{text}"

Requirements:
- Use professional clinical and psychological terminology
- Maintain the patient's actual perspective and beliefs
- Be concise but comprehensive
- Include relevant psychological constructs when appropriate
- Preserve important details while improving clarity'''
            }]
        }
        
        response = requests.post(
            'https://api.anthropic.com/v1/messages',
            headers=headers,
            json=claude_payload,
            timeout=30
        )
        
        if response.status_code == 200:
            enhanced_text = response.json()['content'][0]['text'].strip()
            return jsonify({
                'success': True,
                'enhanced_text': enhanced_text
            })
        else:
            return jsonify({'success': False, 'error': 'AI service unavailable'}), 503
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# Add these endpoints to your existing app.py file

@app.route('/api/ai/examination-guidance', methods=['POST'])
def examination_guidance():
    """Provide examination technique guidance for specific test categories"""
    try:
        data = request.get_json()
        test_category = data.get('test_category', '')
        suspected_condition = data.get('suspected_condition', '')
        
        if not test_category:
            return jsonify({'error': 'Test category is required'}), 400
        
        # Generic clinical prompt - no patient data
        prompt = f"""
        As a clinical educator, provide examination guidance for: {test_category}
        
        Context: {suspected_condition if suspected_condition else 'General examination planning'}
        
        Please provide:
        1. Proper examination technique and procedure
        2. What to look for during testing
        3. Safety considerations and contraindications
        4. Expected normal vs abnormal findings
        5. Clinical significance of results
        
        Format as clear, practical guidance for physiotherapists.
        Keep response concise but comprehensive (max 300 words).
        """
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'guidance': response.content[0].text,
            'category': test_category
        })
        
    except Exception as e:
        logger.error(f"Error in examination guidance: {str(e)}")
        return jsonify({'error': 'Failed to generate examination guidance'}), 500

@app.route('/api/ai/test-selection', methods=['POST'])
def test_selection_ai():
    """Suggest appropriate tests based on clinical presentation"""
    try:
        data = request.get_json()
        symptoms = data.get('symptoms', '')
        body_region = data.get('body_region', '')
        suspected_pathology = data.get('suspected_pathology', '')
        
        # Generic clinical reasoning - no patient identifiers
        prompt = f"""
        As a clinical reasoning expert, suggest examination tests for:
        
        Body Region: {body_region}
        Symptoms: {symptoms}
        Suspected Condition: {suspected_pathology}
        
        Please recommend:
        1. Priority 1 tests (essential/high-yield)
        2. Priority 2 tests (if time permits)
        3. Special tests to consider
        4. Tests to avoid or use with caution
        5. Optimal examination sequence
        
        Format as practical recommendations for examination planning.
        Focus on evidence-based, efficient testing protocols.
        """
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'recommendations': response.content[0].text,
            'body_region': body_region
        })
        
    except Exception as e:
        logger.error(f"Error in test selection: {str(e)}")
        return jsonify({'error': 'Failed to generate test recommendations'}), 500

@app.route('/api/ai/examination-safety', methods=['POST'])
def examination_safety():
    """Provide safety alerts and contraindications"""
    try:
        data = request.get_json()
        planned_tests = data.get('planned_tests', [])
        patient_conditions = data.get('patient_conditions', '')
        
        # Safety-focused prompt - no patient identifiers
        prompt = f"""
        As a clinical safety expert, review these planned examination tests:
        
        Planned Tests: {', '.join(planned_tests)}
        Relevant Conditions: {patient_conditions}
        
        Please identify:
        1. Absolute contraindications (do not perform)
        2. Relative contraindications (use caution)
        3. Modifications needed for safe testing
        4. Red flags to watch for during examination
        5. When to stop or modify testing
        
        Format as clear safety guidelines.
        Prioritize patient safety above all else.
        """
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'safety_guidance': response.content[0].text,
            'planned_tests': planned_tests
        })
        
    except Exception as e:
        logger.error(f"Error in examination safety: {str(e)}")
        return jsonify({'error': 'Failed to generate safety guidance'}), 500

@app.route('/api/ai/examination-protocol', methods=['POST'])
def examination_protocol():
    """Generate step-by-step examination protocols"""
    try:
        data = request.get_json()
        body_region = data.get('body_region', '')
        examination_focus = data.get('examination_focus', '')
        time_available = data.get('time_available', 'standard')
        
        # Protocol generation - no patient data
        prompt = f"""
        As a clinical protocol expert, create an examination sequence for:
        
        Body Region: {body_region}
        Focus: {examination_focus}
        Time Frame: {time_available}
        
        Provide a structured protocol with:
        1. Optimal sequence of tests (start to finish)
        2. Estimated time for each component
        3. Patient positioning requirements
        4. Equipment needed
        5. Key clinical pearls for efficiency
        
        Format as a clear, step-by-step protocol.
        Make it practical for clinical use.
        """
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'protocol': response.content[0].text,
            'body_region': body_region,
            'focus': examination_focus
        })
        
    except Exception as e:
        logger.error(f"Error in examination protocol: {str(e)}")
        return jsonify({'error': 'Failed to generate examination protocol'}), 500

@app.route('/api/ai/plan-documentation', methods=['POST'])
def plan_documentation():
    """Enhance examination plan documentation"""
    try:
        data = request.get_json()
        examination_plan = data.get('examination_plan', '')
        
        if not examination_plan:
            return jsonify({'error': 'Examination plan text is required'}), 400
        
        # Documentation enhancement - no patient identifiers
        prompt = f"""
        As a clinical documentation expert, enhance this examination plan:
        
        "{examination_plan}"
        
        Please improve by:
        1. Using professional clinical terminology
        2. Following standard documentation format
        3. Ensuring completeness and clarity
        4. Adding appropriate clinical reasoning
        5. Making it suitable for medical records
        
        Return only the enhanced version.
        Maintain all original clinical intent.
        """
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'enhanced_plan': response.content[0].text,
            'original_plan': examination_plan
        })
        
    except Exception as e:
        logger.error(f"Error in plan documentation: {str(e)}")
        return jsonify({'error': 'Failed to enhance documentation'}), 500

@app.route('/api/ai/differential-testing', methods=['POST'])
def differential_testing():
    """Suggest tests for differential diagnosis"""
    try:
        data = request.get_json()
        differential_list = data.get('differential_diagnoses', [])
        primary_symptoms = data.get('primary_symptoms', '')
        
        # Differential diagnosis testing - no patient data
        prompt = f"""
        As a diagnostic reasoning expert, suggest examination tests to differentiate between:
        
        Differential Diagnoses: {', '.join(differential_list)}
        Primary Symptoms: {primary_symptoms}
        
        Recommend:
        1. Tests that help rule IN each condition
        2. Tests that help rule OUT each condition
        3. Most discriminating tests for differential diagnosis
        4. Testing sequence for efficient differentiation
        5. Key findings that distinguish each condition
        
        Format as diagnostic testing strategy.
        Focus on tests with high diagnostic utility.
        """
        
        response = client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'testing_strategy': response.content[0].text,
            'differentials': differential_list
        })
        
    except Exception as e:
        logger.error(f"Error in differential testing: {str(e)}")
        return jsonify({'error': 'Failed to generate testing strategy'}), 500

# Add these endpoints to your app.py file after your existing AI endpoints

# Pathomechanism-specific AI Guidance
@app.route('/api/ai/pathomechanism-guidance', methods=['POST'])
@mobile_auth_required
def api_pathomechanism_guidance():
    try:
        data = request.get_json()
        field_type = data.get('field_type')  # area_involved, presenting_symptom, etc.
        
        # Define pathomechanism-specific guidance prompts
        pathomechanism_prompts = {
            'area_involved': """Provide expert physiotherapy guidance for documenting Area Involved in pathomechanism analysis.
            
            Guidance for identifying and documenting anatomical areas:
            - Focus on specific anatomical structures
            - Consider primary vs secondary areas of involvement
            - Include relevant anatomical landmarks
            - Document precise location descriptions
            
            Format as 4-5 key assessment points with brief explanations.""",
            
            'presenting_symptom': """Provide expert physiotherapy guidance for documenting Presenting Symptoms in pathomechanism analysis.
            
            Guidance for symptom documentation:
            - Primary vs secondary symptoms
            - Symptom characteristics and behavior
            - Aggravating and easing factors
            - Temporal patterns and progression
            
            Format as 4-5 key documentation points with brief explanations.""",
            
            'pain_type': """Provide expert physiotherapy guidance for Pain Type classification in pathomechanism analysis.
            
            Modern pain science classification:
            - Nociceptive pain characteristics
            - Neuropathic pain indicators
            - Nociplastic pain features
            - Mixed pain presentations
            - Clinical assessment approaches
            
            Format as structured guidance for pain type identification.""",
            
            'pain_nature': """Provide expert physiotherapy guidance for Pain Nature assessment in pathomechanism analysis.
            
            Pain quality assessment:
            - Descriptive characteristics (sharp, dull, burning, etc.)
            - Clinical significance of different pain qualities
            - Relationship to underlying pathology
            - Patient language interpretation
            
            Format as assessment guidance with clinical interpretations.""",
            
            'pain_severity': """Provide expert physiotherapy guidance for Pain Severity assessment in pathomechanism analysis.
            
            Comprehensive severity assessment:
            - Numerical rating scales and interpretation
            - Functional impact assessment
            - Activity limitation correlation
            - Quality of life considerations
            
            Format as structured assessment approach with measurement tools.""",
            
            'pain_irritability': """Provide expert physiotherapy guidance for Pain Irritability assessment in pathomechanism analysis.
            
            Irritability assessment framework:
            - Ease of provocation criteria
            - Time to settle characteristics
            - Activity modification requirements
            - Treatment approach implications
            
            Format as clinical decision-making guidance.""",
            
            'symptom_source': """Provide expert physiotherapy guidance for Symptom Source identification in pathomechanism analysis.
            
            Source identification guidance:
            - Tissue-based vs non-tissue sources
            - Peripheral vs central mechanisms
            - Inflammatory vs mechanical sources
            - Psychosocial contributing factors
            
            Format as systematic source analysis approach.""",
            
            'tissue_healing_stage': """Provide expert physiotherapy guidance for Tissue Healing Stage assessment in pathomechanism analysis.
            
            Healing stage identification:
            - Acute inflammatory phase characteristics
            - Subacute proliferation phase features
            - Chronic remodeling phase indicators
            - Clinical implications for each stage
            
            Format as stage-specific guidance with treatment implications."""
        }
        
        prompt = pathomechanism_prompts.get(field_type)
        
        if not prompt:
            return jsonify({'error': 'Invalid field type'}), 400
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'guidance': response.content[0].text,
            'field_type': field_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Pain Science Education Assistant
@app.route('/api/ai/pain-science-education', methods=['POST'])
@mobile_auth_required
def api_pain_science_education():
    try:
        data = request.get_json()
        pain_type = data.get('pain_type', '')
        
        prompt = f"""Provide modern pain science education for physiotherapists about pain mechanisms.
        
        Focus area: {pain_type if pain_type else 'general pain mechanisms'}
        
        Provide evidence-based education covering:
        1. Current understanding of pain mechanisms
        2. Clinical presentation characteristics
        3. Assessment approaches
        4. Treatment implications
        5. Patient education considerations
        
        Keep explanations clinically relevant and evidence-based.
        Format as structured educational content."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'education': response.content[0].text
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Pathomechanism Analysis Assistant
@app.route('/api/ai/pathomechanism-analysis', methods=['POST'])
@mobile_auth_required
def api_pathomechanism_analysis():
    try:
        data = request.get_json()
        completed_fields = data.get('completed_fields', {})
        
        # Build analysis prompt from completed fields (de-identified)
        analysis_text = "Pathomechanism analysis for physiotherapy reasoning:\n\n"
        
        field_labels = {
            'area_involved': 'Area Involved',
            'presenting_symptom': 'Presenting Symptom',
            'pain_type': 'Pain Type',
            'pain_nature': 'Pain Nature', 
            'pain_severity': 'Pain Severity',
            'pain_irritability': 'Pain Irritability',
            'symptom_source': 'Symptom Source',
            'tissue_healing_stage': 'Tissue Healing Stage'
        }
        
        for field, value in completed_fields.items():
            if value and value.strip():
                label = field_labels.get(field, field.replace('_', ' ').title())
                analysis_text += f"{label}: {value}\n"
        
        prompt = f"""Analyze this pathomechanism assessment for clinical reasoning patterns.

        {analysis_text}
        
        Provide analysis focusing on:
        1. Consistency between different pathomechanism components
        2. Clinical reasoning patterns that emerge
        3. Potential diagnostic hypotheses suggested
        4. Areas needing further assessment
        5. Treatment planning implications
        
        Format as structured clinical reasoning analysis."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=500,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'analysis': response.content[0].text
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Clinical Decision Support for Pathomechanism
@app.route('/api/ai/pathomechanism-prompts', methods=['POST'])
@mobile_auth_required
def api_pathomechanism_prompts():
    try:
        data = request.get_json()
        completed_domains = data.get('completed_domains', [])
        
        domains_text = ", ".join(completed_domains) if completed_domains else "none"
        
        prompt = f"""Provide expert clinical reasoning prompts for pathomechanism analysis in physiotherapy.

        Completed pathomechanism domains: {domains_text}
        
        Provide 5-6 clinical reasoning questions focusing on:
        1. Pain mechanism identification and classification
        2. Tissue pathology and healing stage assessment  
        3. Symptom source and irritability evaluation
        4. Integration with subjective examination findings
        5. Preparation for objective assessment planning
        
        Format as numbered clinical reasoning questions with brief rationale."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'prompts': response.content[0].text
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# Smart Template Suggestions
@app.route('/api/ai/pathomechanism-templates', methods=['POST'])
@mobile_auth_required
def api_pathomechanism_templates():
    try:
        data = request.get_json()
        condition_area = data.get('condition_area', 'general')  # e.g., 'spine', 'shoulder', 'knee'
        field_type = data.get('field_type', '')
        
        prompt = f"""Provide a clinical template for {field_type.replace('_', ' ')} assessment in {condition_area.replace('_', ' ')} conditions.

        Create a professional template focusing on:
        - Evidence-based assessment criteria
        - Standardized terminology
        - Clinical decision-making guidance
        - Professional documentation format
        
        Return as a template that can be customized for individual patients."""
        
        response = claude_client.messages.create(
            model="claude-3-5-sonnet-20241022",
            max_tokens=300,
            messages=[{"role": "user", "content": prompt}]
        )
        
        return jsonify({
            'success': True,
            'template': response.content[0].text,
            'condition_area': condition_area,
            'field_type': field_type
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)