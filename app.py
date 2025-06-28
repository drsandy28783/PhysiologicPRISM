import os
from flask import Flask, render_template, request, redirect, session, url_for, make_response, jsonify
import io, csv
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_init import firebase_admin  # uses your existing setup
from firebase_admin import firestore
db = firestore.client()
import anthropic
DEBUG_AI = True  # Set to False in production


client = anthropic.Anthropic(
    api_key=os.getenv("CLAUDE_API_KEY")
)


def log_action(user_id, action, details=None):
    db.collection('audit_logs').add({
        'user_id': user_id,
        'action': action,
        'details': details,
        'timestamp': firestore.SERVER_TIMESTAMP
    })

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_default')


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

@app.route("/api/ai/intake-insights", methods=["POST"])
def ai_intake_insights():
    data = request.get_json()

    # Clinical fields only – no PII sent to Claude
    age_sex = data.get("age_sex", "")
    present_history = data.get("present_history", "")
    past_history = data.get("past_history", "")

    # Claude-safe clinical reasoning prompt
    prompt = f"""
You are a clinical assistant helping a physiotherapist assess a new patient.

Given:
- Age/Sex: {age_sex}
- Presenting Symptoms: {present_history}
- Relevant Past History: {past_history}

Your task is:
1. Summarize possible key concerns or symptom patterns.
2. Suggest 3–4 **follow-up questions** the therapist should ask to better understand the problem.
3. List any **underlying conditions** (like diabetes or thyroid issues) that should be screened for, based on the symptoms.

Do not include or infer any patient names or personal identifiers.
Keep each section concise in bullet points.
"""

    ai_response = call_claude(prompt)
    return jsonify({"response": ai_response})

@app.route("/api/ai/subjective-exam", methods=["POST"])
def ai_subjective_exam():
    data = request.get_json()
    patient_id = data.get("patient_id")

    # 🔍 Pull present & past history from Firestore
    patient_doc = db.collection("patients").document(patient_id).get()
    if not patient_doc.exists:
        return jsonify({"error": "Patient not found"}), 404

    patient_data = patient_doc.to_dict()
    present_history = patient_data.get("present_history", "")
    past_history = patient_data.get("past_history", "")

    prompt = f"""
You are assisting a physiotherapist in completing a clinical subjective examination using ICF framework.

Use the following clinical inputs:

Present History:
{present_history}

Past History:
{past_history}

Suggest appropriate entries for the following 6 categories:
1. Impairment of body structure  
2. Impairment of body function  
3. Activity Limitation / Restriction – Performance  
4. Activity Limitation / Restriction – Capacity  
5. Contextual Factors – Environmental  
6. Contextual Factors – Personal  

Your suggestions should be phrased as **single-line clinical statements** for each section.
Do not include patient identifiers. Focus only on relevant clinical insight.
"""

    ai_response = call_claude(prompt)
    return jsonify({"response": ai_response})

@app.route("/api/ai/patient-perspectives", methods=["POST"])
def ai_patient_perspectives():
    data = request.get_json()
    patient_id = data.get("patient_id")

    # 🔍 Pull patient data from Firestore
    patient_doc = db.collection("patients").document(patient_id).get()
    if not patient_doc.exists:
        return jsonify({"error": "Patient not found"}), 404

    patient_data = patient_doc.to_dict()
    present_history = patient_data.get("present_history", "")
    past_history = patient_data.get("past_history", "")
    subjective_exam = patient_data.get("subjective_exam", "")

    prompt = f"""
You are assisting a physiotherapist in assessing **Patient Perspectives**.

Use this case history:
Present History: {present_history}
Past History: {past_history}
Subjective Examination: {subjective_exam}

Based on the above, provide clinical suggestions for the following:
1. Knowledge of Illness  
2. Illness Attribution  
3. Expectation  
4. Awareness of Control  
5. Locus of Control  
6. Affective Aspect  

Write each section as a clear, one-line clinical interpretation.  
Use general phrasing (e.g., "Patient believes condition is due to overuse").  
Avoid any personal identifiers or names.
"""

    ai_response = call_claude(prompt)
    return jsonify({"response": ai_response})

@app.route("/api/ai/initial_plan", methods=["POST"])
def ai_initial_plan():
    data = request.get_json()
    patient_id = data.get("patient_id")

    # Pull previous data from Firestore
    patient_doc = db.collection("patients").document(patient_id).get()
    if not patient_doc.exists:
        return jsonify({"error": "Patient not found"}), 404

    patient_data = patient_doc.to_dict()
    present_history = patient_data.get("present_history", "")
    past_history = patient_data.get("past_history", "")
    body_structure = patient_data.get("impairment_body_structure", "")
    body_function = patient_data.get("impairment_body_function", "")
    performance = patient_data.get("activity_performance", "")
    capacity = patient_data.get("activity_capacity", "")
    context_env = patient_data.get("contextual_environmental", "")
    context_personal = patient_data.get("contextual_personal", "")

    # Construct prompt
    prompt = f"""
    A physiotherapist is determining the appropriate initial assessment plan for a new patient.

    Clinical Information:
    - Present History: {present_history}
    - Past History: {past_history}
    - Impairment of Body Structure: {body_structure}
    - Impairment of Body Function: {body_function}
    - Activity Limitation – Performance: {performance}
    - Activity Limitation – Capacity: {capacity}
    - Contextual Factors – Environmental: {context_env}
    - Contextual Factors – Personal: {context_personal}

    Suggest:
    1. Whether an assessment is Mandatory, Contraindicated, or to be done with Precaution.
    2. Which movements should be tested (Active, Passive, Resisted).
    3. Precautions to keep in mind.
    4. Conditions that may influence assessment or require modification.

    Provide responses as concise **bullet points**. No patient identifiers.
    """

    ai_response = call_claude(prompt)
    return jsonify({"response": ai_response})

@app.route("/api/ai/pathophysiological", methods=["POST"])
def ai_pathophysiological():
    data = request.get_json()
    patient_id = data.get("patient_id")

    # 🔄 Fetch data from Firestore
    patient_doc = db.collection("patients").document(patient_id).get()
    if not patient_doc.exists:
        return jsonify({"error": "Patient not found"}), 404

    patient_data = patient_doc.to_dict()

    # 🔁 Get required fields (safe defaults for empty values)
    area_involved = patient_data.get("area_involved", "")
    presenting_symptom = patient_data.get("presenting_symptom", "")
    pain_type = patient_data.get("pain_type", "")
    pain_nature = patient_data.get("pain_nature", "")
    pain_severity = patient_data.get("pain_severity", "")
    pain_irritability = patient_data.get("pain_irritability", "")
    symptom_source = patient_data.get("symptom_source", "")
    healing_stage = patient_data.get("healing_stage", "")

    # 🧠 Construct AI Prompt
    prompt = f"""
You are a clinical physiotherapist. Based on the given patient presentation, generate a possible pathophysiological mechanism or hypothesis. Include how pain characteristics (type, nature, irritability, severity), tissue healing stage, and symptom source help guide the hypothesis.

Patient Data:
- Area Involved: {area_involved}
- Presenting Symptom: {presenting_symptom}
- Pain Type: {pain_type}
- Pain Nature: {pain_nature}
- Pain Severity (VAS): {pain_severity}
- Pain Irritability: {pain_irritability}
- Possible Source of Symptoms: {symptom_source}
- Stage of Tissue Healing: {healing_stage}

Your output should include:
1. A likely hypothesis for the mechanism (e.g., tendinopathy, nerve entrapment, etc.)
2. Reasoning for the hypothesis based on symptoms
3. Any suggestions for further assessment if needed
"""

    # ✨ Claude AI Call
    ai_response = call_claude(prompt)
    return jsonify({"response": ai_response})

@app.route("/api/ai/chronic_disease", methods=["POST"])
def ai_chronic_disease():
    data = request.get_json()
    patient_id = data.get("patient_id")

    # 🔍 Pull from Firestore
    patient_doc = db.collection("patients").document(patient_id).get()
    if not patient_doc.exists:
        return jsonify({"error": "Patient not found"}), 404

    patient_data = patient_doc.to_dict()
    present_history = patient_data.get("present_history", "")
    past_history = patient_data.get("past_history", "")

    # 🧠 Prompt for Claude
    prompt = f"""
You are assisting a physiotherapist in analyzing chronic contributing factors for a musculoskeletal condition.

Clinical Details:
Present History: {present_history}
Past History: {past_history}

Based on this, suggest possible contributors to chronicity from the following categories:
- Physical/Biomechanical
- Psychological
- Social/Environmental
- Lifestyle/Behavioral
- Work-related
- Others

Respond in bullet points with clinical reasoning, without including any identifiable information.
"""

    ai_response = call_claude(prompt)
    return jsonify({"response": ai_response})

@app.route("/api/ai/clinical_flags", methods=["POST"])
def ai_clinical_flags():
    data = request.get_json()
    patient_id = data.get("patient_id")

    patient_doc = db.collection("patients").document(patient_id).get()
    if not patient_doc.exists:
        return jsonify({"error": "Patient not found"}), 404

    patient_data = patient_doc.to_dict()
    present_history = patient_data.get("present_history", "")
    past_history = patient_data.get("past_history", "")

    prompt = f"""
You are helping a physiotherapist identify psychosocial flags based on patient history.

Clinical Summary:
Present History: {present_history}
Past History: {past_history}

Using this context, identify if any of the following flags may be relevant:
- 🔴 Red Flag (Serious pathology)
- 🟠 Orange Flag (Psychiatric concerns)
- 🟡 Yellow Flag (Psychosocial issues)
- ⚫ Black Flag (Compensation or legal/workplace barriers)
- 🔵 Blue Flag (Perceptions about workplace/stress)

Provide a brief clinical reasoning under each flag (even if no flag is suspected, say 'None evident').
Respond in bullet points.
"""

    ai_response = call_claude(prompt)
    return jsonify({"response": ai_response})

@app.route('/get_ai_suggestion/objective_assessment/<patient_id>', methods=['POST'])
def get_ai_objective_assessment_suggestion(patient_id):
    patient_data = get_patient_data(patient_id)
    
    # Use data from previous steps to generate prompt
    prompt = f"""
    Based on the following patient data:
    
    Subjective Examination: {patient_data.get('subjective_examination')}
    Initial Plan: {patient_data.get('initial_plan')}
    Pathophysiological Mechanism: {patient_data.get('patho_mechanism')}
    
    Suggest the most appropriate plan for objective assessment (choose from: 
    - Comprehensive without modification, 
    - Comprehensive with modifications), and explain any relevant observations or modifications that should be recorded.
    
    Provide the output in this format:
    Plan: <your answer>
    Notes: <your suggestions>
    """
    
    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}],
        max_tokens=300
    )
    
    output = response.choices[0].message['content']
    try:
        plan_line = next(line for line in output.splitlines() if line.startswith("Plan:"))
        notes_line = next(line for line in output.splitlines() if line.startswith("Notes:"))
        return jsonify({
            "plan": plan_line.replace("Plan:", "").strip(),
            "notes": notes_line.replace("Notes:", "").strip()
        })
    except Exception:
        return jsonify({"error": "Unexpected AI output format."}), 500

@app.route('/get_ai_provisional_diagnosis/<patient_id>')
def get_ai_provisional_diagnosis(patient_id):
    doc_ref = db.collection('patients').document(patient_id)
    patient_data = doc_ref.get().to_dict()

    subjective = patient_data.get('subjective_examination', {})
    mechanism = patient_data.get('patho_mechanism', {})
    flags = patient_data.get('clinical_flags', {})
    objective = patient_data.get('objective_assessment', {})

    ai_prompt = f"""
You are a physiotherapy AI assistant. Based on the following patient data, suggest a Provisional Diagnosis:

Subjective Examination: {subjective}
Patho-Physiological Mechanism: {mechanism}
Clinical Flags: {flags}
Objective Assessment: {objective}

Return the following:
- Likelihood of Diagnosis
- Structure at Fault
- Symptom
- Findings Supporting the Diagnosis
- Findings Rejecting the Diagnosis
- Hypothesis Supported (Yes/No)
"""

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": ai_prompt}]
    )

    return jsonify(response['choices'][0]['message']['content'])

@app.route('/get_ai_smart_goals/<patient_id>')
def get_ai_smart_goals(patient_id):
    doc_ref = db.collection('patients').document(patient_id)
    patient_data = doc_ref.get().to_dict()

    diagnosis = patient_data.get('provisional_diagnosis', {})
    subjective = patient_data.get('subjective_examination', {})
    objective = patient_data.get('objective_assessment', {})

    prompt = f"""
You are a physiotherapy AI assistant. Based on the patient's Provisional Diagnosis, Subjective and Objective data, suggest SMART Goals (Specific, Measurable, Achievable, Relevant, Time-bound).

Provisional Diagnosis: {diagnosis}
Subjective: {subjective}
Objective: {objective}

Return the following in plain format:
- Goals (Patient-Centric)
- Baseline Status
- Measurable Outcomes Expected
- Time Duration
"""

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )

    return jsonify(response['choices'][0]['message']['content'])

@app.route('/get_ai_treatment_plan/<patient_id>')
def get_ai_treatment_plan(patient_id):
    doc_ref = db.collection('patients').document(patient_id)
    patient_data = doc_ref.get().to_dict()

    diagnosis = patient_data.get('provisional_diagnosis', {})
    goals = patient_data.get('smart_goals', {})
    subjective = patient_data.get('subjective_examination', {})
    objective = patient_data.get('objective_assessment', {})

    prompt = f"""
You are a physiotherapy AI assistant. Based on the data below, suggest a physiotherapy treatment plan.

Subjective Data: {subjective}
Objective Data: {objective}
Provisional Diagnosis: {diagnosis}
SMART Goals: {goals}

Respond in the following format:
- Treatment Plan:
- Goal Targeted:
- Reasoning:
- Reference:
"""

    response = openai.ChatCompletion.create(
        model="gpt-4",
        messages=[{"role": "user", "content": prompt}]
    )

    return jsonify(response['choices'][0]['message']['content'])

@app.route("/api/ai/follow_up", methods=["POST"])
def ai_follow_up():
    from flask import request, jsonify
    from firestore import get_patient_data
    import os
    import openai

    patient_id = request.json.get("patient_id")
    if not patient_id:
        return jsonify({"response": "Invalid request: missing patient ID"}), 400

    # ⬇️ Fetch relevant previous data to inform follow-up suggestions
    patient_data = get_patient_data(patient_id)
    subjective = patient_data.get("subjective_examination", {})
    treatment_plan = patient_data.get("treatment_plan", {})
    past_followups = patient_data.get("follow_ups", [])

    # 🧠 Build prompt
    prompt = f"""A patient has undergone treatment. Based on the following details, suggest:
- Grade of Achievement
- Perception of Treatment
- Feedback
- Plan for Next Treatment

Subjective Info: {subjective}
Treatment Plan: {treatment_plan}
Past Follow-Ups: {past_followups}
"""

    # ⬇️ Claude or OpenAI call here — pseudocode
    ai_response = call_claude(prompt)

    return jsonify({"response": ai_response})

@app.route("/view_ai_summary", methods=["POST"])
def view_ai_summary():
    from flask import request, render_template
    patient_id = request.form.get("patient_id")
    log_action(session.get("user_id", "unknown"), f"Viewed AI summary for patient {patient_id}")

    # Fetch patient data
    patient_ref = db.collection("patients").document(patient_id)
    patient_doc = patient_ref.get()
    patient_data = patient_doc.to_dict() or {}

    # Check if summary already exists and skip Claude call
    summary = patient_data.get("ai_summary")
    regenerate = request.form.get("regenerate") == "true"

    if not summary or regenerate:
        # Build fresh Claude prompt
        prompt = f"""Generate a clinical summary for physiotherapy follow-up based on:
- Subjective examination: {patient_data.get('subjective_examination')}
- Objective assessment: {patient_data.get('objective_assessment')}
- Diagnosis: {patient_data.get('provisional_diagnosis')}
- SMART Goals: {patient_data.get('smart_goals')}
- Treatment Plan: {patient_data.get('treatment_plan')}
- Follow-Up Logs: {patient_data.get('follow_ups', [])}

Keep it concise and professional, summarizing the patient's current clinical status, goals, and progress.
"""

        summary = call_claude(prompt)

        # Save summary to Firestore
        patient_ref.update({
            "ai_summary": summary,
            "ai_summary_timestamp": datetime.utcnow().isoformat()
        })
    else:
        prompt = "[Using cached summary]"

    return render_template("ai_summary.html", summary=summary, patient_id=patient_id, prompt=prompt, debug=DEBUG_AI)

 


@app.route("/download_ai_summary", methods=["POST"])
def download_ai_summary():
    patient_id = request.form.get("patient_id")
    summary = request.form.get("summary")

    # HTML content to render as PDF
    html = render_template_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {
                    font-family: Arial, sans-serif;
                    padding: 30px;
                    line-height: 1.5;
                    color: #333;
                }
                h2 {
                    text-align: center;
                    color: #0A6847;
                }
                .summary {
                    white-space: pre-wrap;
                    border: 1px solid #ccc;
                    padding: 15px;
                    background-color: #f9f9f9;
                }
            </style>
        </head>
        <body>
            <h2>AI-Generated Summary for {{ patient_id }}</h2>
            <div class="summary">{{ summary }}</div>
        </body>
        </html>
    """, patient_id=patient_id, summary=summary)

    # Generate PDF using WeasyPrint
    pdf = HTML(string=html).write_pdf()

    # Return PDF as downloadable response
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename=AI_Summary_{patient_id}.pdf'
    log_action(session.get("user_id", "unknown"), f"Downloaded AI summary for patient {patient_id}")


    return response


if __name__ == '__main__':
    app.run(debug=True)
