import os
from flask import Flask, render_template, request, redirect, session, url_for, make_response, jsonify
import io, csv
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from firebase_init import firebase_admin  # uses your existing setup
from firebase_admin import firestore
db = firestore.client()
import anthropic
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


DEBUG_AI = True  # Set to False in production
client = anthropic.Anthropic(api_key=os.getenv("CLAUDE_API_KEY"))

def call_claude(prompt):
    """Calls Claude AI with the given prompt and returns the response."""
    try:
        response = client.messages.create(
            model="claude-3-5-sonnet-20240620",
            temperature=0.4,
            max_tokens=1000,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text
    except Exception as e:
        if DEBUG_AI:
            return f"AI Error: {str(e)}"
        else:
            return "AI service is temporarily unavailable. Please try again later."



def log_action(user_id, action, details=None):
    db.collection('audit_logs').add({
        'user_id': user_id,
        'action': action,
        'details': details,
        'timestamp': firestore.SERVER_TIMESTAMP
    })

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fallback_default')

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "20 per minute"]
)


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

# REPLACE your AI endpoints with these enhanced versions that collect cumulative data

def get_cumulative_patient_data(patient_id):
    """Helper function to collect ALL data from previous workflow steps"""
    data = {}
    
    # Basic patient info
    patients = db.collection('patients').where('patient_id', '==', patient_id).stream()
    patient_doc = next(patients, None)
    if patient_doc:
        patient_data = patient_doc.to_dict()
        # Remove PHI (name, contact)
        patient_data.pop('name', None)
        patient_data.pop('contact', None)
        data['patient'] = patient_data

    
    # Collect data from each workflow step
    collections = [
        'subjective_examination',
        'patient_perspectives', 
        'initial_plan',
        'patho_mechanism',
        'chronic_diseases',
        'clinical_flags',
        'objective_assessment',
        'provisional_diagnosis',
        'smart_goals',
        'treatment_plan'
    ]
    
    for collection in collections:
        docs = db.collection(collection).where('patient_id', '==', patient_id).stream()
        for doc in docs:
            data[collection] = doc.to_dict()
            break  # Get first/latest entry
    
    return data

# ENHANCED AI ENDPOINTS - Replace your existing ones with these:
@limiter.limit("5 per minute")
@app.route("/api/ai/subjective-exam", methods=["POST"])
@login_required()
def ai_subjective_exam():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get ALL cumulative data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Using the details below, generate one clinical statement for each of the 6 ICF categories:

1. Impairment of Body Structure  
2. Impairment of Body Function  
3. Activity Limitation – Performance  
4. Activity Limitation – Capacity  
5. Contextual Factors – Environmental  
6. Contextual Factors – Personal

Patient Info:
- Age: {patient.get('age')}
- Sex: {patient.get('sex')}
- Occupation: {patient.get('occupation')}
- Present History: {patient.get('present_history')}
- Past History: {patient.get('past_history')}
"""

        ai_response = call_claude(prompt)
        log_action(
    user_id=session['user_id'],
    action="AI Suggestion",
    details=f"Generated AI suggestion for {request.path} on patient {patient_id}"
)

        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/patient-perspectives", methods=["POST"])
@login_required()
def ai_patient_perspectives():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get cumulative data including subjective examination
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Summarize the patient's psychosocial profile across the following six perspectives:

1. Knowledge of Illness  
2. Illness Attribution  
3. Expectations from Therapy  
4. Awareness of Control  
5. Locus of Control  
6. Affective Aspects

Use one brief clinical statement per category.

Patient Input:
{perspectives}
"""
        ai_response = call_claude(prompt)
        log_action(
    user_id=session['user_id'],
    action="AI Suggestion",
    details=f"Generated AI suggestion for {request.path} on patient {patient_id}"
)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/initial-plan", methods=["POST"])
@login_required()
def ai_initial_plan():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get cumulative data from patient + subjective + perspectives
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Based on the patient’s clinical profile, suggest:

- Assessments that are mandatory  
- Assessments requiring precautions  
- Contraindicated assessments

Input Summary:
- Symptoms: {subjective.get('present_history')}
- Pathophysiology: {patho}
- Chronic Conditions: {chronic}
- Clinical Flags: {flags}

Keep suggestions short and categorized.
"""
        ai_response = call_claude(prompt)
        log_action(
    user_id=session['user_id'],
    action="AI Suggestion",
    details=f"Generated AI suggestion for {request.path} on patient {patient_id}"
)

        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/pathophysiological", methods=["POST"])
@login_required()
def ai_pathophysiological():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get cumulative data from all previous steps
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        
        prompt = f"""
Interpret the likely pathophysiological mechanisms based on the inputs below. Address key areas like pain type, source, irritability, and stage of healing.

Inputs:
- Present History: {subjective.get('present_history')}
- Provisional Diagnosis: {diagnosis}

List 3–5 bullet points covering distinct mechanisms.
"""
        ai_response = call_claude(prompt)
        log_action(
    user_id=session['user_id'],
    action="AI Suggestion",
    details=f"Generated AI suggestion for {request.path} on patient {patient_id}"
)

        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")   
@app.route("/api/ai/chronic-disease", methods=["POST"])
@login_required()
def ai_chronic_disease():
    try:
        data = request.json
        patient_id = data.get("patient_id")
        if not patient_id:
            return jsonify({"error": "Patient ID missing"}), 400

        # Fetch relevant patient data
        cumulative_data = get_cumulative_patient_data(patient_id)
        subjective = cumulative_data.get("subjective", {})
        diagnosis = cumulative_data.get("diagnosis", {})
        perspectives = cumulative_data.get("perspectives", {})

        # Claude AI prompt
        prompt = f"""
Based on symptoms, diagnosis, and psychosocial inputs, suggest chronic or lifestyle factors that may be maintaining the patient’s condition.

Inputs:
- Presenting Symptoms: {subjective.get('present_history')}
- Provisional Diagnosis: {diagnosis}
- Psychosocial Perspective: {perspectives}

List 2–3 likely contributing factors.
"""

        ai_response = call_claude(prompt)

        # Log usage
        log_action(
            user_id=session['user_id'],
            action="AI Suggestion",
            details=f"Generated chronic maintenance factor suggestions for patient {patient_id}"
        )

        return jsonify({"ai_suggestion": ai_response})

    except Exception as e:
        if DEBUG_AI:
            return jsonify({"error": str(e)}), 500
        return jsonify({"error": "Something went wrong"}), 500


@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-flags", methods=["POST"])
@login_required()
def ai_clinical_flags():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get comprehensive data from all previous steps
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        patho = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Identify possible clinical flags based on the patient's case. Include a short justification for each flag you list.

Types to consider:
- Red: Medical emergency
- Orange: Psychiatric condition
- Yellow: Emotional/cognitive barrier
- Blue: Work-related belief
- Black: System or social barrier

Inputs:
- Symptoms: {subjective.get('present_history')}
- Psychosocial: {perspectives}
- Diagnosis: {diagnosis}
"""
        ai_response = call_claude(prompt)
        log_action(
    user_id=session['user_id'],
    action="AI Suggestion",
    details=f"Generated AI suggestion for {request.path} on patient {patient_id}"
)

        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")   
@app.route("/api/ai/objective-assessment", methods=["POST"])
@login_required()
def ai_objective_assessment():
    try:
        data = request.json
        patient_id = data.get("patient_id")
        if not patient_id:
            return jsonify({"error": "Patient ID missing"}), 400

        # Fetch cumulative patient data
        cumulative_data = get_cumulative_patient_data(patient_id)
        subjective = cumulative_data.get("subjective", {})
        diagnosis = cumulative_data.get("diagnosis", {})
        patho = cumulative_data.get("pathophysiology", {})

        # Claude AI prompt (Optimized)
        prompt = f"""
Based on the case details below, suggest appropriate objective assessments for the physiotherapy examination. Structure your response under three categories:

1. Recommended Tests  
2. Modified Tests (due to pain/irritability or precautions)  
3. Contraindicated Tests (to be avoided)

Inputs:
- Presenting Symptoms: {subjective.get('present_history')}
- Provisional Diagnosis: {diagnosis}
- Pathophysiology Summary: {patho}

Keep explanations brief and clinically focused.
"""

        ai_response = call_claude(prompt)

        # Log usage
        log_action(
            user_id=session['user_id'],
            action="AI Suggestion",
            details=f"Generated objective assessment suggestions for patient {patient_id}"
        )

        return jsonify({"ai_suggestion": ai_response})

    except Exception as e:
        if DEBUG_AI:
            return jsonify({"error": str(e)}), 500
        return jsonify({"error": "Something went wrong"}), 500


@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis", methods=["POST"])
@login_required()
def ai_provisional_diagnosis():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get ALL previous clinical data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract all relevant data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho = all_data.get('patho_mechanism', {})
        chronic = all_data.get('chronic_diseases', {})
        flags = all_data.get('clinical_flags', {})
        objective = all_data.get('objective_assessment', {})
        
        prompt = f"""
Based on the following case inputs, provide:

1. A short provisional diagnosis  
2. One-line clinical reasoning to support it

Inputs:
- Symptoms: {subjective.get('present_history')}
- Objective Findings: {objective}
- Relevant Flags: {flags}

Based on the above, provide:
1. Most likely provisional diagnosis with confidence level
2. Primary structure(s) at fault
3. Key symptoms supporting the diagnosis
4. Clinical findings that support this diagnosis
5. Findings that might contradict this diagnosis  
6. Overall assessment of whether hypothesis is supported

Format as structured clinical reasoning.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/smart-goals", methods=["POST"])
@login_required()
def ai_smart_goals():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get comprehensive clinical data for goal setting
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        patho = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Based on the patient’s case summary, generate 3 SMART goals. Each goal must include:

1. Patient-Centric Goal  
2. Baseline Status  
3. Measurable Outcome Expected  
4. Time Duration to achieve it

Inputs:
- Presenting Symptoms: {subjective.get('present_history')}
- Provisional Diagnosis: {diagnosis}
- Objective Findings: {objective}

Format your output like this:

Goal 1:
- Goal: ...
- Baseline: ...
- Outcome: ...
- Duration: ...

Goal 2:
...
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/treatment-plan", methods=["POST"])
@login_required()
def ai_treatment_plan():
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get ALL clinical data for comprehensive treatment planning
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical picture
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho = all_data.get('patho_mechanism', {})
        chronic = all_data.get('chronic_diseases', {})
        flags = all_data.get('clinical_flags', {})
        objective = all_data.get('objective_assessment', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        goals = all_data.get('smart_goals', {})
        
        prompt = f"""
Based on the following case summary, suggest a structured physiotherapy treatment plan.

Include:
1. Manual Therapy (if any)  
2. Therapeutic Exercises  
3. Electrotherapy or Modalities  
4. Frequency & Duration (per week)  
5. Progression criteria  
6. Special precautions (if needed)

Inputs:
- Presenting Symptoms: {subjective.get('present_history')}
- Objective Findings: {objective}
- Provisional Diagnosis: {diagnosis}
- SMART Goals: {smart_goals}

Keep the plan realistic and relevant to the diagnosis and goals.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

# ADD THESE FOLLOW-UP AI ENDPOINTS TO THE END OF YOUR APP.PY
# (After your clinical workflow AI endpoints, before if __name__ == '__main__':)
@limiter.limit("5 per minute")
@app.route("/api/ai/followup-recommendations", methods=["POST"])
@login_required()
def ai_followup_recommendations():
    """AI recommendations for follow-up session based on patient history and previous sessions"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_number = data.get("session_number", "")
        
        if not patient_id:
            return jsonify({"error": "Patient ID required"}), 400

        # Get comprehensive patient data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Get existing follow-ups to analyze progress
        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.DESCENDING) \
                      .stream()
        
        followup_list = [f.to_dict() for f in followups]

        # Extract key data for AI analysis
        patient = all_data['patient']
        treatment_plan = all_data.get('treatment_plan', {})
        goals = all_data.get('smart_goals', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        
        # Build follow-up history for context
        previous_sessions = []
        if followup_list:
            for i, followup in enumerate(followup_list[:5]):  # Last 5 sessions
                session_info = f"Session {followup.get('session_number', '')}: Grade '{followup.get('grade', '')}', Perception '{followup.get('belief_treatment', '')}', Plan: {followup.get('treatment_plan', '')[:100]}..."
                previous_sessions.append(session_info)

        prompt = f"""
You are assisting a physiotherapist with follow-up session planning for patient {patient_id}.

PATIENT OVERVIEW:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Upcoming Session: {session_number}

TREATMENT CONTEXT:
- Provisional Diagnosis: {diagnosis.get('structure_fault', '')} - {diagnosis.get('symptom', '')}
- Treatment Goals: {goals.get('patient_goal', '')}
- Current Treatment Plan: {treatment_plan.get('treatment_plan', '')}
- Goal Timeline: {goals.get('time_duration', '')}

PREVIOUS SESSION HISTORY:
{chr(10).join(previous_sessions) if previous_sessions else 'This is the first follow-up session'}

Based on this clinical information, provide recommendations for this follow-up session:

1. GRADE OF ACHIEVEMENT GUIDANCE:
   - Expected grade range for this session (Goal Achieved, Partially Achieved, Not Achieved)
   - Factors that might influence achievement level
   - Progress indicators to assess

2. PERCEPTION OF TREATMENT ASSESSMENT:
   - Expected patient perception (Very Effective, Effective, Moderately Effective, Not Effective)
   - Key questions to ask about treatment effectiveness
   - Signs of positive/negative treatment response

3. FEEDBACK COLLECTION:
   - Important feedback areas to explore
   - Patient-reported outcome measures to consider
   - Functional improvements to assess

4. TREATMENT PLAN MODIFICATIONS:
   - Suggested adjustments based on expected progress
   - Exercise progression recommendations
   - New interventions to consider
   - Discharge planning considerations if appropriate

5. SESSION FOCUS AREAS:
   - Priority areas for this session
   - Assessment techniques to use
   - Patient education points
   - Home program updates

Keep recommendations practical and specific to physiotherapy follow-up sessions.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Follow-up Recommendations",
            details=f"Generated AI recommendations for patient {patient_id} session {session_number}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI follow-up recommendations error: {str(e)}")
        return jsonify({"error": "AI recommendations failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/followup-progress-analysis", methods=["POST"])
@login_required()
def ai_followup_progress_analysis():
    """AI analysis of patient progress based on all follow-up sessions"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        if not patient_id:
            return jsonify({"error": "Patient ID required"}), 400

        # Get comprehensive patient data
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Get ALL follow-up sessions for progress analysis
        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.ASCENDING) \
                      .stream()
        
        followup_list = [f.to_dict() for f in followups]

        if not followup_list:
            return jsonify({"response": "No follow-up sessions recorded yet. Complete some sessions first to get progress analysis."})

        # Extract treatment data
        patient = all_data['patient']
        goals = all_data.get('smart_goals', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        treatment_plan = all_data.get('treatment_plan', {})
        
        # Analyze progress trends
        grade_progression = []
        perception_progression = []
        for followup in followup_list:
            grade_progression.append(f"Session {followup.get('session_number', '')}: {followup.get('grade', '')}")
            perception_progression.append(f"Session {followup.get('session_number', '')}: {followup.get('belief_treatment', '')}")

        prompt = f"""
Analyze the physiotherapy treatment progress for patient {patient_id}.

INITIAL PRESENTATION:
- Diagnosis: {diagnosis.get('structure_fault', '')} - {diagnosis.get('symptom', '')}
- Treatment Goals: {goals.get('patient_goal', '')}
- Expected Timeline: {goals.get('time_duration', '')}
- Baseline Status: {goals.get('baseline_status', '')}

TREATMENT APPROACH:
- Treatment Plan: {treatment_plan.get('treatment_plan', '')}
- Goals Targeted: {treatment_plan.get('goal_targeted', '')}

PROGRESS DATA ({len(followup_list)} sessions completed):

Grade of Achievement Progression:
{chr(10).join(grade_progression)}

Patient Perception Progression:
{chr(10).join(perception_progression)}

Treatment Plans by Session:
{chr(10).join([f"Session {f.get('session_number', '')}: {f.get('treatment_plan', '')}" for f in followup_list])}

Patient Feedback:
{chr(10).join([f"Session {f.get('session_number', '')}: {f.get('belief_feedback', '')}" for f in followup_list if f.get('belief_feedback')])}

Based on this comprehensive progress data, provide:

1. OVERALL PROGRESS ASSESSMENT:
   - Treatment effectiveness evaluation
   - Progress trend analysis (improving/plateau/declining)
   - Comparison with expected timeline

2. GRADE ACHIEVEMENT ANALYSIS:
   - Pattern of goal achievement over time
   - Factors contributing to success/challenges
   - Expected vs actual progress

3. PATIENT PERCEPTION TRENDS:
   - Patient satisfaction with treatment
   - Changes in treatment perception over time
   - Correlation between perception and objective progress

4. TREATMENT RESPONSE ANALYSIS:
   - Most effective interventions identified
   - Areas needing treatment modification
   - Patient engagement and compliance indicators

5. FUTURE RECOMMENDATIONS:
   - Next phase treatment suggestions
   - Goal modifications if needed
   - Discharge planning timeline
   - Long-term management considerations

6. OUTCOME PREDICTION:
   - Expected final outcomes based on current progress
   - Factors that may influence future success
   - Risk factors for treatment plateau or regression

Provide specific, evidence-based analysis suitable for clinical decision-making.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Progress Analysis",
            details=f"Generated progress analysis for patient {patient_id} based on {len(followup_list)} sessions"
        )
        
        return jsonify({
            "response": ai_response,
            "session_count": len(followup_list),
            "latest_grade": followup_list[-1].get('grade', '') if followup_list else '',
            "latest_perception": followup_list[-1].get('belief_treatment', '') if followup_list else ''
        })
        
    except Exception as e:
        print(f"AI progress analysis error: {str(e)}")
        return jsonify({"error": "AI progress analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/followup-session-insights", methods=["POST"])
@login_required()
def ai_followup_session_insights():
    """AI insights for a specific follow-up session"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_number = data.get("session_number")
        grade = data.get("grade", "")
        perception = data.get("perception", "")
        feedback = data.get("feedback", "")
        treatment_plan = data.get("treatment_plan", "")
        
        if not patient_id:
            return jsonify({"error": "Patient ID required"}), 400

        # Get patient context
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        goals = all_data.get('smart_goals', {})
        diagnosis = all_data.get('provisional_diagnosis', {})
        
        # Get previous sessions for context
        previous_followups = db.collection('follow_ups') \
                              .where('patient_id', '==', patient_id) \
                              .order_by('session_date', direction=firestore.Query.DESCENDING) \
                              .stream()
        
        previous_sessions = [f.to_dict() for f in previous_followups]

        prompt = f"""
Provide clinical insights for this specific follow-up session:

PATIENT CONTEXT:
- Patient: {patient.get('age_sex', '')}
- Condition: {diagnosis.get('structure_fault', '')}
- Treatment Goals: {goals.get('patient_goal', '')}

CURRENT SESSION DATA:
- Session Number: {session_number}
- Grade of Achievement: {grade}
- Patient Perception: {perception}
- Patient Feedback: {feedback}
- Treatment Plan: {treatment_plan}

PREVIOUS PROGRESS:
{chr(10).join([f"Session {p.get('session_number', '')}: {p.get('grade', '')} - {p.get('belief_treatment', '')}" for p in previous_sessions[:3]]) if previous_sessions else 'No previous sessions'}

Based on this session data, provide:

1. SESSION INTERPRETATION:
   - Analysis of the grade of achievement
   - Significance of patient perception
   - Clinical meaning of patient feedback

2. PROGRESS INDICATORS:
   - Positive indicators from this session
   - Areas of concern to monitor
   - Comparison with previous sessions

3. TREATMENT EFFECTIVENESS:
   - Assessment of current treatment approach
   - Suggested modifications based on session outcomes
   - Patient response patterns

4. NEXT SESSION PLANNING:
   - Recommendations for next treatment session
   - Areas to focus on
   - Expected progression

5. CLINICAL DECISION POINTS:
   - Key decisions needed based on this session
   - Risk factors to address
   - Opportunities for treatment advancement

Keep analysis practical and actionable for immediate clinical use.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Session Insights",
            details=f"Generated insights for patient {patient_id} session {session_number}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI session insights error: {str(e)}")
        return jsonify({"error": "AI session insights failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/past-history-questions", methods=["POST"])
@login_required()
def ai_past_history_questions():
    """AI suggests specific past history questions based on present history"""
    try:
        data = request.get_json()
        present_history = data.get("present_history", "")
        age_sex = data.get("age_sex", "")
        
        if not present_history:
            return jsonify({"error": "Present history required"}), 400

        prompt = f"""
You are an expert physiotherapist conducting patient intake. Based on the presenting complaint, suggest specific, targeted past history questions that are most clinically relevant.

PATIENT INFORMATION:
- Age/Sex: {age_sex}
- Present History/Chief Complaint: {present_history}

Based on this presentation, provide:

**🎯 PRIORITY PAST HISTORY QUESTIONS:**
(Top 5-8 most important questions to ask)

1. **Previous Episodes:** 
   - Has this problem occurred before? When? How was it treated?
   - Any similar symptoms in the past?

2. **Medical History:**
   - [Condition-specific medical conditions to screen for]
   - [Relevant surgical history to explore]

3. **Medication History:**
   - [Specific medications that might be relevant]
   - Pain medication usage patterns

4. **Activity/Occupation History:**
   - [Specific activities/occupations that might relate to condition]
   - Sports/exercise history relevant to presentation

5. **Family History:**
   - [Condition-specific genetic/familial factors]

6. **System-Specific Questions:**
   - [Based on presenting complaint - ask about related body systems]

**🚨 RED FLAG SCREENING QUESTIONS:**
(Critical questions to rule out serious pathology)
- [Specific red flag questions for this presentation]

**💡 CLINICAL REASONING:**
- Why these questions are important for this presentation
- What conditions you're screening for/ruling out
- How responses will guide examination planning

Provide specific, actionable questions that a physiotherapist would actually ask. Make questions clear and patient-friendly.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Past History Questions",
            details=f"Generated past history questions for: {present_history[:50]}..."
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI past history questions error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/preliminary-diagnosis", methods=["POST"])
@login_required()
def ai_preliminary_diagnosis():
    """AI generates preliminary diagnostic hypotheses based on initial patient data"""
    try:
        data = request.get_json()
        age_sex = data.get("age_sex", "")
        present_history = data.get("present_history", "")
        past_history = data.get("past_history", "")
        
        if not present_history:
            return jsonify({"error": "Present history required"}), 400

        prompt = f"""
You are an expert physiotherapist developing preliminary diagnostic hypotheses. Based on limited initial information, provide educated clinical hypotheses to guide examination planning.

INITIAL PATIENT DATA:
- Demographics: {age_sex}
- Present History: {present_history}
- Past History: {past_history}

**🎯 PRELIMINARY DIAGNOSTIC HYPOTHESES:**

**PRIMARY HYPOTHESIS (Most Likely):**
- Condition: [Most probable diagnosis]
- Confidence Level: [High/Moderate/Low]
- Reasoning: [Why this is most likely]
- Key Features Supporting: [Specific symptoms/factors]

**ALTERNATIVE HYPOTHESES:**
1. **Secondary Hypothesis:**
   - Condition: [Second most likely]
   - Reasoning: [Clinical reasoning]

2. **Third Hypothesis:**
   - Condition: [Alternative consideration]
   - Reasoning: [Why to consider]

**🚨 SERIOUS PATHOLOGY CONSIDERATIONS:**
- Red Flag Conditions to Rule Out: [Specific conditions]
- Screening Priority: [High/Medium/Low]
- Immediate Concerns: [Any urgent considerations]

**📋 EXAMINATION PRIORITIES:**
Based on these hypotheses, prioritize:
1. **Must Assess:** [Critical tests/areas to examine]
2. **Should Assess:** [Important but not critical]
3. **Could Assess:** [Additional considerations]

**⚠️ PRECAUTIONS FOR EXAMINATION:**
- Movement restrictions to consider
- Assessment modifications needed
- Safety considerations

**🎓 PATIENT EDUCATION PRIORITIES:**
- Key points to explain about likely condition
- Reassurance vs precaution balance
- Activity modifications to discuss

**📊 OUTCOME MEASURES TO CONSIDER:**
- Appropriate baseline measures for likely conditions
- Functional tests to establish
- Pain/disability scales relevant

Remember: These are preliminary hypotheses to guide examination. Maintain diagnostic flexibility and avoid premature closure. Focus on ruling out serious pathology and establishing a systematic examination approach.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Preliminary Diagnosis",
            details=f"Generated diagnostic hypotheses for: {present_history[:50]}..."
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI preliminary diagnosis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-intake-summary", methods=["POST"])
@login_required()
def ai_clinical_intake_summary():
    """AI provides comprehensive intake summary and next steps"""
    try:
        data = request.get_json()
        patient_data = {
            'age_sex': data.get("age_sex", ""),
            'present_history': data.get("present_history", ""),
            'past_history': data.get("past_history", ""),
            'contact': data.get("contact", "")
        }
        
        if not patient_data['present_history']:
            return jsonify({"error": "Present history required"}), 400

        prompt = f"""
You are completing patient intake and preparing for subjective examination. Provide a comprehensive clinical summary and examination planning.

COMPLETE PATIENT INTAKE:
- Demographics: {patient_data['age_sex']}
- Chief Complaint: {patient_data['present_history']}
- Past Medical History: {patient_data['past_history']}

**📊 CLINICAL INTAKE SUMMARY:**

**Patient Profile:**
- Age/demographic considerations for condition
- Key presenting symptoms and their significance
- Relevant past history factors
- Clinical complexity level: [Simple/Moderate/Complex]

**⚠️ IMMEDIATE CLINICAL PRIORITIES:**
1. **Safety Assessment:**
   - Red flag screening results: [Clear/Needs monitoring/Concerning]
   - Immediate precautions needed
   
2. **Symptom Severity:**
   - Likely pain/disability level: [Mild/Moderate/Severe]
   - Functional impact assessment
   - Urgency of intervention: [Routine/Expedited/Urgent]

**🎯 TOP 3 DIAGNOSTIC HYPOTHESES:**
1. [Most likely condition] - [confidence %]
2. [Alternative diagnosis] - [confidence %]  
3. [Other consideration] - [confidence %]

**📋 SUBJECTIVE EXAMINATION PLANNING:**

**ICF Framework Priorities:**
- **Body Structure/Function:** [Key areas to explore]
- **Activity/Participation:** [Functional limitations to assess]
- **Contextual Factors:** [Environmental/personal factors to explore]

**Key Questions for Next Phase:**
- Pain behavior and mechanisms to explore
- Functional limitations to quantify
- Psychosocial factors to assess
- Work/activity demands to understand

**📏 BASELINE MEASURES TO ESTABLISH:**
- Pain scales: [Recommended scales]
- Functional measures: [Specific outcome measures]
- Activity assessments: [Key functional tests]

**🎓 PATIENT EDUCATION OPPORTUNITIES:**
- Condition explanation approach
- Reassurance vs realistic expectations
- Activity modification guidance
- Treatment timeline expectations

**⏭️ NEXT SESSION OBJECTIVES:**
1. Complete comprehensive subjective examination
2. Establish baseline functional measures
3. Develop initial treatment hypotheses
4. Plan objective examination priorities

This intake establishes a strong foundation for evidence-based physiotherapy assessment and treatment planning.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Clinical Intake Summary",
            details=f"Generated intake summary for patient presentation"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI clinical intake summary error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

# ADD THESE NEW AI ENDPOINTS TO YOUR APP.PY (after the previous 3 endpoints)

@limiter.limit("5 per minute")
@app.route("/api/ai/body-structure-suggestions", methods=["POST"])
@login_required()
def ai_body_structure_suggestions():
    """AI suggests body structure impairments based on patient history and current input"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        current_input = data.get("current_input", "")
        
        # Get cumulative patient data from add_patient
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Based on patient history and current input, suggest specific body structure impairments for ICF framework.

PATIENT BACKGROUND:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

CURRENT INPUT: {current_input}

Provide specific body structure impairment suggestions:

**🏗️ BODY STRUCTURE IMPAIRMENTS:**
- Focus on anatomical structures likely involved
- Consider tissue-specific impairments (bone, joint, muscle, nerve, fascia)
- Include structural deviations, damage, or abnormalities
- Use precise anatomical terminology
- Consider age-related and condition-specific changes

**Examples for this presentation:**
1. [Specific structure 1]: [Type of impairment]
2. [Specific structure 2]: [Type of impairment]
3. [Additional structures if relevant]

**Clinical Reasoning:**
- Why these structures are likely involved
- How patient history supports these suggestions
- Relationship to presenting symptoms

Keep suggestions specific, clinically relevant, and ready for direct use in documentation.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/body-function-suggestions", methods=["POST"])
@login_required()
def ai_body_function_suggestions():
    """AI suggests body function impairments based on cumulative data"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        current_input = data.get("current_input", "")
        body_structure = data.get("body_structure", "")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Suggest body function impairments based on patient presentation and body structure findings.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

BODY STRUCTURE INPUT: {body_structure}
CURRENT FUNCTION INPUT: {current_input}

**⚙️ BODY FUNCTION IMPAIRMENTS:**

**Primary Function Impairments:**
- Pain/nociceptive functions
- Movement functions (range, quality, control)
- Muscle power functions
- Sensory functions (touch, proprioception, vibration)
- Neuromusculoskeletal functions

**Secondary Function Impairments:**
- Cardiovascular functions (if relevant)
- Respiratory functions (if relevant)
- Sleep functions
- Energy/fatigue functions

**Specific Suggestions for this Case:**
1. **Pain Functions:** [Specific pain characteristics/mechanisms]
2. **Movement Functions:** [Specific movement impairments]
3. **Muscle Functions:** [Strength/endurance/power issues]
4. **Sensory Functions:** [Sensory changes expected]
5. **Other Relevant Functions:** [Additional impairments]

**Functional Mechanisms:**
- How these functions relate to the structural impairments
- Primary vs secondary impairment patterns
- Expected functional relationships

Provide specific, measurable function descriptions ready for clinical documentation.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/activity-performance-suggestions", methods=["POST"])
@login_required()
def ai_activity_performance_suggestions():
    """AI suggests activity performance limitations based on cumulative data"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        current_input = data.get("current_input", "")
        previous_fields = data.get("previous_fields", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Suggest activity performance limitations based on patient presentation and impairments identified.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

IDENTIFIED IMPAIRMENTS:
- Body Structure: {previous_fields.get('body_structure', '')}
- Body Function: {previous_fields.get('body_function', '')}

CURRENT INPUT: {current_input}

**🏃‍♂️ ACTIVITY PERFORMANCE LIMITATIONS:**

**Daily Living Activities:**
- Self-care activities (dressing, bathing, grooming)
- Household tasks (cleaning, cooking, lifting)
- Mobility activities (walking, stairs, transfers)

**Work/Occupational Activities:**
- Job-specific task limitations
- Workplace movement restrictions
- Ergonomic considerations
- Productivity impacts

**Recreation/Sports Activities:**
- Sports-specific limitations
- Exercise restrictions
- Leisure activity impacts
- Social activity participation

**Specific Performance Issues for this Case:**
1. **Primary Limitations:** [Most significant activity restrictions]
2. **Secondary Limitations:** [Related activity impacts]
3. **Compensatory Behaviors:** [How patient adapts/modifies activities]
4. **Avoidance Patterns:** [Activities patient stops doing]

**Performance Context:**
- Real-world environment challenges
- Time-of-day variations
- Load/intensity effects
- Environmental barriers

**Quantification Suggestions:**
- Measurable performance indicators
- Frequency/duration limitations
- Quality of performance issues
- Pain/symptom relationship to activities

Focus on what the patient actually does in their real environment, including modifications and limitations.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/activity-capacity-suggestions", methods=["POST"])
@login_required()
def ai_activity_capacity_suggestions():
    """AI suggests activity capacity limitations for standardized assessment"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        current_input = data.get("current_input", "")
        previous_fields = data.get("previous_fields", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Suggest activity capacity limitations for standardized clinical assessment.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}

IDENTIFIED FACTORS:
- Body Structure: {previous_fields.get('body_structure', '')}
- Body Function: {previous_fields.get('body_function', '')}
- Performance Issues: {previous_fields.get('activity_performance', '')}

CURRENT INPUT: {current_input}

**💪 ACTIVITY CAPACITY LIMITATIONS:**

**Standardized Assessment Predictions:**
- Maximum capacity under optimal conditions
- Standardized test performance expectations
- Clinical assessment limitations
- Controlled environment capabilities

**Specific Capacity Areas:**
1. **Movement Capacity:**
   - Range of motion limitations
   - Movement quality restrictions
   - Speed/agility capacity
   - Coordination capacity

2. **Strength/Power Capacity:**
   - Maximum strength limitations
   - Endurance capacity restrictions
   - Power output limitations
   - Fatigue response patterns

3. **Functional Capacity:**
   - Lifting/carrying capacity
   - Standing/walking tolerance
   - Stair climbing ability
   - Balance/stability capacity

**Assessment Recommendations:**
- Specific tests to measure capacity
- Expected baseline measurements
- Safety considerations for testing
- Modifications needed for assessment

**Capacity vs Performance Gap:**
- Expected difference between what patient can do vs does do
- Factors limiting performance despite capacity
- Rehabilitation potential indicators

**Standardized Measures to Consider:**
- Functional capacity evaluations
- Standardized movement tests
- Strength testing protocols
- Endurance assessments

Focus on maximum ability under controlled, standardized conditions rather than real-world performance.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/environmental-factors-suggestions", methods=["POST"])
@login_required()
def ai_environmental_factors_suggestions():
    """AI suggests environmental contextual factors"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        current_input = data.get("current_input", "")
        previous_fields = data.get("previous_fields", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Suggest environmental contextual factors that may facilitate or hinder recovery and function.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

ACTIVITY LIMITATIONS IDENTIFIED:
- Performance: {previous_fields.get('activity_performance', '')}
- Capacity: {previous_fields.get('activity_capacity', '')}

CURRENT INPUT: {current_input}

**🌍 ENVIRONMENTAL FACTORS:**

**Physical Environment:**
- Home environment (stairs, layout, accessibility)
- Workplace ergonomics and demands
- Transportation considerations
- Community accessibility
- Exercise/recreation facilities

**Support Systems:**
- Family/caregiver support
- Healthcare team coordination
- Workplace support/accommodations
- Community resources
- Insurance/financial support

**Technology/Equipment:**
- Assistive devices needed
- Workplace equipment modifications
- Home equipment considerations
- Technology supports available

**Work Environment Factors:**
- Physical demands of work
- Workplace culture and support
- Schedule flexibility
- Return-to-work considerations
- Occupational health resources

**Social Environment:**
- Social support networks
- Community participation opportunities
- Cultural factors affecting treatment
- Language/communication considerations

**Specific Environmental Considerations:**
1. **Facilitators:** [Environmental factors that help recovery/function]
2. **Barriers:** [Environmental factors that hinder progress]
3. **Modifications Needed:** [Environmental changes to recommend]
4. **Resources Required:** [Support systems to engage]

**Assessment Questions to Explore:**
- Key environmental factors to investigate
- Support systems to evaluate
- Barriers to identify and address
- Resources to mobilize

Focus on external factors that impact the patient's condition, recovery, and functional participation.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/personal-factors-suggestions", methods=["POST"])
@login_required()
def ai_personal_factors_suggestions():
    """AI suggests personal contextual factors"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        current_input = data.get("current_input", "")
        previous_fields = data.get("previous_fields", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Suggest personal contextual factors that influence the patient's condition and treatment approach.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

COMPREHENSIVE ICF CONTEXT:
- Body Structure: {previous_fields.get('body_structure', '')}
- Body Function: {previous_fields.get('body_function', '')}
- Activity Performance: {previous_fields.get('activity_performance', '')}
- Environmental Factors: {previous_fields.get('contextual_environmental', '')}

CURRENT INPUT: {current_input}

**👤 PERSONAL FACTORS:**

**Demographic Factors:**
- Age-related considerations for this condition
- Gender-specific factors affecting presentation/treatment
- Life stage implications
- Cultural background influences

**Lifestyle Factors:**
- Activity level and fitness background
- Occupation demands and characteristics
- Sleep patterns and quality
- Nutrition and health habits
- Substance use considerations

**Psychological Factors:**
- Coping strategies and resilience
- Previous healthcare experiences
- Health beliefs and attitudes
- Motivation for recovery
- Anxiety/fear patterns
- Self-efficacy beliefs

**Medical/Health Factors:**
- Comorbidity impacts
- Medication effects
- Previous injury/treatment history
- General health status
- Pain experience and coping

**Social/Educational Factors:**
- Education level affecting understanding
- Health literacy considerations
- Social roles and responsibilities
- Previous physical therapy experience
- Learning preferences

**Specific Personal Considerations:**
1. **Facilitating Factors:** [Personal strengths supporting recovery]
2. **Risk Factors:** [Personal factors that may hinder progress]
3. **Adaptation Factors:** [How patient typically copes with challenges]
4. **Motivation Factors:** [What drives this patient's engagement]

**Clinical Implications:**
- How these factors affect treatment planning
- Communication style considerations
- Education approach modifications
- Goal-setting considerations
- Compliance/adherence factors

Focus on internal patient characteristics that influence their health condition, treatment response, and outcomes.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/subjective-exam-summary", methods=["POST"])
@login_required()
def ai_subjective_exam_summary():
    """AI provides comprehensive subjective examination summary and next steps"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        subjective_data = data.get("subjective_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Provide comprehensive subjective examination summary and clinical reasoning for next steps.

PATIENT BACKGROUND:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

COMPLETE ICF SUBJECTIVE EXAMINATION:
- Body Structure: {subjective_data.get('body_structure', '')}
- Body Function: {subjective_data.get('body_function', '')}
- Activity Performance: {subjective_data.get('activity_performance', '')}
- Activity Capacity: {subjective_data.get('activity_capacity', '')}
- Environmental Factors: {subjective_data.get('contextual_environmental', '')}
- Personal Factors: {subjective_data.get('contextual_personal', '')}

**📊 COMPREHENSIVE SUBJECTIVE SUMMARY:**

**Clinical Profile:**
- Overall complexity level: [Simple/Moderate/Complex]
- Primary impairment pattern: [Dominant clinical pattern]
- Functional impact severity: [Mild/Moderate/Severe]
- Psychosocial complexity: [Low/Moderate/High]

**ICF Framework Analysis:**
1. **Impairment Level:** [Key body structure/function issues]
2. **Activity Level:** [Primary functional limitations]
3. **Participation Level:** [Life role impacts]
4. **Contextual Influences:** [Key facilitators and barriers]

**🎯 REFINED DIAGNOSTIC HYPOTHESES:**
Based on comprehensive subjective data:
1. **Primary Hypothesis:** [Most likely diagnosis with confidence]
2. **Alternative Hypotheses:** [Other possibilities to consider]
3. **Red Flag Assessment:** [Serious pathology screening results]

**🔍 OBJECTIVE EXAMINATION PRIORITIES:**

**Must Assess (High Priority):**
- [Critical tests/measurements needed]
- [Safety-related assessments]
- [Diagnostic confirmation tests]

**Should Assess (Moderate Priority):**
- [Important functional measures]
- [Impairment quantification]
- [Baseline outcome measures]

**Could Assess (Lower Priority):**
- [Additional tests if time permits]
- [Research/quality measures]

**⚠️ CLINICAL PRECAUTIONS:**
- Movement restrictions to observe
- Assessment modifications needed
- Safety considerations for testing
- Patient-specific precautions

**🎓 PATIENT EDUCATION PLANNING:**
- Key concepts to explain about condition
- Reassurance vs realistic expectations
- Activity modification guidance
- Pain education needs

**📋 NEXT SESSION OBJECTIVES:**
1. Complete systematic objective examination
2. Establish baseline functional measures
3. Confirm/refine diagnostic hypotheses
4. Develop evidence-based treatment plan

**📊 OUTCOME MEASURES RECOMMENDATIONS:**
- Condition-specific measures to use
- Generic functional assessments
- Pain/disability scales appropriate
- Return-to-activity measures

This subjective examination provides a solid foundation for evidence-based clinical reasoning and treatment planning.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Subjective Exam Summary",
            details=f"Generated subjective examination summary for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/patient-perspectives-planning", methods=["POST"])
@login_required()
def ai_patient_perspectives_planning():
    """AI provides planning for patient perspectives assessment based on subjective findings"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        subjective_data = data.get("subjective_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        
        prompt = f"""
Plan patient perspectives assessment based on comprehensive subjective examination findings.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

SUBJECTIVE EXAMINATION FINDINGS:
- Functional Impact: {subjective_data.get('activity_performance', '')}
- Personal Factors: {subjective_data.get('contextual_personal', '')}
- Environmental Context: {subjective_data.get('contextual_environmental', '')}
- Body Function Issues: {subjective_data.get('body_function', '')}

**🧠 PATIENT PERSPECTIVES ASSESSMENT PLANNING:**

**Key Areas to Explore:**

**1. Knowledge of Illness:**
- Patient's understanding of their condition
- Accuracy of illness perceptions
- Information needs identified
- Educational priorities

**2. Illness Attribution:**
- Patient's beliefs about what caused their problem
- Attribution patterns (internal vs external)
- Blame or guilt patterns
- Control beliefs

**3. Expectation Management:**
- Recovery timeline expectations
- Treatment outcome expectations
- Return to activity expectations
- Realistic vs unrealistic expectations

**4. Control and Self-Efficacy:**
- Patient's sense of control over condition
- Confidence in ability to manage symptoms
- Self-management capabilities
- Locus of control orientation

**5. Affective Responses:**
- Emotional reactions to condition
- Fear-avoidance behaviors
- Anxiety or depression indicators
- Coping strategies employed

**🎯 SPECIFIC QUESTIONS TO EXPLORE:**
Based on subjective findings:
- [Targeted questions about illness perceptions]
- [Specific expectation clarifications needed]
- [Control/self-efficacy areas to assess]
- [Emotional/affective aspects to explore]

**🚨 PSYCHOSOCIAL RISK INDICATORS:**
From subjective examination:
- Yellow flag indicators identified
- Blue flag considerations
- Risk stratification level
- Intervention priorities

**📋 PERSPECTIVES ASSESSMENT PRIORITIES:**
1. **Immediate Concerns:** [Urgent psychosocial issues]
2. **Education Needs:** [Knowledge gaps to address]
3. **Expectation Alignment:** [Unrealistic expectations to modify]
4. **Coping Enhancement:** [Coping strategies to develop]

**⏭️ INTEGRATION WITH CLINICAL PLAN:**
- How perspectives will influence treatment approach
- Patient-centered goal development considerations
- Communication style adaptations needed
- Collaborative treatment planning approach

This perspectives assessment will ensure patient-centered, biopsychosocial treatment planning.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Patient Perspectives Planning",
            details=f"Generated perspectives planning for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500
    

# ADD THESE NEW AI ENDPOINTS TO YOUR APP.PY (after the subjective examination endpoints)

@limiter.limit("5 per minute")
@app.route("/api/ai/knowledge-illness-suggestions", methods=["POST"])
@login_required()
def ai_knowledge_illness_suggestions():
    """AI suggests knowledge of illness analysis based on dropdown selection and cumulative data"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        dropdown_value = data.get("dropdown_value", "")
        current_input = data.get("current_input", "")
        
        # Get ALL cumulative patient data
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Based on patient's clinical presentation and their knowledge level selection, provide detailed analysis of their illness understanding.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

SUBJECTIVE FINDINGS:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Issues: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

SELECTED KNOWLEDGE LEVEL: {dropdown_value}
CURRENT INPUT: {current_input}

**🧠 KNOWLEDGE OF ILLNESS ANALYSIS:**

**Patient's Current Understanding:**
- What the patient likely knows about their condition
- Accuracy of their understanding based on presentation
- Common misconceptions for this condition
- Knowledge gaps to address

**Education Priorities:**
- Key concepts to explain about their condition
- Anatomical/physiological education needs
- Prognosis and timeline information
- Activity/lifestyle education requirements

**Communication Strategy:**
- Appropriate level of medical terminology
- Visual aids or analogies that would help
- Family/caregiver education needs
- Written information to provide

**Specific Suggestions for "{dropdown_value}" Knowledge Level:**
- Tailored education approach for this knowledge level
- Information delivery strategy
- Assessment of understanding methods
- Follow-up education planning

**Red Flags in Understanding:**
- Concerning beliefs about their condition
- Unrealistic expectations to address
- Fear-inducing misconceptions to correct
- Barriers to learning to overcome

Provide specific, actionable insights that guide patient education and communication strategies.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Knowledge Illness Analysis",
            details=f"Generated knowledge analysis for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/attribution-suggestions", methods=["POST"])
@login_required()
def ai_attribution_suggestions():
    """AI suggests attribution analysis based on selection and cumulative data"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        dropdown_value = data.get("dropdown_value", "")
        current_input = data.get("current_input", "")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Analyze patient's illness attribution beliefs and their clinical implications.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Present History: {patient.get('present_history', '')}
- Past History: {patient.get('past_history', '')}

CLINICAL PRESENTATION:
- Activity Limitations: {subjective.get('activity_performance', '')}
- Personal Context: {subjective.get('contextual_personal', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}

SELECTED ATTRIBUTION: {dropdown_value}
CURRENT INPUT: {current_input}

**🎯 ATTRIBUTION ANALYSIS:**

**Patient's Causal Beliefs:**
- What the patient believes caused their problem
- Internal vs external attribution patterns
- Accuracy of their causal beliefs
- Impact on treatment engagement

**Attribution Implications:**
- How attribution affects coping strategies
- Influence on treatment compliance
- Self-blame or external blame patterns
- Control beliefs related to attribution

**Clinical Significance:**
- Helpful vs unhelpful attribution patterns
- Risk factors for poor outcomes
- Protective factors for recovery
- Treatment approach modifications needed

**Intervention Strategies for "{dropdown_value}" Attribution:**
- Specific approaches for this attribution pattern
- Cognitive restructuring needs
- Education to modify unhelpful beliefs
- Reinforcement of helpful beliefs

**Therapeutic Communication:**
- How to discuss causation appropriately
- Validation vs challenge strategies
- Guilt/blame reduction approaches
- Empowerment through understanding

**Yellow Flag Considerations:**
- Attribution patterns that increase chronicity risk
- Psychosocial intervention needs
- Referral considerations
- Monitoring strategies

Provide insights that inform patient-centered communication and intervention planning.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/expectation-suggestions", methods=["POST"])
@login_required()
def ai_expectation_suggestions():
    """AI suggests expectation analysis and management strategies"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        dropdown_value = data.get("dropdown_value", "")
        current_input = data.get("current_input", "")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Analyze patient expectations and develop appropriate expectation management strategies.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- History: {patient.get('past_history', '')}

FUNCTIONAL IMPACT:
- Performance Issues: {subjective.get('activity_performance', '')}
- Capacity Limitations: {subjective.get('activity_capacity', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

EXPECTATION LEVEL: {dropdown_value}
CURRENT INPUT: {current_input}

**⏰ EXPECTATION ANALYSIS:**

**Current Expectations Assessment:**
- Realistic vs unrealistic expectations
- Timeline expectations for recovery
- Functional outcome expectations
- Treatment process expectations

**Evidence-Based Prognosis:**
- Typical recovery patterns for this condition
- Factors affecting prognosis in this case
- Expected timeline milestones
- Potential complications or setbacks

**Expectation Management Strategy:**
- How to align expectations with reality
- Gradual expectation adjustment approach
- Hope vs realism balance
- Family/caregiver expectation alignment

**Specific Guidance for "{dropdown_value}" Expectations:**
- Tailored communication for this expectation level
- Adjustment strategies needed
- Reinforcement vs modification approach
- Timeline discussions required

**Goal Setting Implications:**
- How expectations influence goal setting
- Short-term vs long-term goal alignment
- Patient motivation considerations
- Success metric definitions

**Communication Scripts:**
- Key phrases for expectation discussions
- Questions to explore expectations further
- Methods to explain realistic timelines
- Strategies for difficult conversations

Provide actionable strategies for managing patient expectations while maintaining therapeutic alliance.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/consequences-awareness-suggestions", methods=["POST"])
@login_required()
def ai_consequences_awareness_suggestions():
    """AI suggests awareness of consequences analysis"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        dropdown_value = data.get("dropdown_value", "")
        current_input = data.get("current_input", "")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Analyze patient's awareness of condition consequences and implications for treatment planning.

PATIENT SITUATION:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- Background: {patient.get('past_history', '')}

IMPACT ASSESSMENT:
- Activity Performance: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}
- Environmental Context: {subjective.get('contextual_environmental', '')}
- Personal Context: {subjective.get('contextual_personal', '')}

AWARENESS LEVEL: {dropdown_value}
CURRENT INPUT: {current_input}

**⚠️ CONSEQUENCES AWARENESS ANALYSIS:**

**Current Awareness Assessment:**
- Understanding of short-term consequences
- Recognition of long-term implications
- Awareness of functional impact
- Understanding of work/life consequences

**Consequence Education Needs:**
- Immediate consequences to highlight
- Long-term risks to discuss
- Prevention strategies to teach
- Self-management importance

**Risk Communication:**
- How to discuss potential consequences
- Balancing concern with hope
- Avoiding catastrophizing
- Motivating behavior change

**Specific Guidance for "{dropdown_value}" Awareness:**
- Tailored education for this awareness level
- Information delivery strategies
- Engagement approaches
- Monitoring understanding

**Behavioral Implications:**
- How awareness affects compliance
- Motivation for lifestyle changes
- Self-advocacy development
- Proactive vs reactive approaches

**Safety Considerations:**
- Consequences patient may not recognize
- Red flag education needs
- When to seek help guidance
- Activity modification awareness

**Empowerment Strategies:**
- Building appropriate concern without fear
- Developing problem-solving skills
- Enhancing self-efficacy
- Support system engagement

Focus on building appropriate awareness that motivates positive behavior change without creating anxiety.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/locus-control-suggestions", methods=["POST"])
@login_required()
def ai_locus_control_suggestions():
    """AI suggests locus of control analysis and intervention strategies"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        dropdown_value = data.get("dropdown_value", "")
        current_input = data.get("current_input", "")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Analyze patient's locus of control and develop intervention strategies to optimize treatment engagement.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- Background: {patient.get('past_history', '')}

FUNCTIONAL CONTEXT:
- Performance Limitations: {subjective.get('activity_performance', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}
- Environmental Support: {subjective.get('contextual_environmental', '')}

CONTROL ORIENTATION: {dropdown_value}
CURRENT INPUT: {current_input}

**🎮 LOCUS OF CONTROL ANALYSIS:**

**Control Beliefs Assessment:**
- Internal vs external control orientation
- Health-specific control beliefs
- Treatment control expectations
- Self-efficacy for recovery

**Clinical Implications:**
- Impact on treatment engagement
- Compliance and adherence patterns
- Self-management capabilities
- Goal achievement likelihood

**Intervention Strategies for "{dropdown_value}" Control:**
- Specific approaches for this control orientation
- Empowerment vs support strategies
- Responsibility sharing approaches
- Motivation enhancement techniques

**Self-Efficacy Building:**
- Skills to develop patient confidence
- Success experience planning
- Gradual responsibility transfer
- Mastery experience design

**Communication Adaptations:**
- Language that resonates with control beliefs
- Decision-making involvement level
- Information presentation style
- Collaborative approach modifications

**Treatment Planning Implications:**
- Home program design considerations
- Goal setting approach
- Progress monitoring strategies
- Setback management planning

**Psychological Support Needs:**
- Control-related anxiety management
- Learned helplessness interventions
- Autonomy support strategies
- Confidence building approaches

Provide specific strategies to work effectively with this patient's control orientation while building optimal self-efficacy.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/affective-aspect-suggestions", methods=["POST"])
@login_required()
def ai_affective_aspect_suggestions():
    """AI suggests affective aspect analysis and emotional support strategies"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        dropdown_value = data.get("dropdown_value", "")
        current_input = data.get("current_input", "")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Analyze patient's emotional and affective responses to their condition and develop appropriate support strategies.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- History: {patient.get('past_history', '')}

PSYCHOSOCIAL CONTEXT:
- Activity Impact: {subjective.get('activity_performance', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}
- Environmental Support: {subjective.get('contextual_environmental', '')}
- Body Function Issues: {subjective.get('body_function', '')}

AFFECTIVE STATE: {dropdown_value}
CURRENT INPUT: {current_input}

**💭 AFFECTIVE ASPECT ANALYSIS:**

**Emotional Response Assessment:**
- Primary emotional reactions to condition
- Adaptive vs maladaptive coping patterns
- Emotional regulation capabilities
- Impact on daily functioning

**Clinical Significance:**
- How emotions affect treatment outcomes
- Risk factors for poor psychological adjustment
- Protective emotional factors
- Treatment engagement implications

**Intervention Strategies for "{dropdown_value}" Affective State:**
- Specific therapeutic approaches
- Emotional support techniques
- Coping skill development
- Stress management strategies

**Fear-Avoidance Considerations:**
- Movement-related fears
- Activity avoidance patterns
- Catastrophic thinking patterns
- Gradual exposure planning

**Communication Approaches:**
- Emotional validation techniques
- Empathetic communication strategies
- Motivational interviewing applications
- Trust building approaches

**Support System Integration:**
- Family/caregiver emotional support
- Professional support referrals
- Peer support considerations
- Community resource connections

**Monitoring and Assessment:**
- Emotional progress indicators
- Warning signs to monitor
- Referral criteria for mental health
- Self-monitoring strategies

**Yellow/Blue Flag Management:**
- Psychosocial risk factor identification
- Early intervention strategies
- Prevention of chronicity factors
- Workplace emotional considerations

Provide compassionate, evidence-based strategies for addressing emotional aspects while maintaining professional boundaries.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/perspectives-comprehensive-summary", methods=["POST"])
@login_required()
def ai_perspectives_comprehensive_summary():
    """AI provides comprehensive patient perspectives summary and initial assessment planning"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        perspectives_data = data.get("perspectives_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        
        prompt = f"""
Provide comprehensive patient perspectives analysis and initial assessment planning.

COMPLETE PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- History: {patient.get('past_history', '')}

SUBJECTIVE EXAMINATION:
- Functional Impact: {subjective.get('activity_performance', '')}
- Capacity Issues: {subjective.get('activity_capacity', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}

PATIENT PERSPECTIVES ASSESSMENT:
- Knowledge: {perspectives_data.get('knowledge', '')} - {perspectives_data.get('knowledge_details', '')}
- Attribution: {perspectives_data.get('attribution', '')} - {perspectives_data.get('attribution_details', '')}
- Expectations: {perspectives_data.get('illness_duration', '')} - {perspectives_data.get('expectation_details', '')}
- Consequences Awareness: {perspectives_data.get('consequences_awareness', '')} - {perspectives_data.get('consequences_details', '')}
- Locus of Control: {perspectives_data.get('locus_of_control', '')} - {perspectives_data.get('control_details', '')}
- Affective Aspect: {perspectives_data.get('affective_aspect', '')} - {perspectives_data.get('affective_details', '')}

**🧠 COMPREHENSIVE PERSPECTIVES SUMMARY:**

**Psychosocial Risk Stratification:**
- Overall psychosocial complexity: [Low/Moderate/High Risk]
- Yellow flag indicators present
- Blue flag considerations
- Protective factors identified

**Patient-Centered Profile:**
- Communication style preferences
- Learning and engagement approach
- Motivation patterns and drivers
- Barrier and facilitator analysis

**Clinical Reasoning Integration:**
- How perspectives influence physical presentation
- Biopsychosocial interaction patterns
- Treatment approach modifications needed
- Goal setting considerations

**🎯 INITIAL ASSESSMENT PLANNING:**

**Assessment Priorities Based on Perspectives:**
- Physical tests requiring psychosocial consideration
- Baseline measures considering patient beliefs
- Functional assessments accounting for fears/expectations
- Pain assessment considering emotional factors

**Communication Strategy:**
- Explanation and education approach
- Terminology and complexity level
- Reassurance vs challenge balance
- Family/caregiver involvement level

**Treatment Planning Implications:**
- Exercise prescription considerations
- Home program design factors
- Progression rate modifications
- Adherence optimization strategies

**⚠️ Red Flag Psychosocial Indicators:**
- Concerning beliefs requiring immediate attention
- Mental health referral considerations
- Safety concerns related to perspectives
- Urgent psychosocial interventions needed

**📋 NEXT SESSION OBJECTIVES:**
1. Complete initial physical assessment with psychosocial awareness
2. Establish therapeutic relationship based on perspectives
3. Begin appropriate patient education
4. Set realistic, patient-centered initial goals

This perspectives analysis provides essential foundation for patient-centered, biopsychosocial physiotherapy care.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Perspectives Comprehensive Summary",
            details=f"Generated comprehensive perspectives summary for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500
    

# ADD THESE NEW AI ENDPOINTS TO YOUR APP.PY (after the patient perspectives endpoints)
@limiter.limit("5 per minute")
@app.route("/api/ai/active-movements-suggestions", methods=["POST"])
@login_required()
def ai_active_movements_suggestions():
    """AI suggests active movement assessment priority based on cumulative patient data"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        # Get ALL cumulative patient data from previous 3 screens
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Based on comprehensive patient assessment data, provide active movement assessment recommendations.

PATIENT PRESENTATION:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

SUBJECTIVE EXAMINATION:
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PATIENT PERSPECTIVES:
- Knowledge Level: {perspectives.get('knowledge', '')}
- Expectations: {perspectives.get('illness_duration', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}

**🏃‍♂️ ACTIVE MOVEMENTS ASSESSMENT RECOMMENDATIONS:**

**ASSESSMENT PRIORITY RECOMMENDATION:** [Mandatory Assessment / Assessment with Caution / Absolutely Contraindicated]

**CLINICAL REASONING:**

**If MANDATORY ASSESSMENT:**
- Why active movements are essential for this patient
- Specific active movements to prioritize
- Expected findings based on presentation
- Diagnostic value for this condition

**If ASSESSMENT WITH CAUTION:**
- Specific precautions needed during active movement testing
- Modifications required for safety
- Warning signs to monitor during assessment
- Gradual progression approach

**If ABSOLUTELY CONTRAINDICATED:**
- Clear contraindications present
- Safety risks that prevent active movement testing
- Alternative assessment methods to use
- When to reassess for active movement clearance

**SPECIFIC ACTIVE MOVEMENT PRIORITIES:**
1. **Primary Movements to Assess:** [Based on condition and presentation]
2. **Movement Patterns to Observe:** [Quality, range, pain response]
3. **Functional Movements:** [Relevant to patient's activity limitations]
4. **Compensatory Patterns:** [Expected adaptations to look for]

**SAFETY CONSIDERATIONS:**
- Patient positioning requirements
- Environmental safety setup
- Emergency procedures if needed
- Family/caregiver involvement

**EXPECTED FINDINGS:**
- Likely movement limitations based on presentation
- Pain patterns during active movement
- Quality of movement expectations
- Red flag signs to watch for

**PATIENT COMMUNICATION:**
- How to explain active movement testing to this patient
- Reassurance vs precaution balance
- Instructions for patient during testing

Provide specific, clinically actionable recommendations for active movement assessment planning.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Active Movements Suggestions",
            details=f"Generated active movement recommendations for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/passive-movements-suggestions", methods=["POST"])
@login_required()
def ai_passive_movements_suggestions():
    """AI suggests passive movement assessment priority"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Recommend passive movement assessment priority based on comprehensive patient evaluation.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- History: {patient.get('past_history', '')}

CLINICAL FINDINGS:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Impairments: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}

PSYCHOSOCIAL FACTORS:
- Patient Knowledge: {perspectives.get('knowledge', '')}
- Attribution Beliefs: {perspectives.get('attribution', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}

**🤲 PASSIVE MOVEMENTS ASSESSMENT RECOMMENDATIONS:**

**ASSESSMENT PRIORITY RECOMMENDATION:** [Mandatory Assessment / Assessment with Caution / Absolutely Contraindicated]

**CLINICAL REASONING:**

**If MANDATORY ASSESSMENT:**
- Why passive movements are crucial for diagnosis
- Specific passive movements to prioritize
- Diagnostic information needed from passive testing
- Differentiation from active movement findings

**If ASSESSMENT WITH CAUTION:**
- Specific precautions for passive movement testing
- Gentle progression protocols
- Patient comfort and consent considerations
- Monitoring parameters during assessment

**If ABSOLUTELY CONTRAINDICATED:**
- Clear contraindications to passive movement
- Risk factors that prevent passive testing
- Alternative assessment strategies
- Conditions requiring medical clearance first

**SPECIFIC PASSIVE MOVEMENT PRIORITIES:**
1. **Range of Motion Assessment:** [Joints and directions to prioritize]
2. **End-Feel Assessment:** [Expected end-feel characteristics]
3. **Pain Response Monitoring:** [Pain patterns during passive movement]
4. **Tissue Texture/Quality:** [Muscle tone, joint mobility expectations]

**PATIENT FACTORS AFFECTING ASSESSMENT:**
- Fear/anxiety about passive movement
- Previous traumatic experiences
- Cultural/personal comfort considerations
- Communication needs during assessment

**EXPECTED CLINICAL FINDINGS:**
- Likely range of motion limitations
- Expected end-feel characteristics
- Pain patterns during passive movement
- Tissue quality observations

**SAFETY PROTOCOLS:**
- Patient positioning for safety and comfort
- Gentle handling techniques required
- Warning signs to stop assessment
- Emergency procedures if needed

**INTEGRATION WITH ACTIVE FINDINGS:**
- How passive findings will compare to active movement
- Diagnostic significance of active vs passive differences
- Clinical reasoning pathway based on findings

Provide evidence-based recommendations for safe, effective passive movement assessment.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/passive-overpressure-suggestions", methods=["POST"])
@login_required()
def ai_passive_overpressure_suggestions():
    """AI suggests passive overpressure assessment priority"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Determine passive overpressure assessment priority with safety considerations.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Presentation: {patient.get('present_history', '')}
- Background: {patient.get('past_history', '')}

IMPAIRMENT ANALYSIS:
- Structure Issues: {subjective.get('body_structure', '')}
- Function Limitations: {subjective.get('body_function', '')}
- Activity Impact: {subjective.get('activity_performance', '')}
- Personal Context: {subjective.get('contextual_personal', '')}

PATIENT FACTORS:
- Illness Understanding: {perspectives.get('knowledge', '')}
- Recovery Expectations: {perspectives.get('illness_duration', '')}
- Emotional Response: {perspectives.get('affective_aspect', '')}

**🔍 PASSIVE OVERPRESSURE ASSESSMENT RECOMMENDATIONS:**

**ASSESSMENT PRIORITY RECOMMENDATION:** [Mandatory Assessment / Assessment with Caution / Absolutely Contraindicated]

**CLINICAL REASONING:**

**If MANDATORY ASSESSMENT:**
- Critical diagnostic information needed from overpressure
- Specific structures requiring overpressure testing
- Expected diagnostic yield from overpressure
- Differentiation of tissue involvement

**If ASSESSMENT WITH CAUTION:**
- Significant precautions required for overpressure
- Modified overpressure techniques needed
- Gradual pressure application protocols
- Enhanced monitoring requirements

**If ABSOLUTELY CONTRAINDICATED:**
- Clear contraindications to overpressure testing
- Risk of tissue damage or symptom exacerbation
- Alternative diagnostic methods required
- Safety priorities superseding diagnostic needs

**OVERPRESSURE TESTING PRIORITIES:**
1. **Primary Movements for Overpressure:** [Based on presentation]
2. **Gentle Overpressure Techniques:** [Specific application methods]
3. **Pressure Gradation:** [How to apply progressive pressure]
4. **Response Monitoring:** [What to assess during overpressure]

**SAFETY PROTOCOLS:**
- Pre-testing patient education and consent
- Gentle pressure application techniques
- Immediate stop criteria
- Patient communication during testing

**EXPECTED FINDINGS:**
- Likely overpressure responses based on condition
- End-feel characteristics with overpressure
- Pain patterns during overpressure testing
- Tissue resistance expectations

**PATIENT PREPARATION:**
- Explanation of overpressure testing purpose
- Reassurance about pressure application
- Communication signals during testing
- Comfort positioning requirements

**RED FLAGS TO MONITOR:**
- Signs requiring immediate test cessation
- Neurological symptoms during overpressure
- Severe pain responses
- Autonomic responses

**CLINICAL INTEGRATION:**
- How overpressure findings integrate with other tests
- Diagnostic confirmation or ruling out conditions
- Treatment planning implications

Provide specific, safety-focused recommendations for overpressure assessment decision-making.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/resisted-movements-suggestions", methods=["POST"])
@login_required()
def ai_resisted_movements_suggestions():
    """AI suggests resisted movement assessment priority"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Recommend resisted movement assessment priority based on comprehensive evaluation.

PATIENT INFORMATION:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical Background: {patient.get('past_history', '')}

CLINICAL ASSESSMENT:
- Structural Issues: {subjective.get('body_structure', '')}
- Functional Impairments: {subjective.get('body_function', '')}
- Performance Limitations: {subjective.get('activity_performance', '')}
- Capacity Issues: {subjective.get('activity_capacity', '')}

PSYCHOSOCIAL CONTEXT:
- Patient Expectations: {perspectives.get('illness_duration', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Emotional Factors: {perspectives.get('affective_aspect', '')}

**💪 RESISTED MOVEMENTS ASSESSMENT RECOMMENDATIONS:**

**ASSESSMENT PRIORITY RECOMMENDATION:** [Mandatory Assessment / Assessment with Caution / Absolutely Contraindicated]

**CLINICAL REASONING:**

**If MANDATORY ASSESSMENT:**
- Essential muscle/tendon diagnostic information needed
- Specific resisted movements crucial for diagnosis
- Strength assessment requirements for treatment planning
- Functional capacity evaluation needs

**If ASSESSMENT WITH CAUTION:**
- Significant precautions for resisted testing
- Modified resistance application techniques
- Gradual loading protocols required
- Enhanced patient monitoring needs

**If ABSOLUTELY CONTRAINDICATED:**
- Clear contraindications to resisted movement testing
- Risk of tissue damage or re-injury
- Inflammatory conditions preventing resistance
- Alternative strength assessment methods needed

**RESISTED MOVEMENT TESTING PRIORITIES:**
1. **Primary Muscle Groups:** [Based on condition and functional needs]
2. **Resistance Application:** [Isometric, isotonic, or functional resistance]
3. **Load Progression:** [Starting resistance levels and progression]
4. **Response Assessment:** [Strength, pain, and quality evaluation]

**STRENGTH TESTING CONSIDERATIONS:**
- Manual muscle testing vs functional strength
- Endurance vs power assessment needs
- Pain-limited vs strength-limited responses
- Bilateral comparison requirements

**PATIENT SAFETY FACTORS:**
- Pain tolerance and fear responses
- Previous injury history affecting testing
- Current inflammation or acute symptoms
- Medication effects on strength testing

**EXPECTED FINDINGS:**
- Likely strength deficits based on presentation
- Pain patterns during resisted movement
- Muscle recruitment pattern expectations
- Compensation strategy identification

**FUNCTIONAL INTEGRATION:**
- Relationship to reported activity limitations
- Work/sport-specific strength requirements
- Daily function strength needs
- Treatment planning strength baselines

**TESTING MODIFICATIONS:**
- Patient positioning for optimal testing
- Alternative testing methods if needed
- Assistance or support during testing
- Progressive loading strategies

Provide evidence-based recommendations for safe, effective resisted movement assessment.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/combined-movements-suggestions", methods=["POST"])
@login_required()
def ai_combined_movements_suggestions():
    """AI suggests combined movement assessment priority"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Determine combined movement assessment priority based on patient presentation and clinical findings.

COMPREHENSIVE PATIENT DATA:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- History: {patient.get('past_history', '')}

MOVEMENT ANALYSIS:
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}

PATIENT PERSPECTIVES:
- Knowledge Level: {perspectives.get('knowledge', '')}
- Attribution: {perspectives.get('attribution', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}

**🔄 COMBINED MOVEMENTS ASSESSMENT RECOMMENDATIONS:**

**ASSESSMENT PRIORITY RECOMMENDATION:** [Mandatory Assessment / Assessment with Caution / Absolutely Contraindicated]

**CLINICAL REASONING:**

**If MANDATORY ASSESSMENT:**
- Why combined movements are essential for diagnosis
- Specific combined movement patterns to assess
- Functional relevance of combined movements
- Diagnostic information unique to combined testing

**If ASSESSMENT WITH CAUTION:**
- Precautions for combined movement testing
- Modified combined movement approaches
- Gradual complexity progression in testing
- Enhanced monitoring during combined movements

**If ABSOLUTELY CONTRAINDICATED:**
- Contraindications to combined movement testing
- Risk factors preventing complex movement assessment
- Alternative assessment strategies for movement patterns
- Conditions requiring simpler movement testing first

**COMBINED MOVEMENT TESTING PRIORITIES:**
1. **Functional Combined Movements:** [Based on activity limitations]
2. **Spinal Combined Movements:** [If spinal condition present]
3. **Extremity Combined Movements:** [Joint-specific combinations]
4. **Provocative Combined Movements:** [To reproduce symptoms]

**MOVEMENT COMPLEXITY CONSIDERATIONS:**
- Starting with simple combined movements
- Progressive complexity based on tolerance
- Functional vs clinical combined movements
- Patient-specific movement patterns

**EXPECTED CLINICAL FINDINGS:**
- Likely movement restrictions in combined patterns
- Pain provocation with combined movements
- Movement quality and compensation patterns
- Functional movement limitations

**PATIENT FACTORS:**
- Fear of complex movements
- Previous experience with movement testing
- Understanding of movement testing purpose
- Coordination and balance considerations

**SAFETY PROTOCOLS:**
- Slow, controlled combined movement progression
- Patient education about combined movement testing
- Immediate stop criteria for safety
- Support and assistance during testing

**FUNCTIONAL INTEGRATION:**
- Relationship to daily activity movements
- Work or sport-specific combined movements
- Home environment movement requirements
- Treatment planning movement priorities

**DIAGNOSTIC VALUE:**
- Combined movements vs single plane movements
- Symptom reproduction with combined movements
- Movement pattern dysfunction identification
- Treatment direction guidance from findings

Provide specific recommendations for safe, effective combined movement assessment planning.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/special-tests-suggestions", methods=["POST"])
@login_required()
def ai_special_tests_suggestions():
    """AI suggests special tests assessment priority"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Recommend special tests assessment priority based on comprehensive patient evaluation.

PATIENT PRESENTATION:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

CLINICAL FINDINGS:
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PATIENT FACTORS:
- Understanding: {perspectives.get('knowledge', '')}
- Expectations: {perspectives.get('illness_duration', '')}
- Emotional Response: {perspectives.get('affective_aspect', '')}

**🔬 SPECIAL TESTS ASSESSMENT RECOMMENDATIONS:**

**ASSESSMENT PRIORITY RECOMMENDATION:** [Mandatory Assessment / Assessment with Caution / Absolutely Contraindicated]

**CLINICAL REASONING:**

**If MANDATORY ASSESSMENT:**
- Critical diagnostic information needed from special tests
- Specific special tests essential for this condition
- Differential diagnosis requirements
- Treatment planning implications of special test results

**If ASSESSMENT WITH CAUTION:**
- Special tests requiring significant precautions
- Modified special test techniques needed
- Patient preparation requirements for special tests
- Enhanced monitoring during provocative testing

**If ABSOLUTELY CONTRAINDICATED:**
- Clear contraindications to special testing
- Risk of symptom exacerbation or tissue damage
- Alternative diagnostic strategies required
- Conditions requiring medical clearance first

**CONDITION-SPECIFIC SPECIAL TESTS:**
Based on presentation, prioritize:
1. **Primary Diagnostic Tests:** [Most relevant special tests for condition]
2. **Differential Diagnosis Tests:** [Tests to rule out other conditions]
3. **Severity Assessment Tests:** [Tests to gauge condition severity]
4. **Functional Special Tests:** [Tests relating to activity limitations]

**SPECIAL TEST CONSIDERATIONS:**
- Patient anxiety about provocative testing
- Previous testing experiences and responses
- Cultural or personal factors affecting testing
- Explanation and consent requirements

**EXPECTED OUTCOMES:**
- Likely special test results based on presentation
- Positive vs negative test interpretations
- Clinical significance of test findings
- Integration with other assessment findings

**SAFETY PROTOCOLS:**
- Pre-test patient education and preparation
- Gentle test application techniques
- Immediate stop criteria for safety
- Post-test symptom monitoring

**TEST PRIORITIZATION:**
- Most diagnostically valuable tests first
- Least provocative to most provocative progression
- Essential tests vs confirmatory tests
- Time-efficient testing sequence

**CLINICAL INTEGRATION:**
- How special test results will influence diagnosis
- Treatment planning implications of findings
- Prognosis considerations based on test results
- Patient education based on test outcomes

**RED FLAG MONITORING:**
- Special tests that might reveal serious pathology
- Neurological assessment priorities
- Vascular assessment considerations
- Immediate referral criteria

Provide evidence-based recommendations for optimal special test selection and application.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/neurodynamic-examination-suggestions", methods=["POST"])
@login_required()
def ai_neurodynamic_examination_suggestions():
    """AI suggests neurodynamic examination assessment priority"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Determine neurodynamic examination priority with comprehensive safety assessment.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Presentation: {patient.get('present_history', '')}
- Background: {patient.get('past_history', '')}

NEUROLOGICAL CONSIDERATIONS:
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Environmental Context: {subjective.get('contextual_environmental', '')}

PATIENT PSYCHOLOGICAL FACTORS:
- Knowledge: {perspectives.get('knowledge', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}

**🧠 NEURODYNAMIC EXAMINATION RECOMMENDATIONS:**

**ASSESSMENT PRIORITY RECOMMENDATION:** [Mandatory Assessment / Assessment with Caution / Absolutely Contraindicated]

**CLINICAL REASONING:**

**If MANDATORY ASSESSMENT:**
- Clear neurodynamic component suspected in presentation
- Specific neurodynamic tests essential for diagnosis
- Nerve involvement requiring assessment
- Treatment planning dependent on neurodynamic findings

**If ASSESSMENT WITH CAUTION:**
- Neurodynamic testing with significant precautions
- Modified neurodynamic test techniques required
- Gradual, gentle neurodynamic assessment approach
- Enhanced patient monitoring during testing

**If ABSOLUTELY CONTRAINDICATED:**
- Clear contraindications to neurodynamic testing
- Risk of neurological symptom exacerbation
- Acute inflammatory neurological conditions
- Alternative neurological assessment methods needed

**NEURODYNAMIC TESTING PRIORITIES:**
1. **Primary Neurodynamic Tests:** [Based on symptom distribution]
2. **Upper Limb Neurodynamic Tests:** [If upper extremity involvement]
3. **Lower Limb Neurodynamic Tests:** [If lower extremity involvement]
4. **Spinal Neurodynamic Tests:** [If spinal nerve involvement suspected]

**NERVE TENSION CONSIDERATIONS:**
- Symptom distribution patterns suggesting nerve involvement
- Mechanical vs inflammatory nerve sensitivity
- Central vs peripheral neurodynamic dysfunction
- Nerve root vs peripheral nerve involvement

**PATIENT SAFETY FACTORS:**
- Fear of nerve testing and manipulation
- Previous neurological symptoms or conditions
- Current neurological medications
- Anxiety about neurological testing

**EXPECTED FINDINGS:**
- Likely neurodynamic test responses based on presentation
- Positive vs negative neurodynamic test interpretation
- Symptom reproduction patterns with neurodynamic testing
- Range of motion limitations with neural bias

**TESTING PROTOCOLS:**
- Gentle, progressive neurodynamic test application
- Patient positioning for optimal testing
- Communication during neurodynamic testing
- Immediate response assessment

**RED FLAG MONITORING:**
- Signs of central nervous system involvement
- Progressive neurological symptoms
- Cauda equina or cord compression signs
- Immediate medical referral criteria

**CLINICAL INTEGRATION:**
- Neurodynamic findings integration with other tests
- Treatment implications of neurodynamic assessment
- Prognosis considerations with nerve involvement
- Patient education about neurodynamic findings

**CONTRAINDICATION ASSESSMENT:**
- Acute nerve root compression
- Recent neurological surgery
- Progressive neurological conditions
- Unstable neurological symptoms

Provide specific, safety-focused recommendations for neurodynamic examination decision-making.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/initial-plan-comprehensive-summary", methods=["POST"])
@login_required()
def ai_initial_plan_comprehensive_summary():
    """AI provides comprehensive initial assessment plan summary and pathophysiological planning"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        assessment_plan_data = data.get("assessment_plan_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Provide comprehensive initial assessment plan summary and pathophysiological analysis planning.

COMPLETE PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- History: {patient.get('past_history', '')}

SUBJECTIVE EXAMINATION SUMMARY:
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PATIENT PERSPECTIVES SUMMARY:
- Knowledge: {perspectives.get('knowledge', '')}
- Attribution: {perspectives.get('attribution', '')}
- Expectations: {perspectives.get('illness_duration', '')}
- Consequences Awareness: {perspectives.get('consequences_awareness', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}
- Affective Aspect: {perspectives.get('affective_aspect', '')}

ASSESSMENT PLAN DECISIONS:
- Active Movements: {assessment_plan_data.get('active_movements', '')}
- Passive Movements: {assessment_plan_data.get('passive_movements', '')}
- Passive Overpressure: {assessment_plan_data.get('passive_over_pressure', '')}
- Resisted Movements: {assessment_plan_data.get('resisted_movements', '')}
- Combined Movements: {assessment_plan_data.get('combined_movements', '')}
- Special Tests: {assessment_plan_data.get('special_tests', '')}
- Neurodynamic Examination: {assessment_plan_data.get('neuro_dynamic_examination', '')}

**📋 COMPREHENSIVE INITIAL ASSESSMENT PLAN SUMMARY:**

**Assessment Approach Overview:**
- Overall assessment complexity: [Simple/Moderate/Complex]
- Primary assessment focus areas
- Safety prioritization level: [High/Moderate/Low precautions]
- Patient-specific assessment modifications

**Assessment Sequence Optimization:**
1. **Priority 1 (Mandatory):** [List all mandatory assessments]
2. **Priority 2 (With Caution):** [List cautious assessments with precautions]
3. **Priority 3 (Contraindicated):** [List contraindicated assessments and alternatives]

**Clinical Safety Integration:**
- Pre-assessment patient preparation needs
- Environmental setup requirements
- Emergency procedures if needed
- Family/caregiver involvement considerations

**Expected Assessment Outcomes:**
- Likely findings from mandatory assessments
- Diagnostic information expected from testing
- Functional capacity assessment predictions
- Red flag monitoring during assessment

**🔬 PATHOPHYSIOLOGICAL ANALYSIS PREPARATION:**

**Leading Diagnostic Hypotheses:**
Based on comprehensive assessment data:
1. **Primary Hypothesis:** [Most likely pathophysiological mechanism]
2. **Alternative Hypotheses:** [Other mechanisms to consider]
3. **Differential Considerations:** [Conditions to rule out]

**Pathophysiological Factors to Explore:**
- **Tissue Involvement:** [Structures likely involved]
- **Pain Mechanisms:** [Nociceptive/neuropathic/central sensitization]
- **Inflammation Patterns:** [Acute/chronic inflammatory processes]
- **Healing Stage:** [Tissue healing timeline considerations]

**Mechanism Analysis Priorities:**
- **Primary Pain Source:** [Most likely pain generator]
- **Secondary Factors:** [Contributing pathophysiological factors]
- **Systemic Considerations:** [Whole-body impacts]
- **Chronicity Factors:** [Factors promoting persistence]

**Patient-Specific Pathophysiology:**
- Age-related pathophysiological considerations
- Comorbidity impacts on mechanisms
- Lifestyle factors affecting pathophysiology
- Psychosocial influences on pain mechanisms

**⏭️ NEXT SESSION OBJECTIVES:**
1. Execute planned assessment safely and systematically
2. Gather pathophysiological mechanism evidence
3. Refine diagnostic hypotheses based on objective findings
4. Begin patient education about findings
5. Plan initial intervention strategies

**Assessment-to-Treatment Bridge:**
- How assessment findings will guide treatment
- Patient education opportunities during assessment
- Baseline measure establishment
- Treatment planning preparation

This comprehensive plan provides systematic, evidence-based approach to objective assessment and pathophysiological analysis.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Initial Plan Comprehensive Summary",
            details=f"Generated comprehensive assessment plan summary for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500    


# ADD THIS NEW AI ENDPOINT TO YOUR APP.PY (after your existing AI endpoints)

@limiter.limit("5 per minute")
@app.route("/api/ai/pathophysiological-comprehensive-diagnosis", methods=["POST"])
@login_required()
def ai_pathophysiological_comprehensive_diagnosis():
    """AI provides comprehensive pathophysiological analysis and clinical diagnosis"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        patho_data = data.get("patho_data", {})
        
        # Get ALL cumulative patient data from previous workflow steps
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        
        prompt = f"""
You are an expert physiotherapist providing comprehensive pathophysiological analysis and clinical diagnosis. Based on the complete clinical assessment data, provide a detailed clinical reasoning analysis.

PATIENT BACKGROUND:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

SUBJECTIVE EXAMINATION FINDINGS:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Impairments: {subjective.get('body_function', '')}
- Activity Performance Limitations: {subjective.get('activity_performance', '')}
- Activity Capacity Issues: {subjective.get('activity_capacity', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PATIENT PERSPECTIVES:
- Knowledge Level: {perspectives.get('knowledge', '')}
- Illness Attribution: {perspectives.get('attribution', '')}
- Recovery Expectations: {perspectives.get('illness_duration', '')}
- Consequences Awareness: {perspectives.get('consequences_awareness', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}
- Emotional Response: {perspectives.get('affective_aspect', '')}

ASSESSMENT PLANNING:
- Active Movements: {initial_plan.get('active_movements', '')}
- Passive Movements: {initial_plan.get('passive_movements', '')}
- Resisted Movements: {initial_plan.get('resisted_movements', '')}
- Special Tests: {initial_plan.get('special_tests', '')}
- Neurodynamic Examination: {initial_plan.get('neuro_dynamic_examination', '')}

PATHOPHYSIOLOGICAL MECHANISM DATA:
- Area Involved: {patho_data.get('area_involved', '')}
- Presenting Symptoms: {patho_data.get('presenting_symptom', '')}
- Pain Type: {patho_data.get('pain_type', '')}
- Pain Nature: {patho_data.get('pain_nature', '')}
- Pain Severity (VAS): {patho_data.get('pain_severity', '')}
- Pain Irritability: {patho_data.get('pain_irritability', '')}
- Symptom Source: {patho_data.get('symptom_source', '')}
- Tissue Healing Stage: {patho_data.get('tissue_healing_stage', '')}

Based on this comprehensive clinical data, provide:

**🎯 CLINICAL DIAGNOSIS & REASONING:**

**PRIMARY DIAGNOSIS:**
- Most likely clinical diagnosis with confidence level
- Anatomical structures primarily involved
- Pathophysiological mechanism underlying the condition
- Clinical reasoning supporting this diagnosis

**DIFFERENTIAL DIAGNOSIS:**
- Alternative diagnoses to consider (ranked by likelihood)
- Key distinguishing features between diagnoses
- Additional tests needed for diagnostic confirmation

**🔬 PATHOPHYSIOLOGICAL ANALYSIS:**

**Pain Mechanism Analysis:**
- Primary pain mechanism (nociceptive/neuropathic/central sensitization)
- Tissue involvement and inflammatory status
- Neurological component assessment
- Centralization vs peripheralization patterns

**Tissue Healing Assessment:**
- Current healing stage analysis and timeline
- Factors promoting or hindering healing
- Expected healing trajectory
- Tissue-specific considerations

**Functional Impact Analysis:**
- How pathophysiology explains functional limitations
- Movement dysfunction patterns related to pathology
- Activity restriction mechanisms
- Participation limitation factors

**🚨 CLINICAL FLAGS ASSESSMENT:**

**Red Flag Screening:**
- Serious pathology indicators present/absent
- Immediate medical referral needs
- Safety considerations for treatment

**Yellow Flag Assessment:**
- Psychosocial risk factors identified
- Chronicity risk evaluation
- Pain behavior patterns
- Treatment engagement predictors

**🎯 TREATMENT IMPLICATIONS:**

**Immediate Treatment Priorities:**
- Phase-appropriate interventions based on healing stage
- Pain management approach recommendations
- Movement and activity modifications
- Patient education priorities

**Prognosis Indicators:**
- Expected recovery timeline based on pathophysiology
- Favorable and unfavorable prognostic factors
- Risk factors for chronicity or complications
- Return to function expectations

**Next Assessment Priorities:**
- Specific objective tests to confirm diagnosis
- Baseline measures to establish
- Red flag monitoring requirements
- Progress monitoring strategies

**🎓 PATIENT EDUCATION FOCUS:**
- Key pathophysiology concepts to explain to patient
- Pain education priorities
- Activity modification rationale
- Expectation management strategies

**📋 CLINICAL REASONING SUMMARY:**
- Integration of all assessment findings
- Confidence level in diagnosis (High/Moderate/Low)
- Areas requiring further investigation
- Treatment approach rationale

Provide evidence-based, clinically actionable analysis that guides immediate treatment planning and next assessment steps.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Pathophysiological Comprehensive Diagnosis",
            details=f"Generated comprehensive diagnosis for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI pathophysiological comprehensive diagnosis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500
    

# ADD THIS NEW AI ENDPOINT TO YOUR APP.PY (after your existing AI endpoints)
@limiter.limit("5 per minute")
@app.route("/api/ai/chronicity-risk-analysis", methods=["POST"])
@login_required()
def ai_chronicity_risk_analysis():
    """AI provides comprehensive chronicity risk analysis and contributing factors assessment"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        chronic_data = data.get("chronic_data", {})
        
        # Get ALL cumulative patient data from previous workflow steps
        all_data = get_cumulative_patient_data(patient_id)
        
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        
        prompt = f"""
You are an expert physiotherapist specializing in chronic pain and persistent conditions. Provide comprehensive chronicity risk analysis based on complete patient assessment data.

PATIENT BACKGROUND:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

FUNCTIONAL IMPACT ASSESSMENT:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Impairments: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PSYCHOSOCIAL PROFILE:
- Knowledge Level: {perspectives.get('knowledge', '')}
- Illness Attribution: {perspectives.get('attribution', '')}
- Recovery Expectations: {perspectives.get('illness_duration', '')}
- Consequences Awareness: {perspectives.get('consequences_awareness', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}
- Emotional Response: {perspectives.get('affective_aspect', '')}

PATHOPHYSIOLOGICAL CONTEXT:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Pain Type: {patho_mechanism.get('pain_type', '')}
- Pain Nature: {patho_mechanism.get('pain_nature', '')}
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Pain Irritability: {patho_mechanism.get('pain_irritability', '')}
- Symptom Source: {patho_mechanism.get('symptom_source', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}

CHRONIC DISEASE FACTORS:
- Primary Contributing Cause: {chronic_data.get('cause', '')}
- Specific Details: {chronic_data.get('cause_detail', '')}

Based on this comprehensive assessment, provide:

**🚨 CHRONICITY RISK ASSESSMENT:**

**Overall Risk Level:** [LOW / MODERATE / HIGH / VERY HIGH]

**Risk Stratification Rationale:**
- Key factors contributing to high/low risk
- Timeline considerations for this patient
- Protective vs risk factors balance

**📊 DETAILED RISK FACTOR ANALYSIS:**

**YELLOW FLAGS (Psychosocial Risk Factors):**
- Depression, anxiety, or mood disorders
- Fear-avoidance behaviors and kinesiophobia
- Catastrophic thinking patterns
- Poor coping strategies
- Previous poor treatment experiences
- Work dissatisfaction or disputes
- Social isolation or poor support

**BLUE FLAGS (Occupational/Social Factors):**
- Work-related stress and demands
- Poor ergonomics or physical work demands
- Workplace culture and support
- Economic pressures and job security
- Family dynamics and responsibilities
- Healthcare system factors

**BLACK FLAGS (System/Compensation Factors):**
- Compensation or litigation issues
- Healthcare system barriers
- Economic incentives for disability
- Poor provider-patient relationships
- System delays and bureaucracy

**ORANGE FLAGS (Psychiatric Factors):**
- Significant mental health conditions
- Personality disorders affecting treatment
- Substance abuse issues
- Cognitive impairments
- Severe psychological distress

**🎯 CONTRIBUTING FACTOR ANALYSIS:**

**Primary Maintenance Factors Identified:**
1. **Biomechanical Factors:** [Analysis of movement, posture, ergonomics]
2. **Psychosocial Factors:** [Stress, beliefs, emotions, coping]
3. **Environmental Factors:** [Work, home, social environment]
4. **Behavioral Factors:** [Activity patterns, avoidance, pacing]
5. **Medical Factors:** [Comorbidities, medications, treatments]

**Factor Interaction Analysis:**
- How different factors reinforce each other
- Vicious cycles maintaining symptoms
- Cascade effects from primary to secondary factors

**📈 PROGNOSIS AND TIMELINE:**

**Recovery Likelihood:**
- Excellent/Good/Fair/Poor prognosis with rationale
- Expected timeline for improvement
- Factors that could accelerate recovery
- Factors that may hinder progress

**Critical Intervention Windows:**
- Optimal timing for interventions
- Risk of transition to chronic pain
- Prevention strategies for chronicity

**🎯 INTERVENTION PRIORITIES:**

**Immediate Priority Interventions:**
1. **High-Impact Factors:** [Most modifiable risk factors]
2. **Low-Hanging Fruit:** [Easily addressable factors]
3. **Safety Factors:** [Immediate risk mitigation]

**Medium-Term Strategies:**
- Comprehensive biopsychosocial approach
- Multidisciplinary team considerations
- Patient education priorities
- Lifestyle modification targets

**Long-Term Management:**
- Chronic pain self-management strategies
- Relapse prevention planning
- Maintenance program considerations

**🔍 SPECIFIC RECOMMENDATIONS:**

**Assessment Needs:**
- Additional screening tools required
- Referrals to other professionals
- Baseline measures for chronicity factors
- Monitoring parameters

**Treatment Modifications:**
- How chronicity risk affects treatment approach
- Emphasis on self-management vs passive treatment
- Pacing and graded exposure considerations
- Pain education and cognitive approaches

**Patient Education Focus:**
- Understanding chronic pain mechanisms
- Self-efficacy building strategies
- Realistic expectation setting
- Active coping strategy development

**Family/Support System:**
- Family education needs
- Support system optimization
- Workplace accommodation discussions

**🚩 RED FLAGS FOR CHRONICITY:**
- Immediate concerns requiring urgent attention
- Signs of rapid deterioration
- Indicators for specialist referral
- System factors requiring advocacy

**📋 MONITORING STRATEGY:**
- Key indicators to track over time
- Warning signs of increasing chronicity risk
- Success metrics for intervention
- Timeline for reassessment

Provide evidence-based, actionable analysis that guides comprehensive biopsychosocial treatment planning for preventing chronicity and optimizing recovery outcomes.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Chronicity Risk Analysis",
            details=f"Generated chronicity risk analysis for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI chronicity risk analysis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

# ADD THESE NEW AI ENDPOINTS TO YOUR APP.PY (after your existing AI endpoints)
@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-flags-red-suggestions", methods=["POST"])
@login_required()
def ai_clinical_flags_red_suggestions():
    """AI suggests red flag indicators based on cumulative patient data"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Analyze patient data for RED FLAG indicators requiring immediate medical attention.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

CURRENT PRESENTATION:
- Pain Type: {patho_mechanism.get('pain_type', '')}
- Pain Nature: {patho_mechanism.get('pain_nature', '')}
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Symptom Source: {patho_mechanism.get('symptom_source', '')}

FUNCTIONAL STATUS:
- Body Function Issues: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}

**🔴 RED FLAG ASSESSMENT:**

Based on this presentation, evaluate for:

**NEUROLOGICAL RED FLAGS:**
- Cauda equina syndrome indicators
- Progressive neurological deficits
- Severe or progressive muscle weakness
- Sensory loss patterns
- Bowel/bladder dysfunction

**SYSTEMIC ILLNESS RED FLAGS:**
- Fever, chills, night sweats
- Unexplained weight loss
- History of cancer
- Immunosuppression
- Recent infection

**TRAUMA/FRACTURE RED FLAGS:**
- Significant trauma history
- Osteoporosis risk factors
- Age-related fracture risk
- Mechanism of injury

**VASCULAR RED FLAGS:**
- Circulatory compromise
- Severe ischemic symptoms
- Aortic aneurysm indicators

**CONDITION-SPECIFIC RED FLAGS:**
- Based on the area involved and presentation
- Age-specific considerations
- Gender-specific considerations

**SCREENING RECOMMENDATIONS:**
- Specific questions to ask
- Physical tests to perform
- When to refer immediately
- Monitoring parameters

Provide specific, actionable red flag assessment for this patient's presentation.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-flags-black-suggestions", methods=["POST"])
@login_required()
def ai_clinical_flags_black_suggestions():
    """AI suggests black flag occupational and system factors"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        
        prompt = f"""
Analyze patient data for BLACK FLAG occupational and system factors affecting recovery.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- Background: {patient.get('past_history', '')}

WORK/ENVIRONMENTAL CONTEXT:
- Environmental Factors: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}

PSYCHOSOCIAL INDICATORS:
- Attribution Beliefs: {perspectives.get('attribution', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Recovery Expectations: {perspectives.get('illness_duration', '')}

CONTRIBUTING FACTORS:
- Chronic Factors: {chronic_disease.get('cause', '')}
- Specific Details: {chronic_disease.get('cause_detail', '')}

**⚫ BLACK FLAG ASSESSMENT:**

Evaluate occupational and system factors:

**COMPENSATION/INSURANCE FACTORS:**
- Workers' compensation claims
- Insurance disputes or delays
- Claim processing difficulties
- Legal proceedings involvement
- Secondary gain considerations

**WORKPLACE FACTORS:**
- Job dissatisfaction or conflicts
- Poor employer-employee relationships
- Workplace harassment or discrimination
- Lack of workplace support
- Inadequate return-to-work programs

**OCCUPATIONAL DEMANDS:**
- Heavy physical demands
- Repetitive work requirements
- Poor ergonomic conditions
- Shift work or irregular hours
- High stress work environment

**SYSTEM/HEALTHCARE FACTORS:**
- Healthcare system delays
- Poor provider coordination
- Conflicting medical opinions
- Treatment access barriers
- Communication breakdowns

**ECONOMIC FACTORS:**
- Financial stress from injury
- Job security concerns
- Economic incentives for disability
- Fear of income loss
- Family financial pressures

**ADMINISTRATIVE BARRIERS:**
- Bureaucratic delays
- Complex claim processes
- Multiple system navigation
- Documentation requirements
- Appeal processes

**SOCIAL/CULTURAL FACTORS:**
- Cultural attitudes toward work
- Family work expectations
- Community work values
- Disability stigma concerns

**ASSESSMENT PRIORITIES:**
- Most significant black flags present
- System barriers to address
- Advocacy needs identified
- Intervention strategies

**INTERVENTION RECOMMENDATIONS:**
- System navigation support
- Workplace accommodation needs
- Communication facilitation
- Advocacy requirements

Provide specific black flag assessment and system intervention strategies.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-flags-blue-suggestions", methods=["POST"])
@login_required()
def ai_clinical_flags_blue_suggestions():
    """AI suggests blue flag workplace perception factors"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Analyze patient data for BLUE FLAG workplace perception factors affecting recovery.

PATIENT INFORMATION:
- Demographics: {patient.get('age_sex', '')}
- Condition: {patient.get('present_history', '')}
- History: {patient.get('past_history', '')}

WORK/ENVIRONMENTAL CONTEXT:
- Environmental Factors: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}
- Activity Performance: {subjective.get('activity_performance', '')}

WORK-RELATED SYMPTOMS:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Pain Nature: {patho_mechanism.get('pain_nature', '')}
- Activity Dependence: {patho_mechanism.get('pain_nature', '')}

PERCEPTION FACTORS:
- Attribution Beliefs: {perspectives.get('attribution', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Consequences Awareness: {perspectives.get('consequences_awareness', '')}

**🔵 BLUE FLAG ASSESSMENT:**

Evaluate workplace perception factors:

**WORKPLACE SUPPORT PERCEPTIONS:**
- Supervisor support availability
- Colleague understanding and assistance
- Management commitment to safety
- Return-to-work program quality
- Workplace culture toward injury

**WORK DEMAND PERCEPTIONS:**
- Physical demands of job
- Time pressures and deadlines
- Workload manageability
- Job control and autonomy
- Skill utilization and variety

**WORKPLACE STRESS FACTORS:**
- High-stress work environment
- Poor work-life balance
- Role ambiguity or conflict
- Organizational change stress
- Performance pressure

**ERGONOMIC AND SAFETY PERCEPTIONS:**
- Workplace safety standards
- Equipment adequacy
- Ergonomic risk factors
- Injury prevention measures
- Safety training effectiveness

**ORGANIZATIONAL FACTORS:**
- Company size and resources
- Union involvement
- Policy clarity and fairness
- Communication effectiveness
- Change management

**INJURY ATTRIBUTION:**
- Work-relatedness beliefs
- Employer responsibility perceptions
- Prevention possibility beliefs
- Recurrence likelihood concerns

**RETURN-TO-WORK PERCEPTIONS:**
- Job availability expectations
- Accommodation possibilities
- Retraining opportunities
- Career impact concerns
- Workplace acceptance

**ASSESSMENT PRIORITIES:**
- Most significant blue flags present
- Workplace intervention needs
- Communication requirements
- Support system gaps

**INTERVENTION RECOMMENDATIONS:**
- Workplace assessment needs
- Ergonomic modifications
- Support system enhancement
- Communication strategies
- Return-to-work planning

Provide specific blue flag assessment and workplace intervention strategies.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-flags-comprehensive-analysis", methods=["POST"])
@login_required()
def ai_clinical_flags_comprehensive_analysis():
    """AI provides comprehensive clinical flags analysis and risk stratification"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        flags_data = data.get("flags_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        
        prompt = f"""
Provide comprehensive clinical flags analysis and biopsychosocial risk stratification.

COMPLETE PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

COMPREHENSIVE ASSESSMENT DATA:
- Body Structure: {subjective.get('body_structure', '')}
- Body Function: {subjective.get('body_function', '')}
- Activity Performance: {subjective.get('activity_performance', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PSYCHOSOCIAL PROFILE:
- Knowledge: {perspectives.get('knowledge', '')}
- Attribution: {perspectives.get('attribution', '')}
- Expectations: {perspectives.get('illness_duration', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}

PATHOPHYSIOLOGICAL CONTEXT:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Pain Irritability: {patho_mechanism.get('pain_irritability', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}

CHRONICITY FACTORS:
- Contributing Causes: {chronic_disease.get('cause', '')}
- Specific Details: {chronic_disease.get('cause_detail', '')}

DOCUMENTED CLINICAL FLAGS:
- Red Flags: {flags_data.get('red_flag', '')}
- Orange Flags: {flags_data.get('orange_flag', '')}
- Yellow Flags: {flags_data.get('yellow_flag', '')}
- Black Flags: {flags_data.get('black_flag', '')}
- Blue Flags: {flags_data.get('blue_flag', '')}

**🚩 COMPREHENSIVE CLINICAL FLAGS ANALYSIS:**

**OVERALL RISK STRATIFICATION:**
- **Primary Risk Level:** [LOW / MODERATE / HIGH / VERY HIGH]
- **Secondary Risk Factors:** [Additional risk considerations]
- **Protective Factors:** [Factors supporting recovery]

**FLAG-SPECIFIC ANALYSIS:**

**🔴 RED FLAG ASSESSMENT:**
- Serious pathology risk: [Present/Absent/Uncertain]
- Immediate medical referral needs
- Safety considerations for physiotherapy
- Monitoring requirements

**🟠 ORANGE FLAG ASSESSMENT:**
- Psychiatric condition indicators: [Present/Absent/Suspected]
- Mental health referral priorities
- Treatment modification needs
- Safety and risk considerations

**🟡 YELLOW FLAG ASSESSMENT:**
- Psychosocial chronicity risk: [Low/Moderate/High]
- Key yellow flags present
- Intervention priorities for psychological factors
- Coping strategy enhancement needs

**⚫ BLACK FLAG ASSESSMENT:**
- System/occupational barrier level: [Low/Moderate/High]
- Workplace intervention needs
- System advocacy requirements
- Return-to-work considerations

**🔵 BLUE FLAG ASSESSMENT:**
- Workplace perception risks: [Low/Moderate/High]
- Environmental modification needs
- Support system enhancement priorities
- Workplace communication requirements

**INTEGRATED RISK ANALYSIS:**

**Biopsychosocial Risk Profile:**
- Biological factors: [Impact level and management needs]
- Psychological factors: [Risk level and intervention needs]  
- Social factors: [Barrier level and support needs]

**Flag Interaction Patterns:**
- How different flags reinforce each other
- Cascade effects between flag categories
- Priority intervention targets

**Recovery Prognosis:**
- Overall recovery likelihood: [Excellent/Good/Fair/Poor]
- Expected timeline with current risk profile
- Factors that could improve prognosis
- Risk factors for poor outcomes

**🎯 INTERVENTION PRIORITIES:**

**Immediate Priority Actions:**
1. **Safety/Medical:** [Urgent medical or safety needs]
2. **High-Impact Interventions:** [Most effective risk modifications]
3. **System/Advocacy:** [External system interventions needed]

**Short-Term Interventions (1-4 weeks):**
- Psychosocial support strategies
- Patient education priorities
- Environmental modifications
- Support system engagement

**Medium-Term Planning (1-3 months):**
- Comprehensive biopsychosocial treatment approach
- Multidisciplinary team coordination
- Workplace intervention strategies
- Lifestyle modification programs

**🔍 MONITORING AND REASSESSMENT:**

**Progress Indicators:**
- Key metrics to track improvement
- Warning signs of deterioration
- Success markers for interventions

**Reassessment Schedule:**
- Frequency of flag reassessment
- Triggers for urgent reassessment
- Outcome measure monitoring

**🤝 COLLABORATIVE CARE RECOMMENDATIONS:**

**Referral Priorities:**
- Medical specialist referrals needed
- Mental health professional involvement
- Occupational therapy/vocational counseling
- Social services or advocacy support

**Team Communication:**
- Key information to share with team
- Coordination strategies
- Progress reporting methods

**📋 TREATMENT PLANNING IMPLICATIONS:**

**Physiotherapy Approach Modifications:**
- Treatment intensity considerations
- Pacing and progression modifications
- Patient education focus areas
- Home program adaptations

**Goal Setting Considerations:**
- Realistic timeline adjustments
- Functional vs impairment-based goals
- Patient-centered priority alignment
- Family/workplace goal integration

This comprehensive analysis provides evidence-based risk stratification and intervention planning for optimal biopsychosocial care coordination.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Clinical Flags Comprehensive Analysis",
            details=f"Generated comprehensive flags analysis for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI clinical flags comprehensive analysis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-flags-orange-suggestions", methods=["POST"])
@login_required()
def ai_clinical_flags_orange_suggestions():
    """AI suggests orange flag indicators for psychiatric conditions"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        perspectives = all_data.get('patient_perspectives', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        
        prompt = f"""
Analyze patient data for ORANGE FLAG indicators of psychiatric illness requiring specialized intervention.

PATIENT BACKGROUND:
- Demographics: {patient.get('age_sex', '')}
- Medical History: {patient.get('past_history', '')}
- Current Condition: {patient.get('present_history', '')}

PSYCHOSOCIAL PROFILE:
- Emotional Response: {perspectives.get('affective_aspect', '')}
- Illness Attribution: {perspectives.get('attribution', '')}
- Locus of Control: {perspectives.get('locus_of_control', '')}
- Consequences Awareness: {perspectives.get('consequences_awareness', '')}

SYMPTOM CONTEXT:
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Pain Nature: {patho_mechanism.get('pain_nature', '')}
- Contributing Factors: {chronic_disease.get('cause', '')}

**🟠 ORANGE FLAG ASSESSMENT:**

Evaluate for psychiatric conditions requiring specialized care:

**MOOD DISORDERS:**
- Clinical depression indicators
- Bipolar disorder signs
- Seasonal affective patterns
- Grief and bereavement issues

**ANXIETY DISORDERS:**
- Generalized anxiety disorder
- Panic disorder symptoms
- PTSD indicators
- Phobias affecting treatment

**SUBSTANCE USE DISORDERS:**
- Alcohol dependency
- Prescription drug misuse
- Illicit substance use
- Withdrawal symptoms

**SERIOUS MENTAL ILLNESS:**
- Psychotic symptoms
- Suicidal ideation
- Self-harm behaviors
- Severe personality disorders

**COGNITIVE DISORDERS:**
- Dementia indicators
- Delirium signs
- Cognitive impairment

**SCREENING RECOMMENDATIONS:**
- Specific assessment tools to use
- Questions for mental health screening
- Referral criteria and urgency
- Safety assessment needs

**TREATMENT CONSIDERATIONS:**
- How psychiatric conditions affect physiotherapy
- Modifications needed for care
- Collaboration with mental health services

Provide specific orange flag assessment for this patient's mental health indicators.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/clinical-flags-yellow-suggestions", methods=["POST"])
@login_required()
def ai_clinical_flags_yellow_suggestions():
    """AI suggests yellow flag psychosocial risk factors"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Analyze patient data for YELLOW FLAG psychosocial risk factors affecting recovery.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Condition Duration: {patient.get('present_history', '')}

PSYCHOSOCIAL FACTORS:
- Knowledge Level: {perspectives.get('knowledge', '')}
- Attribution Beliefs: {perspectives.get('attribution', '')}
- Recovery Expectations: {perspectives.get('illness_duration', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}

FUNCTIONAL IMPACT:
- Activity Performance: {subjective.get('activity_performance', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}
- Environmental Context: {subjective.get('contextual_environmental', '')}

PAIN PROFILE:
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Pain Irritability: {patho_mechanism.get('pain_irritability', '')}

**🟡 YELLOW FLAG ASSESSMENT:**

Evaluate psychosocial risk factors for chronicity:

**PAIN BELIEFS AND ATTITUDES:**
- Fear-avoidance behaviors
- Catastrophic thinking patterns
- Pain as signal of harm beliefs
- Passive coping strategies

**EMOTIONAL FACTORS:**
- Stress and distress levels
- Anxiety about pain/movement
- Frustration and anger
- Mood changes

**BEHAVIORAL PATTERNS:**
- Activity avoidance
- Overprotective behaviors
- All-or-nothing activity patterns
- Sleep disturbances

**COGNITIVE FACTORS:**
- Negative thought patterns
- Poor concentration
- Memory difficulties
- Attention to pain

**SOCIAL FACTORS:**
- Social withdrawal
- Family overprotection
- Relationship conflicts
- Communication difficulties

**TREATMENT-RELATED FACTORS:**
- Previous negative experiences
- Treatment expectations
- Compliance concerns
- Healthcare relationships

**WORK/ACTIVITY FACTORS:**
- Job dissatisfaction
- Role conflicts
- Activity restrictions
- Return-to-work concerns

**RISK STRATIFICATION:**
- Low/Moderate/High risk assessment
- Most significant yellow flags present
- Protective factors identified
- Intervention priorities

Provide specific yellow flag assessment and risk mitigation strategies.
"""
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500


# ADD THESE NEW AI ENDPOINTS TO YOUR APP.PY (after your existing AI endpoints)
@limiter.limit("5 per minute")
@app.route("/api/ai/objective-assessment-recommendations", methods=["POST"])
@login_required()
def ai_objective_assessment_recommendations():
    """AI provides overall objective assessment strategy recommendations"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        clinical_flags = all_data.get('clinical_flags', {})
        
        prompt = f"""
You are an expert physiotherapist developing an objective assessment strategy. Based on comprehensive patient data, provide specific assessment recommendations.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

SUBJECTIVE FINDINGS:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Impairments: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}

PATHOPHYSIOLOGICAL CONTEXT:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Pain Type/Nature: {patho_mechanism.get('pain_type', '')} / {patho_mechanism.get('pain_nature', '')}
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Irritability: {patho_mechanism.get('pain_irritability', '')}
- Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}

PSYCHOSOCIAL FACTORS:
- Yellow Flags: {clinical_flags.get('yellow_flag', '')}
- Patient Fears/Concerns: {perspectives.get('affective_aspect', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}

INITIAL ASSESSMENT PLANNING:
- Active Movements: {initial_plan.get('active_movements', '')}
- Passive Movements: {initial_plan.get('passive_movements', '')}
- Resisted Movements: {initial_plan.get('resisted_movements', '')}
- Special Tests: {initial_plan.get('special_tests', '')}
- Neurodynamic Exam: {initial_plan.get('neuro_dynamic_examination', '')}

CLINICAL FLAGS:
- Red Flags: {clinical_flags.get('red_flag', '')}
- Orange Flags: {clinical_flags.get('orange_flag', '')}

**🎯 OBJECTIVE ASSESSMENT STRATEGY:**

**OVERALL ASSESSMENT APPROACH RECOMMENDATION:**
- **Recommended Strategy:** [Comprehensive/Selective/Limited/Screening/Functional/Progressive]
- **Rationale:** [Why this approach is optimal for this patient]
- **Safety Considerations:** [Key precautions based on clinical flags]

**ASSESSMENT PRIORITIZATION:**

**Priority 1 (Essential/Mandatory):**
- Most critical assessments for diagnosis confirmation
- Safety screening requirements
- Baseline functional measures

**Priority 2 (Important):**
- Supporting diagnostic tests
- Impairment quantification
- Outcome measure establishment

**Priority 3 (If Time/Tolerance Permits):**
- Additional confirmatory tests
- Research measures
- Comprehensive screening

**SAFETY MODIFICATIONS REQUIRED:**
- Movement restrictions and precautions
- Pain monitoring protocols
- Assessment sequence modifications
- Patient positioning considerations

**EXPECTED ASSESSMENT FINDINGS:**
- Likely positive/negative test results
- Expected movement limitations
- Probable functional deficits
- Diagnostic confirmation expectations

**PATIENT-SPECIFIC CONSIDERATIONS:**
- Fear-avoidance accommodation strategies
- Communication approach during assessment
- Motivation and engagement strategies
- Cultural and personal factor accommodations

**ASSESSMENT SEQUENCING:**
- Optimal order of assessment components
- Rest periods and pacing considerations
- Assessment session planning
- Follow-up assessment needs

This assessment strategy is designed to be safe, efficient, and diagnostically valuable for this specific patient presentation.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Objective Assessment Recommendations",
            details=f"Generated assessment strategy for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI objective assessment recommendations error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/objective-assessment-movement-suggestions", methods=["POST"])
@login_required()
def ai_objective_assessment_movement_suggestions():
    """AI suggests movement assessment strategies"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        initial_plan = all_data.get('initial_plan', {})
        clinical_flags = all_data.get('clinical_flags', {})
        
        prompt = f"""
Provide specific movement assessment recommendations based on patient presentation.

MOVEMENT CONTEXT:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Pain Irritability: {patho_mechanism.get('pain_irritability', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}

ASSESSMENT PLANNING:
- Active Movements: {initial_plan.get('active_movements', '')}
- Passive Movements: {initial_plan.get('passive_movements', '')}
- Combined Movements: {initial_plan.get('combined_movements', '')}

SAFETY CONSIDERATIONS:
- Red Flags: {clinical_flags.get('red_flag', '')}
- Patient Fears: Present based on presentation

**🏃‍♂️ MOVEMENT ASSESSMENT STRATEGY:**

**ACTIVE MOVEMENT ASSESSMENT:**
- Specific active movements to prioritize
- Range of motion expectations
- Pain monitoring during active movement
- Quality of movement assessment
- Functional movement patterns

**PASSIVE MOVEMENT ASSESSMENT:**
- Passive ROM testing priorities
- End-feel assessment expectations
- Joint mobility evaluation
- Tissue texture assessment

**MOVEMENT QUALITY ANALYSIS:**
- Compensation patterns to observe
- Movement coordination assessment
- Balance and proprioception evaluation
- Motor control testing

**FUNCTIONAL MOVEMENT ASSESSMENT:**
- Activity-specific movement testing
- Work/sport-related movement patterns
- Daily living movement evaluation
- Environmental context movement

**SAFETY PROTOCOLS:**
- Movement testing precautions
- Pain response monitoring
- Stop criteria during testing
- Patient education during movement

**EXPECTED FINDINGS:**
- Likely movement restrictions
- Expected pain responses
- Quality indicators to assess
- Functional limitations anticipated

Provide specific, safe movement assessment recommendations for this patient.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/objective-assessment-strength-suggestions", methods=["POST"])
@login_required()
def ai_objective_assessment_strength_suggestions():
    """AI suggests strength and function assessment strategies"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404
        
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        initial_plan = all_data.get('initial_plan', {})
        
        prompt = f"""
        Based on comprehensive patient assessment data, provide specific strength and functional assessment recommendations:
        
        PATIENT CONTEXT:
        - Demographics: {patient.get('age_sex', '')}
        - Condition: {patient.get('present_history', '')}
        - Body Structures: {subjective.get('body_structure', '')}
        - Activity Performance: {subjective.get('activity_performance', '')}
        - Initial Assessment Plan: {initial_plan}
        
        STRENGTH ASSESSMENT PRIORITIES:
        
        1. **MUSCLE STRENGTH TESTING:**
           - Primary muscle groups to assess
           - Manual muscle testing priorities (0-5 scale)
           - Functional strength testing recommendations
           - Isometric vs dynamic strength assessment
        
        2. **FUNCTIONAL STRENGTH ASSESSMENT:**
           - Task-specific strength requirements
           - Endurance vs power assessment needs
           - Functional movement screening priorities
           - Weight-bearing vs non-weight-bearing tests
        
        3. **ASSESSMENT SAFETY CONSIDERATIONS:**
           - Contraindications to strength testing
           - Pain monitoring during assessment
           - Fatigue management protocols
           - Red flag monitoring during testing
        
        4. **SPECIFIC TEST RECOMMENDATIONS:**
           - Standardized strength assessment tools
           - Functional capacity evaluation components
           - Baseline measurements for goal setting
           - Progress monitoring strategies
        
        5. **ASSESSMENT SEQUENCE:**
           - Order of strength testing
           - Rest periods between tests
           - Patient positioning considerations
           - Equipment requirements
        
        Provide evidence-based strength assessment strategy tailored to this patient's presentation and functional needs.
        """
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Strength Assessment Strategy",
            details=f"Generated strength assessment recommendations for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI strength assessment error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

# ADD THESE NEW AI ENDPOINTS TO YOUR APP.PY (after your existing AI endpoints)

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-analysis", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_analysis():
    """AI provides overall diagnostic analysis based on complete assessment"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        clinical_flags = all_data.get('clinical_flags', {})
        objective_assessment = all_data.get('objective_assessment', {})
        
        prompt = f"""
You are an expert physiotherapist providing diagnostic analysis. Based on comprehensive assessment data, provide evidence-based diagnostic reasoning.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

SUBJECTIVE ASSESSMENT:
- Body Structure Issues: {subjective.get('body_structure', '')}
- Body Function Impairments: {subjective.get('body_function', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}

PATHOPHYSIOLOGICAL ANALYSIS:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Pain Profile: {patho_mechanism.get('pain_type', '')} - {patho_mechanism.get('pain_nature', '')}
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Symptom Source: {patho_mechanism.get('symptom_source', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}

PSYCHOSOCIAL FACTORS:
- Clinical Flags: Red: {clinical_flags.get('red_flag', '')}, Yellow: {clinical_flags.get('yellow_flag', '')}
- Patient Perspectives: {perspectives.get('affective_aspect', '')}

CHRONICITY FACTORS:
- Contributing Factors: {chronic_disease.get('cause', '')}

OBJECTIVE ASSESSMENT:
- Assessment Plan: {objective_assessment.get('plan', '')}
- Assessment Details: {objective_assessment.get('plan_details', '')}

**🔬 COMPREHENSIVE DIAGNOSTIC ANALYSIS:**

**PRIMARY DIAGNOSTIC HYPOTHESIS:**
- Most likely diagnosis with confidence level
- Anatomical structures involved
- Pathophysiological mechanism
- Clinical reasoning supporting this diagnosis

**DIFFERENTIAL DIAGNOSIS:**
- Alternative diagnostic possibilities (ranked by likelihood)
- Key distinguishing features
- Additional tests needed for confirmation

**DIAGNOSTIC CONFIDENCE ASSESSMENT:**
- Overall confidence level (High/Moderate/Low)
- Quality of supporting evidence
- Areas of diagnostic uncertainty
- Need for further assessment

**CLINICAL REASONING INTEGRATION:**
- How subjective findings support diagnosis
- Pathophysiological consistency
- Psychosocial factor integration
- Chronicity risk implications

**EVIDENCE QUALITY ANALYSIS:**
- Strength of supporting evidence
- Reliability of diagnostic indicators
- Gaps in assessment data
- Diagnostic certainty factors

**TREATMENT PLANNING IMPLICATIONS:**
- How diagnosis guides treatment approach
- Prognosis implications
- Risk stratification for treatment
- Multidisciplinary needs

**DIAGNOSTIC MONITORING:**
- Signs of diagnostic accuracy
- Red flags for alternative diagnoses
- Progress indicators to confirm diagnosis
- Reassessment needs

Provide evidence-based, clinically sound diagnostic analysis for this patient.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Provisional Diagnosis Analysis",
            details=f"Generated diagnostic analysis for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI provisional diagnosis analysis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-likelihood-suggestions", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_likelihood_suggestions():
    """AI suggests likelihood assessment for diagnosis"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        patho_mechanism = all_data.get('patho_mechanism', {})
        objective_assessment = all_data.get('objective_assessment', {})
        clinical_flags = all_data.get('clinical_flags', {})
        
        prompt = f"""
Provide diagnostic likelihood assessment based on clinical presentation and assessment findings.

CLINICAL CONTEXT:
- Condition: {patient.get('present_history', '')}
- Demographics: {patient.get('age_sex', '')}
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Pain Profile: {patho_mechanism.get('pain_type', '')} - {patho_mechanism.get('pain_severity', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}

ASSESSMENT FINDINGS:
- Assessment Approach: {objective_assessment.get('plan', '')}
- Detailed Findings: {objective_assessment.get('plan_details', '')}
- Red Flag Status: {clinical_flags.get('red_flag', '')}

**📊 DIAGNOSTIC LIKELIHOOD ASSESSMENT:**

**CONFIDENCE LEVEL ANALYSIS:**
- High Confidence (80-95%): Clear diagnostic indicators present
- Moderate Confidence (60-79%): Good evidence with some uncertainty
- Low Confidence (40-59%): Limited evidence, multiple possibilities
- Very Low Confidence (<40%): Insufficient data for diagnosis

**EVIDENCE STRENGTH EVALUATION:**
- Quality of supporting clinical evidence
- Consistency of findings with suspected diagnosis
- Reliability of assessment data
- Diagnostic test sensitivity/specificity

**DIAGNOSTIC CERTAINTY FACTORS:**
- Pathognomonic signs present/absent
- Classic presentation vs atypical presentation
- Objective findings correlation
- Response to previous treatments

**LIKELIHOOD STATEMENT EXAMPLES:**
- "High confidence (85%) - Classic presentation with multiple confirmatory findings"
- "Moderate confidence (70%) - Consistent with diagnosis but some atypical features"
- "Low confidence (50%) - Limited diagnostic clarity, requires further assessment"

**UNCERTAINTY FACTORS:**
- Areas requiring further clarification
- Alternative diagnostic possibilities
- Missing assessment data
- Conflicting findings

Provide specific likelihood assessment with confidence percentages and clinical reasoning.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-structure-suggestions", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_structure_suggestions():
    """AI suggests anatomical structures at fault"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        objective_assessment = all_data.get('objective_assessment', {})
        
        prompt = f"""
Identify anatomical structures at fault based on clinical presentation and assessment.

STRUCTURAL ANALYSIS CONTEXT:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Body Structure Issues: {subjective.get('body_structure', '')}
- Pain Type/Source: {patho_mechanism.get('pain_type', '')} - {patho_mechanism.get('symptom_source', '')}
- Assessment Findings: {objective_assessment.get('plan_details', '')}

**🏗️ ANATOMICAL STRUCTURE ANALYSIS:**

**PRIMARY STRUCTURES:**
- Main anatomical structures involved
- Tissue types affected (joint, muscle, ligament, nerve, etc.)
- Specific anatomical locations
- Primary vs secondary involvement

**TISSUE-SPECIFIC ANALYSIS:**
- Articular structures (joint capsule, cartilage, synovium)
- Periarticular structures (ligaments, tendons, bursae)
- Myofascial structures (muscles, fascia, trigger points)
- Neural structures (nerve roots, peripheral nerves)
- Vascular structures (if relevant)

**ANATOMICAL REASONING:**
- How clinical presentation localizes to specific structures
- Biomechanical factors affecting these structures
- Pain referral patterns from identified structures
- Functional anatomy relationships

**STRUCTURE PRIORITIZATION:**
- Primary structure most likely at fault
- Secondary structures contributing to symptoms
- Associated structures requiring consideration
- Compensatory structure involvement

**PATHOLOGICAL PROCESSES:**
- Type of tissue pathology (inflammatory, mechanical, degenerative)
- Acute vs chronic structural changes
- Healing capacity of identified structures
- Progressive vs stable structural involvement

**CLINICAL CORRELATION:**
- How identified structures explain symptom patterns
- Movement limitations related to structural involvement
- Treatment implications for specific structures
- Prognosis based on structures involved

Provide specific anatomical structure identification with clinical reasoning.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-symptom-suggestions", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_symptom_suggestions():
    """AI suggests symptom pattern analysis"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Analyze symptom patterns that support the diagnostic hypothesis.

SYMPTOM CONTEXT:
- Present History: {patient.get('present_history', '')}
- Presenting Symptoms: {patho_mechanism.get('presenting_symptom', '')}
- Pain Profile: {patho_mechanism.get('pain_type', '')} - {patho_mechanism.get('pain_nature', '')}
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Pain Irritability: {patho_mechanism.get('pain_irritability', '')}
- Activity Impact: {subjective.get('activity_performance', '')}

**⚡ SYMPTOM PATTERN ANALYSIS:**

**PAIN CHARACTERISTICS:**
- Quality of pain (sharp, dull, burning, aching)
- Temporal patterns (constant, intermittent, variable)
- Intensity patterns and fluctuations
- Pain behavior throughout day

**AGGRAVATING FACTORS:**
- Specific movements that worsen symptoms
- Positions that increase pain
- Activities that provoke symptoms
- Environmental factors affecting symptoms

**RELIEVING FACTORS:**
- Movements/positions that ease symptoms
- Activities that provide relief
- Treatment responses observed
- Rest patterns and symptom relief

**SYMPTOM DISTRIBUTION:**
- Primary symptom location
- Referred symptom patterns
- Radiation or spreading patterns
- Bilateral vs unilateral presentation

**FUNCTIONAL SYMPTOM CORRELATION:**
- How symptoms relate to functional activities
- Impact on daily living tasks
- Work/sport-specific symptom patterns
- Sleep and rest-related symptoms

**NEUROLOGICAL SYMPTOM PATTERNS:**
- Sensory symptoms (numbness, tingling, burning)
- Motor symptoms (weakness, fatigue, coordination)
- Autonomic symptoms (if present)
- Central vs peripheral symptom patterns

**SYMPTOM EVOLUTION:**
- Onset pattern (gradual vs sudden)
- Progression over time
- Response to previous treatments
- Seasonal or cyclical patterns

**DIAGNOSTIC SYMPTOM SIGNIFICANCE:**
- Pathognomonic symptoms for suspected condition
- Red flag symptoms screening
- Symptom patterns supporting specific diagnoses
- Atypical symptoms requiring consideration

Provide comprehensive symptom pattern analysis supporting diagnostic reasoning.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-supporting-suggestions", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_supporting_suggestions():
    """AI suggests findings that support the diagnosis"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        objective_assessment = all_data.get('objective_assessment', {})
        clinical_flags = all_data.get('clinical_flags', {})
        
        prompt = f"""
Identify examination findings that support the provisional diagnosis.

ASSESSMENT CONTEXT:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Assessment Plan: {objective_assessment.get('plan', '')}
- Assessment Details: {objective_assessment.get('plan_details', '')}
- Special Tests Planned: {initial_plan.get('special_tests', '')}
- Movement Assessment: {initial_plan.get('active_movements', '')} / {initial_plan.get('passive_movements', '')}

**✅ SUPPORTING EXAMINATION FINDINGS:**

**MOVEMENT ASSESSMENT FINDINGS:**
- Range of motion limitations supporting diagnosis
- Movement quality abnormalities
- Pain reproduction with specific movements
- Functional movement restrictions

**SPECIAL TEST RESULTS:**
- Positive special tests for suspected condition
- Diagnostic test sensitivity and specificity
- Cluster of tests supporting diagnosis
- Orthopedic test battery results

**PALPATION FINDINGS:**
- Tissue texture abnormalities
- Tenderness patterns
- Muscle tone changes
- Joint alignment findings

**NEUROLOGICAL FINDINGS:**
- Sensory testing results
- Motor testing findings
- Reflex changes
- Neurodynamic test results

**FUNCTIONAL ASSESSMENT:**
- Activity limitation patterns
- Performance deficits
- Compensatory movement patterns
- Functional capacity limitations

**STRENGTH TESTING:**
- Muscle weakness patterns
- Strength deficit distribution
- Pain-limited vs true weakness
- Functional strength deficits

**JOINT ASSESSMENT:**
- Joint mobility restrictions
- End-feel characteristics
- Joint stability findings
- Accessory motion limitations

**POSTURAL ASSESSMENT:**
- Static postural deviations
- Dynamic postural control
- Alignment abnormalities
- Compensatory postures

**SUBJECTIVE CORRELATION:**
- Patient-reported symptoms matching findings
- Functional complaints correlating with tests
- Pain behavior consistency
- Response to examination procedures

**DIAGNOSTIC CLUSTER ANALYSIS:**
- Combination of findings supporting diagnosis
- Clinical prediction rules applicable
- Evidence-based diagnostic criteria
- Pattern recognition for condition

Provide specific examination findings that confirm the diagnostic hypothesis.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-rejecting-suggestions", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_rejecting_suggestions():
    """AI suggests findings that rule out alternative diagnoses"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        patho_mechanism = all_data.get('patho_mechanism', {})
        objective_assessment = all_data.get('objective_assessment', {})
        clinical_flags = all_data.get('clinical_flags', {})
        initial_plan = all_data.get('initial_plan', {})
        
        prompt = f"""
Identify findings that rule out alternative diagnostic possibilities.

DIFFERENTIAL DIAGNOSIS CONTEXT:
- Present History: {patient.get('present_history', '')}
- Pain Source: {patho_mechanism.get('symptom_source', '')}
- Red Flag Assessment: {clinical_flags.get('red_flag', '')}
- Neurodynamic Assessment: {initial_plan.get('neuro_dynamic_examination', '')}
- Assessment Findings: {objective_assessment.get('plan_details', '')}

**❌ FINDINGS RULING OUT ALTERNATIVE DIAGNOSES:**

**NEUROLOGICAL RULE-OUTS:**
- Normal neurological screening rules out nerve compression
- Negative neurodynamic tests rule out nerve entrapment
- Normal reflexes rule out upper motor neuron lesions
- Intact sensation rules out sensory nerve damage
- Normal strength rules out motor nerve involvement

**SERIOUS PATHOLOGY RULE-OUTS:**
- Negative red flag screening rules out serious conditions
- Normal systems review rules out systemic disease
- Age-appropriate presentation rules out malignancy
- Mechanical pain pattern rules out inflammatory conditions
- Localized symptoms rule out systemic involvement

**STRUCTURAL RULE-OUTS:**
- Negative instability tests rule out ligament rupture
- Normal joint alignment rules out fracture/dislocation
- Negative compression tests rule out disc herniation
- Normal end-feel rules out capsular restriction
- Symmetrical findings rule out unilateral pathology

**VASCULAR RULE-OUTS:**
- Normal pulses rule out vascular compromise
- Normal skin color/temperature rule out circulatory issues
- Absence of claudication rules out vascular insufficiency
- Normal capillary refill rules out perfusion problems

**INFLAMMATORY RULE-OUTS:**
- Absence of systemic symptoms rules out inflammatory disease
- Normal morning stiffness pattern rules out arthritis
- Mechanical pain pattern rules out inflammatory pain
- Localized presentation rules out systemic inflammation

**PSYCHOSOCIAL RULE-OUTS:**
- Appropriate pain behavior rules out non-organic presentation
- Consistent examination findings rule out symptom magnification
- Reasonable functional limitations rule out malingering
- Organic pain pattern rules out central sensitization

**CONDITION-SPECIFIC RULE-OUTS:**
- Based on area involved and presentation
- Negative tests for common differential diagnoses
- Absence of characteristic signs for alternative conditions
- Inconsistent presentation with other diagnoses

**MECHANISM-BASED RULE-OUTS:**
- Biomechanical vs pathological mechanisms
- Acute vs chronic presentation patterns
- Local vs referred symptom patterns
- Mechanical vs inflammatory processes

Provide specific findings that eliminate alternative diagnostic possibilities.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-hypothesis-suggestions", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_hypothesis_suggestions():
    """AI suggests overall hypothesis support assessment"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive data for hypothesis evaluation
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        objective_assessment = all_data.get('objective_assessment', {})
        clinical_flags = all_data.get('clinical_flags', {})
        
        prompt = f"""
Evaluate overall support for diagnostic hypothesis based on complete clinical assessment.

COMPREHENSIVE CLINICAL PICTURE:
- Patient Profile: {patient.get('age_sex', '')} - {patient.get('present_history', '')}
- Pathophysiology: {patho_mechanism.get('area_involved', '')} - {patho_mechanism.get('pain_type', '')}
- Assessment Quality: {objective_assessment.get('plan', '')}
- Clinical Complexity: {clinical_flags.get('red_flag', '')} / {clinical_flags.get('yellow_flag', '')}

**🎯 HYPOTHESIS SUPPORT EVALUATION:**

**STRONGLY SUPPORTED (High Confidence):**
- Multiple confirmatory findings present
- Classic presentation with typical features
- Positive diagnostic tests with high specificity
- Consistent subjective and objective findings
- Clear treatment response if applicable

**MODERATELY SUPPORTED (Good Confidence):**
- Majority of findings support diagnosis
- Some atypical features present
- Good correlation between symptoms and signs
- Minor inconsistencies in presentation
- Alternative diagnoses less likely

**WEAKLY SUPPORTED (Limited Confidence):**
- Limited confirmatory findings
- Mixed or inconsistent presentation
- Alternative diagnoses equally possible
- Incomplete assessment data
- Unclear symptom patterns

**INCONCLUSIVE (Uncertain):**
- Conflicting examination findings
- Multiple equally likely diagnoses
- Insufficient assessment data
- Atypical presentation patterns
- Need for further investigation

**NOT SUPPORTED (Contradicted):**
- Findings contradict initial hypothesis
- Alternative diagnosis more likely
- Evidence points to different condition
- Symptoms don't match expected pattern
- Treatment response contradicts diagnosis

**EVIDENCE QUALITY FACTORS:**
- Reliability of assessment methods used
- Completeness of examination
- Patient cooperation and accuracy
- Examiner experience and skill
- Objective vs subjective finding balance

**DECISION-MAKING FACTORS:**
- Clinical experience correlation
- Evidence-based practice alignment
- Risk-benefit of diagnostic certainty
- Treatment planning requirements
- Monitoring and reassessment needs

**RECOMMENDATIONS:**
- Level of diagnostic confidence achieved
- Additional assessment needs
- Treatment trial considerations
- Specialist referral requirements
- Follow-up and monitoring plans

Provide specific hypothesis support assessment with clear reasoning.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/provisional-diagnosis-comprehensive-reasoning", methods=["POST"])
@login_required()
def ai_provisional_diagnosis_comprehensive_reasoning():
    """AI provides comprehensive diagnostic reasoning and treatment planning"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        diagnosis_data = data.get("diagnosis_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract all available clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        clinical_flags = all_data.get('clinical_flags', {})
        objective_assessment = all_data.get('objective_assessment', {})
        
        prompt = f"""
Provide comprehensive diagnostic reasoning and clinical decision-making analysis.

COMPLETE PATIENT ASSESSMENT:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

COMPREHENSIVE CLINICAL DATA:
- Subjective Findings: {subjective.get('body_function', '')} / {subjective.get('activity_performance', '')}
- Pathophysiology: {patho_mechanism.get('area_involved', '')} - {patho_mechanism.get('tissue_healing_stage', '')}
- Psychosocial Profile: {perspectives.get('affective_aspect', '')} / {clinical_flags.get('yellow_flag', '')}
- Assessment Strategy: {objective_assessment.get('plan', '')}
- Chronicity Factors: {chronic_disease.get('cause', '')}

PROVISIONAL DIAGNOSIS ANALYSIS:
- Likelihood Assessment: {diagnosis_data.get('likelihood', '')}
- Structure at Fault: {diagnosis_data.get('structure_fault', '')}
- Symptom Pattern: {diagnosis_data.get('symptom', '')}
- Supporting Findings: {diagnosis_data.get('findings_support', '')}
- Rejecting Findings: {diagnosis_data.get('findings_reject', '')}
- Hypothesis Support: {diagnosis_data.get('hypothesis_supported', '')}

**🧠 COMPREHENSIVE DIAGNOSTIC REASONING:**

**CLINICAL REASONING SYNTHESIS:**
- Integration of all assessment findings
- Biopsychosocial model application
- Evidence-based diagnostic approach
- Clinical pattern recognition analysis

**DIAGNOSTIC CONFIDENCE ANALYSIS:**
- Overall diagnostic certainty level
- Quality of supporting evidence
- Reliability of assessment data
- Areas requiring further clarification

**DIFFERENTIAL DIAGNOSIS HIERARCHY:**
- Primary diagnosis with confidence level
- Secondary diagnostic possibilities
- Rule-out diagnoses considered
- Red flag conditions excluded

**PROGNOSIS ASSESSMENT:**
- Expected recovery timeline
- Favorable prognostic indicators
- Risk factors for poor outcomes
- Complications to monitor

**🎯 TREATMENT PLANNING IMPLICATIONS:**

**Treatment Approach Framework:**
- Tissue-specific treatment needs
- Phase-appropriate interventions
- Biopsychosocial treatment integration
- Evidence-based treatment selection

**Goal Setting Implications:**
- Realistic timeline expectations
- Functional outcome priorities
- Patient-centered goal alignment
- Measurable progress indicators

**Risk Stratification:**
- Treatment complexity requirements
- Safety considerations and precautions
- Chronicity risk management
- Psychosocial intervention needs

**Multidisciplinary Considerations:**
- Specialist referral requirements
- Team collaboration needs
- Shared care responsibilities
- Communication priorities

**📊 CLINICAL DECISION POINTS:**

**Immediate Decisions:**
- Treatment initiation strategies
- Safety and precaution protocols
- Patient education priorities
- Baseline measurement establishment

**Short-term Monitoring:**
- Progress indicators to track
- Treatment response expectations
- Reassessment trigger points
- Modification criteria

**Long-term Planning:**
- Outcome measurement strategy
- Discharge planning considerations
- Relapse prevention planning
- Maintenance program needs

**🔍 QUALITY ASSURANCE:**

**Diagnostic Accuracy Monitoring:**
- Signs confirming diagnostic accuracy
- Red flags for diagnostic error
- Treatment response as diagnostic confirmation
- Reassessment and revision protocols

**Evidence Integration:**
- Research evidence supporting approach
- Clinical guidelines application
- Best practice alignment
- Outcome prediction accuracy

**Professional Development:**
- Learning opportunities from case
- Diagnostic reasoning refinement
- Clinical skill enhancement areas
- Knowledge gap identification

This comprehensive analysis provides evidence-based diagnostic reasoning with clear treatment planning direction and quality assurance measures.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Comprehensive Diagnostic Reasoning",
            details=f"Generated comprehensive diagnostic reasoning for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI comprehensive diagnostic reasoning error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

# ADD THESE NEW AI ENDPOINTS TO YOUR APP.PY (after your existing AI endpoints)
@limiter.limit("5 per minute")
@app.route("/api/ai/smart-goals-recommendations", methods=["POST"])
@login_required()
def ai_smart_goals_recommendations():
    """AI provides overall SMART goals strategy recommendations"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        clinical_flags = all_data.get('clinical_flags', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        
        prompt = f"""
You are an expert physiotherapist developing evidence-based SMART goals. Based on comprehensive assessment and diagnosis, provide intelligent goal-setting recommendations.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

DIAGNOSTIC CONTEXT:
- Provisional Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Symptom Pattern: {provisional_diagnosis.get('symptom', '')}
- Diagnostic Confidence: {provisional_diagnosis.get('hypothesis_supported', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}

FUNCTIONAL IMPACT:
- Activity Limitations: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PAIN PROFILE:
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Pain Irritability: {patho_mechanism.get('pain_irritability', '')}
- Pain Nature: {patho_mechanism.get('pain_nature', '')}

PSYCHOSOCIAL FACTORS:
- Patient Expectations: {perspectives.get('illness_duration', '')}
- Recovery Beliefs: {perspectives.get('locus_of_control', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}
- Yellow Flags: {clinical_flags.get('yellow_flag', '')}

CHRONICITY RISK:
- Contributing Factors: {chronic_disease.get('cause', '')}

**🎯 SMART GOALS STRATEGY RECOMMENDATIONS:**

**GOAL SETTING FRAMEWORK:**
- **Primary Goal Categories:** [Functional, pain, participation, quality of life]
- **Goal Prioritization:** [Patient priorities vs clinical priorities alignment]
- **Realistic Timeline:** [Based on diagnosis and healing factors]
- **Measurement Strategy:** [Appropriate outcome measures for this condition]

**SPECIFIC GOAL RECOMMENDATIONS:**

**Short-Term Goals (2-4 weeks):**
- Pain management and initial function improvement
- Early mobility and movement restoration
- Patient education and self-management
- Acute symptom management

**Medium-Term Goals (4-8 weeks):**
- Functional capacity building
- Activity progression and tolerance
- Strength and endurance development
- Work/activity preparation

**Long-Term Goals (8-12+ weeks):**
- Return to full function
- Activity participation restoration
- Preventive strategies implementation
- Long-term self-management

**PATIENT-CENTERED CONSIDERATIONS:**
- Alignment with patient's life priorities
- Work/occupation-specific goals
- Recreation/sport-specific needs
- Family/caregiver involvement

**EVIDENCE-BASED EXPECTATIONS:**
- Typical recovery timelines for this condition
- Prognostic factors affecting outcomes
- Realistic functional expectations
- Risk factors for delayed recovery

**MEASUREMENT RECOMMENDATIONS:**
- Condition-specific outcome measures
- Functional performance tests
- Pain and disability scales
- Quality of life assessments

**GOAL MODIFICATION FACTORS:**
- Psychosocial risk considerations
- Chronicity prevention priorities
- Environmental adaptation needs
- Support system optimization

This SMART goals strategy provides evidence-based, patient-centered goal development for optimal treatment outcomes.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI SMART Goals Recommendations",
            details=f"Generated SMART goals strategy for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI SMART goals recommendations error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/smart-goals-patient-goals-suggestions", methods=["POST"])
@login_required()
def ai_smart_goals_patient_goals_suggestions():
    """AI suggests patient-centered goals"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        
        prompt = f"""
Develop patient-centered, functional goals based on patient priorities and daily life needs.

PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Life Situation: {patient.get('present_history', '')}
- Activity Limitations: {subjective.get('activity_performance', '')}
- Environmental Context: {subjective.get('contextual_environmental', '')}
- Personal Factors: {subjective.get('contextual_personal', '')}

PATIENT PERSPECTIVES:
- Recovery Expectations: {perspectives.get('illness_duration', '')}
- Consequences Awareness: {perspectives.get('consequences_awareness', '')}
- Knowledge Level: {perspectives.get('knowledge', '')}

CONDITION IMPACT:
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Functional Impact: {subjective.get('activity_capacity', '')}

**🎯 PATIENT-CENTERED GOALS:**

**DAILY LIVING GOALS:**
- Personal care and self-care activities
- Household tasks and responsibilities
- Family and social role participation
- Community and leisure activities

**WORK/OCCUPATION GOALS:**
- Job-specific functional requirements
- Workplace activity demands
- Career and productivity goals
- Work-life balance objectives

**RECREATIONAL/SPORT GOALS:**
- Hobby and leisure activity participation
- Sports and exercise goals
- Social and recreational engagement
- Physical activity and fitness

**PAIN AND SYMPTOM GOALS:**
- Pain reduction and management
- Symptom control and relief
- Activity tolerance improvement
- Sleep and rest quality

**INDEPENDENCE GOALS:**
- Functional independence maintenance
- Mobility and transportation goals
- Self-management and autonomy
- Reduced dependency on others

**QUALITY OF LIFE GOALS:**
- Mood and emotional well-being
- Confidence and self-efficacy
- Life satisfaction and fulfillment
- Future planning and security

**SPECIFIC GOAL EXAMPLES:**
Based on this patient's presentation:
- [Condition-specific functional goals]
- [Activity-specific goals based on limitations]
- [Work/occupation-related goals if applicable]
- [Personal priority goals based on patient factors]

**GOAL PRIORITIZATION:**
- Most important goals for this patient
- Realistic vs aspirational goals
- Short-term vs long-term priorities
- Patient motivation factors

Provide specific, meaningful, patient-centered goals that reflect what matters most to this individual.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/smart-goals-baseline-suggestions", methods=["POST"])
@login_required()
def ai_smart_goals_baseline_suggestions():
    """AI suggests baseline status measurements"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        objective_assessment = all_data.get('objective_assessment', {})
        
        prompt = f"""
Establish comprehensive baseline measurements for tracking progress toward goals.

CURRENT PRESENTATION:
- Condition: {provisional_diagnosis.get('structure_fault', '')}
- Pain Profile: {patho_mechanism.get('pain_severity', '')} - {patho_mechanism.get('pain_type', '')}
- Activity Impact: {subjective.get('activity_performance', '')}
- Capacity Issues: {subjective.get('activity_capacity', '')}

ASSESSMENT FINDINGS:
- Assessment Details: {objective_assessment.get('plan_details', '')}
- Current Symptoms: {provisional_diagnosis.get('symptom', '')}

**📊 BASELINE STATUS MEASUREMENTS:**

**PAIN MEASUREMENTS:**
- Current pain levels (VAS/NRS scales)
- Pain patterns and timing
- Pain impact on activities
- Medication usage patterns

**FUNCTIONAL MEASUREMENTS:**
- Range of motion limitations
- Strength deficits (specific muscles/groups)
- Endurance and tolerance levels
- Balance and coordination status

**ACTIVITY MEASUREMENTS:**
- Specific activity limitations (time, distance, load)
- Work capacity and restrictions
- Daily living activity performance
- Sleep quality and patterns

**PARTICIPATION MEASUREMENTS:**
- Social and recreational limitations
- Work attendance and productivity
- Family and community role participation
- Quality of life impact

**STANDARDIZED MEASURES:**
- Condition-specific outcome measures
- Disability rating scales
- Functional performance tests
- Patient-reported outcome measures

**OBJECTIVE BASELINES:**
- Measurable physical parameters
- Standardized test results
- Observational assessments
- Performance benchmarks

**PSYCHOSOCIAL BASELINES:**
- Fear-avoidance levels
- Self-efficacy ratings
- Coping strategy usage
- Motivation and engagement levels

**SPECIFIC BASELINE EXAMPLES:**
Based on this patient's condition:
- [Condition-specific measurements]
- [Functional capacity baselines]
- [Activity tolerance baselines]
- [Pain and symptom baselines]

Provide specific, measurable baseline data that will enable clear progress tracking.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/smart-goals-measurable-outcomes-suggestions", methods=["POST"])
@login_required()
def ai_smart_goals_measurable_outcomes_suggestions():
    """AI suggests measurable outcome criteria"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Define specific, quantifiable outcome measures and success criteria.

CONDITION CONTEXT:
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Current Symptoms: {provisional_diagnosis.get('symptom', '')}
- Pain Severity: {patho_mechanism.get('pain_severity', '')}
- Tissue Healing: {patho_mechanism.get('tissue_healing_stage', '')}

FUNCTIONAL CONTEXT:
- Activity Limitations: {subjective.get('activity_performance', '')}
- Capacity Issues: {subjective.get('activity_capacity', '')}
- Personal Goals: {perspectives.get('consequences_awareness', '')}

**📏 MEASURABLE OUTCOMES CRITERIA:**

**PAIN OUTCOME MEASURES:**
- Specific pain reduction targets (VAS/NRS scores)
- Pain-free activity duration goals
- Medication reduction objectives
- Sleep quality improvement targets

**FUNCTIONAL OUTCOME MEASURES:**
- Range of motion improvement targets
- Strength gain objectives (% improvement)
- Endurance and tolerance goals
- Balance and coordination targets

**ACTIVITY OUTCOME MEASURES:**
- Specific activity performance goals
- Work capacity and productivity targets
- Daily living task completion criteria
- Recreation and leisure participation goals

**PARTICIPATION OUTCOME MEASURES:**
- Social engagement restoration goals
- Work return-to-duty criteria
- Family role participation targets
- Community activity involvement goals

**QUALITY OF LIFE MEASURES:**
- Disability index improvement targets
- Self-efficacy enhancement goals
- Mood and well-being indicators
- Life satisfaction improvement criteria

**OBJECTIVE MEASUREMENT TARGETS:**
- Physical performance test goals
- Standardized assessment targets
- Functional capacity evaluation criteria
- Biomechanical improvement objectives

**PATIENT-REPORTED TARGETS:**
- Condition-specific questionnaire scores
- Global improvement ratings
- Patient satisfaction indicators
- Self-management confidence levels

**CONDITION-SPECIFIC MEASURES:**
Based on this patient's diagnosis:
- [Specific outcome measures for condition]
- [Functional targets relevant to presentation]
- [Activity-specific success criteria]
- [Participation goals aligned with patient needs]

**SUCCESS CRITERIA EXAMPLES:**
- Reduce pain from current level to ≤X/10
- Increase activity tolerance from X to Y minutes
- Achieve X° range of motion improvement
- Return to X% of normal function/work capacity

Provide specific, measurable, evidence-based outcome targets for this patient.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/smart-goals-timeline-suggestions", methods=["POST"])
@login_required()
def ai_smart_goals_timeline_suggestions():
    """AI suggests realistic timeframes and milestones"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        patho_mechanism = all_data.get('patho_mechanism', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        clinical_flags = all_data.get('clinical_flags', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Establish realistic timeframes with progressive milestones based on tissue healing and patient factors.

HEALING CONTEXT:
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Diagnostic Confidence: {provisional_diagnosis.get('hypothesis_supported', '')}

PROGNOSTIC FACTORS:
- Chronicity Risk: {chronic_disease.get('cause', '')}
- Psychosocial Factors: {clinical_flags.get('yellow_flag', '')}
- Patient Expectations: {perspectives.get('illness_duration', '')}
- Patient Factors: {perspectives.get('locus_of_control', '')}

**⏰ TIMELINE & MILESTONES STRATEGY:**

**TISSUE HEALING TIMELINE:**
- Acute phase considerations (0-72 hours)
- Subacute phase planning (4-21 days)
- Chronic phase management (>3 weeks)
- Remodeling phase expectations (6 weeks+)

**PROGRESSIVE MILESTONE FRAMEWORK:**

**Week 1-2 (Initial Phase):**
- Pain and inflammation management
- Protection and early movement
- Patient education and engagement
- Basic function restoration

**Week 3-4 (Early Recovery):**
- Movement progression
- Strength foundation building
- Activity tolerance improvement
- Self-management skill development

**Week 5-6 (Progression Phase):**
- Functional capacity building
- Work/activity preparation
- Endurance and conditioning
- Advanced movement patterns

**Week 7-8 (Integration Phase):**
- Full activity progression
- Work/sport-specific training
- Independence and confidence
- Maintenance planning

**Week 9-12+ (Consolidation):**
- Goal achievement verification
- Long-term self-management
- Prevention and maintenance
- Discharge planning

**TIMELINE MODIFICATION FACTORS:**

**Accelerating Factors:**
- Good tissue healing capacity
- High patient motivation
- Optimal psychosocial profile
- Early treatment intervention

**Delaying Factors:**
- Chronic presentation
- Psychosocial risk factors
- Comorbidities and complications
- Previous treatment failures

**MILESTONE EXAMPLES:**
Based on this patient's presentation:
- Week 2: [Specific early targets]
- Week 4: [Functional improvement goals]
- Week 6: [Activity progression targets]
- Week 8: [Integration milestones]
- Final: [Ultimate goal achievement]

**MONITORING SCHEDULE:**
- Weekly progress reviews
- Bi-weekly formal assessments
- Monthly outcome measurements
- Treatment plan modifications

**REALISTIC EXPECTATIONS:**
- Evidence-based recovery timelines
- Patient-specific considerations
- Flexibility for individual variation
- Clear communication of expectations

Provide realistic, evidence-based timeline with progressive milestones for this patient.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/smart-goals-comprehensive-analysis", methods=["POST"])
@login_required()
def ai_smart_goals_comprehensive_analysis():
    """AI provides comprehensive SMART goals analysis and optimization"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        goals_data = data.get("goals_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive clinical data
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        clinical_flags = all_data.get('clinical_flags', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        
        prompt = f"""
Provide comprehensive SMART goals analysis and optimization with treatment planning integration.

COMPLETE PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

DIAGNOSTIC CONTEXT:
- Provisional Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Diagnostic Confidence: {provisional_diagnosis.get('hypothesis_supported', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}
- Pain Profile: {patho_mechanism.get('pain_severity', '')} - {patho_mechanism.get('pain_irritability', '')}

PSYCHOSOCIAL PROFILE:
- Recovery Expectations: {perspectives.get('illness_duration', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Emotional State: {perspectives.get('affective_aspect', '')}
- Yellow Flags: {clinical_flags.get('yellow_flag', '')}

CHRONICITY RISK:
- Contributing Factors: {chronic_disease.get('cause', '')}

DEVELOPED SMART GOALS:
- Patient Goals: {goals_data.get('patient_goal', '')}
- Baseline Status: {goals_data.get('baseline_status', '')}
- Measurable Outcomes: {goals_data.get('measurable_outcome', '')}
- Timeline: {goals_data.get('time_duration', '')}

**🚀 COMPREHENSIVE SMART GOALS ANALYSIS:**

**SMART CRITERIA EVALUATION:**

**SPECIFIC Analysis:**
- Clarity and precision of goals
- Behavioral specificity assessment
- Functional relevance evaluation
- Patient understanding alignment

**MEASURABLE Analysis:**
- Quantification adequacy
- Measurement tool appropriateness
- Progress tracking feasibility
- Objective vs subjective balance

**ACHIEVABLE Analysis:**
- Realistic expectation assessment
- Patient capacity evaluation
- Timeline feasibility analysis
- Resource requirement evaluation

**RELEVANT Analysis:**
- Patient priority alignment
- Clinical importance assessment
- Life context integration
- Motivation factor analysis

**TIME-bound Analysis:**
- Timeline realism evaluation
- Milestone appropriateness
- Urgency consideration
- Flexibility assessment

**🎯 GOAL OPTIMIZATION RECOMMENDATIONS:**

**Goal Refinement Suggestions:**
- Specificity improvements needed
- Measurement enhancement opportunities
- Achievability adjustments required
- Relevance optimization strategies
- Timeline modification recommendations

**Evidence-Based Validation:**
- Research support for goals and timelines
- Clinical guideline alignment
- Outcome prediction accuracy
- Best practice integration

**Risk-Benefit Analysis:**
- Goal achievement probability
- Risk factors for goal failure
- Modification strategies needed
- Success enhancement opportunities

**📋 TREATMENT PLANNING INTEGRATION:**

**Treatment Strategy Alignment:**
- How goals guide intervention selection
- Treatment progression planning
- Therapy intensity and frequency
- Modality selection rationale

**Progress Monitoring Strategy:**
- Assessment schedule recommendations
- Outcome measure selection
- Progress indicator tracking
- Modification trigger points

**Patient Engagement Optimization:**
- Motivation enhancement strategies
- Self-efficacy building approaches
- Shared decision-making integration
- Compliance optimization techniques

**🔍 QUALITY ASSURANCE MEASURES:**

**Goal Validity Assessment:**
- Clinical appropriateness verification
- Evidence-base confirmation
- Patient-centeredness evaluation
- Outcome prediction reliability

**Monitoring and Evaluation Plan:**
- Progress tracking methodology
- Success criteria verification
- Modification protocols
- Outcome measurement strategy

**Professional Development:**
- Learning opportunities from goal setting
- Clinical reasoning enhancement
- Outcome prediction improvement
- Best practice integration

This comprehensive analysis ensures evidence-based, patient-centered SMART goals that optimize treatment outcomes and patient satisfaction.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Comprehensive SMART Goals Analysis",
            details=f"Generated comprehensive goals analysis for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI comprehensive SMART goals analysis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

# ADD THESE FINAL AI ENDPOINTS TO YOUR APP.PY (after your existing AI endpoints)
@limiter.limit("5 per minute")
@app.route("/api/ai/treatment-plan-strategy", methods=["POST"])
@login_required()
def ai_treatment_plan_strategy():
    """AI provides comprehensive treatment strategy based on complete assessment"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract ALL comprehensive clinical data - this is the culmination
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        clinical_flags = all_data.get('clinical_flags', {})
        objective_assessment = all_data.get('objective_assessment', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        smart_goals = all_data.get('smart_goals', {})
        
        prompt = f"""
You are an expert physiotherapist developing a comprehensive, evidence-based treatment strategy. Based on complete clinical assessment and diagnosis, provide intelligent treatment recommendations.

PATIENT PROFILE:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

DIAGNOSTIC CONCLUSIONS:
- Provisional Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Symptom Pattern: {provisional_diagnosis.get('symptom', '')}
- Diagnostic Confidence: {provisional_diagnosis.get('hypothesis_supported', '')}
- Supporting Evidence: {provisional_diagnosis.get('findings_support', '')}

PATHOPHYSIOLOGICAL CONTEXT:
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Pain Profile: {patho_mechanism.get('pain_type', '')} - {patho_mechanism.get('pain_severity', '')}
- Tissue Healing Stage: {patho_mechanism.get('tissue_healing_stage', '')}
- Pain Irritability: {patho_mechanism.get('pain_irritability', '')}

FUNCTIONAL ASSESSMENT:
- Activity Limitations: {subjective.get('activity_performance', '')}
- Activity Capacity: {subjective.get('activity_capacity', '')}
- Body Function Issues: {subjective.get('body_function', '')}
- Environmental Factors: {subjective.get('contextual_environmental', '')}

SMART GOALS ESTABLISHED:
- Patient Goals: {smart_goals.get('patient_goal', '')}
- Baseline Status: {smart_goals.get('baseline_status', '')}
- Measurable Outcomes: {smart_goals.get('measurable_outcome', '')}
- Timeline: {smart_goals.get('time_duration', '')}

PSYCHOSOCIAL PROFILE:
- Yellow Flags: {clinical_flags.get('yellow_flag', '')}
- Patient Perspectives: {perspectives.get('affective_aspect', '')}
- Control Beliefs: {perspectives.get('locus_of_control', '')}
- Recovery Expectations: {perspectives.get('illness_duration', '')}

CHRONICITY RISK FACTORS:
- Contributing Factors: {chronic_disease.get('cause', '')}
- Risk Mitigation Needs: {clinical_flags.get('yellow_flag', '')}

OBJECTIVE ASSESSMENT FINDINGS:
- Assessment Results: {objective_assessment.get('plan_details', '')}

**🎯 COMPREHENSIVE TREATMENT STRATEGY:**

**TREATMENT APPROACH FRAMEWORK:**
- **Primary Treatment Category:** [Manual therapy/Exercise/Education/Multimodal]
- **Treatment Intensity:** [High/Moderate/Low intensity based on irritability]
- **Treatment Duration:** [Expected total treatment length]
- **Treatment Frequency:** [Sessions per week recommendation]

**PHASE-BASED TREATMENT STRATEGY:**

**Phase 1: Acute Management (Weeks 1-2)**
- Primary objectives for tissue healing stage
- Pain management and protection strategies
- Early mobility and function restoration
- Patient education priorities

**Phase 2: Progressive Loading (Weeks 3-4)**
- Movement restoration and strengthening
- Functional activity progression
- Psychosocial support integration
- Self-management skill development

**Phase 3: Functional Integration (Weeks 5-6)**
- Advanced strengthening and conditioning
- Work/activity-specific training
- Independence and confidence building
- Maintenance strategy introduction

**Phase 4: Return to Function (Weeks 7+)**
- Full activity progression
- Long-term self-management
- Prevention and maintenance
- Discharge planning

**EVIDENCE-BASED INTERVENTION SELECTION:**
- Manual therapy recommendations with rationale
- Exercise therapy progression based on evidence
- Pain management strategies supported by research
- Patient education approaches with proven efficacy

**BIOPSYCHOSOCIAL INTEGRATION:**
- Biological factor management
- Psychological support strategies
- Social and environmental considerations
- Holistic treatment approach

**GOAL-ALIGNED TREATMENT:**
- How treatment phases align with SMART goals
- Specific interventions targeting established goals
- Progress monitoring integration
- Outcome optimization strategies

**RISK MANAGEMENT:**
- Safety considerations and contraindications
- Red flag monitoring during treatment
- Chronicity prevention strategies
- Adverse event management

This comprehensive treatment strategy provides evidence-based, patient-centered care planning for optimal outcomes.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Treatment Plan Strategy",
            details=f"Generated comprehensive treatment strategy for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI treatment plan strategy error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/treatment-plan-treatment-plan-suggestions", methods=["POST"])
@login_required()
def ai_treatment_plan_treatment_plan_suggestions():
    """AI suggests detailed treatment plan with specific interventions"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        patient = all_data['patient']
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        smart_goals = all_data.get('smart_goals', {})
        clinical_flags = all_data.get('clinical_flags', {})
        
        prompt = f"""
Provide detailed treatment plan with specific interventions and progression.

TREATMENT CONTEXT:
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Tissue Healing: {patho_mechanism.get('tissue_healing_stage', '')}
- Pain Level: {patho_mechanism.get('pain_severity', '')}
- Irritability: {patho_mechanism.get('pain_irritability', '')}
- Treatment Goals: {smart_goals.get('patient_goal', '')}
- Timeline: {smart_goals.get('time_duration', '')}

**📋 DETAILED TREATMENT PLAN:**

**PHASE 1: ACUTE MANAGEMENT (Weeks 1-2)**

*Manual Therapy:*
- Specific joint mobilization techniques for involved structures
- Soft tissue techniques for muscle tension and trigger points
- Gentle manipulation if indicated and tolerated
- Frequency: 2-3x per week

*Exercise Therapy:*
- Pain-free range of motion exercises
- Gentle stretching for restricted tissues
- Postural awareness and correction
- Basic stabilization exercises

*Pain Management:*
- Therapeutic modalities (ice/heat, TENS)
- Activity modification guidelines
- Pain pacing strategies
- Sleep hygiene education

*Patient Education:*
- Condition explanation and anatomy
- Pain science education
- Activity do's and don'ts
- Self-management strategies

**PHASE 2: PROGRESSIVE LOADING (Weeks 3-4)**

*Manual Therapy:*
- Progressive joint mobilization
- Advanced soft tissue techniques
- Movement re-education
- Frequency: 2x per week

*Exercise Therapy:*
- Strengthening exercise introduction
- Dynamic stability training
- Functional movement patterns
- Cardiovascular conditioning

*Functional Training:*
- Basic ADL training
- Work simulation activities
- Movement quality focus
- Activity tolerance building

**PHASE 3: FUNCTIONAL INTEGRATION (Weeks 5-6)**

*Exercise Progression:*
- Advanced strengthening protocols
- Sport/work-specific exercises
- Endurance and conditioning
- Complex movement patterns

*Functional Training:*
- High-level functional activities
- Return-to-work preparation
- Sport-specific skill training
- Independence building

**PHASE 4: RETURN TO FUNCTION (Weeks 7+)**

*Maintenance Program:*
- Independent exercise program
- Self-monitoring strategies
- Progression protocols
- Long-term prevention

*Discharge Planning:*
- Goal achievement verification
- Maintenance education
- Follow-up recommendations
- Emergency contact protocols

**TREATMENT MODIFICATIONS:**
- Progression criteria between phases
- Red flag monitoring protocols
- Pain flare-up management
- Individual adaptation strategies

Provide specific, evidence-based treatment interventions with clear progression criteria.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/treatment-plan-goal-targeting-suggestions", methods=["POST"])
@login_required()
def ai_treatment_plan_goal_targeting_suggestions():
    """AI suggests goal-treatment alignment strategies"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        smart_goals = all_data.get('smart_goals', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Explain how treatment plan specifically addresses established SMART goals.

SMART GOALS CONTEXT:
- Patient Goals: {smart_goals.get('patient_goal', '')}
- Baseline Status: {smart_goals.get('baseline_status', '')}
- Measurable Outcomes: {smart_goals.get('measurable_outcome', '')}
- Timeline: {smart_goals.get('time_duration', '')}

TREATMENT CONTEXT:
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Treatment Focus: {patho_mechanism.get('area_involved', '')}

**🎯 GOAL-TREATMENT ALIGNMENT:**

**PRIMARY GOAL TARGETING:**
For each established SMART goal:
- Specific interventions directly addressing the goal
- Treatment rationale for goal achievement
- Expected timeline correlation
- Progress monitoring strategy

**GOAL-SPECIFIC INTERVENTIONS:**

*Pain Reduction Goals:*
- Manual therapy techniques for pain relief
- Exercise prescription for pain management
- Education strategies for pain understanding
- Self-management tools for pain control

*Functional Improvement Goals:*
- Specific exercises targeting functional deficits
- Progressive activity training protocols
- Movement re-education strategies
- Capacity building interventions

*Return-to-Activity Goals:*
- Work/sport-specific training programs
- Graduated return-to-activity protocols
- Conditioning and preparation strategies
- Confidence building approaches

*Quality of Life Goals:*
- Psychosocial support interventions
- Self-efficacy enhancement strategies
- Lifestyle modification guidance
- Long-term wellness planning

**MILESTONE INTEGRATION:**
- Week 2 goals: Specific interventions and expected outcomes
- Week 4 goals: Treatment progression and achievement strategies
- Week 6 goals: Advanced interventions and functional integration
- Final goals: Maintenance and independence strategies

**OUTCOME MEASUREMENT INTEGRATION:**
- How treatment progression aligns with measurable outcomes
- Assessment tools integrated into treatment
- Progress tracking methods
- Goal modification protocols

**PATIENT ENGAGEMENT:**
- Goal-focused patient education
- Self-monitoring and self-assessment
- Patient-driven progression
- Motivation and adherence optimization

Provide specific connections between treatment interventions and established goals.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/treatment-plan-reasoning-suggestions", methods=["POST"])
@login_required()
def ai_treatment_plan_reasoning_suggestions():
    """AI suggests clinical reasoning for treatment decisions"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract comprehensive reasoning context
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        clinical_flags = all_data.get('clinical_flags', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        
        prompt = f"""
Provide comprehensive clinical reasoning for treatment approach and decisions.

COMPREHENSIVE CLINICAL CONTEXT:
- Patient: {patient.get('age_sex', '')} - {patient.get('present_history', '')}
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Confidence: {provisional_diagnosis.get('hypothesis_supported', '')}
- Pathophysiology: {patho_mechanism.get('tissue_healing_stage', '')} - {patho_mechanism.get('pain_irritability', '')}

BIOPSYCHOSOCIAL FACTORS:
- Functional Impact: {subjective.get('activity_performance', '')}
- Psychosocial Profile: {perspectives.get('affective_aspect', '')}
- Yellow Flags: {clinical_flags.get('yellow_flag', '')}
- Chronicity Risk: {chronic_disease.get('cause', '')}

**🧠 COMPREHENSIVE CLINICAL REASONING:**

**DIAGNOSIS-BASED RATIONALE:**
- How provisional diagnosis guides intervention selection
- Pathophysiological mechanisms informing treatment
- Evidence-based approaches for this specific condition
- Tissue-specific treatment considerations

**BIOPSYCHOSOCIAL INTEGRATION:**

*Biological Factors:*
- Tissue healing and inflammation considerations
- Pain mechanisms and management strategies
- Physical impairments and targeted interventions
- Biomechanical factors influencing treatment

*Psychological Factors:*
- Fear-avoidance behavior management
- Self-efficacy and confidence building
- Coping strategy enhancement
- Motivation and engagement optimization

*Social Factors:*
- Environmental modification strategies
- Work and lifestyle adaptation
- Support system utilization
- Community resource integration

**PATIENT-SPECIFIC CONSIDERATIONS:**
- Individual patient factors affecting treatment
- Cultural and personal preference accommodation
- Previous treatment experiences and responses
- Patient goals and priority alignment

**EVIDENCE-BASED JUSTIFICATION:**
- Research evidence supporting intervention choices
- Clinical guidelines informing decisions
- Best practice integration for this condition
- Outcome prediction based on evidence

**RISK-BENEFIT ANALYSIS:**
- Treatment benefits vs potential risks
- Safety considerations and contraindications
- Monitoring requirements and protocols
- Adverse event prevention and management

**CHRONICITY PREVENTION:**
- Risk factor identification and mitigation
- Early intervention strategies
- Psychosocial support integration
- Long-term outcome optimization

**TREATMENT PROGRESSION RATIONALE:**
- Phase-based approach justification
- Progression criteria and timelines
- Modification strategies and triggers
- Outcome monitoring and adjustment

**MULTIDISCIPLINARY CONSIDERATIONS:**
- Collaboration needs and referrals
- Team communication and coordination
- Shared care responsibilities
- Specialist consultation requirements

Provide evidence-based clinical reasoning that justifies every aspect of the treatment approach.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/treatment-plan-references-suggestions", methods=["POST"])
@login_required()
def ai_treatment_plan_references_suggestions():
    """AI suggests relevant evidence and references"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        
        prompt = f"""
Suggest relevant evidence and references supporting the treatment approach.

CONDITION CONTEXT:
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Area Involved: {patho_mechanism.get('area_involved', '')}
- Tissue Type: {patho_mechanism.get('symptom_source', '')}

**📚 EVIDENCE-BASED REFERENCES:**

**CLINICAL PRACTICE GUIDELINES:**
- Professional organization guidelines for this condition
- Systematic review and meta-analysis recommendations
- National/international clinical standards
- Evidence-based practice protocols

**MANUAL THERAPY EVIDENCE:**
- Research supporting manual therapy for this condition
- Systematic reviews on joint mobilization effectiveness
- Soft tissue technique efficacy studies
- Manual therapy safety and contraindication research

**EXERCISE THERAPY RESEARCH:**
- Exercise effectiveness studies for this condition
- Progressive loading and strengthening evidence
- Functional exercise and rehabilitation research
- Exercise prescription guidelines and protocols

**PAIN MANAGEMENT LITERATURE:**
- Pain science and education research
- Modality effectiveness for this condition type
- Biopsychosocial pain management approaches
- Chronic pain prevention and management

**PSYCHOSOCIAL INTERVENTION EVIDENCE:**
- Fear-avoidance and psychological factor research
- Patient education and self-management studies
- Biopsychosocial treatment approach evidence
- Outcome improvement through psychosocial intervention

**OUTCOME MEASURES RESEARCH:**
- Validation studies for recommended measures
- Minimal clinically important differences
- Prognostic factor research for this condition
- Treatment response prediction studies

**RECENT DEVELOPMENTS:**
- Current research on emerging treatments
- Updated clinical guidelines and recommendations
- Technology-assisted rehabilitation evidence
- Telehealth and remote monitoring research

**REFERENCE FORMAT EXAMPLES:**

*Clinical Guidelines:*
- [Professional Organization]. Clinical Practice Guideline for [Condition]. [Year]. Available at: [URL]

*Systematic Reviews:*
- Author A, et al. Manual therapy for [condition]: systematic review and meta-analysis. J Physiotherapy. 2023;45(2):123-135.

*Research Studies:*
- Smith J, Jones K. Exercise therapy effectiveness in [condition]: randomized controlled trial. Phys Ther. 2023;103(4):456-467.

*Professional Guidelines:*
- World Confederation for Physical Therapy. Standards of practice for [condition] management. 2023.

**EVIDENCE QUALITY ASSESSMENT:**
- High-quality systematic reviews and RCTs
- Professional guideline recommendations
- Large-scale cohort and outcome studies
- Expert consensus and best practice documents

Provide current, high-quality evidence sources that support the comprehensive treatment approach.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/treatment-plan-comprehensive-analysis", methods=["POST"])
@login_required()
def ai_treatment_plan_comprehensive_analysis():
    """AI provides final comprehensive treatment plan analysis and optimization"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        treatment_data = data.get("treatment_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Extract ALL patient data - this is the final comprehensive analysis
        patient = all_data['patient']
        subjective = all_data.get('subjective_examination', {})
        perspectives = all_data.get('patient_perspectives', {})
        initial_plan = all_data.get('initial_plan', {})
        patho_mechanism = all_data.get('patho_mechanism', {})
        chronic_disease = all_data.get('chronic_diseases', {})
        clinical_flags = all_data.get('clinical_flags', {})
        objective_assessment = all_data.get('objective_assessment', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        smart_goals = all_data.get('smart_goals', {})
        
        prompt = f"""
Provide the final comprehensive treatment plan analysis with implementation guidance and outcome optimization.

COMPLETE PATIENT ASSESSMENT SUMMARY:
- Demographics: {patient.get('age_sex', '')}
- Chief Complaint: {patient.get('present_history', '')}
- Medical History: {patient.get('past_history', '')}

DIAGNOSTIC CONCLUSIONS:
- Provisional Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Diagnostic Confidence: {provisional_diagnosis.get('hypothesis_supported', '')}
- Supporting Evidence: {provisional_diagnosis.get('findings_support', '')}

COMPREHENSIVE CLINICAL PICTURE:
- Pathophysiology: {patho_mechanism.get('area_involved', '')} - {patho_mechanism.get('tissue_healing_stage', '')}
- Functional Impact: {subjective.get('activity_performance', '')}
- Psychosocial Profile: {clinical_flags.get('yellow_flag', '')}
- Chronicity Risk: {chronic_disease.get('cause', '')}

ESTABLISHED SMART GOALS:
- Patient Priorities: {smart_goals.get('patient_goal', '')}
- Measurable Outcomes: {smart_goals.get('measurable_outcome', '')}
- Timeline: {smart_goals.get('time_duration', '')}

DEVELOPED TREATMENT PLAN:
- Treatment Approach: {treatment_data.get('treatment_plan', '')}
- Goal Integration: {treatment_data.get('goal_targeted', '')}
- Clinical Reasoning: {treatment_data.get('reasoning', '')}
- Evidence Base: {treatment_data.get('reference', '')}

**🚀 COMPREHENSIVE TREATMENT PLAN ANALYSIS:**

**TREATMENT PLAN OPTIMIZATION:**

*Strengths of Current Plan:*
- Evidence-based intervention selection
- Appropriate phase-based progression
- Goal-aligned treatment strategies
- Biopsychosocial integration

*Enhancement Opportunities:*
- Additional interventions to consider
- Timeline optimization strategies
- Goal achievement acceleration
- Risk mitigation improvements

**IMPLEMENTATION STRATEGY:**

*Phase 1 Implementation:*
- Immediate priorities and setup
- Patient preparation and education
- Safety protocol establishment
- Early progress monitoring

*Progressive Implementation:*
- Phase transition criteria
- Progression decision-making
- Modification protocols
- Advanced intervention integration

*Outcome Optimization:*
- Success maximization strategies
- Barrier identification and management
- Patient engagement enhancement
- Long-term outcome planning

**QUALITY ASSURANCE MEASURES:**

*Treatment Fidelity:*
- Evidence-based protocol adherence
- Intervention quality standards
- Progress monitoring accuracy
- Outcome measurement consistency

*Risk Management:*
- Safety monitoring protocols
- Adverse event prevention
- Red flag surveillance
- Emergency procedures

*Patient-Centered Care:*
- Patient preference integration
- Shared decision-making
- Cultural competency considerations
- Communication optimization

**PROGNOSIS AND OUTCOME PREDICTION:**

*Expected Outcomes:*
- Short-term progress predictions
- Long-term outcome expectations
- Functional recovery timeline
- Quality of life improvements

*Success Indicators:*
- Key performance indicators
- Milestone achievement markers
- Goal completion criteria
- Discharge readiness factors

*Risk Factors for Poor Outcomes:*
- Identified risk factors and mitigation
- Early warning signs
- Intervention modification needs
- Referral criteria

**PROFESSIONAL DEVELOPMENT OPPORTUNITIES:**

*Clinical Learning:*
- Case complexity analysis
- Clinical reasoning refinement
- Evidence integration skills
- Outcome prediction accuracy

*Quality Improvement:*
- Treatment effectiveness evaluation
- Process optimization opportunities
- Patient satisfaction enhancement
- Outcome measurement improvement

**FINAL RECOMMENDATIONS:**

*Implementation Priorities:*
- Most critical implementation elements
- Timeline for treatment initiation
- Resource requirements
- Success measurement strategy

*Long-term Planning:*
- Maintenance program development
- Prevention strategy integration
- Follow-up and monitoring needs
- Discharge planning preparation

This comprehensive analysis provides complete treatment plan optimization with evidence-based implementation guidance for optimal patient outcomes.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Comprehensive Treatment Plan Analysis",
            details=f"Generated final comprehensive treatment analysis for patient {patient_id}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI comprehensive treatment plan analysis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500

# ENHANCED FOLLOW-UP AI ENDPOINTS TO ADD TO YOUR APP.PY
# These can work alongside your existing follow-up endpoints
@limiter.limit("5 per minute")
@app.route("/api/ai/followup-progress-suggestions", methods=["POST"])
@login_required()
def ai_followup_progress_suggestions():
    """AI suggests progress assessment based on treatment history and current session"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_data = data.get("session_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Get previous follow-ups for progress analysis
        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.DESCENDING) \
                      .stream()
        
        followup_list = [f.to_dict() for f in followups]
        
        # Extract treatment context
        smart_goals = all_data.get('smart_goals', {})
        treatment_plan = all_data.get('treatment_plan', {})
        
        prompt = f"""
Analyze expected progress for this follow-up session based on treatment plan and goals.

TREATMENT CONTEXT:
- Patient Goals: {smart_goals.get('patient_goal', '')}
- Treatment Timeline: {smart_goals.get('time_duration', '')}
- Treatment Plan: {treatment_plan.get('treatment_plan', '')}

CURRENT SESSION:
- Session Number: {session_data.get('session_number', '')}

PREVIOUS SESSIONS PATTERN:
{chr(10).join([f"Session {f.get('session_number', '')}: {f.get('grade', '')} - {f.get('belief_treatment', '')}" for f in followup_list[:3]]) if followup_list else 'No previous sessions recorded'}

**📈 PROGRESS ASSESSMENT GUIDANCE:**

**EXPECTED PROGRESS FOR THIS SESSION:**
- Realistic achievement level based on treatment phase
- Goal milestone expectations for this timepoint
- Typical progress patterns for similar conditions
- Factors that may influence progress assessment

**ACHIEVEMENT LEVEL GUIDANCE:**

*Goal Achieved:*
- Criteria for selecting this level
- Expected functional improvements
- Pain reduction expectations
- Activity tolerance milestones

*Partially Achieved:*
- Signs of significant but incomplete progress
- Functional gains that indicate good progress
- Expected timeline for full achievement

*Minimal Progress:*
- Normal variation in recovery process
- Factors that may slow progress temporarily
- When minimal progress is acceptable

*No Progress/Regression:*
- Red flags requiring treatment modification
- Need for reassessment or referral
- Potential barriers to progress

**PROGRESS MONITORING FOCUS:**
- Key indicators to assess this session
- Outcome measures to re-evaluate
- Functional tests to repeat
- Patient-reported improvements to explore

**REALISTIC EXPECTATIONS:**
- Normal progress variation for this condition
- Individual patient factors affecting timeline
- Treatment phase considerations
- Goal achievement probability

Provide specific guidance for assessing progress at this stage of treatment.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/followup-response-suggestions", methods=["POST"])
@login_required()
def ai_followup_response_suggestions():
    """AI suggests treatment response assessment"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_data = data.get("session_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        treatment_plan = all_data.get('treatment_plan', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        
        prompt = f"""
Provide guidance for assessing patient's perception of treatment effectiveness.

TREATMENT CONTEXT:
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Treatment Approach: {treatment_plan.get('treatment_plan', '')}
- Session Number: {session_data.get('session_number', '')}
- Current Progress: {session_data.get('grade', '')}

**💊 TREATMENT RESPONSE ASSESSMENT:**

**EFFECTIVENESS LEVEL GUIDANCE:**

*Very Effective:*
- Significant symptom improvement
- Functional gains exceeding expectations
- High patient satisfaction
- Rapid goal achievement

*Effective:*
- Good symptom reduction
- Steady functional improvement
- Patient satisfaction with progress
- On track for goal achievement

*Moderately Effective:*
- Some symptom improvement
- Gradual functional gains
- Mixed patient satisfaction
- Slower than expected progress

*Minimally Effective:*
- Limited symptom improvement
- Minimal functional changes
- Patient questioning benefit
- Below expected progress

*Not Effective:*
- No symptom improvement
- No functional gains
- Patient dissatisfaction
- Treatment modification needed

**RESPONSE ASSESSMENT FACTORS:**
- Symptom changes since treatment started
- Functional improvement indicators
- Patient satisfaction and confidence
- Adherence to treatment recommendations

**TREATMENT MODIFICATION INDICATORS:**
- Signs that current treatment needs adjustment
- When to progress or regress intervention intensity
- Indication for alternative treatment approaches
- Need for additional assessments or referrals

**PATIENT EXPECTATION ALIGNMENT:**
- Realistic vs unrealistic expectation assessment
- Communication strategies for response discussion
- Motivation and engagement factors
- Long-term treatment planning considerations

Provide specific guidance for evaluating treatment effectiveness at this stage.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/followup-feedback-suggestions", methods=["POST"])
@login_required()
def ai_followup_feedback_suggestions():
    """AI suggests patient feedback collection strategies"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_data = data.get("session_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        smart_goals = all_data.get('smart_goals', {})
        perspectives = all_data.get('patient_perspectives', {})
        
        prompt = f"""
Guide patient feedback collection for optimal treatment monitoring.

PATIENT CONTEXT:
- Treatment Goals: {smart_goals.get('patient_goal', '')}
- Patient Factors: {perspectives.get('locus_of_control', '')}
- Current Progress: {session_data.get('grade', '')}
- Treatment Response: {session_data.get('belief_treatment', '')}

**💬 PATIENT FEEDBACK COLLECTION GUIDE:**

**KEY FEEDBACK AREAS TO EXPLORE:**

*Pain and Symptom Changes:*
- Current pain levels vs baseline
- Pain pattern changes (timing, triggers)
- Symptom intensity and frequency
- Impact on sleep and daily activities

*Functional Improvements:*
- Specific activity improvements noted
- Work/home task performance changes
- Exercise tolerance and capacity
- Movement quality and confidence

*Treatment Response:*
- Home exercise program adherence
- Response to manual therapy
- Benefits from patient education
- Self-management strategy effectiveness

*Psychosocial Factors:*
- Confidence and self-efficacy changes
- Fear-avoidance behavior modifications
- Motivation and engagement levels
- Family/work support adequacy

*Quality of Life Indicators:*
- Sleep quality changes
- Mood and emotional well-being
- Social activity participation
- Work productivity and satisfaction

**FEEDBACK COLLECTION STRATEGIES:**

*Open-Ended Questions:*
- "What changes have you noticed since our last session?"
- "How has your daily routine been affected?"
- "What aspects of treatment are most/least helpful?"

*Specific Inquiries:*
- Target goal-specific improvements
- Address previous concerns raised
- Explore adherence challenges
- Assess expectation alignment

*Red Flag Screening:*
- Worsening symptoms or new concerns
- Decreased function or increased pain
- Psychological distress indicators
- Safety concerns or adverse events

**FEEDBACK DOCUMENTATION:**
- Patient's own words and expressions
- Specific examples and measurements
- Concerns and questions raised
- Priorities for next session focus

Provide specific guidance for collecting meaningful patient feedback at this treatment stage.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/followup-treatment-planning-suggestions", methods=["POST"])
@login_required()
def ai_followup_treatment_planning_suggestions():
    """AI suggests next session treatment planning"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_data = data.get("session_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        treatment_plan = all_data.get('treatment_plan', {})
        smart_goals = all_data.get('smart_goals', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        
        prompt = f"""
Provide next session treatment planning based on current progress and response.

TREATMENT CONTEXT:
- Original Treatment Plan: {treatment_plan.get('treatment_plan', '')}
- Treatment Goals: {smart_goals.get('patient_goal', '')}
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}

CURRENT SESSION RESPONSE:
- Progress Level: {session_data.get('grade', '')}
- Treatment Effectiveness: {session_data.get('belief_treatment', '')}
- Patient Feedback: {session_data.get('belief_feedback', '')}
- Session Number: {session_data.get('session_number', '')}

**🎯 NEXT SESSION PLANNING RECOMMENDATIONS:**

**TREATMENT PROGRESSION STRATEGY:**

*Based on Current Progress Level:*

If "Goal Achieved":
- Advance to next treatment phase
- Progress exercise difficulty/complexity
- Introduce higher-level functional activities
- Begin discharge planning preparation

If "Partially Achieved":
- Continue current interventions with modifications
- Gradual progression of successful techniques
- Address barriers to full achievement
- Maintain motivation and engagement

If "Minimal Progress":
- Reassess treatment approach effectiveness
- Consider intervention modifications
- Explore adherence and compliance issues
- Possible technique or modality changes

If "No Progress/Regression":
- Comprehensive reassessment required
- Significant treatment plan modification
- Consider referral or specialist consultation
- Address psychosocial barriers

**SPECIFIC INTERVENTION PLANNING:**

*Manual Therapy Adjustments:*
- Technique progression or modification
- Frequency and intensity changes
- New approaches based on response
- Patient comfort and tolerance

*Exercise Therapy Progression:*
- Resistance and complexity advancement
- Functional exercise integration
- Home program updates and challenges
- Motor learning and skill development

*Patient Education Updates:*
- Reinforce successful strategies
- Address new concerns or questions
- Progress-based education topics
- Self-management skill advancement

*Outcome Measurement:*
- Reassess baseline measures
- Track progress toward goals
- Modify outcome targets if needed
- Plan formal reassessment timing

**SESSION STRUCTURE OPTIMIZATION:**
- Time allocation for different interventions
- Priority areas for next session focus
- Patient engagement and motivation strategies
- Homework and self-management assignments

**DISCHARGE PLANNING CONSIDERATIONS:**
- Progress toward independence
- Self-management capability assessment
- Long-term maintenance planning
- Follow-up and monitoring needs

Provide specific, evidence-based recommendations for the next treatment session.
"""
        
        ai_response = call_claude(prompt)
        return jsonify({"response": ai_response})
        
    except Exception as e:
        return jsonify({"error": "AI analysis failed"}), 500

@limiter.limit("5 per minute")
@app.route("/api/ai/followup-comprehensive-analysis", methods=["POST"])
@login_required()
def ai_followup_comprehensive_analysis():
    """AI provides comprehensive follow-up session analysis and optimization"""
    try:
        data = request.get_json()
        patient_id = data.get("patient_id")
        session_data = data.get("session_data", {})
        
        all_data = get_cumulative_patient_data(patient_id)
        if not all_data.get('patient'):
            return jsonify({"error": "Patient not found"}), 404

        # Get ALL follow-up sessions for comprehensive progress analysis
        followups = db.collection('follow_ups') \
                      .where('patient_id', '==', patient_id) \
                      .order_by('session_date', direction=firestore.Query.ASCENDING) \
                      .stream()
        
        followup_list = [f.to_dict() for f in followups]

        # Extract complete treatment context
        patient = all_data['patient']
        smart_goals = all_data.get('smart_goals', {})
        treatment_plan = all_data.get('treatment_plan', {})
        provisional_diagnosis = all_data.get('provisional_diagnosis', {})
        clinical_flags = all_data.get('clinical_flags', {})
        
        prompt = f"""
Provide comprehensive follow-up session analysis with treatment optimization strategies.

COMPLETE PATIENT CONTEXT:
- Demographics: {patient.get('age_sex', '')}
- Diagnosis: {provisional_diagnosis.get('structure_fault', '')}
- Treatment Goals: {smart_goals.get('patient_goal', '')}
- Expected Timeline: {smart_goals.get('time_duration', '')}

TREATMENT APPROACH:
- Treatment Plan: {treatment_plan.get('treatment_plan', '')}
- Clinical Reasoning: {treatment_plan.get('reasoning', '')}

CURRENT SESSION DATA:
- Session Number: {session_data.get('session_number', '')}
- Progress Grade: {session_data.get('grade', '')}
- Treatment Response: {session_data.get('belief_treatment', '')}
- Patient Feedback: {session_data.get('belief_feedback', '')}
- Next Session Plan: {session_data.get('treatment_plan', '')}

TREATMENT HISTORY:
{chr(10).join([f"Session {f.get('session_number', '')}: {f.get('grade', '')} - {f.get('belief_treatment', '')}" for f in followup_list]) if followup_list else 'No previous sessions recorded'}

RISK FACTORS:
- Psychosocial Flags: {clinical_flags.get('yellow_flag', '')}

**🔍 COMPREHENSIVE SESSION ANALYSIS:**

**PROGRESS TRAJECTORY ANALYSIS:**
- Overall progress trend assessment
- Treatment response pattern evaluation
- Goal achievement probability
- Expected vs actual progress comparison

**TREATMENT EFFECTIVENESS EVALUATION:**
- Intervention success analysis
- Patient satisfaction trends
- Adherence and engagement assessment
- Outcome optimization opportunities

**CLINICAL DECISION ANALYSIS:**
- Treatment plan adherence evaluation
- Modification and progression appropriateness
- Evidence-based practice alignment
- Patient-centered care optimization

**RISK-BENEFIT ASSESSMENT:**
- Current treatment approach risks
- Benefit maximization strategies
- Safety consideration updates
- Long-term outcome predictions

**🎯 OPTIMIZATION RECOMMENDATIONS:**

**Treatment Plan Refinement:**
- Intervention effectiveness enhancement
- Technique or approach modifications
- Progression timeline adjustments
- Patient engagement improvements

**Goal Achievement Acceleration:**
- Strategies to enhance progress
- Barrier identification and removal
- Motivation enhancement techniques
- Self-efficacy building approaches

**Quality of Care Enhancement:**
- Evidence-based practice improvements
- Patient satisfaction optimization
- Outcome measurement refinement
- Communication strategy enhancement

**📊 OUTCOME PREDICTION:**

**Short-term Projections (Next 2-4 sessions):**
- Expected progress milestones
- Likely treatment responses
- Potential challenges or barriers
- Intervention modification needs

**Long-term Outlook:**
- Ultimate goal achievement probability
- Discharge timeline predictions
- Maintenance program requirements
- Follow-up and monitoring needs

**🔄 QUALITY IMPROVEMENT:**

**Clinical Learning Opportunities:**
- Case complexity insights
- Treatment approach effectiveness
- Patient response patterns
- Professional development areas

**System Optimization:**
- Treatment protocol improvements
- Outcome measurement enhancements
- Patient experience optimization
- Efficiency and effectiveness gains

**📋 ACTIONABLE RECOMMENDATIONS:**

**Immediate Actions:**
- Next session priority modifications
- Treatment technique adjustments
- Patient communication improvements
- Outcome tracking enhancements

**Strategic Planning:**
- Medium-term treatment adjustments
- Goal timeline modifications
- Discharge planning preparation
- Long-term maintenance strategies

This comprehensive analysis provides evidence-based optimization strategies for enhanced treatment outcomes and patient satisfaction.
"""
        
        ai_response = call_claude(prompt)
        
        log_action(
            user_id=session['user_id'],
            action="AI Comprehensive Follow-up Analysis",
            details=f"Generated comprehensive session analysis for patient {patient_id} session {session_data.get('session_number', '')}"
        )
        
        return jsonify({"response": ai_response})
        
    except Exception as e:
        print(f"AI comprehensive follow-up analysis error: {str(e)}")
        return jsonify({"error": "AI analysis failed"}), 500     

if __name__ == '__main__':
    app.run(debug=True)