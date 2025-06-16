from flask import Flask, render_template, request, redirect, session, url_for, make_response
import sqlite3, io
from weasyprint import HTML
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from notifications import send_push_notification
from flask import request, jsonify

from firebase_init import auth  # uses the initialized Firebase app

from flask import request, jsonify
from functools import wraps

def firebase_token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Missing auth token'}), 401

        try:
            token = auth_header.split('Bearer ')[1]
            decoded = auth.verify_id_token(token)
            request.user = decoded  # attach user info to request
        except Exception as e:
            return jsonify({'error': 'Invalid or expired token', 'details': str(e)}), 403

        return f(*args, **kwargs)
    return decorated


def log_action(user_id, action, details=None):
    conn = get_db()
    conn.execute(
        'INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
        (user_id, action, details)
    )
    conn.commit()
    conn.close()

app = Flask(__name__)
app.secret_key = 'your_secret_key'

def get_db():
    conn = sqlite3.connect('physio.db')
    conn.row_factory = sqlite3.Row
    return conn

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
        conn = get_db()
        # Check if email or phone already exists
        existing = conn.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (email, phone)).fetchone()
        if existing:
            return "Email or phone number already registered."

        # Proceed with registration
        conn.execute('''
            INSERT INTO users (name, email, password, phone, is_admin, institute, approved)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, email, password, phone, is_admin, institute, approved))
        conn.commit()

        conn.close()
        log_action(user_id=None, action="Register", details=f"{name} registered as Individual Physio")

        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if not user:
            return "Invalid login credentials."

        if check_password_hash(user['password'], password):
            if user['approved'] == 1 and user['active'] == 1:
                session['user_id'] = user['id']
                session['user_name'] = user['name']
                session['institute'] = user['institute']
                session['is_admin'] = user['is_admin']
                session['approved'] = user['approved']
                log_action(user['id'], "Login", f"{user['name']} logged in.")
                return redirect('/dashboard')
            elif user['active'] == 0:
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

    conn = get_db()
    pending_physios = conn.execute(
        'SELECT * FROM users WHERE is_admin = 0 AND approved = 0 AND institute = ?',
        (session['institute'],)
    ).fetchall()
    conn.close()

    return render_template('admin_dashboard.html', pending_physios=pending_physios, name=session['user_name'], institute=session['institute'])
@app.route('/view_patients')
@login_required()
def view_patients():
    conn = get_db()

    # Base query and filters
    query = 'SELECT * FROM patients WHERE 1=1'
    params = []

    # Apply filtering by name
    name_filter = request.args.get('name')
    if name_filter:
        query += ' AND name LIKE ?'
        params.append(f'%{name_filter}%')

    # Apply filtering by patient_id
    id_filter = request.args.get('patient_id')
    if id_filter:
        query += ' AND patient_id LIKE ?'
        params.append(f'%{id_filter}%')

    # Route-based restrictions
    if session.get('is_admin') == 1:
        query += ' AND physio_id IN (SELECT id FROM users WHERE institute = ?)'
        params.append(session['institute'])
    else:
        query += ' AND physio_id = ?'
        params.append(session['user_id'])

    patients = conn.execute(query, params).fetchall()
    conn.close()

    return render_template('view_patients.html', patients=patients)


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
        conn = get_db()
        existing = conn.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (email, phone)).fetchone()
        if existing:
            return "Email or phone number already registered."

        conn.execute('''
            INSERT INTO users (name, email, phone, password, institute, is_admin, approved)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, email, phone, password, institute, is_admin, approved))
        conn.commit()

        conn.close()
        log_action(user_id=None, action="Register", details=f"{name} registered as Institute Admin")

        return redirect('/login_institute')
    return render_template('register_institute.html')

@app.route('/login_institute', methods=['GET', 'POST'])
def login_institute():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            if user['approved'] == 0:
                return "Your account is pending approval by the institute admin."

            if user['active'] == 0:
                return "Your account has been deactivated. Please contact your admin."

            session['user_id'] = user['id']
            session['user_name'] = user['name']
            session['institute'] = user['institute']
            session['is_admin'] = user['is_admin']
            session['approved'] = user['approved']
            log_action(user['id'], "Login", f"{user['name']} (Admin: {user['is_admin']}) logged in.")


            if user['is_admin'] == 1:
                return redirect('/admin_dashboard')
            else:
                return redirect('/dashboard')

        return "Invalid credentials or account doesn't exist."
    return render_template('login_institute.html')



@app.route('/approve_physios')
def approve_physios():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/login_institute')
    conn = get_db()
    pending_physios = conn.execute('''SELECT * FROM users WHERE is_admin = 0 AND approved = 0 AND institute = ?''',
                                   (session['institute'],)).fetchall()
    conn.close()
    return render_template('approve_physios.html', physios=pending_physios)

@app.route('/audit_logs')
@login_required()
def audit_logs():
    conn = get_db()

    if session.get('is_admin') == 1:
        # Institute admin: show logs only for users in their institute
        logs = conn.execute('''
            SELECT audit_logs.*, users.name
            FROM audit_logs
            JOIN users ON audit_logs.user_id = users.id
            WHERE users.institute = ?
            ORDER BY timestamp DESC
        ''', (session['institute'],)).fetchall()

    elif session.get('is_admin') == 0:
        # Individual physio: show only their own logs
        logs = conn.execute('''
            SELECT audit_logs.*, users.name
            FROM audit_logs
            JOIN users ON audit_logs.user_id = users.id
            WHERE users.id = ?
            ORDER BY timestamp DESC
        ''', (session['user_id'],)).fetchall()
    else:
        logs = []

    conn.close()
    return render_template('audit_logs.html', logs=logs)


@app.route('/export_audit_logs')
def export_audit_logs():
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/login_institute')

    conn = get_db()
    institute = session['institute']
    logs = conn.execute('''
        SELECT users.name, audit_logs.action, audit_logs.details, audit_logs.timestamp
        FROM audit_logs
        JOIN users ON audit_logs.user_id = users.id
        WHERE users.institute = ?
        ORDER BY audit_logs.timestamp DESC
    ''', (institute,)).fetchall()
    conn.close()
    import io
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(['User', 'Action', 'Details', 'Timestamp'])

    for row in logs:
        writer.writerow([row['name'], row['action'], row['details'], row['timestamp']])

    response = make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename=audit_logs.csv'
    response.headers['Content-Type'] = 'text/csv'
    return response

@app.route('/reject_user/<int:user_id>')
@login_required()
def reject_user(user_id):
    if session.get('is_admin') != 1:
        return "Unauthorized", 403

    conn = get_db()
    conn.execute('DELETE FROM users WHERE id = ? AND approved = 0', (user_id,))
    conn.commit()
    conn.close()

    return redirect('/approve_physios')



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

        conn = get_db()
        cursor = conn.execute('SELECT COUNT(*) FROM patients')
        count = cursor.fetchone()[0]
        new_id = f"PAT-{count+1:03d}"

        conn.execute('''
            INSERT INTO patients (physio_id, patient_id, name, age_sex, contact, present_history, past_history)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (session['user_id'], new_id, name, age_sex, contact, present_history, past_history))
        conn.commit()
        conn.close()

        # 📋 Log this action
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
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if request.method == 'POST':
        body_structure = request.form['body_structure']
        body_function = request.form['body_function']
        activity_performance = request.form['activity_performance']
        activity_capacity = request.form['activity_capacity']
        contextual_environmental = request.form['contextual_environmental']
        contextual_personal = request.form['contextual_personal']

        conn = get_db()
        conn.execute('''INSERT INTO subjective_examination (
                            patient_id, body_structure, body_function,
                            activity_performance, activity_capacity,
                            contextual_environmental, contextual_personal)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (patient_id, body_structure, body_function,
                      activity_performance, activity_capacity,
                      contextual_environmental, contextual_personal))
        conn.commit()
        conn.close()
        return redirect(f'/perspectives/{patient_id}')


    return render_template('subjective.html', patient_id=patient_id)

@app.route('/perspectives/<patient_id>', methods=['GET', 'POST'])
@login_required()
def perspectives(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        knowledge = request.form['knowledge']
        attribution = request.form['attribution']
        illness_duration = request.form['illness_duration']
        consequences_awareness = request.form['consequences_awareness']
        locus_of_control = request.form['locus_of_control']
        affective_aspect = request.form['affective_aspect']

        conn = get_db()
        conn.execute('''
            INSERT INTO patient_perspectives (
                patient_id, knowledge, attribution, illness_duration,
                consequences_awareness, locus_of_control, affective_aspect
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            patient_id, knowledge, attribution, illness_duration,
            consequences_awareness, locus_of_control, affective_aspect
        ))
        conn.commit()
        conn.close()

        return redirect(f'/initial_plan/{patient_id}')


    return render_template('perspectives.html', patient_id=patient_id)

@app.route('/initial_plan/<patient_id>', methods=['GET', 'POST'])
@login_required()
def initial_plan(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if 'user_id' not in session:
        return redirect('/login')

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

        data = {field: request.form[field] for field in fields}
        details = {field + '_details': request.form.get(field + '_details', '') for field in fields}

        conn.execute('''
            INSERT INTO initial_plan (
                patient_id,
                active_movements, active_movements_details,
                passive_movements, passive_movements_details,
                passive_over_pressure, passive_over_pressure_details,
                resisted_movements, resisted_movements_details,
                combined_movements, combined_movements_details,
                special_tests, special_tests_details,
                neuro_dynamic_examination, neuro_dynamic_examination_details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            patient_id,
            data['active_movements'], details['active_movements_details'],
            data['passive_movements'], details['passive_movements_details'],
            data['passive_over_pressure'], details['passive_over_pressure_details'],
            data['resisted_movements'], details['resisted_movements_details'],
            data['combined_movements'], details['combined_movements_details'],
            data['special_tests'], details['special_tests_details'],
            data['neuro_dynamic_examination'], details['neuro_dynamic_examination_details']
        ))
        conn.commit()
        conn.close()

        return redirect(f'/patho_mechanism/{patient_id}')

    return render_template('initial_plan.html', patient_id=patient_id)

@app.route('/patho_mechanism/<patient_id>', methods=['GET', 'POST'])
@login_required()
def patho_mechanism(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        area_involved = request.form['area_involved']
        presenting_symptom = request.form['presenting_symptom']
        pain_type = request.form['pain_type']
        pain_nature = request.form['pain_nature']
        pain_severity = request.form['pain_severity']
        pain_irritability = request.form['pain_irritability']
        symptom_source = request.form['symptom_source']
        tissue_healing_stage = request.form['tissue_healing_stage']

        conn = get_db()
        conn.execute('''
            INSERT INTO patho_mechanism (
                patient_id, area_involved, presenting_symptom, pain_type,
                pain_nature, pain_severity, pain_irritability,
                symptom_source, tissue_healing_stage
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            patient_id, area_involved, presenting_symptom, pain_type,
            pain_nature, pain_severity, pain_irritability,
            symptom_source, tissue_healing_stage
        ))
        conn.commit()
        conn.close()

        return redirect(f'/chronic_disease/{patient_id}')


    return render_template('patho_mechanism.html', patient_id=patient_id)

@app.route('/chronic_disease/<patient_id>', methods=['GET', 'POST'])
@login_required()
def chronic_disease(patient_id):
    if request.method == 'POST':
        cause = request.form['cause']
        cause_detail = request.form.get('cause_detail', '')  # Optional field

        conn = get_db()
        conn.execute('''
            INSERT INTO chronic_diseases (patient_id, cause, cause_detail)
            VALUES (?, ?, ?)
        ''', (patient_id, cause, cause_detail))
        conn.commit()
        conn.close()

        return redirect(f'/clinical_flags/{patient_id}')

    return render_template('chronic_disease.html', patient_id=patient_id)


@app.route('/clinical_flags/<patient_id>', methods=['GET', 'POST'])
@login_required()
def clinical_flags(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        red_flag = request.form['red_flag']
        orange_flag = request.form['orange_flag']
        yellow_flag = request.form['yellow_flag']
        black_flag = request.form['black_flag']
        blue_flag = request.form['blue_flag']

        conn = get_db()
        conn.execute('''
            INSERT INTO clinical_flags (
                patient_id, red_flag, orange_flag, yellow_flag, black_flag, blue_flag
            ) VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            patient_id, red_flag, orange_flag, yellow_flag, black_flag, blue_flag
        ))
        conn.commit()
        conn.close()

        return redirect(f'/objective_assessment/{patient_id}')


    return render_template('clinical_flags.html', patient_id=patient_id)

@app.route('/objective_assessment/<patient_id>', methods=['GET', 'POST'])
@login_required()
def objective_assessment(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if request.method == 'POST':
        plan = request.form['plan']
        plan_details = request.form.get('plan_details', '')

        conn.execute('''
            INSERT INTO objective_assessment (patient_id, plan, plan_details)
            VALUES (?, ?, ?)
        ''', (patient_id, plan, plan_details))
        conn.commit()
        conn.close()

        return redirect(f'/provisional_diagnosis/{patient_id}')

    return render_template('objective_assessment.html', patient_id=patient_id)

@app.route('/provisional_diagnosis/<patient_id>', methods=['GET', 'POST'])
@login_required()
def provisional_diagnosis(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        likelihood = request.form['likelihood']
        structure_fault = request.form['structure_fault']
        symptom = request.form['symptom']
        findings_support = request.form['findings_support']
        findings_reject = request.form['findings_reject']
        hypothesis_supported = request.form['hypothesis_supported']

        conn.execute('''
            INSERT INTO provisional_diagnosis (
                patient_id, likelihood, structure_fault,
                symptom, findings_support, findings_reject, hypothesis_supported
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            patient_id, likelihood, structure_fault,
            symptom, findings_support, findings_reject, hypothesis_supported
        ))
        conn.commit()
        conn.close()

        return redirect(f'/smart_goals/{patient_id}')

    return render_template('provisional_diagnosis.html', patient_id=patient_id)

@app.route('/smart_goals/<patient_id>', methods=['GET', 'POST'])
@login_required()
def smart_goals(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        patient_goal = request.form['patient_goal']
        baseline_status = request.form['baseline_status']
        measurable_outcome = request.form['measurable_outcome']
        time_duration = request.form['time_duration']

        conn.execute('''
            INSERT INTO smart_goals (
                patient_id, patient_goal, baseline_status,
                measurable_outcome, time_duration
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            patient_id, patient_goal, baseline_status,
            measurable_outcome, time_duration
        ))
        conn.commit()
        conn.close()

        return redirect(f'/treatment_plan/{patient_id}')

    return render_template('smart_goals.html', patient_id=patient_id)


@app.route('/treatment_plan/<patient_id>', methods=['GET', 'POST'])
@login_required()
def treatment_plan(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if 'user_id' not in session:
        return redirect('/login')

    if request.method == 'POST':
        treatment_plan = request.form['treatment_plan']
        goal_targeted = request.form['goal_targeted']
        reasoning = request.form['reasoning']
        reference = request.form['reference']

        conn.execute('''
            INSERT INTO treatment_plan (
                patient_id, treatment_plan, goal_targeted,
                reasoning, reference
            ) VALUES (?, ?, ?, ?, ?)
        ''', (
            patient_id, treatment_plan, goal_targeted,
            reasoning, reference
        ))
        conn.commit()
        conn.close()

        return redirect('/dashboard')

    return render_template('treatment_plan.html', patient_id=patient_id)


@app.route('/first_follow_up/<patient_id>', methods=['GET', 'POST'])
@login_required()
def first_follow_up(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if request.method == 'POST':
        goal_number = request.form.get('goal_number')
        goals = request.form.get('goals')
        baseline = request.form.get('baseline')
        achieved = request.form.get('achieved')
        grade = request.form.get('grade')
        belief_treatment = request.form.get('belief_treatment')
        belief_feedback = request.form.get('belief_feedback')

        conn.execute('''
            INSERT INTO first_follow_up (
                patient_id, goal_number, goals, baseline, achieved,
                grade, belief_treatment, belief_feedback
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            patient_id, goal_number, goals, baseline, achieved,
            grade, belief_treatment, belief_feedback
        ))
        conn.commit()
        conn.close()

        return redirect('/dashboard')

    conn.close()
    return render_template('first_follow_up.html', patient_id=patient_id)

@app.route('/update_push_token', methods=['POST'])
@login_required(approved_only=False)
def update_push_token():
    token = request.json.get('token')

    if not token:
        return jsonify({"error": "No token provided"}), 400

    conn = get_db()
    conn.execute('UPDATE users SET push_token = ? WHERE id = ?', (token, session['user_id']))
    conn.commit()
    conn.close()

    return jsonify({"message": "Push token saved successfully."}), 200


@app.route('/patient_report/<patient_id>')
@login_required()
def patient_report(patient_id):
    conn = get_db()

    # Fetch the patient
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    # Restrict access
    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0:
        if patient['physio_id'] != session['user_id']:
            conn.close()
            return "Access denied."

    # Continue fetching report details
    subjective = conn.execute('SELECT * FROM subjective_examination WHERE patient_id = ?', (patient_id,)).fetchone()
    perspectives = conn.execute('SELECT * FROM patient_perspectives WHERE patient_id = ?', (patient_id,)).fetchone()
    diagnosis = conn.execute('SELECT * FROM provisional_diagnosis WHERE patient_id = ?', (patient_id,)).fetchone()
    treatment = conn.execute('SELECT * FROM treatment_plan WHERE patient_id = ?', (patient_id,)).fetchone()
    goals = conn.execute('SELECT * FROM smart_goals WHERE patient_id = ?', (patient_id,)).fetchone()

    conn.close()

    return render_template('patient_report.html', patient=patient,
                           subjective=subjective, perspectives=perspectives,
                           diagnosis=diagnosis, goals=goals, treatment=treatment)




from weasyprint import HTML
from flask import make_response, session, render_template  # ensure these are imported

@app.route('/download_report/<patient_id>')
@login_required()
def download_report(patient_id):
    conn = get_db()

    patient = conn.execute(
        'SELECT * FROM patients WHERE patient_id = ?', (patient_id,)
    ).fetchone()

    # Restrict access
    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    # Fetch report sections
    subjective = conn.execute(
        'SELECT * FROM subjective_examination WHERE patient_id = ?', (patient_id,)
    ).fetchone()

    perspectives = conn.execute(
        'SELECT * FROM patient_perspectives WHERE patient_id = ?', (patient_id,)
    ).fetchone()

    diagnosis = conn.execute(
        'SELECT * FROM provisional_diagnosis WHERE patient_id = ?', (patient_id,)
    ).fetchone()

    treatment = conn.execute(
        'SELECT * FROM treatment_plan WHERE patient_id = ?', (patient_id,)
    ).fetchone()

    goals = conn.execute(
        'SELECT * FROM smart_goals WHERE patient_id = ?', (patient_id,)
    ).fetchone()

    conn.close()

    # Render template and generate PDF
    rendered = render_template(
        'patient_report.html',
        patient=patient,
        subjective=subjective,
        perspectives=perspectives,
        diagnosis=diagnosis,
        treatment=treatment,
        goals=goals
    )

    pdf = HTML(string=rendered).write_pdf()

    # Create response with PDF
    response = make_response(pdf)
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'attachment; filename={patient_id}_report.pdf'

    # Log action
    log_action(
        user_id=session['user_id'],
        action="Download Report",
        details=f"Downloaded PDF report for patient {patient_id}"
    )

    return response


@app.route('/register_with_institute', methods=['GET', 'POST'])
def register_with_institute():
    conn = get_db()

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        phone = request.form['phone']
        password = generate_password_hash(request.form['password'])
        institute = request.form['institute']
        is_admin = 0
        approved = 0  # Pending admin approval

        # Check if user already exists
        existing = conn.execute('SELECT * FROM users WHERE email = ? OR phone = ?', (email, phone)).fetchone()
        if existing:
            conn.close()
            return "Email or phone number already registered."

        # Register the new physiotherapist under the selected institute
        conn.execute('''
            INSERT INTO users (name, email, phone, password, institute, is_admin, approved)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (name, email, phone, password, institute, is_admin, approved))
        conn.commit()

        log_action(user_id=None, action="Register", details=f"{name} registered as Institute Physio (pending approval)")
        conn.close()

        return "Registration successful! Awaiting admin approval."

    # Fetch list of registered institutes from existing admins
    institutes = conn.execute('SELECT DISTINCT institute FROM users WHERE is_admin = 1').fetchall()
    conn.close()
    return render_template('register_with_institute.html', institutes=institutes)


@app.route('/approve_user/<int:user_id>')
def approve_user(user_id):
    if 'user_id' not in session or session.get('is_admin') != 1:
        return redirect('/login_institute')

    conn = get_db()
    conn.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
    conn.commit()

    # Fetch the user info for logging
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

    conn.close()

    # Log the approval
    log_action(
        user_id=session['user_id'],
        action="Approve User",
        details=f"Approved user {user['name']} (Email: {user['email']})"
    )

    return redirect('/approve_physios')


@app.route('/edit_patient/<patient_id>', methods=['GET', 'POST'])
@login_required()
def edit_patient(patient_id):
    conn = get_db()

    # 🔒 Restriction check
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    if not patient:
        return "Patient not found."
    if session.get('is_admin') != 1 and patient['physio_id'] != session['user_id']:
        return "Access denied."

    if request.method == 'POST':
        name = request.form['name']
        age_sex = request.form['age_sex']
        contact = request.form['contact']

        conn.execute('''
            UPDATE patients
            SET name = ?, age_sex = ?, contact = ?
            WHERE patient_id = ?
        ''', (name, age_sex, contact, patient_id))
        conn.commit()
        log_action(
            user_id=session['user_id'],
            action="Edit Patient",
            details=f"Edited patient {patient_id}"
        )

        conn.close()
        return redirect('/view_patients')

    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()
    
    conn.close()
    return render_template('edit_patient.html', patient=patient)

@app.route('/manage_users')
@login_required()
def manage_users():
    if session.get('is_admin') != 1:
        return "Access Denied: Admins only."

    conn = get_db()
    users = conn.execute('''
        SELECT * FROM users
        WHERE is_admin = 0 AND approved = 1 AND institute = ?
    ''', (session['institute'],)).fetchall()
    conn.close()

    return render_template('manage_users.html', users=users)


@app.route('/deactivate_user/<int:user_id>')
@login_required()
def deactivate_user(user_id):
    if session.get('is_admin') != 1:
        return "Access Denied"

    conn = get_db()
    conn.execute('UPDATE users SET active = 0 WHERE id = ?', (user_id,))
    conn.commit()
    log_action(
        user_id=session['user_id'],
        action="Deactivate User",
        details=f"User ID {user_id} was deactivated"
    )
    conn.close()
    return redirect('/manage_users')


@app.route('/reactivate_user/<int:user_id>')
@login_required()
def reactivate_user(user_id):
    if session.get('is_admin') != 1:
        return "Access Denied"

    conn = get_db()
    conn.execute('UPDATE users SET active = 1 WHERE id = ?', (user_id,))
    conn.commit()
    log_action(
        user_id=session['user_id'],
        action="Reactivate User",
        details=f"User ID {user_id} was reactivated"
    )
    conn.close()
    return redirect('/manage_users')



@app.route('/follow_up_new/<patient_id>', methods=['GET', 'POST'])
@login_required()
def follow_up_new(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        conn.close()
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        conn.close()
        return "Access denied."

    if request.method == 'POST':
        session_number = request.form['session_number']
        session_date = request.form['session_date']
        grade = request.form['grade']
        belief_treatment = request.form['belief_treatment']
        belief_feedback = request.form['belief_feedback']
        treatment_plan = request.form['treatment_plan']

        conn.execute('''
            INSERT INTO follow_ups (
                patient_id, session_number, session_date, grade,
                belief_treatment, belief_feedback, treatment_plan
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            patient_id, session_number, session_date, grade,
            belief_treatment, belief_feedback, treatment_plan
        ))
        conn.commit()
        conn.close()

        return redirect(f'/view_follow_ups/{patient_id}')

    conn.close()
    return render_template('follow_up_new.html', patient_id=patient_id)


@app.route('/view_follow_ups/<patient_id>')
@login_required()
def view_follow_ups(patient_id):
    conn = get_db()
    patient = conn.execute('SELECT * FROM patients WHERE patient_id = ?', (patient_id,)).fetchone()

    if not patient:
        return "Patient not found."

    if session.get('is_admin') == 0 and patient['physio_id'] != session['user_id']:
        return "Access denied."

    followups = conn.execute('''
        SELECT * FROM follow_ups
        WHERE patient_id = ?
        ORDER BY session_date DESC
    ''', (patient_id,)).fetchall()
    conn.close()
    return render_template('view_follow_ups.html', patient_id=patient_id, followups=followups)

@app.route('/send-push', methods=['POST'])
def send_push():
    data = request.get_json()
    token = data.get('token')
    message = data.get('message')

    if not token or not message:
        return jsonify({"error": "Missing token or message"}), 400

    response = send_push_notification(token, message)
    return jsonify(response), 200


@app.route('/api/patients', methods=['GET'])
@login_required()
def api_get_patients():
    conn = get_db()
    user_id = session['user_id']
    is_admin = session.get('is_admin')
    institute = session.get('institute')

    if is_admin:
        # Admin: all patients in their institute
        patients = conn.execute('''
            SELECT * FROM patients
            WHERE physio_id IN (SELECT id FROM users WHERE institute = ?)
        ''', (institute,)).fetchall()
    else:
        # Regular physio: only their patients
        patients = conn.execute('''
            SELECT * FROM patients WHERE physio_id = ?
        ''', (user_id,)).fetchall()

    conn.close()

    return jsonify([
        {
            'patient_id': row['patient_id'],
            'name': row['name'],
            'age_sex': row['age_sex'],
            'contact': row['contact']
        }
        for row in patients
    ])

@app.route('/firebase-secure', methods=['GET'])
@firebase_token_required
def firebase_secure():
    user = request.user  # this is the Firebase user info
    return jsonify({
        'message': f"Hello {user['email']}, your UID is {user['uid']}",
        'firebase_user': user
    })


if __name__ == '__main__':
    app.run(debug=True)
