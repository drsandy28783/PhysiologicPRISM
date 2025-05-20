
import sqlite3

def init_db():
    conn = sqlite3.connect('physio.db')
    c = conn.cursor()

    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT UNIQUE,
        phone TEXT,
        password TEXT,
        is_admin INTEGER DEFAULT 0,
        institute TEXT,
        approved INTEGER DEFAULT 1,
        active INTEGER DEFAULT 1
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS patients (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        physio_id INTEGER,
        patient_id TEXT UNIQUE,
        name TEXT,
        age_sex TEXT,
        contact TEXT,
        present_history TEXT,
        past_history TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (physio_id) REFERENCES users (id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS subjective_examination (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        body_structure TEXT,
        body_function TEXT,
        activity_performance TEXT,
        activity_capacity TEXT,
        contextual_environmental TEXT,
        contextual_personal TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS patient_perspectives (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        knowledge TEXT,
        attribution TEXT,
        illness_duration TEXT,
        consequences_awareness TEXT,
        locus_of_control TEXT,
        affective_aspect TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS initial_plan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        active_movements TEXT,
        active_movements_details TEXT,
        passive_movements TEXT,
        passive_movements_details TEXT,
        passive_over_pressure TEXT,
        passive_over_pressure_details TEXT,
        resisted_movements TEXT,
        resisted_movements_details TEXT,
        combined_movements TEXT,
        combined_movements_details TEXT,
        special_tests TEXT,
        special_tests_details TEXT,
        neuro_dynamic_examination TEXT,
        neuro_dynamic_examination_details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS patho_mechanism (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        area_involved TEXT,
        presenting_symptom TEXT,
        pain_type TEXT,
        pain_nature TEXT,
        pain_severity TEXT,
        pain_irritability TEXT,
        symptom_source TEXT,
        tissue_healing_stage TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS chronic_diseases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        cause TEXT,
        cause_detail TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS clinical_flags (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        red_flag TEXT,
        orange_flag TEXT,
        yellow_flag TEXT,
        black_flag TEXT,
        blue_flag TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS objective_assessment (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        plan TEXT,
        plan_details TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS provisional_diagnosis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        likelihood TEXT,
        structure_fault TEXT,
        symptom TEXT,
        findings_support TEXT,
        findings_reject TEXT,
        hypothesis_supported TEXT,
        further_assessment TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS smart_goals (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        patient_goal TEXT,
        baseline_status TEXT,
        measurable_outcome TEXT,
        time_duration TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS treatment_plan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        treatment_plan TEXT,
        goal_targeted TEXT,
        reasoning TEXT,
        reference TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS first_follow_up (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        goal_number TEXT,
        goals TEXT,
        baseline TEXT,
        achieved TEXT,
        grade TEXT,
        belief_treatment TEXT,
        belief_feedback TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients (patient_id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        details TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )
    ''')

    c.execute('''
    CREATE TABLE IF NOT EXISTS follow_ups (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        patient_id TEXT,
        session_number TEXT,
        session_date TEXT,
        grade TEXT,
        belief_treatment TEXT,
        belief_feedback TEXT,
        treatment_plan TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (patient_id) REFERENCES patients(patient_id)
    )
    ''')

    conn.commit()
    conn.close()

if __name__ == '__main__':
    init_db()
