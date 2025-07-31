# app.py
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # Create tables
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        full_name TEXT,
        email TEXT
    );
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS menus (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        date TEXT NOT NULL,
        breakfast TEXT,
        lunch TEXT,
        snacks TEXT,
        dinner TEXT,
        created_by INTEGER,
        FOREIGN KEY (created_by) REFERENCES users (id)
    );
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL,
        category TEXT NOT NULL,
        date_posted TEXT NOT NULL,
        posted_by INTEGER,
        FOREIGN KEY (posted_by) REFERENCES users (id)
    );
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS placements (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        company_name TEXT NOT NULL,
        job_role TEXT NOT NULL,
        package TEXT,
        eligibility TEXT,
        last_date TEXT,
        description TEXT,
        posted_by INTEGER,
        date_posted TEXT NOT NULL,
        FOREIGN KEY (posted_by) REFERENCES users (id)
    );
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        category TEXT NOT NULL,
        content TEXT NOT NULL,
        rating INTEGER NOT NULL,
        submitted_by INTEGER,
        date_submitted TEXT NOT NULL,
        FOREIGN KEY (submitted_by) REFERENCES users (id)
    );
    ''')
    
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS transport (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bus_number TEXT NOT NULL,
        route TEXT NOT NULL,
        morning_timing TEXT NOT NULL,
        evening_timing TEXT NOT NULL,
        updated_by INTEGER,
        last_updated TEXT NOT NULL,
        FOREIGN KEY (updated_by) REFERENCES users (id)
    );
    ''')
    
    # Insert default admin user if not exists
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        hashed_password = generate_password_hash('admin123')
        cursor.execute("INSERT INTO users (username, password, role, full_name) VALUES (?, ?, ?, ?)",
                      ('admin', hashed_password, 'college_admin', 'College Admin'))
    
    conn.commit()
    conn.close()

init_db()

# Helper functions
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Routes
@app.route('/')
def home():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')
# Add this new route after the login route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        full_name = request.form['full_name']
        email = request.form['email']
        role = request.form['role']
        
        # Validate inputs
        if not username or not password or not confirm_password:
            flash('Username and password are required!', 'danger')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))
        
        conn = get_db_connection()
        
        try:
            hashed_password = generate_password_hash(password)
            conn.execute('''
                INSERT INTO users (username, password, role, full_name, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hashed_password, role, full_name, email))
            conn.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    role = session['role']
    
    if role == 'college_admin':
        return redirect(url_for('admin_dashboard'))
    elif role == 'canteen_admin':
        return redirect(url_for('canteen_dashboard'))
    elif role == 'transport_admin':
        return redirect(url_for('transport_dashboard'))
    else:
        return redirect(url_for('student_dashboard'))

# College Admin Dashboard
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'username' not in session or session['role'] != 'college_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC LIMIT 5').fetchall()
    placements = conn.execute('SELECT * FROM placements ORDER BY date_posted DESC LIMIT 5').fetchall()
    conn.close()
    
    return render_template('dashboard_admin.html', notifications=notifications, placements=placements)

@app.route('/admin/notifications', methods=['GET', 'POST'])
def manage_notifications():
    if 'username' not in session or session['role'] != 'college_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        category = request.form['category']
        date_posted = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn.execute('INSERT INTO notifications (title, content, category, date_posted, posted_by) VALUES (?, ?, ?, ?, ?)',
                    (title, content, category, date_posted, session['user_id']))
        conn.commit()
        flash('Notification added successfully!', 'success')
    
    notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC').fetchall()
    conn.close()
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/admin/placements', methods=['GET', 'POST'])
def manage_placements():
    if 'username' not in session or session['role'] != 'college_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        company_name = request.form['company_name']
        job_role = request.form['job_role']
        package = request.form['package']
        eligibility = request.form['eligibility']
        last_date = request.form['last_date']
        description = request.form['description']
        date_posted = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn.execute('''INSERT INTO placements 
                      (company_name, job_role, package, eligibility, last_date, description, posted_by, date_posted)
                      VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                    (company_name, job_role, package, eligibility, last_date, description, session['user_id'], date_posted))
        conn.commit()
        flash('Placement opportunity added successfully!', 'success')
    
    placements = conn.execute('SELECT * FROM placements ORDER BY date_posted DESC').fetchall()
    conn.close()
    
    return render_template('placements.html', placements=placements)

@app.route('/admin/delete_notification/<int:id>')
def delete_notification(id):
    if 'username' not in session or session['role'] != 'college_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM notifications WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Notification deleted successfully!', 'success')
    return redirect(url_for('manage_notifications'))

@app.route('/admin/delete_placement/<int:id>')
def delete_placement(id):
    if 'username' not in session or session['role'] != 'college_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM placements WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Placement opportunity deleted successfully!', 'success')
    return redirect(url_for('manage_placements'))

# Canteen Admin Dashboard
@app.route('/canteen/dashboard')
def canteen_dashboard():
    if 'username' not in session or session['role'] != 'canteen_admin':
        return redirect(url_for('login'))
    
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    conn = get_db_connection()
    menu = conn.execute('SELECT * FROM menus WHERE date = ?', (today,)).fetchone()
    conn.close()
    
    return render_template('dashboard_canteen.html', menu=menu, today=today)

@app.route('/canteen/menu', methods=['GET', 'POST'])
def manage_menu():
    if 'username' not in session or session['role'] != 'canteen_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        date = request.form['date']
        breakfast = request.form['breakfast']
        lunch = request.form['lunch']
        snacks = request.form['snacks']
        dinner = request.form['dinner']
        
        # Check if menu for this date already exists
        existing = conn.execute('SELECT id FROM menus WHERE date = ?', (date,)).fetchone()
        
        if existing:
            conn.execute('''UPDATE menus SET 
                          breakfast = ?, lunch = ?, snacks = ?, dinner = ?
                          WHERE date = ?''',
                        (breakfast, lunch, snacks, dinner, date))
        else:
            conn.execute('''INSERT INTO menus 
                          (date, breakfast, lunch, snacks, dinner, created_by)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                        (date, breakfast, lunch, snacks, dinner, session['user_id']))
        
        conn.commit()
        flash('Menu updated successfully!', 'success')
    
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    menu = conn.execute('SELECT * FROM menus WHERE date = ?', (today,)).fetchone()
    conn.close()
    
    return render_template('menu_management.html', menu=menu, today=today)

# Transport Admin Dashboard
@app.route('/transport/dashboard')
def transport_dashboard():
    if 'username' not in session or session['role'] != 'transport_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    routes = conn.execute('SELECT * FROM transport ORDER BY route').fetchall()
    conn.close()
    
    return render_template('dashboard_transport.html', routes=routes)

@app.route('/transport/manage', methods=['GET', 'POST'])
def manage_transport():
    if 'username' not in session or session['role'] != 'transport_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        bus_number = request.form['bus_number']
        route = request.form['route']
        morning_timing = request.form['morning_timing']
        evening_timing = request.form['evening_timing']
        last_updated = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Check if route already exists
        existing = conn.execute('SELECT id FROM transport WHERE route = ?', (route,)).fetchone()
        
        if existing:
            conn.execute('''UPDATE transport SET 
                          bus_number = ?, morning_timing = ?, evening_timing = ?,
                          updated_by = ?, last_updated = ?
                          WHERE route = ?''',
                        (bus_number, morning_timing, evening_timing, session['user_id'], last_updated, route))
        else:
            conn.execute('''INSERT INTO transport 
                          (bus_number, route, morning_timing, evening_timing, updated_by, last_updated)
                          VALUES (?, ?, ?, ?, ?, ?)''',
                        (bus_number, route, morning_timing, evening_timing, session['user_id'], last_updated))
        
        conn.commit()
        flash('Transport details updated successfully!', 'success')
    
    routes = conn.execute('SELECT * FROM transport ORDER BY route').fetchall()
    conn.close()
    
    return render_template('transport.html', routes=routes)

@app.route('/transport/delete/<int:id>')
def delete_route(id):
    if 'username' not in session or session['role'] != 'transport_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    conn.execute('DELETE FROM transport WHERE id = ?', (id,))
    conn.commit()
    conn.close()
    flash('Route deleted successfully!', 'success')
    return redirect(url_for('manage_transport'))

# Student Dashboard
@app.route('/student/dashboard')
def student_dashboard():
    if 'username' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    today = datetime.datetime.now().strftime('%Y-%m-%d')
    conn = get_db_connection()
    menu = conn.execute('SELECT * FROM menus WHERE date = ?', (today,)).fetchone()
    notifications = conn.execute('SELECT * FROM notifications ORDER BY date_posted DESC LIMIT 5').fetchall()
    placements = conn.execute('SELECT * FROM placements ORDER BY date_posted DESC LIMIT 5').fetchall()
    routes = conn.execute('SELECT * FROM transport ORDER BY route').fetchall()
    conn.close()
    
    return render_template('dashboard_student.html', 
                         menu=menu, 
                         notifications=notifications, 
                         placements=placements,
                         routes=routes,
                         today=today)

@app.route('/student/feedback', methods=['GET', 'POST'])
def submit_feedback():
    if 'username' not in session or session['role'] != 'student':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        category = request.form['category']
        content = request.form['content']
        rating = request.form['rating']
        date_submitted = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        conn = get_db_connection()
        conn.execute('''INSERT INTO feedback 
                      (category, content, rating, submitted_by, date_submitted)
                      VALUES (?, ?, ?, ?, ?)''',
                    (category, content, rating, session['user_id'], date_submitted))
        conn.commit()
        conn.close()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('student_dashboard'))
    
    return render_template('feedback.html')

@app.route('/admin/users', methods=['GET', 'POST'])
def manage_users():
    if 'username' not in session or session['role'] != 'college_admin':
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    
    if request.method == 'POST':
        username = request.form['username']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']
        full_name = request.form['full_name']
        email = request.form['email']
        
        try:
            conn.execute('''
                INSERT INTO users (username, password, role, full_name, email)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, password, role, full_name, email))
            conn.commit()
            flash('User added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('Username already exists!', 'danger')
    
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    
    return render_template('users.html', users=users)
@app.route('/admin/delete_user/<int:id>')
def delete_user(id):
    if 'username' not in session or session['role'] != 'college_admin':
        return redirect(url_for('login'))
    
    # Prevent deleting the default admin
    conn = get_db_connection()
    user = conn.execute('SELECT username FROM users WHERE id = ?', (id,)).fetchone()
    
    if user and user['username'] == 'admin':
        flash('Cannot delete the default admin account!', 'danger')
    else:
        conn.execute('DELETE FROM users WHERE id = ?', (id,))
        conn.commit()
        flash('User deleted successfully!', 'success')
    
    conn.close()
    return redirect(url_for('manage_users'))
if __name__ == '__main__':
    app.run(debug=True)