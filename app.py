from flask import Flask, render_template, redirect, url_for, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from models import db, User, Todo

app = Flask(__name__)
app.config.from_object('config.Config')

db.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
migrate = Migrate(app, db)

# Initialize Database
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
@login_required
def index():
    todos = Todo.query.filter_by(user_id=current_user.id).all()
    return render_template('index.html', todos=todos)

@app.route('/add_task', methods=['POST'])
@login_required
def add_task():
    task_content = request.form['task_content']  # Get task content from form
    new_task = Todo(content=task_content, user_id=current_user.id)
    db.session.add(new_task)  # Add new task to the database
    db.session.commit()  # Commit the change
    return redirect(url_for('index'))  # Redirect to index to see updated list

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# Mark task as done
@app.route('/mark_done/<int:task_id>')
@login_required
def mark_done(task_id):
    task = Todo.query.get_or_404(task_id)
    if task.user_id == current_user.id:  # Ensure the task belongs to the current user
        task.done = True
        db.session.commit()
    return redirect(url_for('index'))

# Delete task
@app.route('/delete_task/<int:task_id>')
@login_required
def delete_task(task_id):
    task = Todo.query.get_or_404(task_id)
    if task.user_id == current_user.id:  # Ensure the task belongs to the current user
        db.session.delete(task)
        db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
