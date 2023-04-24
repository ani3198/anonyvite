
from flask import Flask, render_template, request, redirect, url_for, session
from flask_socketio import SocketIO, send, emit
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import random
import string
from flask_migrate import Migrate

# ...


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://test_user:test@localhost/chat_app'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
socketio = SocketIO(app)
migrate = Migrate(app, db)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

message_history = []
online_users = {}


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64))
    message = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Message {self.id}>'


class ChatAppUser(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True)
    password = db.Column(db.String(128))
    registration_code = db.Column(db.String(6), unique=True, nullable=True)
    invited_by =db.Column(db.String(128))

    def __repr__(self):
        return f'<User {self.username}>'



@login_manager.user_loader
def load_user(user_id):
    return ChatAppUser.query.get(int(user_id))


@app.route('/')
@login_required
def index():
    messages = Message.query.order_by(Message.timestamp).all()
    return render_template('index.html', messages=messages)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = ChatAppUser.query.filter_by(username=username).first()
        if user is None or not check_password_hash(user.password, password):
            return render_template('login.html', error='Invalid username or password')

        login_user(user)
        return redirect(url_for('index'))

    return render_template('login.html')




@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        registration_code = request.form['registration_code']

        existing_user = ChatAppUser.query.filter_by(username=username).first()
        if existing_user:
            return render_template('register.html', error='Username already exists')

        code_user = ChatAppUser.query.filter_by(registration_code=registration_code).first()
        print(code_user.username,code_user.username != registration_code )
        if code_user.username != registration_code :
            return render_template('register.html', error='Invalid registration code')

        code_user.username = username
        code_user.password = generate_password_hash(password)
        db.session.commit()
        login_user(code_user)
        return redirect(url_for('index'))

    return render_template('register.html')



@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@socketio.on('connect')
@login_required
def handle_connect():
    user = current_user
    online_users[user.username] = request.sid
    emit('join', {'username': user.username}, broadcast=True)
    emit('update_online_users', list(online_users.keys()), broadcast=True)


@socketio.on('message')
@login_required
def handle_message(data):
    username = current_user.username
    message = data['message']
    message_obj = Message(username=username, message=message)
    db.session.add(message_obj)
    db.session.commit()
    send({'username': username, 'message': message}, broadcast=True)


@socketio.on('media')
@login_required
def handle_media(data):
    username = current_user.username
    message_history.append({'type': 'media', 'data': data})
    emit('media', {'username': username,
         'type': data['type'], 'data': data['data']}, broadcast=True)


@app.route('/generate_code')
@login_required
def generate_code():
    code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))
    user = ChatAppUser(username=code,
                           password=code,registration_code = code,invited_by =current_user.username)
    db.session.add(user)
    db.session.commit()
    return render_template('generated_code.html', code=code)



@socketio.on('disconnect')
@login_required
def handle_disconnect():
    user = current_user
    online_users.pop(user.username, None)
    emit('leave', {'username': user.username}, broadcast=True)
    emit('update_online_users', list(online_users.keys()), broadcast=True)


def generate_random_code(length=6):
    return ''.join(random.choices(string.digits, k=length))


if __name__ == '__main__':
    socketio.run(app, debug=True)
