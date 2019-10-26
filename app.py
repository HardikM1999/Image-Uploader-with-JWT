from flask import Flask,request,jsonify,render_template,make_response,redirect,url_for,flash
from flask_sqlalchemy import SQLAlchemy
import uuid
import jwt
import datetime
import os
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash,check_password_hash
from functools import wraps


UPLOAD_FOLDER = './Uploads/'
ALLOWED_EXTENSIONS = set(['jpg','png','jpeg'])

app = Flask(__name__)

app.config['SECRET_KEY'] = 'secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    public_id = db.Column(db.String(10),unique=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(50))
    admin = db.Column(db.Boolean)

def token_required(f):
    @wraps(f)
    def decorated(*args,**kwargs):
        token = None
        if 'access-token' in request.headers:
            token = request.headers['access-token']
        if not token:
            return jsonify({'message': 'Token not given!'})
        try:
            data = jwt.decode(token,app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'Token is Invalid!'})
        return f(current_user,*args,*kwargs)
    return decorated

def allowed_filename(filename):
    return '.' in filename and \
        filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/file')
def uploaded_file():
    name = request.args.get('filename')
    return render_template('uploaded_file.html',name=name)

@app.route('/upload',methods=['GET','POST'])
@token_required
def upload(current_user):
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file Part!')
            #return redirect(request.url)
            return jsonify({'message':'file not found!'})
        file = request.files['file']
        if file and allowed_filename(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'])+filename)
            #return redirect(url_for('uploaded_file',filename=filename))
            return jsonify({'message': 'file uploaded'})
    return render_template('upload.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password,method='sha256')
        new_user = User(public_id=str(uuid.uuid4()),username=username,password = hashed_password,admin=False)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "New User Created!"})
    return render_template('register.html')

@app.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Auth details not complete!', 401,{'WWW-Authenticate':'Basic realm="Login Required!"'})
    user = User.query.filter_by(username=auth.username).first()
    if not user:
        return jsonify({'message': 'No User found!'})
    if check_password_hash(user.password,auth.password):
        token = jwt.encode({'public_id': user.public_id,'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},app.config['SECRET_KEY'])
        return jsonify({'token': token.decode('UTF-8')})

if __name__ == '__main__':
    app.run(debug=True)