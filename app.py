import os
from flask import Flask,request, redirect, url_for,flash,render_template
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = './Uploads/'
ALLOWED_EXTENSIONS = set(['jpg','png','jpeg'])

app = Flask(__name__)
app.secret_key = 'secret key'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/file')
def uploaded_file():
    name = request.args.get('filename')
    return render_template('uploaded_file.html',name = name)

@app.route('/',methods=['GET','POST'])
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('no file part')
            return redirect(request.url)
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'])+filename)
            return redirect(url_for('uploaded_file',filename=filename))
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
    