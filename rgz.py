from flask import Blueprint,redirect, url_for, render_template, request, session
from Db import db
from Db.models import User, Initiative, Vote
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_user, login_required, current_user,logout_user
import re

rgz = Blueprint("rgz",__name__)

def create_admin():
    admin_username = 'admin'
    admin_password = 'admin'
    hashed_password = generate_password_hash(admin_password)
    admin_user = User(username=admin_username, password=hashed_password, is_admin=True)
    db.session.add(admin_user)
    db.session.commit()

def calculate_votes(initiative_id):
    upvotes = Vote.query.filter_by(initiative_id=initiative_id, vote_type=True).count()
    downvotes = Vote.query.filter_by(initiative_id=initiative_id, vote_type=False).count()
    return upvotes - downvotes

@rgz.route('/')
@rgz.route("/home")

@rgz.route("/home/<int:page>")
def home(page=1):
    per_page = 20
    initiatives = Initiative.query.order_by(Initiative.date_created.desc()).paginate(page=page, per_page=per_page, error_out=False)
    if current_user.is_authenticated and getattr(current_user, 'is_admin', False):
        return redirect("/admin/users")
    else:
        if current_user.is_authenticated:
            username = current_user.username
        else:
            username = "Anonymous"
        return render_template("home.html", initiatives=initiatives, username=username)
    


@rgz.route('/admin/users')
@rgz.route('/admin/users/<int:page>')
@login_required
def admin_users(page=1):
    errors = ''
    if not current_user.is_authenticated or not current_user.is_admin:
        return "Access Denied", 403

    users = User.query.all()
    per_page = 20
    
    initiatives = Initiative.query.order_by(Initiative.date_created.desc()).paginate(page=page, per_page=per_page, error_out=False)
    for user in users:
        if user.has_initiative:
            errors = 'Вы не можете удалить пользователя, который имеет инициативу!'

    return render_template("admin_users.html", users=users, initiatives = initiatives, errors=errors)


@rgz.route("/home/register", methods=['GET', 'POST'])
def registerPage():
    errors = ''

    if request.method =='GET':
        return render_template("register.html", errors = errors)
    
    username_form = request.form.get("username")
    password_form = request.form.get("password")

    if not (username_form or password_form):
        errors = "Пожалуйста, заполните все поля"
        print(errors)
        return render_template("register.html", errors=errors)

    isUserExist = User.query.filter_by(username=username_form).first()

    if isUserExist is not None:
        errors = "Пользователь с таким именем уже существует"
        return render_template("register.html", errors=errors)
    
    if not re.match("^[A-Za-z0-9@#$%^&+=]{4,}$", username_form):
        errors = "Логин должен содержать только латинские буквы, цифры и знаки препинания и иметь длину не менее 4 символов"        
        return render_template("register.html", errors=errors)
    
    if not re.match("^[A-Za-z0-9@#$%^&+=]{5,}$", password_form):
        errors = "Пароль должен содержать только латинские буквы, цифры и знаки препинания и иметь длину не менее 5 символов"        
        return render_template("register.html", errors=errors)
    
    hashedPswd = generate_password_hash(password_form, method='pbkdf2')
    newUser = User(username=username_form, password=hashedPswd)

    db.session.add(newUser)
    db.session.commit()
    return redirect("/home/login")

@rgz.route("/home/login", methods=['GET', 'POST'])
def login():
    errors = ''
    if request.method =='GET':
        return render_template("login.html")
    
    username_form = request.form.get("username")
    password_form = request.form.get("password")

    isUserExist = User.query.filter_by(username=username_form).first()

    my_user = User.query.filter_by(username=username_form).first()
    
    if username_form is None and password_form is None:
        errors = 'Заполните все поля!'
        return render_template("login.html", errors=errors)
    else:
        if my_user is not None:
            if check_password_hash(my_user.password, password_form):
                login_user(my_user, remember=False)
                return redirect("/home")
            else:
                errors = 'Неверный пароль!'
                return render_template("login.html", errors=errors)
        else:
            errors = 'Пользователя с таким именем не существует!'
            return render_template("login.html", errors=errors)


@rgz.route("/home/new_initiative", methods=['GET', 'POST'])
@login_required
def new_initiative():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        if not title or not description:
            error = 'Пожалуйста, заполните все поля!'
            return render_template("new_initiative.html", error=error)

        initiative = Initiative(title=title, description=description, user_id=current_user.id)
        db.session.add(initiative)
        db.session.commit()
        return redirect(url_for('rgz.home'))
    return render_template("new_initiative.html")

@rgz.route('/home/delete_initiative/<int:initiative_id>', methods=['POST'])
@login_required
def delete_initiative(initiative_id):
    initiative = Initiative.query.get_or_404(initiative_id)
    if initiative.user_id != current_user.id:
        return "Access Denied", 403  

    db.session.delete(initiative)
    db.session.commit()
    return redirect(url_for('rgz.home'))

@rgz.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_authenticated or not current_user.is_admin:
        return "Access Denied", 403

 
    if current_user.id == user_id:
        error = "You cannot delete yourself."
        return redirect(url_for('rgz.admin_users'))

    user_to_delete = User.query.get_or_404(user_id)
    db.session.delete(user_to_delete)
    db.session.commit()
    error = "User deleted successfully."
    return redirect(url_for('rgz.admin_users'))

@rgz.route('/admin/delete_initiative/<int:initiative_id>', methods=['POST'])
@login_required
def admin_delete_initiative(initiative_id):
    print("Current User:", current_user.username)  # Debug: вывести текущего пользователя
    print("Is Admin:", current_user.is_admin)  # Debug: Print является ли пользователь администратором

    if not current_user.is_admin:
        print("Access Denied: User is not an admin.")  # Debug: Print сообщение, если доступ запрещен
        return "Access Denied", 403

    initiative_to_delete = Initiative.query.get_or_404(initiative_id)
    db.session.delete(initiative_to_delete)
    db.session.commit()
    return redirect(url_for('rgz.admin_users'))  #Перенаправление на соответствующую страницу

@rgz.route('/vote/up/<int:initiative_id>', methods=['POST'])
@login_required
def upvote(initiative_id):
    existing_vote = Vote.query.filter_by(user_id=current_user.id, initiative_id=initiative_id).first()
    if existing_vote:
        if existing_vote.vote_type is True:  # Уже проголосовали за
            return redirect(url_for('rgz.home'))
        existing_vote.vote_type = True
    else:
        vote = Vote(user_id=current_user.id, initiative_id=initiative_id, vote_type=True)
        db.session.add(vote)
    db.session.commit()

    if calculate_votes(initiative_id) < -10:
        initiative = Initiative.query.get_or_404(initiative_id)
        db.session.delete(initiative)
        db.session.commit()

    return redirect(url_for('rgz.home'))

@rgz.route('/vote/down/<int:initiative_id>', methods=['POST'])
@login_required
def downvote(initiative_id):
    existing_vote = Vote.query.filter_by(user_id=current_user.id, initiative_id=initiative_id).first()
    if existing_vote:
        if existing_vote.vote_type is False:  # Уже проголосовали против
            return redirect(url_for('rgz.home'))
        existing_vote.vote_type = False
    else:
        vote = Vote(user_id=current_user.id, initiative_id=initiative_id, vote_type=False)
        db.session.add(vote)
    db.session.commit()

    if calculate_votes(initiative_id) < -10:
        initiative = Initiative.query.get_or_404(initiative_id)
        db.session.delete(initiative)
        db.session.commit()

    return redirect(url_for('rgz.home'))


@rgz.route("/home/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('rgz.login')) 


