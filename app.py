from flask import Flask, render_template, request, redirect, url_for, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from werkzeug.utils import secure_filename
import os
from flask_migrate import Migrate
from flask_login import current_user, login_required
from sqlalchemy import func
import io
import base64
import secrets
from datetime import datetime
from PIL import Image
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, TextAreaField, SelectField, FileField
from wtforms.validators import DataRequired, Email, Length
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError
import pytz
import google.generativeai as genai
import requests

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.refresh_view = 'login'
login_manager.needs_refresh_message = 'Please log in again to access this page.'
login_manager.needs_refresh_message_category = 'info'

migrate = Migrate(app, db)

eat_tz = pytz.timezone('Africa/Nairobi')

genai.configure(api_key=os.getenv('GEMINI_API_KEY'))
model = genai.GenerativeModel('gemini-pro')

def moderate_content(content):
    try:
        prompt = f"""
        Please review the following content and determine if it violates Meta's Community Standards:
        "{content}"
        
        Respond with either "ALLOWED" or "VIOLATES" followed by a brief explanation.
        """

        response = model.generate_content(prompt)
        result = response.text.strip().upper()

        return result.startswith("ALLOWED")
    except Exception as e:
        print(f"Error in content moderation: {str(e)}")
        return True
class Follow(db.Model):
    __tablename__ = 'follows'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    follower_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    followed_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=lambda: datetime.now(eat_tz))

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    profile_picture = db.Column(db.String(20), nullable=True, default='default.jpg')
    gender = db.Column(db.String(10), nullable=True)
    date_joined = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    unique_name = db.Column(db.String(20), unique=True, nullable=True)
    pronouns = db.Column(db.String(30))
    display_name = db.Column(db.String(50))
    location = db.Column(db.String(100))
    website = db.Column(db.String(200))
    interests = db.Column(db.String(200))
    posts = db.relationship('Post', backref='author', lazy=True)
    goals = db.relationship('Goal', backref='user', lazy=True)
    likes = db.relationship('Like', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    following = db.relationship('Follow',
                                foreign_keys=[Follow.follower_id],
                                backref=db.backref('follower', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    daily_usage = db.Column(db.Float, default=0)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.profile_picture}')"
    
    def follow(self, user):
        if not self.is_following(user):
            follow = Follow(follower=self, followed=user)
            db.session.add(follow)

    def unfollow(self, user):
        follow = self.following.filter_by(followed_id=user.id).first()
        if follow:
            db.session.delete(follow)

    def is_following(self, user):
        return self.following.filter_by(followed_id=user.id).first() is not None



class CommentReply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(eat_tz))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    author = db.relationship('User', backref='replies', lazy=True)
class CommentLike(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=True)
    image = db.Column(db.String(100), nullable=True)
    date_posted = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(eat_tz))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    approved = db.Column(db.Boolean, default=False, nullable=False)
    likes = db.relationship('Like', backref='post', lazy=True)
    comments = db.relationship('Comment', backref='post', lazy=True, cascade="all, delete-orphan")
    title = db.Column(db.String(100), nullable=False)
    hashtags = db.Column(db.String(200))
    
class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    deadline = db.Column(db.Date, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Like(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)
    replies = db.relationship('CommentReply', backref='comment', lazy='dynamic')
    reactions = db.relationship('CommentReaction', backref='comment', lazy='dynamic')

    def get_reaction_counts(self):
        reaction_counts = {}
        for reaction in self.reactions:
            reaction_counts[reaction.reaction] = reaction_counts.get(reaction.reaction, 0) + 1
        return reaction_counts

    def get_user_reaction(self, user_id):
        user_reaction = CommentReaction.query.filter_by(comment_id=self.id, user_id=user_id).first()
        return user_reaction.reaction if user_reaction else None
    
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    message = db.Column(db.String(500), nullable=False)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

class EditProfileForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    bio = TextAreaField('Bio', validators=[Length(max=500)])
    gender = SelectField('Gender', choices=[('male', 'Male'), ('female', 'Female'), ('non-binary', 'Non-binary'), ('other', 'Other'), ('prefer_not_to_say', 'Prefer not to say')])
    pronouns = StringField('Preferred Pronouns')
    display_name = StringField('Display Name', validators=[Length(max=50)])
    profile_picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg', 'png'])])
    location = StringField('Location', validators=[Length(max=100)])
    website = StringField('Website', validators=[Length(max=200)])
    interests = StringField('Interests (comma-separated)', validators=[Length(max=200)])

class CommentReaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    comment_id = db.Column(db.Integer, db.ForeignKey('comment.id'), nullable=False)
    reaction = db.Column(db.String(20), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def moderate_content(content):
    try:
        guidelines_url = os.getenv('META_GUIDELINES_URL')
        prompt = f"Analyze the following content and determine if it violates Meta's community guidelines (available at {guidelines_url}). Respond with 'APPROPRIATE' or 'INAPPROPRIATE' followed by a brief explanation. If inappropriate, specify if insults or vulgar words were used:\n\n{content}\n\nAnalysis:"
        response = model.generate_content(prompt)
        
        if response.candidates and response.candidates[0].content and response.candidates[0].content.parts:
            result = response.candidates[0].content.parts[0].text.upper()
            if "APPROPRIATE" in result:
                return True, response.candidates[0].content.parts[0].text
            else:
                return False, response.candidates[0].content.parts[0].text
        else:
            # If no valid response, assume the content is inappropriate
            return False, "Content moderation failed. Treating as inappropriate for safety."
    except Exception as e:
        print(f"Error in content moderation: {str(e)}")
        # If an error occurs, err on the side of caution and treat as inappropriate
        return False, "Content moderation error. Treating as inappropriate for safety."

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def notify_user(user, message):
    notification = Notification(user_id=user.id, message=message)
    db.session.add(notification)
    db.session.commit()

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def suggest_hashtags(content):
    words = content.lower().split()
    common_hashtags = ['hashtags']
    suggested = [tag for tag in common_hashtags if any(word in tag for word in words)]
    return suggested[:3]

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def follow_user(follower_id, followed_id):
    new_follow = Follow(follower_id=follower_id, followed_id=followed_id)
    db.session.add(new_follow)
    db.session.commit()

def save_picture(form_picture):
    random_hex = secrets.token_hex(8)
    _, f_ext = os.path.splitext(form_picture.filename)
    picture_fn = random_hex + f_ext
    picture_path = os.path.join(app.root_path, 'static/profile_pics', picture_fn)
    os.makedirs(os.path.dirname(picture_path), exist_ok=True)
    output_size = (125, 125)
    i = Image.open(form_picture)
    i.thumbnail(output_size)
    i.save(picture_path)
    
    return picture_fn

@app.route('/update_usage', methods=['POST'])
@login_required
def update_usage():
    hours = float(request.form['hours'])
    current_user.daily_usage = hours
    db.session.commit()
    return redirect(url_for('profile', username=current_user.username))

@app.route('/')
def home():
    if current_user.is_authenticated:
        page = request.args.get('page', 1, type=int)
        posts_per_page = 10
        followed_users = [follow.followed_id for follow in current_user.following]
        followed_users.append(current_user.id)
        posts = Post.query.filter(Post.user_id.in_(followed_users))\
                          .filter_by(approved=True)\
                          .order_by(Post.date_posted.desc())\
                          .paginate(page=page, per_page=posts_per_page)
        
        for post in posts.items:
            post.comments = Comment.query.filter_by(post_id=post.id).all()
        
        suggested_posts = Post.query.filter(~Post.user_id.in_(followed_users))\
                                    .filter_by(approved=True)\
                                    .order_by(func.random())\
                                    .limit(5)\
                                    .all()
        
        return render_template('home.html', posts=posts.items, page=posts, suggested_posts=suggested_posts)
    else:
        return redirect(url_for('login'))

@app.route('/suggested_posts')
@login_required
def suggested_posts():
    user_interests = set(current_user.interests.split(','))
    suggested_posts = Post.query.filter(Post.user_id != current_user.id)\
                                .filter_by(approved=True)\
                                .order_by(func.random())\
                                .limit(20)\
                                .all()
    
    filtered_posts = [post for post in suggested_posts if set(post.hashtags.split()).intersection(user_interests)]
    
    return render_template('suggested_posts.html', suggested_posts=filtered_posts[:10])

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    posts = Post.query.filter_by(user_id=user.id).order_by(Post.date_posted.desc()).all()
    goals = Goal.query.filter_by(user_id=user.id).order_by(Goal.deadline).all()
    is_owner = user == current_user
    form = EditProfileForm(obj=user)
    return render_template('profile.html', user=user, posts=posts, goals=goals, form=form, is_owner=is_owner)

@app.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
        form = EditProfileForm()
        if form.validate_on_submit():
            if form.profile_picture.data:
                picture_file = save_picture(form.profile_picture.data)
                current_user.profile_picture = picture_file
            current_user.username = form.username.data
            current_user.email = form.email.data
            current_user.bio = form.bio.data
            current_user.gender = form.gender.data
            current_user.pronouns = form.pronouns.data
            current_user.display_name = form.display_name.data
            current_user.location = form.location.data
            current_user.website = form.website.data
            current_user.interests = form.interests.data
            db.session.commit()
            flash('Your profile has been updated!', 'success')
            return redirect(url_for('profile', username=current_user.username))
        elif request.method == 'GET':
            form.username.data = current_user.username
            form.email.data = current_user.email
            form.bio.data = current_user.bio
            form.gender.data = current_user.gender
            form.pronouns.data = current_user.pronouns
            form.display_name.data = current_user.display_name
            form.location.data = current_user.location
            form.website.data = current_user.website
            form.interests.data = current_user.interests
        return render_template('edit_profile.html', title='Edit Profile', form=form)

@app.route('/search')
def search():
    query = request.args.get('q')
    users = User.query.filter(
        (User.username.ilike(f'%{query}%')) |
        (User.display_name.ilike(f'%{query}%'))
    ).all()
    posts = Post.query.filter(Post.hashtags.ilike(f'%{query}%')).all()
    return render_template('search_results.html', users=users, posts=posts, query=query)

@app.route('/follow/<username>')
@login_required
def follow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'error')
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot follow yourself!', 'error')
        return redirect(url_for('profile', username=username))
    current_user.follow(user)
    db.session.commit()
    notify_user(user, f"{current_user.username} started following you.")
    flash(f'You are now following {username}!', 'success')
    return redirect(url_for('profile', username=username))

@app.route('/unfollow/<username>')
@login_required
def unfollow(username):
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash('User not found.', 'error')
        return redirect(url_for('home'))
    if user == current_user:
        flash('You cannot unfollow yourself!', 'error')
        return redirect(url_for('profile', username=username))
    current_user.unfollow(user)
    db.session.commit()
    flash(f'You have unfollowed {username}.', 'success')
    return redirect(url_for('profile', username=username))

@app.route('/followers/<username>')
@login_required
def followers(username):
    user = User.query.filter_by(username=username).first_or_404()
    followers = user.followers.all()
    return render_template('followers.html', user=user, followers=followers)

@app.route('/following/<username>')
@login_required
def following(username):
    user = User.query.filter_by(username=username).first_or_404()
    following = user.following.all()
    return render_template('following.html', user=user, following=following)

def get_trending_hashtags():
    recent_posts = Post.query.order_by(Post.date_posted.desc()).limit(100).all()
    hashtags = {}
    for post in recent_posts:
        for tag in post.hashtags.split():
            hashtags[tag] = hashtags.get(tag, 0) + 1
    return sorted(hashtags.items(), key=lambda x: x[1], reverse=True)[:5]

@app.context_processor
def inject_trending_hashtags():
    return dict(trending_hashtags=get_trending_hashtags())

@app.route('/recommended_users')
@login_required
def recommended_users():
    if current_user.is_authenticated:
        followed_users = [follow.followed.id for follow in current_user.following]
    else:
        followed_users = []
    recommended = User.query.filter(
        ~User.id.in_(followed_users + [current_user.id])
    ).order_by(func.random()).limit(5).all()
    return render_template('recommended_users.html', recommended_users=recommended)

@app.route('/delete_post/<int:post_id>', methods=['POST'])
@login_required
def delete_post(post_id):
    post = Post.query.get_or_404(post_id)
    if post.author != current_user:
        abort(403)
    
    likes = Like.query.filter_by(post_id=post_id).all()
    Comment.query.filter_by(post_id=post_id).delete()
    for like in likes:
        db.session.delete(like)
    
    post = Post.query.get(post_id)  
    db.session.delete(post)
    
    try:
        db.session.commit()
        flash('Your post has been deleted.', 'success')
    except Exception as e:
        db.session.rollback()
        flash('An error occurred while deleting the post.', 'error')
        print(f"Error deleting post: {str(e)}")
    
    return redirect(url_for('profile', username=current_user.username))

@app.route('/delete_comment/<int:comment_id>', methods=['POST'])
@login_required
def delete_comment(comment_id):
    comment = Comment.query.get_or_404(comment_id)
    if comment.author != current_user:
        abort(403)
    db.session.delete(comment)
    db.session.commit()
    return jsonify({'status': 'success', 'message': 'Comment deleted successfully'})

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email address already exists. Please use a different email.', 'error')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, email=email, password=hashed_password)
        
        try:
            db.session.add(new_user)
            db.session.commit()

            # Send data to Zapier webhook
            zapier_webhook_url = "https://hooks.zapier.com/hooks/catch/19639396/2uf0dpk/"
            payload = {
                "username": username,
                "email": email
            }
            response = requests.post(zapier_webhook_url, json=payload)
            
            if response.status_code == 200:
                print("Data sent to Zapier successfully")
            else:
                print(f"Failed to send data to Zapier. Status code: {response.status_code}")

            flash('Account created successfully', 'success')
            return redirect(url_for('login'))
        except IntegrityError:
            db.session.rollback()
            flash('An error occurred. Please try again.', 'error')
            return redirect(url_for('signup'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid username or password', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def dashboard():
    posts = Post.query.filter_by(user_id=current_user.id).order_by(Post.date_posted.desc()).all()
    goals = Goal.query.filter_by(user_id=current_user.id).order_by(Goal.deadline).all()
    return render_template('profile.html', posts=posts, goals=goals)


@app.route('/hashtag/<hashtag>')
def hashtag(hashtag):
    posts = Post.query.filter(Post.hashtags.ilike(f'%{hashtag}%')).order_by(Post.date_posted.desc()).all()
    return render_template('hashtag.html', posts=posts, hashtag=hashtag)

@app.route('/post', methods=['GET', 'POST'])
@login_required
def post():
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        hashtags = request.form.get('hashtags', '')
        
        if not title:
            flash('Title is required', 'error')
            return render_template('post.html')

        is_allowed, moderation_message = moderate_content(title + " " + content)
        if not is_allowed:
            flash(f'Your post may violate community guidelines: {moderation_message}. Please review and revise your content.', 'error')
            return render_template('post.html', title=title, content=content, hashtags=hashtags)
        
        file = request.files.get('image')
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            new_post = Post(title=title, content=content, hashtags=hashtags, image=filename, user_id=current_user.id, approved=True)
        else:
            new_post = Post(title=title, content=content, hashtags=hashtags, user_id=current_user.id, approved=True)
        
        db.session.add(new_post)
        db.session.commit()
        flash('Your post has been submitted', 'success')
        return redirect(url_for('home'))
    
    return render_template('post.html')

@app.route('/like/<int:post_id>', methods=['POST'])
@login_required
def like(post_id):
    post = Post.query.get_or_404(post_id)
    like = Like.query.filter_by(user_id=current_user.id, post_id=post_id).first()
    
    if like:
        db.session.delete(like)
        db.session.commit()
        return jsonify({'status': 'unliked', 'likes_count': len(post.likes)})
    else:
        new_like = Like(user_id=current_user.id, post_id=post_id)
        db.session.add(new_like)
        db.session.commit()
        notify_user(post.author, f"{current_user.username} liked your post.")
        return jsonify({'status': 'liked', 'likes_count': len(post.likes)})

@app.route('/comment/<int:post_id>', methods=['POST'])
@login_required
def comment(post_id):
    post = Post.query.get_or_404(post_id)
    content = request.form['content']
    is_allowed, moderation_message = moderate_content(content)
    if is_allowed:
        new_comment = Comment(content=content, user_id=current_user.id, post_id=post_id)
        db.session.add(new_comment)
        db.session.commit()
        notify_user(post.author, f"{current_user.username} commented on your post.")
        return jsonify({
            'status': 'success', 
            'comment': {
                'id': new_comment.id, 
                'content': new_comment.content, 
                'author': current_user.username
            }
        })
    else:
        return jsonify({
            'status': 'error', 
            'message': f'Your comment may violate community guidelines: {moderation_message}. Please review and revise your content.'
        }), 400

@app.route('/reply_to_comment/<int:comment_id>', methods=['POST'])
@login_required
def reply_to_comment(comment_id):
    content = request.form.get('content')
    if not content:
        return jsonify({'error': 'Reply content is required'}), 400
    
    is_allowed, moderation_message = moderate_content(content)
    if is_allowed:
        comment = Comment.query.get_or_404(comment_id)
        reply = CommentReply(content=content, user_id=current_user.id, comment_id=comment_id)
        db.session.add(reply)
        db.session.commit()
        
        return jsonify({
            'status': 'success',
            'id': reply.id,
            'content': reply.content,
            'timestamp': reply.date_posted.strftime('%Y-%m-%d %H:%M:%S'),
            'username': current_user.username
        }), 201
    else:
        return jsonify({'status': 'error', 'message': f'Your reply may violate community guidelines: {moderation_message}. Please review and revise your content.'})

@app.route('/react_to_comment/<int:comment_id>', methods=['POST'])
@login_required
def react_to_comment(comment_id):
    reaction = request.form.get('reaction')
    if not reaction:
        return jsonify({'error': 'Reaction is required'}), 400
    
    comment = Comment.query.get_or_404(comment_id)
    existing_reaction = CommentReaction.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    
    if existing_reaction:
        if existing_reaction.reaction == reaction:
            db.session.delete(existing_reaction)
        else:
            existing_reaction.reaction = reaction
    else:
        new_reaction = CommentReaction(user_id=current_user.id, comment_id=comment_id, reaction=reaction)
        db.session.add(new_reaction)
    
    db.session.commit()
    
    return jsonify({
        'message': 'Reaction updated successfully',
        'reactions': comment.get_reaction_counts()
    }), 200
    
@app.route('/like_comment/<int:comment_id>', methods=['POST'])
@login_required
def like_comment(comment_id):
    like = CommentLike.query.filter_by(user_id=current_user.id, comment_id=comment_id).first()
    if like:
        db.session.delete(like)
    else:
        new_like = CommentLike(user_id=current_user.id, comment_id=comment_id)
        db.session.add(new_like)
    db.session.commit()
    return redirect(url_for('home'))

@app.route('/goal', methods=['GET', 'POST'])
@login_required
def goal():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        deadline = datetime.strptime(request.form['deadline'], '%Y-%m-%d').date()
        new_goal = Goal(title=title, description=description, deadline=deadline, user_id=current_user.id)
        db.session.add(new_goal)
        db.session.commit()
        flash('New goal added successfully', 'success')
        return redirect(url_for('home'))
    return render_template('goal.html')

@app.route('/complete_goal/<int:goal_id>')
@login_required
def complete_goal(goal_id):
    goal = Goal.query.get_or_404(goal_id)
    if goal.user_id != current_user.id:
        abort(403)
    goal.completed = True
    db.session.commit()
    flash('Goal marked as completed', 'success')
    return redirect(url_for('home'))


@app.route('/notifications')
@login_required
def notifications():
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.timestamp.desc()).all()
    return render_template('notifications.html', notifications=notifications)

@app.route('/mark_notification_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        abort(403)
    notification.read = True
    db.session.commit()
    flash('Notification marked as read', 'success')
    return redirect(url_for('notifications'))

@app.route('/user_activity')
@login_required
def user_activity():
    posts = Post.query.filter_by(user_id=current_user.id).all()
    comments = Comment.query.filter_by(user_id=current_user.id).all()
    likes = Like.query.filter_by(user_id=current_user.id).all()

    activity_data = {
        'posts': len(posts),
        'comments': len(comments),
        'likes': len(likes)
    }

    return render_template('user_activity.html', activity_data=activity_data)


if __name__ == '__main__':
    app.run(debug=True)