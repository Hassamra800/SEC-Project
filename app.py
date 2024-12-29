from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from flask_session import Session
from textblob import TextBlob
import requests
import sqlite3
import random
import string
import json
import os
import re

app = Flask(__name__)

# Configurations for the Flask app
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', '234234fa2312')  # Secret Key for sessions
app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem for persistent sessions
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_FILE_DIR'] = './.flask_sessions'  # Optional, specify session storage location
# Flask-Mail Configurations (For password reset email)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'hassamra125@gmail.com'
app.config['MAIL_DEFAULT_SENDER'] = 'hassamra125@gmail.com'  # Replace with your email
app.config['MAIL_PASSWORD'] = 'wrku eesa trtq phbs'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True


mail = Mail(app)

# Database setup
DATABASE = 'news.db'

def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT NOT NULL,
                  preferences TEXT,
                  reset_token TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    c.execute('''CREATE TABLE IF NOT EXISTS news
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  title TEXT NOT NULL,
                  description TEXT,
                  source TEXT,
                  published_at TEXT,
                  content TEXT,
                  sentiment_score REAL,
                  category TEXT)''')
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def get_sentiment_score(text):
    if not isinstance(text, str) or not text.strip():  # Check for non-string or empty string
        return 0.0  # Return a neutral score or handle as needed
    blob = TextBlob(text)
    return blob.sentiment.polarity

def fetch_news_from_api():
    url = f'https://newsapi.org/v2/top-headlines?country=us&apiKey=05e38fa71bef43299ecf24bd7db3edf6'
    response = requests.get(url)
    data = response.json()

    if data.get('status') == 'ok':
        articles = data.get('articles', [])
        conn = get_db()
        c = conn.cursor()
        for article in articles:
            title = article.get('title', 'Untitled')
            description = article.get('description', '')
            if not title or not description:
                continue  # Skip invalid articles
            sentiment_score = get_sentiment_score(description)
            source = article['source'].get('name', 'Unknown')
            published_at = article.get('publishedAt', datetime.now().isoformat())
            category = article.get('category')
            c.execute('''
                INSERT INTO news (title, description, source, published_at, content, sentiment_score, category)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (title, description, source, published_at, article.get('content', ''), sentiment_score, category))

        conn.commit()
        conn.close()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
        conn.commit()
        conn.close()
        flash("Account created successfully! Please log in.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash("Logged in successfully!")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid username or password.")
            return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/api/dashboard')
def api_dashboard():
    conn = get_db()
    c = conn.cursor()
    # Ensure news table is not empty
    c.execute('SELECT COUNT(*) FROM news')
    if c.fetchone()[0] == 0:
        flash("No news data available. Please refresh later.", "error")
        return redirect(url_for('home'))
    # Fetch personalized feed data
    c.execute('SELECT title, description, sentiment_score FROM news ORDER BY published_at DESC LIMIT 5')
    feed_data = c.fetchall()
    print("Personalized Feed Data:", feed_data)  # Debugging line
    # Fetch topic popularity (e.g., how many articles per category)
    c.execute('SELECT category, COUNT(*) FROM news GROUP BY category')
    topic_popularity = c.fetchall()
    print("Topic Popularity Data:", topic_popularity)  # Debugging line
    # Most read articles (mocked read count for simplicity)
    c.execute('SELECT title, COUNT(*) FROM news GROUP BY title ORDER BY COUNT(*) DESC LIMIT 5')
    most_read_articles = c.fetchall()
    print("Most Read Articles:", most_read_articles)  # Debugging line
    # Format the data to return
    dashboard_data = {
        "personalized_feed": [{"title": article[0], "description": article[1], "sentiment_score": article[2]} for article in feed_data],
        "topic_popularity": {category: count for category, count in topic_popularity},
        "most_read_articles": [{"title": article[0], "read_count": article[1]} for article in most_read_articles],
    }
    # Write the data to the JSON file
    with open('dashboard_data.json', 'w') as json_file:
        json.dump(dashboard_data, json_file, indent=4)
    print("Dashboard data saved to JSON file.")  # Debugging line
    conn.close()
    return jsonify(dashboard_data)

@app.route("/api/sentiment_trends")
def api_sentiment_trends():
    """Provide sentiment trends data."""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT category, AVG(sentiment_score) FROM news GROUP BY category')
    trends = c.fetchall()
    conn.close()
    return jsonify([{"category": trend[0], "avg_score": trend[1]} for trend in trends])

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("You need to log in first.")
        return redirect(url_for('login'))

    # Attempt to regenerate the dashboard data if the file is missing
    try:
        with open('dashboard_data.json', 'r') as json_file:
            dashboard_data = json.load(json_file)
    except (FileNotFoundError, json.JSONDecodeError):
        flash("Regenerating dashboard data. Please wait...", "info")
        redirect(url_for('api_dashboard'))  # Redirect to regenerate data

    # Extract data for rendering
    personalized_feed = dashboard_data.get('personalized_feed', [])
    topic_popularity = dashboard_data.get('topic_popularity', {})
    most_read_articles = dashboard_data.get('most_read_articles', [])

    return render_template(
        'dashboard.html',
        username=session['username'],
        personalized_feed=personalized_feed,
        topic_popularity=topic_popularity,
        most_read_articles=most_read_articles
    )

# Forgot password functionality
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user:
            reset_token = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
            conn = get_db()
            conn.execute('UPDATE users SET reset_token = ? WHERE email = ?', (reset_token, email))
            conn.commit()
            conn.close()
            reset_url = url_for('reset_password', token=reset_token, _external=True)
            msg = Message("Password Reset Request", recipients=[email])
            msg.body = f"Click the link to reset your password: {reset_url}"
            try:
                mail.send(msg)
                flash("Password reset link has been sent to your email.", "success")
                return redirect(url_for('login'))
            except Exception as e:
                flash(f"Error sending email: {e}", "error")
                return redirect(url_for('forgot_password'))
        else:
            flash("Email not found", "error")
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE reset_token = ?', (token,)).fetchone()
    conn.close()
    if not user:
        flash("Invalid or expired token", "error")
        return redirect(url_for('login'))
    if request.method == 'POST':
        new_password = request.form['password']
        hashed_password = generate_password_hash(new_password)
        conn = get_db()
        conn.execute('UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?', (hashed_password, token))
        conn.commit()
        conn.close()
        flash("Password successfully reset. Please login with your new password.", "success")
        return redirect('/login')

@app.route('/filter_articles', methods=['GET'])
def filter_articles():
    sentiment_preference = request.args.get('sentiment', 'all')  # 'positive', 'neutral', 'negative', 'all'
    conn = get_db()
    c = conn.cursor()
    if sentiment_preference == 'positive':
        c.execute("SELECT * FROM news WHERE sentiment_score > 0")
    elif sentiment_preference == 'negative':
        c.execute("SELECT * FROM news WHERE sentiment_score < 0")
    elif sentiment_preference == 'neutral':
        c.execute("SELECT * FROM news WHERE sentiment_score = 0")
    else:
        c.execute("SELECT * FROM news")
    articles = c.fetchall()
    conn.close()
    return render_template('filtered_articles.html', articles=articles)

@app.route('/polarizing_articles', methods=['GET'])
def polarizing_articles():
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT * FROM news')
    articles = c.fetchall()
    polarizing_articles = []
    for article in articles:
        sentiment_score = article['sentiment_score']
        if sentiment_score > 0.9 or sentiment_score < -0.9:
            polarizing_articles.append(article) 
    conn.close()
    return render_template('polarizing_articles.html', articles=polarizing_articles)

@app.route('/analyze_sentiment_for_topic', methods=['GET'])
def analyze_sentiment_for_topic():
    selected_topic = request.args.get('topic')
    if not selected_topic:
        flash("Topic is required", "error")
        return redirect(url_for('dashboard'))  # Or redirect to an appropriate page
    conn = get_db()
    c = conn.cursor()
    # Fetch articles based on the selected topic
    c.execute('SELECT title, content FROM news WHERE category = ?', (selected_topic,))
    articles = c.fetchall()
    sentiment_analysis = []
    for article in articles:
        sentiment = analyze_sentiment(article['content'])
        sentiment_analysis.append({
            "title": article['title'],
            "sentiment": sentiment['sentiment'],
            "polarity": sentiment['polarity']
        })
    conn.close()
    return render_template('sentiment_analysis_for_topic.html', sentiment_analysis=sentiment_analysis, topic=selected_topic)


@app.route('/analyze_sentiment', methods=["POST"])
def analyze_sentiment_route():
    article = request.json.get("article")
    if not article:
        return jsonify({"error": "No article content provided"}), 400
    sentiment = analyze_sentiment(article)
    return jsonify(sentiment)
def analyze_sentiment(text):
    """Analyze the sentiment of a given text and return sentiment and polarity."""
    blob = TextBlob(text)
    polarity = blob.sentiment.polarity
    if polarity > 0:
        sentiment = "Positive"
    elif polarity < 0:
        sentiment = "Negative"
    else:
        sentiment = "Neutral"
    return {"sentiment": sentiment, "polarity": polarity}

@app.route('/logout', methods=['POST'])
def logout():
    """
    Logs the user out by clearing the session.
    """
    session.clear()  # Clear session data
    flash("You have been logged out.", "success")
    return redirect(url_for('login'))  # Redirect to login page or home

if __name__ == '__main__':
    init_db()
    fetch_news_from_api() # Fetch news articles from News API
    app.run(debug=False)