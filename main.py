#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import webapp2
import os
import jinja2
import time
import random
import string
import hashlib
import hmac
import re

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

#store wiki pages
class Wiki(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)
    version = db.IntegerProperty()

class Wiki_History(db.Model):
    title = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    version = db.IntegerProperty(required = True)

#store user account information
class User(db.Model):
    username = db.StringProperty(required = True)
    hashed_pw = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

def make_salt():
    return ''.join(random.choice(string.letters) for x in range(5))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s|%s' % (h, salt)

def valid_pw(name, pw, h):
    salt = h.split('|')[1]
    if h == make_pw_hash(name, pw, salt):
        return True

SECRET = 'JBqwVPQuUI'

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    val = h.split('|')[0]
    if h == make_secure_val(val):
        return val
    
def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **params):
        self.write(self.render_str(template, **params))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        user_cookie = self.request.cookies.get('user_id')
        u_id = user_cookie and check_secure_val(user_cookie)
        self.user = u_id and User.get_by_id(int(u_id))

class MainHandler(Handler):
    def get(self):
        wiki = db.GqlQuery("select * from Wiki "
                           "where title='/'").get()
        if not wiki or (not wiki.content): content = "Welcome to my wiki website!"
        else: content = wiki.content
        username = self.user and self.user.username
        self.render("WikiPage.html", title = '/',
                    content = content, username = username)

class SignupHandler(Handler):
    def get(self):
        self.render("Signup.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True
        else:
            user_exists = db.GqlQuery("select * from User "
                                      "where username='%s'" % username).get()
            if user_exists:
                params['error_username'] = "Username already exists."
                have_error = True

        if not valid_password(password):
            params['error_password'] = "That's not a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('Signup.html', **params)
        else:
            hashed_pw = make_pw_hash(username, password)
            user = User(username=username, hashed_pw=hashed_pw, email=email)
            user.put()
            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s;Path=/' % make_secure_val(str(user.key().id())))
            self.redirect('/')            

class LoginHandler(Handler):
    def get(self):
        self.render('Login.html', error = '')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')
        user = db.GqlQuery("select * from User where username='%s'" % username).get()
        if not user:
            self.render('Login.html', error = 'User doesn\'t exist.')
            return
        if valid_pw(username, password, user.hashed_pw):
            self.response.headers.add_header('Set-Cookie',
                                             'user_id=%s;Path=/' % make_secure_val(str(user.key().id())))
            self.redirect('/')
        else:
            self.render('Login.html', error = 'Invalid login.')
            
class LogoutHandler(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=;Path=/')
        #self.redirect('/signup')
        self.redirect('/')

class EditPageHandler(Handler):
    def get(self, title):
        username = self.user and self.user.username
        if not username:
            self.redirect('/signup')
            return
        wiki = db.GqlQuery("select * from Wiki "
                           "where title='%s'" % title).get()
        if wiki: content = wiki.content
        else: content = ''
        self.render("EditWikiPage.html", content = content, username = username)
        self.write(content) #Testing purpose

    def post(self, title):
        content = self.request.get('content')
        if not content:
            self.render("EditWikiPage.html", content = content)
            self.write("Content can't be empty!")
            return
        wiki = db.GqlQuery("select * from Wiki "
                           "where title='%s'" % title).get()
        if wiki:
            if wiki.version is None: wiki.version = 0
            else: wiki.version += 1
            wiki.content = content
        else:
            wiki = Wiki(title = title, content = content, version = 1)
        wiki_h = Wiki_History(title = wiki.title, content = wiki.content,
                              version = wiki.version)
        wiki.put()
        wiki_h.put()
        self.redirect(title)

        time.sleep(0.1) #This is to avoid replication lab

class WikiPageHandler(Handler):
    def get(self, title):
        version = self.request.get('v') and int(self.request.get('v'))
        if version:
            wiki = db.GqlQuery("select * from Wiki_History "
                               "where title='%s' and version=%d" % (title, version)).get()
        else:
            wiki = db.GqlQuery("select * from Wiki "
                               "where title='%s'" % title).get()
        if not wiki:
            self.redirect('/_edit' + title)
            return
        username = self.user and self.user.username
        self.render("WikiPage.html", title = title,
                    content = wiki.content, username = username)

class HistoryHandler(Handler):
    def get(self, title):
        history = db.GqlQuery("select * from Wiki_History "
                              "where title='%s' "
                              "order by version desc" % title)
        history = list(history)
        self.render("History.html", title = title, history = history)

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/', MainHandler),
                               ('/signup', SignupHandler),
                               ('/login', LoginHandler),
                               ('/logout', LogoutHandler),
                               ('/_edit' + PAGE_RE, EditPageHandler),
                               ('/_history' + PAGE_RE, HistoryHandler),
                               (PAGE_RE, WikiPageHandler)], debug=True)
