import os
import re # regular expression
import random
import hashlib
import hmac
from string import letters

import webapp2
import jinja2

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

### UTILITY CLASSES
class Validator:
	"""Contains methods to validate form input through use of regex
	"""
	user_re = re.compile(r'^[a-zA-Z0-9_-]{3,20}$')
	pass_re = re.compile(r'^.{3,20}$')
	email_re = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

	@classmethod
	def valid_password(cls, password):
		"""checks that password exists and if it matches acceptable regex"""
		return password and cls.pass_re.match(password)

	@classmethod
	def valid_username(cls, username):
		"""checks that username exists and if it matches acceptable regex"""
		return username and cls.user_re.match(username)

	@classmethod
	def valid_email(cls, email):
		"""checks if email exists, if it does, it checks if it matches regex"""
		return not email or cls.email_re.match(email)


class Security:
	"""Contains methods to improve security of cookies and passwords
	"""
	secret = 'thisisasecret'

	@classmethod
	def make_secure(cls, val):
		"""hashes val and returns cookie ready value"""
		return '%s|%s' % (val, hmac.new(cls.secret, val).hexdigest())

	@classmethod
	def check_secure(cls, secure_val):
		"""checks cookie for tampering by rehashing"""
		val = secure_val.split('|')[0]
		if secure_val == cls.make_secure(val):
			return val

	@staticmethod
	def make_salt(length = 5):
		"""creates a string of 5 random letters"""
		return ''.join(random.choice(letters) for x in xrange(length))

	@classmethod
	def make_pw_hash(cls, name, pw, salt = None):
		"""hashes password with a salt"""
		if not salt:
			salt = cls.make_salt()
		h = hashlib.sha256(name + pw + salt).hexdigest()
		return '%s,%s' % (salt, h)

	@classmethod
	def valid_pw(cls, name, password, h):
		"""compares given password to db password"""
		salt = h.split(',')[0]
		return h == cls.make_pw_hash(name, password, salt)


### DATA MODELS
class User(db.Model):
	"""datastore data model for user"""
	name = db.StringProperty(required = True)
	pw_hash = db.StringProperty(required = True)
	email = db.StringProperty

	@classmethod
	def by_id(cls, uid):
		"""retrieve entity(record) by id"""
		return User.get_by_id(uid)

	@classmethod
	def by_name(cls, name):
		"""retrieve entity(record) by name"""
		u = User.all().filter('name =', name).get()
		return u

	@classmethod
	def register(cls, name, pw, email = None):
		"""hash new user password and return new user entity"""
		pw_hash = Security.make_pw_hash(name, pw)
		return User(name = name,
					pw_hash = pw_hash,
					email = email)

	@classmethod
	def login(cls, name, pw):
		"""check valid login credentials"""
		u = cls.by_name(name)
		if u and Security.valid_pw(name, pw, u.pw_hash):
			return u


class Page(db.Model):
	"""datastore data model for page content"""
	content = db.StringProperty(required = True, multiline = True)
	created = db.DateTimeProperty(auto_now_add = True)

	@classmethod
	def page_key(cls, name = 'default'):
		"""return valid key to be used as parent/ancestor id"""
		return db.Key.from_path('pages', name)
	

### URL HANDLERS
class ParentHandler(webapp2.RequestHandler):
	"""parent handler containing methods that abstract working with webapp2
	"""
	def initialize(self, *a, **kw):
		"""overide default initialize and set logged in user via cookies"""
		webapp2.RequestHandler.initialize(self, *a, **kw)
		# read incoming request for cookie header for user
		uid = self.read_secure_cookie('user_id')
		# set user if user exists and get entity
		self.user = uid and User.by_id(int(uid))

	def write(self, *a, **kw):
		"""writes to screen"""
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		"""returns string of html generated via jinja2 template"""
		# add user to params
		params['user'] = self.user
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		"""writes generated template to screen"""
		self.write(self.render_str(template, **kw))

	def set_secure_cookie(self, name, val):
		"""adds cookie to http response"""
		cookie_val = Security.make_secure(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		"""checks for tampering and returns cookie from http request"""
		cookie_val = self.request.cookies.get(name)
		return cookie_val and Security.check_secure(cookie_val)
		
	def login(self, user):
		"""sets user_id cookie to allow session browsing"""
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		"""clears user_id cookie on logout"""
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')


class SignUp(ParentHandler):
	def get(self):
		self.render("signup.html")

	def post(self):
		self.username = self.request.get('username')
		self.password = self.request.get('password')
		self.verify = self.request.get('verify')
		self.email = self.request.get('email')

		params = dict(username = self.username,
						email = self.email)

		have_error = False

		if not Validator.valid_username(self.username):
			have_error = True
			params['error_username'] = 'Invalid username!'

		if not Validator.valid_password(self.password):
			have_error = True
			params['error_password'] = 'Invalid password!'
		elif self.password != self.verify:
			have_error = True
			params['error_verify'] = 'Passwords do not match!'

		if not Validator.valid_email(self.email):
			have_error = True
			params['error_email'] = 'Invalid email address!'

		if have_error:
			self.render("signup.html", **params)
		else:
			self.done()

	def done(self, *a, **kw):
		#We could implement the class register here but instead we separate it out
		raise NotImplementedError


class Register(SignUp):
	def done(self):
		#Make sure user doesn't already exist
		u = User.by_name(self.username)
		if u:
			msg = 'Username already exists!'
			self.render('signup.html', error_username = msg)
		else:
			u = User.register(self.username, self.password, self.email)
			u.put()
			self.login(u)
			self.redirect('/')


class Login(ParentHandler):
	def get(self):
		self.render('login.html')

	def post(self):
		#Get the parameters out of the request
		username = self.request.get('username')
		password = self.request.get('password')

		#Get info from datastore for comparison
		u = User.login(username, password)
		if u:
			self.login(u)
			self.redirect('/')
		else:
			msg = 'Failed login attempt!'
			self.render('login.html', error = msg)


class Logout(ParentHandler):
	def get(self):
		self.logout()
		self.redirect('/')


class EditPage(ParentHandler):
	def get(self, url_path):
		if not self.user:
			self.redirect("/login")
			return

		#Form key from path
		parent = url_path
		ancestor_id = Page.page_key(parent)

		#Change flow if query string exists
		uni_id = self.request.get('v')
		if uni_id:
			key = db.Key.from_path('Page', int(uni_id), parent = ancestor_id)
			record = db.get(key)

			if record:
				self.render("edit.html", content = record.content)
				return
			self.write("Error: EditPage; no record for query string")
			return

		#Get all Page entities based on ancestor
		q = Page.all()
		pages = q.ancestor(ancestor_id).order('-created')

		if pages.count() > 0:
			self.render("edit.html", content = pages[0].content, page_path = parent)
		else:
			self.render("edit.html", content="")

	def post(self, url_path):
		if not self.user:
			self.redirect("/login")
			return

		parent = url_path
		ancestor_id = Page.page_key(parent)

		content = self.request.get('content')

		if content:
			#Change flow if query string exists
			uni_id = self.request.get('v')
			if uni_id:
				key = db.Key.from_path('Page', int(uni_id), parent = ancestor_id)
				p = db.get(key)
				#Update content
				p.content = content
			else:
				#If no query string create new Page entity
				p = Page(parent = ancestor_id, content = content)

			p.put()
			self.redirect('//%s' % parent)
		else:
			self.render("edit.html", parent = ancestor_id, content = content,
				error_content = "Oops! You forgot to enter content!")


class HistoryPage(ParentHandler):
	def get(self, url_path):
		#Form key from path
		parent = url_path
		ancestor_id = Page.page_key(parent)

		#Get all Page entities based on ancestor
		q = Page.all()
		pages = q.ancestor(ancestor_id).order('-created')

		self.render("history.html", pages = pages, page_path = parent)


class PageGenerator(ParentHandler):
	def get(self, url_path):
		#Form key from path
		parent = url_path
		ancestor_id = Page.page_key(parent)

		#Change flow if query string exists
		uni_id = self.request.get('v')
		if uni_id:
			key = db.Key.from_path('Page', int(uni_id), parent = ancestor_id)
			record = db.get(key)

			if record:
				self.render("page.html", content = record.content, page_path = parent)
				return
			self.write("no record")
			return

		#Get all Page entities based on ancestor
		q = Page.all()
		pages = q.ancestor(ancestor_id).order('-created')
		
		if pages.count() > 0:
			self.render("page.html", content = pages[0].content, page_path = parent)
		else:
			self.redirect('/_edit' + parent)

	
PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'

app = webapp2.WSGIApplication([
	('/signup', Register),
	('/login', Login),
	('/logout', Logout),
	('/_edit' + PAGE_RE, EditPage),
	('/_history' + PAGE_RE, HistoryPage),
	(PAGE_RE, PageGenerator)
	], debug = True)

