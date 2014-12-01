'use strict';
const crypto = require('crypto'),
    parseToken = /^[\w+/]{84}\|(\d+)/,
	vowels = 'aeiouy'.split(''),
	consonents = 'bcdfghjklmnpqrstvwxz'.split('');
function sanitizeAccount(item) {
	item._writable = true;
	item._username = item.__username;
	delete item.__auth;
	return item;
}
function generatePassword(length) {
	return (Array.prototype.map.call(crypto.randomBytes(length), function (random, index) {
		return ((index % 2 === 0) ?
			consonents[random % consonents.length]:
			vowels[random % vowels.length]);
	}).join(''));
}
module.exports = {
	mixins: [require('./base.controller')],
	hash: function (login, password) {
		return crypto
			.createHash('sha512')
			.update(login, 'utf8')
			.update(password, 'utf8')
			.update(this.secret.account, 'utf8')
			.digest('base64');
	},
	getNewPassword: function () {
		return generatePassword(6, true);
	},
	generateToken: function (minutes) {
		var token = this.fibers.wait(crypto, 'randomBytes', 63).toString('base64') + '|' + (Math.ceil(Date.now() / 60000) + minutes);
		setTimeout(function () {
			this.redis.getset(token, '');
		}.bind(this), 60000);
		return token;
	},
	getPermissions: function (accountId) {
		accountId = this.models.validoid.bind(this)(accountId);
		const permissions = {};
		this.mongo.get('accounts_permissions').find({__removed: null, __expired: { $gt: Date.now()}, accounts_id: accountId}).wait()
			.forEach(function (permission) { permissions[permission.value] = permission.__expired; });
		return permissions;
	},
	renewPermissions: function (accountId) {
		accountId = this.models.validoid.bind(this)(accountId);
		const keys = this.redis.keys('portal,session,' + accountId + ',*').wait(),
			sessions = this.redis.mget(keys);
		session.user._permissions = this.getPermissions(accountId);
		const sessionString = JSON.stringify(session);
		this.fibers.wait(keys.map(function (key) {
			return this.redis.setex(key, 604800, sessionString);
		}.bind(this)));
	},
	available: function (email) {
		if (this.mongo.get(this.collection).findOne({ __username: email, __removed: null }).wait()) {
			throw new this.ClientError('error:availability:accounts');
		}
		return [email];
	},
	models: {
		validpassword: function (password, args, index) {
			if ('string' === typeof password && password.length >= 6) {
				return password;
			}
			throw new this.ClientError('error:validation:password');
		},
		validtoken: function (token, args, index) {
			if (parseToken.test(token) && (((parseToken.exec(token) || [])[1]|0) * 60000) > Date.now()) {
				return token;
			}
			throw new this.ClientError('error:validation:token');
		}
	},
	methods: {
		login: function (email, password) {
			var user = this.mongo.get('accounts').findOne({
						__auth: this.hash(email, password),
						__username: email,
						__removed: null,
					}).wait();
			if (!user) { throw new this.ClientError('error:login:accounts');	}
			user._gravatar = crypto.createHash('md5').update(user.__username, 'utf8').digest('hex');
			user._permissions = this.getPermissions(user._id);
			this.xSessionKey = 'portal,session,' + user._id + ',' + this.fibers.wait(crypto, 'randomBytes', 513).toString('base64');
			delete user.__auth;
			this.redis.setex(this.xSessionKey, 604800, JSON.stringify({user:user, key: this.xSessionKey}));
			return [user];
		}
	},
	api: {
		session: ['authenticate', function () {
			return [this.session.user];
		}],
		logout: [function () {
			this.redis.del(this.session.key);
			return [];
		}],
		token: ['authenticate', function () {
			var token = this.fibers.wait(crypto, 'randomBytes', 63).toString('base64') + '|' + Math.ceil(Date.now() / 60000);
			this.redis.setex('portal,token,'+ token, 300000, this.sessionKey);
			return [token];
		}],
		find: ['admin', 'adminfind'],
		create: [['object'], function (document) {
			this.models.validemail.bind(this)(document.email);
			var email = this.available(document.email.trim().toLowerCase())[0],
				permissionsCollection = this.mongo.get('accounts_permissions'),
				password, id, account;
			if(typeof document.password1 === 'string') {
				if (document.password1.length < 6 || document.password1 !== document.password2) {
					throw new this.ClientError('error:validation:password');
				}
				password = document.password1;
			} else {
				password = this.getNewPassword();
			}
			id = document._id = this.mongo.oid();
			delete document.password1;
			delete document.password2;
			document.__username = email;
			document.__auth = this.hash(email, password);
			document.__permissions = ['read:account:' + id, 'write:account:' + id];
			document._created = Date.now();
			document._updated = Date.now();
			document.email = email;
			document.name = (document.name ? ('' + document.name) : '') || email.split('@')[0];
			account = this.mongo.get(this.collection).insert(document).wait();
			this.fibers.wait(['read:account:' + id, 'write:account:' + id, 'read:account:all', 'write:account:all']
				.map(function (permission) {
					return permissionsCollection.insert({
						accounts_id: id,
						value: permission,
						__permissions: ['read:account:' + id],
						__created: Date.now(),
						__updated: Date.now(),
						__expired: 32503701600000,
						__removed: null
					});
				}.bind(this)));
			this.ses('/accounts/create', {
				to: email,
				user: account,
				link: 'http://' + this.host + '/accounts/login/',
				password: password,
			});
			return [email, password];
		}, ['validemail', 'validpassword'], 'login'],
		login: [['validemail', 'validpassword'], 'login'],
		update: ['authenticate', ['defined'], ['query', 'object'], 'update', function () {
			const account = this.mongo.get('accounts').findOne({
					_id: this.session.user._id
				}).wait();
			if(!account) { throw new this.ServerError('Account Not Found.  Account: ' + this.session.user._id); }
			account._permissions = this.getPermissions(account._id);
			account._gravatar = crypto.createHash('md5').update(account.__username, 'utf8').digest('hex');
			this.redis.setex(this.session.key, 604800, JSON.stringify({ user: account, key: this.session.key}));
			return [account];
		}],
		resetpasswordemail: [['validemail'], function (email) {
			const accounts = this.mongo.get('accounts'),
				result = accounts.update({ __username: email, __removed: null, }, { $set: { __token: this.generateToken(24 * 60), }}).wait();
			if (result > 0) {
				const user = accounts.findOne({ __username: email, __removed: null, }).wait();
				this.ses('/accounts/resetpasswordemail', {
					to: email,
					user: user,
					link: 'http://' + this.host + '/resetpassword#token=' + encodeURIComponent(user.__token) + '&email=' + encodeURIComponent(user.__username) + '&action=resetpassword',
				});
			}
			return [];
		}],
		resetpassword: [['validemail', 'validtoken'], function (email, token) {
			const password = this.getNewPassword(),
				accounts = this.mongo.get('accounts'),
				result = accounts.update({
						__username: email,
						__token: token,
						__removed: null
					}, {
						$set: {
							__token: null,
							__auth: this.hash(email, password)
						}
				}).wait();
			if (result > 0) {
				const user = accounts.findOne({ __username: email, __auth: this.hash(email, password), __removed: null, }).wait();
				this.ses('/accounts/resetpassword', {
					to: email,
					user: user,
					link: 'http://' + this.host + '/',
					password: password,
				});
				return [];
			}
			throw new this.ClientError('error:validation:token');
		}],
		changepassword: ['authenticate', ['validemail', 'validpassword', 'validpassword'], function (email, password, changePassword) {
			const result = this.mongo.get('accounts').update({
					_id: this.session.user._id,
					__username: email,
					__auth: this.hash(email, password),
					__removed: null,
				}, {
					$set: {
						__token: null,
						__auth: this.hash(email, changePassword),
					}
				}).wait();
			if (result === 0) { throw new this.ClientError('error:validation:credentials'); }
			return [];
		}],
		changeusernameemail: ['authenticate', ['validemail', 'validpassword', 'validemail'], function (email, password, changeUsername) {
			this.available(changeUsername);
			const account = this.mongo.get('accounts'),
				result = account.update({
					_id: this.session.user._id,
					__username: email,
					__auth: this.hash(email, password),
					__removed: null,
				}, {
					$set: {
						__token: this.generateToken(24 * 60) + '|' + changeUsername,
					}
				}).wait();
			if (result === 0) { throw new this.ClientError('error:validation:credentials'); }
			const user = account.findOne({ __username: email, __removed: null }).wait();
			this.ses('/accounts/changeusername', {
				to: changeUsername,
				user: user,
				link: 'http://' + this.host + '/changeusername#token=' + encodeURIComponent(user.__token)+ '&email=' + encodeURIComponent(user.__username) + '&action=changeusername',
			});
			return [];
		}],
		changeusername: [['validemail', 'validpassword', 'validtoken'], function (email, password, token) {
			const changeUsername = (/[^\|]+$/.exec(token)||{})[0],
				result = this.mongo.get('accounts').update({
					__username: email,
					__auth: this.hash(email, password),
					__token: token,
					__removed: null,
				}, {
					$set: {
						__token: null,
						__username: changeUsername,
						__auth: this.hash(changeUsername, password),
					}
				}).wait();
			if (result === 0) { throw new this.ClientError('error:credentials:accounts'); }
			return [];
		}]
	}
};