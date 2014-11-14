'use strict';
function $search(search) {
	var terms = [];
	(''+(search||'')).replace(/\".*?\"|\w+/g, function (term) {
		term = term.toLowerCase().replace(/^and$/, '');
		if (/^"/.test(term)) {
			term = term.replace(/"/g, '').replace(/([.*+?^=!:${}()|\[\]\/\\])/g, "\\$1").replace(/^\W+|\W+$/g, '').replace(/\W+/g, '\\W+');
		}
		if (term) { terms.push(term); }
	});
	return { $regex: (/^\^/.test(search) ? '^' : '' ) + terms.join('[^\|]*?').replace(/\.\*\?or\.\*\?/g, '|').replace(/^\.\*\?or|or\.\*\?$/g, '') + (/\$$/.test(search) ? '$' : '' ), $options: 'i' };
}
function filter(filter, permissions, includeRemoved) {
	if ('string' === typeof filter) {
		filter = { _id: filter };
	}
	filter = filter || {};
	//TODO: delete $where: scripts
	if (permissions instanceof RegExp) {
		permissions = Object.keys(this.session.permissions).filter(function (permission) { return (permissions.test(permission) && this.session.permissions[permission] > Date.now()); }, this);
	} else if (permissions instanceof Function) {
		permissions = Object.keys(this.session.permissions).filter(function (permission) { this.session.permissions[permission] > Date.now(); }, this).filter(permissions, this);
	}
	if (Array.isArray(permissions) && permissions.length > 0) {
		filter.__permissions = { $in: permissions };
	}
	if (!includeRemoved) {
		filter.__removed = null;
	}
	return filter;
}

function adminfilter(filter, permissions, includeRemoved) {
	if ('string' === typeof filter) {
		filter = { _id: filter };
	}
	filter = filter || {};
	//TODO: delete $where: scripts
	
	//remove permission checking on permissions
	// if (permissions instanceof RegExp) {
		// permissions = Object.keys(this.session.permissions).filter(function (permission) { return (permissions.test(permission) && this.session.permissions[permission] > Date.now()); }, this);
	// } else if (permissions instanceof Function) {
		// permissions = Object.keys(this.session.permissions).filter(function (permission) { this.session.permissions[permission] > Date.now(); }, this).filter(permissions, this);
	// }
	// if (Array.isArray(permissions) && permissions.length > 0) {
		// filter.__permissions = { $in: permissions };
	// }
	
	
	if (!includeRemoved) {
		filter.__removed = null;
	}
	return filter;
}

function permits(permissions, filter) {
	var userPermissions = Object.keys(this.session.permissions).filter(function (permission) { return this.session.permissions[permission] > Date.now(); }, this),
		index, userIndex,
		length, userLength;
	if (filter instanceof RegExp) {
		userPermissions = userPermissions.filter(function (permission) {
			return filter.test(permission);
		});
	} else if (filter instanceof Function) {
		userPermissions = userPermissions.filter(filter);
	}
	length = permissions.length;
	userLength = userPermissions.length;
	index = 0;
	while (index < length) {
		userIndex = 0;
		while (userIndex < userLength) {
			if (userPermissions[userIndex].toLowerCase() === permissions[index].toLowerCase()) {
				return true;
			}
			userIndex += 1;
		}
		index += 1;
	}
	return false;
}
function $bypass(option) {
	Object.keys(option).forEach(function (key) {
		if (/^\$_[^_]/.test(key)) {
			option[key.substring(1)] = option[key];
			delete option[key];
			key = key.substring(1);
		}
	});
}
module.exports = {
	namespace: '',
	initialization: function () {
		if (this.collection && !/\.controller\.js$/.test(this.collection)) {
			const collection = this.mongo.get(this.collection);
			collection.ensureIndex('_created');
			collection.ensureIndex('_updated');
			collection.ensureIndex('__removed');
		}
	},
	methods: {
		authenticate: function () {
			if(!this.session.user) { throw new this.ClientError('error:authentication:authenticate'); }
			return Array.prototype.slice.call(arguments);
		},
		admin:['authenticate', function () {
			if (!this.session.user.__admin) { throw new this.ClientError('error:authentication:authenticate'); }
			return Array.prototype.slice.call(arguments);
		}],
		adminfind: function (query, options) {
			if (options && options.more) { options.limit += 1; }
			const results = this.mongo.get(this.collection).find(adminfilter.bind(this)(query, /^read/), options).wait()
				.map(function (item) {
					item._writable = true;
					return item;
				}.bind(this));
			if (options && options.more) {
				options.limit -= 1;
				query.search = query.__search;
				Object.keys(query).forEach(function () {
					if (query[key] && query[key].$regex) {
						query[key] = { $search: query[key].search };
					}
				});
				let more = { previous: (options.skip > 0), next: (results.length > options.limit), query: this.originalArguments[0], options: this.originalArguments[1] };
				if (more && results.length > options.limit) { results.pop(); }
				return [results, more];
			}
			return [results];
		},
		find: [['query', 'options'], function (query, options) {
			if (options && options.more) { options.limit += 1; }
			const results = this.mongo.get(this.collection).find(filter.bind(this)(query, /^read/), options).wait()
				.map(function (item) {
					item._writable = permits.bind(this)(item.__permissions, /^write/);
					return item;
				}.bind(this));
			if (options && options.more) {
				options.limit -= 1;
				query.search = query.__search;
				Object.keys(query).forEach(function () {
					if (query[key] && query[key].$regex) {
						query[key] = { $search: query[key].search };
					}
				});
				let more = { previous: (options.skip > 0), next: (results.length > options.limit), query: this.originalArguments[0], options: this.originalArguments[1] };
				if (more && results.length > options.limit) { results.pop(); }
				return [results, more];
			}
			return [results];
		}],
		count: [['query', 'options'], function (query, options) {
			return [this.mongo.get(this.collection).count(filter.bind(this)(query, /^read/), options).wait()];
		}],
		create: [['object'], function (document) {
			document.__permissions = (Array.isArray(document.__permissions) ? document.__permissions : []).concat([
				'read:account:' + this.session.user._id,
				'write:account:' + this.session.user._id
			]);
			document.__owner_id= this.session.user._id;
			document._created = Date.now();
			document._updated = Date.now();
			
			document.__search = JSON.stringify(Object.keys(document)
				.sort()
				.reduce(function (reducedObj, key) {
					if (!/^__/.test(key)) {
						reducedObj[key] = document[key];
					}
					return reducedObj;
				}, {}));
			return [this.mongo.get(this.collection).insert(document).wait()]
		}],
		remove: [['query'], function (query) {
			return [this.mongo.get(this.collection).update(filter.bind(this)(query, /^write/), { $set: { __removed: Date.now() } }).wait()]
		}],
		update: [['query', 'object'], function (query, document) {
			const setDocument = {},
				unsetDocument = {},
				update = {},
				oldDoc = this.mongo.get(this.collection)
					.findOne(filter.bind(this)(query, /^write/))
					.wait(),
				search = JSON.parse(oldDoc.__search || null) || Object.keys(oldDoc)
					.reduce(function (reducedObj, key) {
						if (!/^__/.test(key)) {
							reducedObj[key] = oldDoc[key];
						}
						return reducedObj;
					}, {});
			document = document || {};
			delete document._created;
			delete document._id;
			delete document.__owner_id;
			delete document.__removed;
			delete document.__permissions;
			document._updated = Date.now();
			Object.keys(document).forEach(function (key) {
				if(document[key] === null) {
					unsetDocument[key] = '';
					update.$unset = unsetDocument;
				} else if(document[key] !== void 0) {
					setDocument[key] = document[key];
				}
			});
			Object.keys(unsetDocument)
				.forEach(function (key) { delete search[key]; });
			
			Object.keys(setDocument)
				.forEach(function (key) { search[key] = setDocument[key]; });
			setDocument.__search = JSON.stringify(search);
			update.$set = setDocument;
			return [this.mongo.get(this.collection).update(filter.bind(this)(query, /^write/), update).wait()];
		}],
		types: [['query', 'options'], function (query, options) {
			if (options && options.more) { options.limit += 1; }
			const results = this.mongo.get(this.collection + '_types').find(filter.bind(this)(query, /^read/), options).wait()
				.map(function (item) {
					item._writable = permits.bind(this)(item.__permissions, /^write/);
					return item;
				}.bind(this));
			if (options && options.more) {
				options.limit -= 1;
				query.search = query.__search;
				Object.keys(query).forEach(function () {
					if (query[key] && query[key].$regex) {
						query[key] = { $search: query[key].search };
					}
				});
				let more = { previous: (options.skip > 0), next: (results.length > options.limit), query: this.originalArguments[0], options: this.originalArguments[1] };
				if (more && results.length > options.limit) { results.pop(); }
				return [results, more];
			}
			return [results];
		}],
		items: [['query', 'options'], function (query, options) {
			if (options && options.more) { options.limit += 1; }
			const results = this.mongo.get(this.collection + '_items').find(filter.bind(this)(query, /^read/), options).wait()
				.map(function (item) {
					item._writable = permits.bind(this)(item.__permissions, /^write/);
					return item;
				}.bind(this));
			if (options && options.more) {
				options.limit -= 1;
				query.search = query.__search;
				Object.keys(query).forEach(function () {
					if (query[key] && query[key].$regex) {
						query[key] = { $search: query[key].search };
					}
				});
				let more = { previous: (options.skip > 0), next: (results.length > options.limit), query: this.originalArguments[0], options: this.originalArguments[1] };
				if (more && results.length > options.limit) { results.pop(); }
				return [results, more];
			}
			return [results];
		}]
	},
	models: {
		falsy: function (object) {
			if (object) {
				throw new this.ClientError('error:validation:falsy');
			}
			return object;
		},
		truthy: function (object) {
			if (!object) {
				throw new this.ClientError('error:validation:truthy');
			}
			return object;
		},
		defined: function (object) {
			if (object == null) {
				throw new this.ClientError('error:validation:defined');
			}
			return object;
		},
		undefined: function (object) {
			if (object != null) {
				throw new this.ClientError('error:validation:undefined');
			}
			return object;
		},
		any: function (object) {
			return object;
		},
		array: function (array) {
			return Array.isArray(array) ? array : [];
		},
		string: function (string) {
			return 'string' === typeof string ? string : (JSON.stringify(string) || '');
		},
		validjsonstring: function (json) {
			try {
				JSON.parse(this.models.validstring.call(this, json));
				return json;
			} catch (e) {
				throw new this.ClientError('error:validation:json');
			}
		},
		object: function (object) {
			return ((object && object.constructor === Object) ? object : {});
		},
		validstring: function (string) {
			if ('string' !== typeof string) { throw new this.ClientError('error:validation:string'); }
			return string;
		},
		validphone: function (phone) {
			phone = phone.replace(/\D+/g, '');
			if (phone.length < 10) { throw new this.ClientError('error:validation:phone'); }
			return phone;
		},
		validarray: function (array) {
			if (!Array.isArray(array)) { throw new this.ClientError('error:validation:array'); }
			return array;
		},
		phone: function (phone) {
			phone = phone.replace(/\D+/g, '');
			if (phone.length < 10) {
				return '';
			}
			return phone;
		},
		validoidarray: function(array) {
			return this.model('array', array).map(function (oid) {
				return this.model('validoid', oid);
			}, this);
		},
		int: function (number) {
			return (0 | number);
		},
		datetime: function (date) {
			date = Math.floor(+date);
			return (date !== date ?  0 : date);
		},
		number: function (number) {
			number = 1 * number;
			return (number !== number ?  0 : number);
		},
		validemail: function (email) {
			if (email !== '' && !/^.+?@.+?\..+?$/.test(email)) {
				throw new this.ClientError('error:validation:email');
			}
			return email;
		},
		email: function (email) {
			if (!/^.+?@.+?\..+?$/.test(email)) {
				return '';
			}
			return email;
		},
		bool: function (bool) {
			return (true === bool ||
				('string' === typeof bool &&
					'true' === bool.toLowerCase()));
		},
		validdomainname: function (domain) {
			domain = ('' + (domain || '')).toLowerCase().replace(/\s+/g, '');
			if (!/^.+?\..+?$/.test(domain)) {
				throw new this.ClientError('error:validation:domain');
			}
			return domain;
		},
		options: function (options) {
			options = options || {};
			if(options.sort) { $bypass(options.sort); }
			if(options.fields) { $bypass(options.fields); }
			return {
				sort: options.sort || '_created',
				fields: options.fields,
				more: !!options.more,
				skip: 0|options.skip,
				limit: 0|options.limit > 1000 ? 1000 : 0|options.limit||25,
			};
		},
		validoid: function (id) {
			if(id) {
				if (id.$oid) { id = id.$oid; }
				if (id instanceof this.fibers.mongo.ObjectID) { return id; }
				id = this.models.string.call(this, id);
				try { if(id.length >= 24) { return this.mongo.oid(id); } } catch (e) {}
			}
			throw new this.ClientError('error:validation:oid');
		},
		validType: function (query) {
			var result = this.mongo.get(this.collection + '_types').findOne(filter.bind(this)(query, /^read/)).wait();
			if (!result) { throw new this.ClientError('error:validation:' + this.collection + '_types'); }
			return result;
		},
		query: function (query) {
			function cleanFilter(filter) {
				var i = 0;
				if (Array.isArray(filter)) {
					while (i < filter.length) {
						filter[i] = cleanFilter.bind(this)(filter[i]);
						i += 1;
					}
				} else if (filter && 'object' === typeof filter) {
					if (filter.$search) { return $search(filter.$search); }
					if (filter.$oid) { return this.models.validoid.call(this, filter.$oid); }
					delete filter.$where;
					delete filter.$regex;
					Object.keys(filter).forEach(function (key) {
						if (/^\$_[^_]/.test(key)) {
							filter[key.substring(1)] = filter[key];
							delete filter[key];
							key = key.substring(1);
						}
						filter[key] = cleanFilter.bind(this)(filter[key]);
						if (/_ids?$/.test(key)) {
							if (Array.isArray(filter[key])) {
								filter[key] = { $in: this.models.validoidarray.call(this, filter[key]) };
							} else {
								filter[key] = this.models.validoid.call(this, filter[key]);
							}
						}
					}.bind(this));
				}
				return filter;
			}
			if ('string' === typeof query || Array.isArray(query)) { query = { _id: query }; }
			query = cleanFilter.bind(this)(query);
			if (!query) { query = {}; }
			if (query.search) {
				query.__search = query.search;
				delete query.search;
			}
			return query;
		},
		sqlquery: function (query) {
			function cleanFilter(filter) {
				var i = 0;
				if (Array.isArray(filter)) {
					while (i < filter.length) {
						filter[i] = cleanFilter.bind(this)(filter[i]);
						i += 1;
					}
				} else if (filter && 'object' === typeof filter) {
					if (filter.$search) { return $search(filter.$search); }
					if (filter.$oid) { return '' + this.models.validoid.call(this, filter.$oid); }
					delete filter.$where;
					delete filter.$regex;
					Object.keys(filter).forEach(function (key) {
						if (/^\$_[^_]/.test(key)) {
							filter[key.substring(1)] = filter[key];
							delete filter[key];
							key = key.substring(1);
						}
						filter[key] = cleanFilter.bind(this)(filter[key]);
						if (/_ids?$/.test(key)) {
							if (Array.isArray(filter[key])) {
								filter[key] = { $in: this.models.validoidarray.call(this, filter[key]).map(function (oid) { return '' + oid; }) };
							} else {
								filter[key] = '' + this.models.validoid.call(this, filter[key]);
							}
						}
					}.bind(this));
				}
				return filter;
			}
			if ('string' === typeof query || Array.isArray(query)) { query = { _id: query }; }
			query = cleanFilter.bind(this)(query);
			if (!query) { query = {}; };
			return query;
		}
	}
};