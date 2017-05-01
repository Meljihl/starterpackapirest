var mongoose = require('mongoose');
var router = require('express').Router();
var passport = require('passport');
var User = mongoose.model('User');
var auth = require('../auth');


router.post('/users', function (req, res, next) {
	var user = new User();

	user.username = req.body.user.username;
	user.email = req.body.user.email;
	user.setPassword(req.body.user.password);

	user.save().then(function() {
		return res.json({user: user.toAuthJson()});
	}).catch(next); // catch error of the ddb
});


router.post('/users/login', function(req, res, next) {
	if(!req.body.user.email) {
		return res.status(422).json({errors: {email: "cannot be empty"}});
	}

	if(!req.body.user.password) {
		return res.status(422).json({errors: {password: "cannot be empty"}});
	}

	passport.authenticate('local', {session: false}, function (err, user, info) { // Define new strategy to login and disable session strat
		if (err) {
			return next(err);
		}

		if (user) {
			user.token = user.generateJWT();
			return res.json({user: user.toAuthJson()});
		} else {
			return res.status(422).json(info);
		}
	})(req, res, next);
});

router.get('/user', auth.required, function(req, res, next) { // Get current user auth payload from his token
	User.findById(req.payload.id).then(function(user) {
		if (!user) {
			return res.sendStatus(401);
		}

		return res.json({user: user.toAuthJson()});
	}).catch(next);
});

router.put('/user', auth.required, function(req, res, next) {
	User.findById(req.payload.id).then(function(user) {
		if (!user) {
			return res.sendStatus(401);
		}

		if (typeof req.body.user.username !== 'undefined') {
			user.username = req.body.user.username;
		}

		if (typeof req.body.user.email !== 'undefined') {
			user.email = req.body.user.email;
		}

		if (typeof req.body.user.bio !== 'undefined') {
			user.bio = req.body.user.bio;
		}

		if (typeof req.body.user.image !== 'undefined') {
			user.image = req.body.user.image;
		}

		if (typeof req.body.user.password !== 'undefined') {
			user.setPassword(req.body.user.password);
		}

		return user.save().then(function() {
			return res.json({user: user.toAuthJson()});
		});

	}).catch(next);
});

module.exports = router;