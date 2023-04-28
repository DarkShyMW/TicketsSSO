const express = require('express');

const bodyParser = require('body-parser');

const passport = require('passport');

const JwtStrategy = require('passport-jwt').Strategy;

const ExtractJwt = require('passport-jwt').ExtractJwt;

const jwt = require('jsonwebtoken');

const mongoose = require('mongoose');

// Подключение к базе данных MongoDB

mongoose.connect('mongodb://localhost/tickets', { useNewUrlParser: true, useUnifiedTopology: true })

  .then(() => console.log('MongoDB connected'))

  .catch(err => console.log(err));

// Определение схемы для тикетов

const ticketSchema = new mongoose.Schema({

  title: String,

  description: String,

  status: { type: String, default: 'open' },

  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }

}, { timestamps: true });

// Определение схемы для пользователей

const userSchema = new mongoose.Schema({

  username: String,

  password: String

});

// Создание модели для тикетов

const Ticket = mongoose.model('Ticket', ticketSchema);

// Создание модели для пользователей

const User = mongoose.model('User', userSchema);

// Секретный ключ для подписи токенов

const secretKey = 'mysecretkey';

// Определение стратегии для аутентификации пользователей

const jwtOptions = {

  jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),

  secretOrKey: secretKey

};

passport.use(new JwtStrategy(jwtOptions, (jwt_payload, done) => {

  User.findById(jwt_payload.id, (err, user) => {

    if (err) {

      return done(err, false);

    }

    if (user) {

      return done(null, user);

    } else {

      return done(null, false);

    }

  });

}));

const app = express();

// Настройка парсера для обработки POST-запросов

app.use(bodyParser.urlencoded({ extended: false }));

app.use(bodyParser.json());

// Запрос на создание тикета

app.post('/tickets', passport.authenticate('jwt', { session: false }), (req, res) => {

  const { title, description } = req.body;

  const user = req.user._id;

  const ticket = new Ticket({ title, description, user });

  ticket.save((err) => {

    if (err) {

      res.status(500).json({ error: err.message });

    } else {

      res.status(201).json({ message: 'Ticket created successfully' });

    }

  });

});

// Запрос на получение списка тикетов

app.get('/tickets', passport.authenticate('jwt', { session: false }), (req, res) => {

  Ticket.find({ user: req.user._id }, (err, tickets) => {

    if (err) {

      res.status(500).json({ error: err.message });

    } else {

      res.json(tickets);

    }

  });

});

// Запрос на изменение статуса тикета

app.put('/tickets/:id', passport.authenticate('jwt', { session: false }), (req, res) => {

  const status = req.body.status;

  Ticket.findByIdAndUpdate(req.params.id, { status }, { new: true }, (err, ticket) => {

    if (err) {

      res.status(500).json({ error: err.message });

    } else if (!ticket) {

      res.status(404).json({ error: 'Ticket not found' });

    } else if (ticket.user.toString() !== req.user._id.toString()) {

      res.status(403).json({ error: 'Not authorized to modify this ticket' });

    } else {

      res.json(ticket);

    }

  });

});

// Запрос на удаление тикета

app.delete('/tickets/:id', passport.authenticate('jwt', { session: false }), (req, res) => {

  Ticket.findById(req.params.id, (err, ticket) => {

    if (err) {

      res.status(500).json({ error: err.message });

    } else if (!ticket) {

      res.status(404).json({ error: 'Ticket not found' });

    } else if (ticket.user.toString() !== req.user._id.toString()) {

      res.status(403).json({ error: 'Not authorized to delete this ticket' });

    } else {

      ticket.remove((err) => {

        if (err) {

          res.status(500).json({ error: err.message });

        } else {

          res.json({ message: 'Ticket deleted successfully' });

        }

      });

    }

  });

});

// Запрос на аутентификацию пользователя и получение токена

app.post('/login', (req, res) => {

  const { username, password } = req.body;

  User.findOne({ username }, (err, user) => {

    if (err) {

      res.status(500).json({ error: err.message });

    } else if (!user) {

      res.status(401).json({ error: 'Incorrect username or password' });

    } else {

      user.comparePassword(password, (err, isMatch) => {

        if (isMatch && !err) {

          const token = jwt.sign({ id: user._id }, secretKey);

          res.json({ token });

        } else {

          res.status(401).json({ error: 'Incorrect username or password' });

        }

      });

    }

  });

});

// Запрос на регистрацию нового пользователя

app.post('/register', (req, res) => {

  const { username, password } = req.body;

  const user = new User({ username, password });

  user.save((err) => {

    if (err) {

      res.status(500).json({ error: err.message });

    } else {

      res.status(201).json({ message: 'User created successfully' });

    }

  });

});

// Запуск сервера

app.listen(3000, () => {

  console.log('Server started on port 3000');

});
