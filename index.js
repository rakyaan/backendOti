const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const secretKey = 'abcd1234';


const users = [];


function authenticateUser(req, res, next) {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, secretKey);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}


const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'test1234',
  database: 'event_registration2',
});


db.connect((err) => {
  if (err) {
    console.error('Error connecting to the database:', err);
    return;
  }
  console.log('Connected to the database');

  db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(255),
      password_hash VARCHAR(255)
    )
  `);

  db.query(`
    CREATE TABLE IF NOT EXISTS events (
      id INT AUTO_INCREMENT PRIMARY KEY,
      name VARCHAR(255),
      description TEXT,
      date_time DATETIME,
      quota_available INT,
      quota_taken INT,
      created_by INT,
      FOREIGN KEY (created_by) REFERENCES users (id)
    )
  `);

  db.query(`
    CREATE TABLE IF NOT EXISTS registrations (
      id INT AUTO_INCREMENT PRIMARY KEY,
      event_id INT,
      user_id INT,
      FOREIGN KEY (event_id) REFERENCES events (id),
      FOREIGN KEY (user_id) REFERENCES users (id)
    )
  `);
});


app.post('/register', (req, res) => {
  const { username, password } = req.body;
  const existingUser = users.find((u) => u.username === username);

  if (existingUser) {
    res.status(400).json({ error: 'Username already exists' });
    return;
  }

  const hashedPassword = bcrypt.hashSync(password, 10);
  const newUser = { id: users.length + 1, username, passwordHash: hashedPassword };
  users.push(newUser);

  db.query('INSERT INTO users (username, password_hash) VALUES (?, ?)', [username, hashedPassword], (err) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }

    res.json({ message: 'User registered successfully' });
  });
});


app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (user && bcrypt.compareSync(password, user.passwordHash)) {
    const token = jwt.sign({ id: user.id, username: user.username }, secretKey, {
      expiresIn: '1h', 
    });
    res.json({ token });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.get('/events', (req, res) => {
  db.query('SELECT * FROM events', (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json(results);
  });
});


app.post('/events/:eventId/register', authenticateUser, (req, res) => {
  const userId = req.user.id;
  const eventId = req.params.eventId;

  db.query('SELECT * FROM events WHERE id = ?', [eventId], (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }

    const event = results[0];
    if (!event) {
      res.status(404).json({ error: 'Event not found' });
      return;
    }

    if (event.quota_available > event.quota_taken) {
      db.query(
        'INSERT INTO registrations (event_id, user_id) VALUES (?, ?)',
        [eventId, userId],
        (err) => {
          if (err) {
            res.status(500).json({ error: err.message });
            return;
          }

          db.query('UPDATE events SET quota_taken = quota_taken + 1 WHERE id = ?', [eventId], (err) => {
            if (err) {
              res.status(500).json({ error: err.message });
              return;
            }

            res.json({ message: 'Registration successful' });
          });
        }
      );
    } else {
      res.status(400).json({ error: 'Event quota is full' });
    }
  });
});

app.delete('/events/:eventId/cancel/:registrationId', authenticateUser, (req, res) => {
  const registrationId = req.params.registrationId;

  const userId = req.user.id;

  db.query('SELECT user_id, event_id FROM registrations WHERE id = ?', [registrationId], (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }

    const registration = results[0];

    if (!registration) {
      res.status(404).json({ error: 'Registration not found' });
      return;
    }

    if (registration.user_id !== userId) {
      res.status(403).json({ error: 'Forbidden - You do not have permission to cancel this registration' });
      return;
    }


    db.query('DELETE FROM registrations WHERE id = ?', [registrationId], (err) => {
      if (err) {
        res.status(500).json({ error: err.message });
        return;
      }

      db.query('UPDATE events SET quota_taken = quota_taken - 1 WHERE id = ?', [registration.event_id], (err) => {
        if (err) {
          res.status(500).json({ error: err.message });
          return;
        }

        res.json({ message: 'Registration canceled successfully' });
      });
    });
  });
});

app.post('/logout', (req, res) => {
    res.json({ message: 'Logout successful' });
  });

app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
