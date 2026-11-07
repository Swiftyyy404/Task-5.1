import { Instructor } from '../models/Instructor.js';

// =============================================================================
//  INSTRUCTOR PORTAL CONTROLLER  —  ⚠️ INTENTIONALLY VULNERABLE (security lab)
// =============================================================================
//
// Unlike the review/auth controllers in this project, these handlers do NOT
// validate input with Joi and the app has NO express-mongo-sanitize. They pass
// `req.body` / `req.query` straight into Mongoose. Because Express parses JSON
// bodies and bracket-notation query strings into nested objects, an attacker
// can smuggle MongoDB query operators ($ne, $gt, $regex, $where, ...) into
// what the code treats as plain strings.
//
// This is the bug students must find and fix. Do not "clean this up".
// =============================================================================

function publicProfile(doc) {
  // A successful login is a "trophy": we deliberately return the sensitive
  // fields so a bypass clearly reveals what it compromised.
  return {
    id: doc._id.toString(),
    name: doc.name,
    username: doc.username,
    department: doc.department,
    role: doc.role,
    apiKey: doc.apiKey,
    privateEmail: doc.privateEmail,
    privatePhone: doc.privatePhone
  };
}

// POST /api/instructors/login
export async function loginInstructor(req, res, next) {
  try {
    const { username, password } = req.body;

    // 1. Type check: only plain strings are allowed. Objects like {$ne:null} or {$regex:"^S"} are rejected before they ever reach MongoDB.
    if (typeof username !== 'string' || typeof password !== 'string' ||
        !username || !password) {
      return res.status(400).json({ message: 'username and password are required' });
    }

    // 2. Look up by username ONLY. The password is never part of the query.
    const instructor = await Instructor.findOne({ username }).select('+password');

    // 3. Check the password in code with bcrypt. Use the SAME response for
    //    "no such user" and "wrong password" so there is no oracle.
    const ok = instructor && (await instructor.comparePassword(password));
    if (!ok) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    return res.json({ instructor: publicProfile(instructor) });
  } catch (err) {
    next(err);
  }
}


// GET /api/instructors
// Public directory. Deliberately limited fields so the contrast with the
// leaky /search endpoint below is obvious.
export async function getDirectory(req, res, next) {
  try {
    const instructors = await Instructor.find()
      .select('name department role')
      .sort({ name: 1 })
      .lean();
    res.json({ instructors });
  } catch (err) {
    next(err);
  }
}


// Escape regex metacharacters so user text is matched literally.
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
} 

// GET /api/instructors/search
export async function searchInstructors(req, res, next) {
  try {
    // 1. Allow-list: only `name` is accepted, and only as a string.
    //    role[$ne], username[$regex], $where... are all ignored.
    const { name } = req.query;
    const filter = {};
    if (typeof name === 'string' && name.trim()) {
      filter.name = { $regex: escapeRegex(name.trim()), $options: 'i' };
    }

    // 2. Projection: only return public fields, never secrets.
    const instructors = await Instructor.find(filter)
      .select('name department role')
      .lean();

    res.json({ count: instructors.length, instructors });
  } catch (err) {
    next(err);
  }
}

